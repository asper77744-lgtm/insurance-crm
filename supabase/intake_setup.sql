-- ══════════════════════════════════════════════════════════════
--  보험CRM · 고객 직접입력(기본정보 / 병력설문) 설정
--  Supabase 대시보드 → SQL Editor → 전체 붙여넣고 Run (1회만)
-- ══════════════════════════════════════════════════════════════

create extension if not exists pgcrypto with schema extensions;

-- 1) 발급한 입력 링크(토큰)
create table if not exists intake_requests (
  token          text primary key,
  user_id        uuid not null references auth.users on delete cascade,
  kind           text not null check (kind in ('basic','medical')),
  customer_name  text,
  customer_id    bigint,              -- 병력설문: CRM 고객 id
  agent_name     text,
  expires_at     timestamptz not null,
  used_at        timestamptz,
  created_at     timestamptz not null default now()
);

-- 2) 고객이 제출한 내용 (접수함)
create table if not exists intake_submissions (
  id             bigserial primary key,
  user_id        uuid not null references auth.users on delete cascade,
  token          text not null,
  kind           text not null,
  customer_name  text,
  customer_id    bigint,
  data           jsonb not null,      -- 입력값 (병력설문은 질문 문구까지 함께 저장)
  meta           jsonb,               -- 동의 내역, 기기 정보
  sha256         text not null,       -- 제출 시점 위변조 확인용 해시
  status         text not null default 'pending', -- pending / imported / rejected
  created_at     timestamptz not null default now(),
  imported_at    timestamptz
);
create index if not exists intake_sub_user_idx on intake_submissions(user_id, status);

alter table intake_requests    enable row level security;
alter table intake_submissions enable row level security;

-- 설계사: 자기 링크만 조회·생성·취소
drop policy if exists req_owner on intake_requests;
create policy req_owner on intake_requests for all
  using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- 설계사: 자기 접수건만 조회 / 상태 변경 / (기본정보만) 삭제
drop policy if exists sub_select on intake_submissions;
drop policy if exists sub_update on intake_submissions;
drop policy if exists sub_delete on intake_submissions;
create policy sub_select on intake_submissions for select using (auth.uid() = user_id);
create policy sub_update on intake_submissions for update
  using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy sub_delete on intake_submissions for delete
  using (auth.uid() = user_id and kind = 'basic');
-- INSERT 정책 없음 → 아래 submit_intake 함수로만 들어옴

-- 3) 병력설문 원본 보호: 내용·제출시각·해시 수정 금지, 삭제 금지
create or replace function intake_guard() returns trigger
language plpgsql as $$
begin
  if tg_op = 'UPDATE' then
    if new.data is distinct from old.data
       or new.meta is distinct from old.meta
       or new.sha256 is distinct from old.sha256
       or new.created_at is distinct from old.created_at
       or new.kind is distinct from old.kind
       or new.token is distinct from old.token
       or new.user_id is distinct from old.user_id then
      raise exception '제출 원본은 수정할 수 없습니다';
    end if;
    return new;
  elsif tg_op = 'DELETE' then
    if old.kind = 'medical' then
      raise exception '병력설문 원본은 삭제할 수 없습니다';
    end if;
    return old;
  end if;
  return null;
end $$;

drop trigger if exists intake_guard_trg on intake_submissions;
create trigger intake_guard_trg before update or delete on intake_submissions
  for each row execute function intake_guard();

-- 해시 계산 (시간대 설정과 무관하게 UTC 고정 형식)
create or replace function intake_hash(p_token text, p_at timestamptz, p_data jsonb)
returns text language sql immutable set search_path = public as $$
  select encode(extensions.digest(convert_to(
    p_token || '|' || to_char(p_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
            || '|' || p_data::text, 'UTF8'), 'sha256'), 'hex')
$$;
revoke all on function intake_hash(text, timestamptz, jsonb) from public;

-- 4) 고객용: 링크 확인 (이름·종류만 반환)
create or replace function get_intake(p_token text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r intake_requests;
begin
  select * into r from intake_requests where token = p_token;
  if not found then return jsonb_build_object('ok', false, 'reason', 'invalid'); end if;
  if r.used_at is not null then return jsonb_build_object('ok', false, 'reason', 'used'); end if;
  if r.expires_at < now() then return jsonb_build_object('ok', false, 'reason', 'expired'); end if;
  return jsonb_build_object('ok', true, 'kind', r.kind, 'customer_name', r.customer_name,
                            'agent_name', r.agent_name, 'expires_at', r.expires_at);
end $$;

-- 5) 고객용: 제출 (1회용, 유효기간 확인, 서버 시각·해시 기록)
create or replace function submit_intake(p_token text, p_data jsonb, p_meta jsonb)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r intake_requests; v_now timestamptz := now(); v_hash text;
begin
  if length(p_data::text) > 400000 then
    return jsonb_build_object('ok', false, 'reason', 'too_large');
  end if;
  select * into r from intake_requests where token = p_token for update;
  if not found then return jsonb_build_object('ok', false, 'reason', 'invalid'); end if;
  if r.used_at is not null then return jsonb_build_object('ok', false, 'reason', 'used'); end if;
  if r.expires_at < v_now then return jsonb_build_object('ok', false, 'reason', 'expired'); end if;

  v_hash := intake_hash(p_token, v_now, p_data);

  insert into intake_submissions(user_id, token, kind, customer_name, customer_id, data, meta, sha256, created_at)
  values (r.user_id, p_token, r.kind, r.customer_name, r.customer_id, p_data, p_meta, v_hash, v_now);

  update intake_requests set used_at = v_now where token = p_token;
  return jsonb_build_object('ok', true, 'submitted_at', v_now, 'receipt', upper(left(v_hash, 12)));
end $$;

-- 6) 설계사용: 저장된 원본이 제출 당시 그대로인지 해시 재계산으로 확인
create or replace function verify_intake(p_id bigint)
returns boolean language plpgsql security definer set search_path = public as $$
declare s intake_submissions;
begin
  select * into s from intake_submissions where id = p_id and user_id = auth.uid();
  if not found then return null; end if;
  return s.sha256 = intake_hash(s.token, s.created_at, s.data);
end $$;
revoke all on function verify_intake(bigint) from public;
grant execute on function verify_intake(bigint) to authenticated;

revoke all on function get_intake(text) from public;
revoke all on function submit_intake(text, jsonb, jsonb) from public;
grant execute on function get_intake(text) to anon, authenticated;
grant execute on function submit_intake(text, jsonb, jsonb) to anon, authenticated;
