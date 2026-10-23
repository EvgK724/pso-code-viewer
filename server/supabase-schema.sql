-- DRAFT: apply only to a NEW, separately approved Supabase project.
-- No patient names, public API credentials, or device private keys belong here.
-- This is a reviewable schema script, not a generated Supabase migration.
begin;

create schema if not exists pso_shortlink_private;
revoke all on schema pso_shortlink_private from public, anon, authenticated;
grant usage on schema pso_shortlink_private to service_role;

create table if not exists pso_shortlink_private.writers (
  sender_id text primary key check (sender_id ~ '^[A-Za-z0-9_-]{43}$'),
  signing_spki text not null check (signing_spki ~ '^[A-Za-z0-9_-]{122}$'),
  enabled boolean not null default false
);

create table if not exists pso_shortlink_private.links (
  id_hash text primary key check (id_hash ~ '^[0-9a-f]{64}$'),
  request_hash text not null check (request_hash ~ '^[0-9a-f]{64}$'),
  sender_id text not null references pso_shortlink_private.writers(sender_id),
  token text not null check (
    token ~ '^PSO1\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{512}\.[A-Za-z0-9_-]{86}$'
  ),
  issued bigint not null,
  expires bigint not null,
  created_at timestamptz not null default clock_timestamp(),
  check (issued > 0 and expires > issued and expires - issued <= 86400000)
);
create index if not exists pso_shortlink_expiry_idx
  on pso_shortlink_private.links (expires);

-- Counters are independent of the ciphertext records, so expiry/deletion cannot
-- reset quotas. Buckets are UTC minutes and UTC days, calculated by the server.
create table if not exists pso_shortlink_private.quotas (
  subject text not null,
  period text not null check (period in ('minute', 'day')),
  bucket bigint not null,
  used integer not null check (used >= 0),
  primary key (subject, period, bucket)
);

alter table pso_shortlink_private.writers enable row level security;
alter table pso_shortlink_private.links enable row level security;
alter table pso_shortlink_private.quotas enable row level security;
revoke all on all tables in schema pso_shortlink_private from public, anon, authenticated;
-- The function service is trusted; no browser receives this role's credential.
grant select, update(enabled) on pso_shortlink_private.writers to service_role;
-- UPDATE on one writer column is required by PostgreSQL for SELECT FOR SHARE;
-- the private schema is not exposed, and there is no writer-update RPC.
grant select, insert on pso_shortlink_private.links to service_role;
grant select, insert, update on pso_shortlink_private.quotas to service_role;

create or replace function public.pso_shortlink_writer(p_sender_id text)
returns jsonb language sql stable security invoker set search_path = '' as $$
  select jsonb_build_object('signing_spki', w.signing_spki, 'enabled', w.enabled)
  from pso_shortlink_private.writers w
  where w.sender_id = p_sender_id and w.enabled;
$$;

create or replace function public.pso_shortlink_put(
  p_id_hash text, p_request_hash text, p_sender_id text,
  p_token text, p_issued bigint, p_expires bigint
) returns text language plpgsql security invoker set search_path = '' as $$
declare
  v_now bigint;
  v_minute bigint;
  v_day bigint;
  v_enabled boolean;
  v_old pso_shortlink_private.links%rowtype;
begin
  if p_id_hash is null or p_id_hash !~ '^[0-9a-f]{64}$'
    or p_request_hash is null or p_request_hash !~ '^[0-9a-f]{64}$'
    or p_sender_id is null or p_sender_id !~ '^[A-Za-z0-9_-]{43}$'
    or p_token is null or p_token !~ '^PSO1\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{512}\.[A-Za-z0-9_-]{86}$'
    or split_part(p_token, '.', 3) <> p_sender_id
    or p_issued is null or p_expires is null
    or p_issued <= 0 or p_expires <= p_issued
    or p_expires::numeric - p_issued::numeric > 86400000
  then return 'denied'; end if;

  -- Small-volume service: serialize admission to make all three quotas and
  -- insert/idempotency checks atomic, including across Edge Function instances.
  perform pg_catalog.pg_advisory_xact_lock(1347637075, 1);
  v_now := floor(extract(epoch from clock_timestamp()) * 1000)::bigint;
  if p_issued < v_now - 60000 or p_issued > v_now + 30000 or p_expires <= v_now
  then return 'denied'; end if;

  -- A concurrent administrator disabling this writer must serialize with this
  -- statement. The Edge Function's earlier key lookup is not authorization here.
  select enabled into v_enabled
    from pso_shortlink_private.writers where sender_id = p_sender_id for share;
  if v_enabled is distinct from true then return 'denied'; end if;

  select * into v_old from pso_shortlink_private.links where id_hash = p_id_hash;
  if found then
    if v_old.request_hash = p_request_hash and v_old.sender_id = p_sender_id
      and v_old.token = p_token and v_old.issued = p_issued and v_old.expires = p_expires
    then return 'exists'; else return 'conflict'; end if;
  end if;

  v_minute := v_now / 60000;
  v_day := v_now / 86400000;
  insert into pso_shortlink_private.quotas(subject, period, bucket, used) values
    ('global', 'day', v_day, 0),
    (p_sender_id, 'day', v_day, 0),
    (p_sender_id, 'minute', v_minute, 0)
  on conflict do nothing;

  if exists (
    select 1 from pso_shortlink_private.quotas
    where (subject = 'global' and period = 'day' and bucket = v_day and used >= 5000)
       or (subject = p_sender_id and period = 'day' and bucket = v_day and used >= 200)
       or (subject = p_sender_id and period = 'minute' and bucket = v_minute and used >= 10)
  ) then return 'limited'; end if;

  update pso_shortlink_private.quotas set used = used + 1
    where (subject = 'global' and period = 'day' and bucket = v_day)
       or (subject = p_sender_id and period = 'day' and bucket = v_day)
       or (subject = p_sender_id and period = 'minute' and bucket = v_minute);
  insert into pso_shortlink_private.links(id_hash, request_hash, sender_id, token, issued, expires)
    values(p_id_hash, p_request_hash, p_sender_id, p_token, p_issued, p_expires);
  return 'created';
end;
$$;

create or replace function public.pso_shortlink_resolve(p_id_hash text)
returns jsonb language sql volatile security invoker set search_path = '' as $$
  select jsonb_build_object('token', l.token, 'expires', l.expires)
  from pso_shortlink_private.links l
  where l.id_hash = p_id_hash
    and l.expires > floor(extract(epoch from clock_timestamp()) * 1000)::bigint;
$$;

create or replace function pso_shortlink_private.cleanup()
returns void language plpgsql security invoker set search_path = '' as $$
declare v_now bigint := floor(extract(epoch from clock_timestamp()) * 1000)::bigint;
begin
  delete from pso_shortlink_private.links where expires <= v_now;
  delete from pso_shortlink_private.quotas
    where (period = 'minute' and bucket < v_now / 60000 - 2880)
       or (period = 'day' and bucket < v_now / 86400000 - 2);
end;
$$;

-- PostgreSQL functions otherwise inherit EXECUTE for PUBLIC at creation.
revoke all on function public.pso_shortlink_writer(text) from public, anon, authenticated;
revoke all on function public.pso_shortlink_put(text,text,text,text,bigint,bigint) from public, anon, authenticated;
revoke all on function public.pso_shortlink_resolve(text) from public, anon, authenticated;
revoke all on function pso_shortlink_private.cleanup() from public, anon, authenticated;
grant execute on function public.pso_shortlink_writer(text) to service_role;
grant execute on function public.pso_shortlink_put(text,text,text,text,bigint,bigint) to service_role;
grant execute on function public.pso_shortlink_resolve(text) to service_role;

commit;

-- REQUIRED before enabling the frontend: enable Supabase Cron / pg_cron, then:
-- select cron.schedule('pso-shortlink-cleanup', '* * * * *',
--   'select pso_shortlink_private.cleanup()');
-- Verify that exactly one such job is active and its job runs succeed.
