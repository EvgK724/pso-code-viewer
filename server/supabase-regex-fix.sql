-- Repair for the initial deployed schema: PostgreSQL bounded regex repetition
-- cannot use {512}. New installations already include this fix in schema.sql.
-- Applied as migration pso_shortlink_regex_and_sender_index on 2026-10-23.
begin;
create index if not exists pso_shortlink_sender_idx on pso_shortlink_private.links (sender_id);
alter table pso_shortlink_private.links drop constraint links_token_check;
alter table pso_shortlink_private.links add constraint links_token_check check (token ~ '^PSO1\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{128}[A-Za-z0-9_-]{128}[A-Za-z0-9_-]{128}[A-Za-z0-9_-]{128}\.[A-Za-z0-9_-]{86}$');
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
    or p_token is null or p_token !~ '^PSO1\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{128}[A-Za-z0-9_-]{128}[A-Za-z0-9_-]{128}[A-Za-z0-9_-]{128}\.[A-Za-z0-9_-]{86}$'
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

commit;
