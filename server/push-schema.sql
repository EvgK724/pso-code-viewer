-- Reviewable schema script for the existing dedicated PSO short-link project.
-- Not a generated migration. Apply once reviewed; never expose this schema.
-- No patient plaintext is stored. Push endpoints and the VAPID private key are
-- server-only credentials; never SELECT their values into logs or client output.
begin;

create schema if not exists pso_push_private;
revoke all on schema pso_push_private from public, anon, authenticated;
grant usage on schema pso_push_private to service_role;

create or replace function pso_push_private.valid_id(p_value text)
returns boolean language sql immutable strict security invoker set search_path = '' as $$
  select p_value ~ '^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$';
$$;
create or replace function pso_push_private.valid_nonce(p_value text)
returns boolean language sql immutable strict security invoker set search_path = '' as $$
  select p_value ~ '^[A-Za-z0-9_-]{21}[AQgw]$';
$$;

create table if not exists pso_push_private.vapid (
  singleton boolean primary key default true check(singleton),
  keys jsonb not null check(jsonb_typeof(keys) = 'object'),
  created_at timestamptz not null default clock_timestamp()
);
create table if not exists pso_push_private.subscriptions (
  device_id text primary key check(pso_push_private.valid_id(device_id)),
  endpoint_hash text not null unique check(endpoint_hash ~ '^[0-9a-f]{64}$'),
  subscription jsonb not null check(jsonb_typeof(subscription) = 'object'),
  senders text[] not null check(cardinality(senders) between 1 and 100),
  refreshed_at timestamptz not null default clock_timestamp()
);
create index if not exists pso_push_subscriptions_refresh_idx on pso_push_private.subscriptions(refreshed_at);
create table if not exists pso_push_private.nonces (
  device_id text not null check(pso_push_private.valid_id(device_id)),
  nonce text not null check(pso_push_private.valid_nonce(nonce)),
  created_at timestamptz not null default clock_timestamp(),
  primary key(device_id,nonce)
);
create index if not exists pso_push_nonces_created_idx on pso_push_private.nonces(created_at);
create table if not exists pso_push_private.quotas (
  subject text not null,
  period text not null check(period in ('minute','day','test-minute')),
  bucket bigint not null,
  used integer not null check(used >= 0),
  primary key(subject,period,bucket)
);
create table if not exists pso_push_private.claims (
  id_hash text primary key check(id_hash ~ '^[0-9a-f]{64}$'),
  sender_id text not null check(pso_push_private.valid_id(sender_id)),
  recipient_id text not null check(pso_push_private.valid_id(recipient_id)),
  endpoint_hash text not null check(endpoint_hash ~ '^[0-9a-f]{64}$'),
  status text not null default 'sending' check(status in ('sending','accepted','gone','failed')),
  created_at timestamptz not null default clock_timestamp()
);
create index if not exists pso_push_claims_created_idx on pso_push_private.claims(created_at);

alter table pso_push_private.vapid enable row level security;
alter table pso_push_private.subscriptions enable row level security;
alter table pso_push_private.nonces enable row level security;
alter table pso_push_private.quotas enable row level security;
alter table pso_push_private.claims enable row level security;
revoke all on all tables in schema pso_push_private from public, anon, authenticated;
grant select,insert on pso_push_private.vapid to service_role;
grant select,insert,update,delete on pso_push_private.subscriptions to service_role;
grant select,insert on pso_push_private.nonces to service_role;
grant select,insert,update on pso_push_private.quotas to service_role;
grant select,insert,update on pso_push_private.claims to service_role;

create or replace function public.pso_push_keys(p_candidate jsonb default null)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare v_keys jsonb;
begin
  -- Configuration initializes only once; normal requests supply NULL.
  perform pg_catalog.pg_advisory_xact_lock(1347637076,2);
  select keys into v_keys from pso_push_private.vapid where singleton;
  if found then return v_keys; end if;
  if p_candidate is null then return null; end if;
  if jsonb_typeof(p_candidate) is distinct from 'object'
    or p_candidate - array['publicKey','privateKey'] <> '{}'::jsonb
    or (p_candidate->>'publicKey') !~ '^[A-Za-z0-9_-]{86}[AEIMQUYcgkosw048]$'
    or p_candidate->>'publicKey' is null
    or jsonb_typeof(p_candidate->'privateKey') is distinct from 'object'
    or p_candidate->'privateKey'->>'kty' is distinct from 'EC'
    or p_candidate->'privateKey'->>'crv' is distinct from 'P-256'
    or pso_push_private.valid_id(p_candidate->'privateKey'->>'x') is distinct from true
    or pso_push_private.valid_id(p_candidate->'privateKey'->>'y') is distinct from true
    or pso_push_private.valid_id(p_candidate->'privateKey'->>'d') is distinct from true
    or octet_length(p_candidate::text) > 2048
  then raise exception 'Invalid push key configuration'; end if;
  -- The Edge Function creates and validates matching P-256 keys. DB only checks
  -- shape; it cannot be reached by a browser role or changed after initialization.
  insert into pso_push_private.vapid(singleton,keys) values(true,p_candidate);
  return p_candidate;
end;
$$;

create or replace function public.pso_push_accept(
  p_device_id text,p_nonce text,p_op text,p_issued bigint
) returns text language plpgsql security invoker set search_path = '' as $$
declare v_now bigint; v_minute bigint; v_day bigint;
begin
  if pso_push_private.valid_id(p_device_id) is distinct from true
    or pso_push_private.valid_nonce(p_nonce) is distinct from true
    or p_op is null or p_op not in ('register','unregister','status','test','notify')
    or p_issued is null then return 'invalid'; end if;
  perform pg_catalog.pg_advisory_xact_lock(1347637076,1);
  v_now := floor(extract(epoch from clock_timestamp())*1000)::bigint;
  if p_issued < v_now-60000 or p_issued > v_now+30000 then return 'invalid'; end if;
  if exists(select 1 from pso_push_private.nonces where device_id=p_device_id and nonce=p_nonce)
    then return 'replay'; end if;
  v_minute:=v_now/60000; v_day:=v_now/86400000;
  -- Check the global budget before creating any per-device records. Unknown
  -- signed identities cannot grow the table once the global limit is exhausted.
  insert into pso_push_private.quotas(subject,period,bucket,used)
    values('global','day',v_day,0) on conflict do nothing;
  if exists(select 1 from pso_push_private.quotas where subject='global'
    and period='day' and bucket=v_day and used>=10000) then return 'limited'; end if;
  insert into pso_push_private.quotas(subject,period,bucket,used) values
    (p_device_id,'minute',v_minute,0),(p_device_id,'day',v_day,0) on conflict do nothing;
  if p_op='test' then
    insert into pso_push_private.quotas values(p_device_id,'test-minute',v_minute,0) on conflict do nothing;
  end if;
  if exists(select 1 from pso_push_private.quotas where
       (subject='global' and period='day' and bucket=v_day and used>=10000)
    or (subject=p_device_id and period='minute' and bucket=v_minute and used>=20)
    or (subject=p_device_id and period='day' and bucket=v_day and used>=500)
    or (p_op='test' and subject=p_device_id and period='test-minute' and bucket=v_minute and used>=3))
    then return 'limited'; end if;
  insert into pso_push_private.nonces(device_id,nonce) values(p_device_id,p_nonce);
  update pso_push_private.quotas set used=used+1 where
       (subject='global' and period='day' and bucket=v_day)
    or (subject=p_device_id and period='minute' and bucket=v_minute)
    or (subject=p_device_id and period='day' and bucket=v_day)
    or (p_op='test' and subject=p_device_id and period='test-minute' and bucket=v_minute);
  return 'ok';
end;
$$;

create or replace function public.pso_push_register(
  p_device_id text,p_subscription jsonb,p_senders text[]
) returns text language plpgsql security invoker set search_path = '' as $$
declare v_hash text; v_senders text[]; v_endpoint text;
begin
  if pso_push_private.valid_id(p_device_id) is distinct from true
    or p_subscription is null or jsonb_typeof(p_subscription) is distinct from 'object'
    or p_subscription - array['endpoint','keys'] <> '{}'::jsonb
    or jsonb_typeof(p_subscription->'keys') is distinct from 'object'
    or (p_subscription->'keys') - array['p256dh','auth'] <> '{}'::jsonb
    or (p_subscription->'keys'->>'p256dh') is null
    or (p_subscription->'keys'->>'p256dh') !~ '^B[A-Za-z0-9_-]{85}[AEIMQUYcgkosw048]$'
    or pso_push_private.valid_nonce(p_subscription->'keys'->>'auth') is distinct from true
    or p_senders is null or cardinality(p_senders)>100
    or exists(select 1 from unnest(p_senders) s where pso_push_private.valid_id(s) is distinct from true)
    or octet_length(p_subscription::text)>4096
  then return 'conflict'; end if;
  v_endpoint:=p_subscription->>'endpoint';
  -- Network implementation additionally parses URL/canonical form, imports the
  -- P-256 point, and forbids redirects. SQL keeps a second bounded allowlist.
  if v_endpoint is null or length(v_endpoint)>2048 or
    v_endpoint !~ '^https://(([a-z0-9-]+\.)+push\.apple\.com|fcm\.googleapis\.com|updates\.push\.services\.mozilla\.com)/[^[:space:]#]+$'
    then return 'conflict'; end if;
  select array_agg(distinct s order by s) into v_senders from unnest(p_senders||array[p_device_id]) s;
  if cardinality(v_senders)>100 then return 'conflict'; end if;
  v_hash:=encode(sha256(convert_to(v_endpoint,'UTF8')),'hex');
  perform pg_catalog.pg_advisory_xact_lock(1347637076,1);
  -- Stale subscriptions neither receive notifications nor reserve the capacity.
  delete from pso_push_private.subscriptions where refreshed_at < clock_timestamp()-interval '90 days';
  if exists(select 1 from pso_push_private.subscriptions where endpoint_hash=v_hash and device_id<>p_device_id)
    then return 'conflict'; end if;
  if not exists(select 1 from pso_push_private.subscriptions where device_id=p_device_id)
    and (select count(*) from pso_push_private.subscriptions)>=500 then return 'limited'; end if;
  insert into pso_push_private.subscriptions(device_id,endpoint_hash,subscription,senders,refreshed_at)
    values(p_device_id,v_hash,p_subscription,v_senders,clock_timestamp())
    on conflict(device_id) do update set endpoint_hash=excluded.endpoint_hash,
      subscription=excluded.subscription,senders=excluded.senders,refreshed_at=excluded.refreshed_at;
  return 'ok';
end;
$$;

create or replace function public.pso_push_unregister(p_device_id text)
returns text language plpgsql security invoker set search_path = '' as $$
begin
  perform pg_catalog.pg_advisory_xact_lock(1347637076,1);
  delete from pso_push_private.subscriptions where device_id=p_device_id;
  return 'ok';
end;
$$;
create or replace function public.pso_push_status(p_device_id text)
returns boolean language sql volatile security invoker set search_path = '' as $$
  select exists(select 1 from pso_push_private.subscriptions
    where device_id=p_device_id and refreshed_at>=clock_timestamp()-interval '90 days');
$$;
create or replace function public.pso_push_test_subscription(p_device_id text)
returns jsonb language sql volatile security invoker set search_path = '' as $$
  select subscription from pso_push_private.subscriptions
    where device_id=p_device_id and refreshed_at>=clock_timestamp()-interval '90 days';
$$;

create or replace function public.pso_push_claim(p_sender_id text,p_id_hash text)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare v_link pso_shortlink_private.links%rowtype;
  v_sub pso_push_private.subscriptions%rowtype;
  v_claim pso_push_private.claims%rowtype;
  v_enabled boolean; v_recipient text; v_now bigint;
begin
  if pso_push_private.valid_id(p_sender_id) is distinct from true
    or p_id_hash is null or p_id_hash !~ '^[0-9a-f]{64}$'
    then return jsonb_build_object('status','unavailable'); end if;
  perform pg_catalog.pg_advisory_xact_lock(1347637076,1);
  v_now:=floor(extract(epoch from clock_timestamp())*1000)::bigint;
  -- Edge authenticates the device signature; DB binds the operation to the
  -- already-verified ciphertext and rechecks disabled writers atomically.
  select enabled into v_enabled from pso_shortlink_private.writers
    where sender_id=p_sender_id for share;
  if v_enabled is distinct from true then return jsonb_build_object('status','unavailable'); end if;
  select * into v_link from pso_shortlink_private.links
    where id_hash=p_id_hash and sender_id=p_sender_id and expires>v_now;
  if not found or split_part(v_link.token,'.',3)<>p_sender_id
    then return jsonb_build_object('status','unavailable'); end if;
  v_recipient:=split_part(v_link.token,'.',2);
  select * into v_claim from pso_push_private.claims where id_hash=p_id_hash;
  if found then
    return jsonb_build_object('status',case when v_claim.status='sending' then 'already' else v_claim.status end);
  end if;
  select * into v_sub from pso_push_private.subscriptions where device_id=v_recipient
    and refreshed_at>=clock_timestamp()-interval '90 days' and p_sender_id=any(senders);
  if not found then return jsonb_build_object('status','unavailable'); end if;
  insert into pso_push_private.claims(id_hash,sender_id,recipient_id,endpoint_hash)
    values(p_id_hash,p_sender_id,v_recipient,v_sub.endpoint_hash);
  return jsonb_build_object('status','ready','subscription',v_sub.subscription,
    'recipient_id',v_recipient,'expires',v_link.expires);
end;
$$;

create or replace function public.pso_push_finish(p_id_hash text,p_status text)
returns text language plpgsql security invoker set search_path = '' as $$
declare v_claim pso_push_private.claims%rowtype;
begin
  if p_status is null or p_status not in ('accepted','gone','failed') then return 'invalid'; end if;
  perform pg_catalog.pg_advisory_xact_lock(1347637076,1);
  select * into v_claim from pso_push_private.claims where id_hash=p_id_hash and status='sending' for update;
  if not found then return 'unchanged'; end if;
  update pso_push_private.claims set status=p_status where id_hash=p_id_hash;
  if p_status='gone' then
    -- Do not delete a newer replacement subscribed while the HTTP call ran.
    delete from pso_push_private.subscriptions where device_id=v_claim.recipient_id
      and endpoint_hash=v_claim.endpoint_hash;
  end if;
  return 'ok';
end;
$$;

create or replace function pso_push_private.cleanup()
returns void language plpgsql security invoker set search_path = '' as $$
declare v_now bigint:=floor(extract(epoch from clock_timestamp())*1000)::bigint;
begin
  perform pg_catalog.pg_advisory_xact_lock(1347637076,1);
  delete from pso_push_private.nonces where created_at<clock_timestamp()-interval '2 minutes';
  delete from pso_push_private.quotas where
    (period in ('minute','test-minute') and bucket<v_now/60000-2880)
    or (period='day' and bucket<v_now/86400000-2);
  delete from pso_push_private.claims where created_at<clock_timestamp()-interval '2 days';
  delete from pso_push_private.subscriptions where refreshed_at<clock_timestamp()-interval '90 days';
end;
$$;

revoke all on all functions in schema pso_push_private from public, anon, authenticated;
grant execute on function pso_push_private.valid_id(text),pso_push_private.valid_nonce(text) to service_role;
revoke all on function public.pso_push_keys(jsonb),public.pso_push_accept(text,text,text,bigint),
  public.pso_push_register(text,jsonb,text[]),public.pso_push_unregister(text),public.pso_push_status(text),
  public.pso_push_test_subscription(text),public.pso_push_claim(text,text),public.pso_push_finish(text,text)
  from public,anon,authenticated;
grant execute on function public.pso_push_keys(jsonb),public.pso_push_accept(text,text,text,bigint),
  public.pso_push_register(text,jsonb,text[]),public.pso_push_unregister(text),public.pso_push_status(text),
  public.pso_push_test_subscription(text),public.pso_push_claim(text,text),public.pso_push_finish(text,text)
  to service_role;

-- New dedicated job; no existing short-link job or schedule is changed.
do $$ begin
  if not exists(select 1 from cron.job where jobname='pso-push-cleanup') then
    perform cron.schedule('pso-push-cleanup','* * * * *','select pso_push_private.cleanup()');
  end if;
end; $$;
commit;
