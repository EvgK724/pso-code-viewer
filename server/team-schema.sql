-- Role-based PSO workflow. Review and apply in the existing dedicated project.
-- This file contains no real staff cards, names, device IDs, or credentials.
-- Bootstrap the administrator separately from an already verified signing key.
begin;
create schema if not exists pso_team_private;
revoke all on schema pso_team_private from public,anon,authenticated;
grant usage on schema pso_team_private to service_role;

create or replace function pso_team_private.valid_id(p_value text)
returns boolean language sql immutable strict security invoker set search_path='' as $$
 select p_value ~ '^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$';
$$;
create or replace function pso_team_private.valid_nonce(p_value text)
returns boolean language sql immutable strict security invoker set search_path='' as $$
 select p_value ~ '^[A-Za-z0-9_-]{21}[AQgw]$';
$$;
create or replace function pso_team_private.valid_hash(p_value text)
returns boolean language sql immutable strict security invoker set search_path='' as $$
 select p_value ~ '^[0-9a-f]{64}$';
$$;
create or replace function pso_team_private.valid_card(p_value text)
returns boolean language sql immutable strict security invoker set search_path='' as $$
 select p_value ~ '^PSO-CARD1\.[A-Za-z0-9_-]+$' and octet_length(p_value) between 100 and 5000;
$$;
create or replace function pso_team_private.valid_token(p_value text)
returns boolean language sql immutable strict security invoker set search_path='' as $$
 select p_value ~ '^PSO1\.[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]\.[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]\.[A-Za-z0-9_-]{128}[A-Za-z0-9_-]{128}[A-Za-z0-9_-]{128}[A-Za-z0-9_-]{128}\.[A-Za-z0-9_-]{85}[AQgw]$';
$$;

create table if not exists pso_team_private.members (
 device_id text primary key check(pso_team_private.valid_id(device_id)),
 name text not null check(char_length(name) between 1 and 60 and name !~ '[[:cntrl:]]'),
 role text not null check(role in ('admin','neurologist','cardiologist','intensivist','bot')),
 state text not null check(state in ('pending','active','revoked')),
 card text check(card is null or pso_team_private.valid_card(card)),
 signing_spki text not null check(signing_spki ~ '^[A-Za-z0-9_-]{121}[AQgw]$'),
 invite_hash text check(invite_hash is null or pso_team_private.valid_hash(invite_hash)),
 created_at timestamptz not null default clock_timestamp(),
 approved_at timestamptz,
 revoked_at timestamptz,
 check(role='admin' or card is not null)
);
create unique index if not exists pso_team_one_cardiologist on pso_team_private.members((role)) where role='cardiologist' and state='active';
create unique index if not exists pso_team_one_bot on pso_team_private.members((role)) where role='bot' and state='active';
create index if not exists pso_team_member_state_role on pso_team_private.members(state,role);
create table if not exists pso_team_private.invites (
 id_hash text primary key check(pso_team_private.valid_hash(id_hash)),
 inviter_id text not null references pso_team_private.members(device_id),
 name text not null check(char_length(name) between 1 and 60 and name !~ '[[:cntrl:]]'),
 role text not null check(role in ('neurologist','cardiologist','intensivist','bot')),
 expires bigint not null,
 claimed_by text check(claimed_by is null or pso_team_private.valid_id(claimed_by)),
 created_at timestamptz not null default clock_timestamp()
);
create index if not exists pso_team_invite_expiry on pso_team_private.invites(expires);
create index if not exists pso_team_invite_inviter on pso_team_private.invites(inviter_id);
create table if not exists pso_team_private.nonces (
 device_id text not null check(pso_team_private.valid_id(device_id)),
 nonce text not null check(pso_team_private.valid_nonce(nonce)),
 created_at timestamptz not null default clock_timestamp(),
 primary key(device_id,nonce)
);
create index if not exists pso_team_nonce_created on pso_team_private.nonces(created_at);
create table if not exists pso_team_private.quotas (
 subject text not null,
 period text not null check(period in ('minute','day','create-minute','create-day','invite-day')),
 bucket bigint not null,
 used integer not null check(used>=0),
 primary key(subject,period,bucket)
);
create table if not exists pso_team_private.links (
 id_hash text primary key check(pso_team_private.valid_hash(id_hash)),
 request_hash text not null check(pso_team_private.valid_hash(request_hash)),
 sender_id text not null references pso_team_private.members(device_id),
 group_name text not null check(group_name in ('cardiology','orit')),
 kind text not null check(kind in ('admission','review')),
 issued bigint not null,
 expires bigint not null,
 created_at timestamptz not null default clock_timestamp(),
 check(issued>0 and expires>issued and expires-issued<=86400000)
);
create index if not exists pso_team_link_expiry on pso_team_private.links(expires);
create index if not exists pso_team_link_sender on pso_team_private.links(sender_id);
create table if not exists pso_team_private.entries (
 id_hash text not null references pso_team_private.links(id_hash) on delete cascade,
 recipient_id text not null references pso_team_private.members(device_id),
 token text not null check(pso_team_private.valid_token(token)),
 primary key(id_hash,recipient_id),
 check(split_part(token,'.',2)=recipient_id)
);
create index if not exists pso_team_entry_recipient on pso_team_private.entries(recipient_id);
create table if not exists pso_team_private.push_claims (
 id_hash text not null references pso_team_private.links(id_hash) on delete cascade,
 recipient_id text not null references pso_team_private.members(device_id),
 endpoint_hash text not null check(pso_team_private.valid_hash(endpoint_hash)),
 status text not null default 'sending' check(status in ('sending','accepted','gone','failed')),
 created_at timestamptz not null default clock_timestamp(),
 primary key(id_hash,recipient_id)
);
create index if not exists pso_team_push_recipient on pso_team_private.push_claims(recipient_id);

alter table pso_team_private.members enable row level security;
alter table pso_team_private.invites enable row level security;
alter table pso_team_private.nonces enable row level security;
alter table pso_team_private.quotas enable row level security;
alter table pso_team_private.links enable row level security;
alter table pso_team_private.entries enable row level security;
alter table pso_team_private.push_claims enable row level security;
revoke all on all tables in schema pso_team_private from public,anon,authenticated;
grant select,insert,update on pso_team_private.members,pso_team_private.invites,pso_team_private.quotas,pso_team_private.push_claims to service_role;
grant select,insert on pso_team_private.nonces,pso_team_private.links,pso_team_private.entries to service_role;

create or replace function pso_team_private.is_admin(p_device_id text)
returns boolean language sql stable security invoker set search_path='' as $$
 select exists(select 1 from pso_team_private.members where device_id=p_device_id and role='admin' and state='active');
$$;
create or replace function public.pso_team_accept(p_device_id text,p_nonce text,p_op text,p_issued bigint,p_card text,p_signing_spki text)
returns text language plpgsql security invoker set search_path='' as $$
declare v_now bigint;v_minute bigint;v_day bigint;v_member pso_team_private.members%rowtype;
begin
 if pso_team_private.valid_id(p_device_id) is distinct from true or pso_team_private.valid_nonce(p_nonce) is distinct from true
 or pso_team_private.valid_card(p_card) is distinct from true or p_signing_spki is null or p_signing_spki !~ '^[A-Za-z0-9_-]{121}[AQgw]$'
 or p_op is null or p_op not in ('status','directory','invite','claim','pending','approve','revoke','create','resolve') or p_issued is null then return 'denied';end if;
 perform pg_catalog.pg_advisory_xact_lock(1347637077,1);
 v_now:=floor(extract(epoch from clock_timestamp())*1000)::bigint;
 if p_issued<v_now-60000 or p_issued>v_now+30000 then return 'denied';end if;
 if exists(select 1 from pso_team_private.nonces where device_id=p_device_id and nonce=p_nonce) then return 'replay';end if;
 select * into v_member from pso_team_private.members where device_id=p_device_id;
 if found and v_member.signing_spki<>p_signing_spki then return 'denied';end if;
 v_minute:=v_now/60000;v_day:=v_now/86400000;
 insert into pso_team_private.quotas values('global','day',v_day,0) on conflict do nothing;
 if exists(select 1 from pso_team_private.quotas where subject='global' and period='day' and bucket=v_day and used>=20000) then return 'limited';end if;
 insert into pso_team_private.quotas values(p_device_id,'minute',v_minute,0),(p_device_id,'day',v_day,0) on conflict do nothing;
 if exists(select 1 from pso_team_private.quotas where subject=p_device_id and ((period='minute' and bucket=v_minute and used>=60) or (period='day' and bucket=v_day and used>=2000))) then return 'limited';end if;
 insert into pso_team_private.nonces(device_id,nonce) values(p_device_id,p_nonce);
 update pso_team_private.quotas set used=used+1 where (subject='global' and period='day' and bucket=v_day) or (subject=p_device_id and ((period='minute' and bucket=v_minute) or (period='day' and bucket=v_day)));
 -- Only a separately bootstrapped approved identity can fill its missing card.
 -- Edge verifies the card identity and signature before this RPC; key remains fixed.
 update pso_team_private.members set card=p_card where device_id=p_device_id and card is null and signing_spki=p_signing_spki;
 return 'ok';
end;
$$;
create or replace function public.pso_team_status(p_device_id text)
returns jsonb language sql stable security invoker set search_path='' as $$
 select coalesce((select jsonb_build_object('state',state,'role',role,'name',name) from pso_team_private.members where device_id=p_device_id),jsonb_build_object('state','unregistered','role',null,'name',null));
$$;
create or replace function public.pso_team_directory(p_device_id text)
returns jsonb language plpgsql stable security invoker set search_path='' as $$
begin
 if not exists(select 1 from pso_team_private.members where device_id=p_device_id and state='active') then return jsonb_build_object('status','denied');end if;
 return jsonb_build_object('members',(select coalesce(jsonb_agg(jsonb_build_object('id',device_id,'name',name,'role',role,'card',card) order by role,name,device_id),'[]'::jsonb) from pso_team_private.members where state='active' and card is not null));
end;
$$;
create or replace function public.pso_team_invite(p_admin_id text,p_id_hash text,p_name text,p_role text)
returns jsonb language plpgsql security invoker set search_path='' as $$
declare v_now bigint;v_day bigint;v_old pso_team_private.invites%rowtype;
begin
 if pso_team_private.valid_hash(p_id_hash) is distinct from true or p_name is null or char_length(p_name) not between 1 and 60 or p_name !~ '[^[:space:]]' or p_name~'[[:cntrl:]]' or p_role is null or p_role not in ('neurologist','cardiologist','intensivist','bot') then return jsonb_build_object('status','invalid');end if;
 perform pg_catalog.pg_advisory_xact_lock(1347637077,1);
 if not pso_team_private.is_admin(p_admin_id) then return jsonb_build_object('status','denied');end if;
 v_now:=floor(extract(epoch from clock_timestamp())*1000)::bigint;v_day:=v_now/86400000;
 select * into v_old from pso_team_private.invites where id_hash=p_id_hash;
 if found then
  if v_old.inviter_id=p_admin_id and v_old.name=p_name and v_old.role=p_role and v_old.expires>v_now and v_old.claimed_by is null then return jsonb_build_object('status','exists','expires',v_old.expires);end if;
  return jsonb_build_object('status','conflict');
 end if;
 if (select count(*) from pso_team_private.invites where expires>v_now and claimed_by is null)>=100 then return jsonb_build_object('status','limited');end if;
 insert into pso_team_private.quotas values(p_admin_id,'invite-day',v_day,0) on conflict do nothing;
 if exists(select 1 from pso_team_private.quotas where subject=p_admin_id and period='invite-day' and bucket=v_day and used>=100) then return jsonb_build_object('status','limited');end if;
 update pso_team_private.quotas set used=used+1 where subject=p_admin_id and period='invite-day' and bucket=v_day;
 insert into pso_team_private.invites(id_hash,inviter_id,name,role,expires) values(p_id_hash,p_admin_id,p_name,p_role,v_now+172800000);
 return jsonb_build_object('status','created','expires',v_now+172800000);
end;
$$;
create or replace function public.pso_team_claim(p_device_id text,p_id_hash text,p_card text,p_signing_spki text)
returns text language plpgsql security invoker set search_path='' as $$
declare v_invite pso_team_private.invites%rowtype;v_member pso_team_private.members%rowtype;v_now bigint;
begin
 if pso_team_private.valid_id(p_device_id) is distinct from true or pso_team_private.valid_hash(p_id_hash) is distinct from true or pso_team_private.valid_card(p_card) is distinct from true or p_signing_spki is null or p_signing_spki !~ '^[A-Za-z0-9_-]{121}[AQgw]$' then return 'denied';end if;
 perform pg_catalog.pg_advisory_xact_lock(1347637077,1);
 v_now:=floor(extract(epoch from clock_timestamp())*1000)::bigint;
 select * into v_invite from pso_team_private.invites where id_hash=p_id_hash;
 if not found or not pso_team_private.is_admin(v_invite.inviter_id) then return 'denied';end if;
 select * into v_member from pso_team_private.members where device_id=p_device_id;
 if found then
  if v_member.invite_hash=p_id_hash and v_invite.claimed_by=p_device_id and v_member.signing_spki=p_signing_spki and v_member.state in ('pending','active') then return v_member.state;end if;
  return 'conflict';
 end if;
 if v_invite.expires<=v_now or v_invite.claimed_by is not null then return 'denied';end if;
 if (select count(*) from pso_team_private.members)>=100 then return 'limited';end if;
 insert into pso_team_private.members(device_id,name,role,state,card,signing_spki,invite_hash) values(p_device_id,v_invite.name,v_invite.role,'pending',p_card,p_signing_spki,p_id_hash);
 update pso_team_private.invites set claimed_by=p_device_id where id_hash=p_id_hash;
 return 'pending';
end;
$$;
create or replace function public.pso_team_pending(p_admin_id text)
returns jsonb language plpgsql stable security invoker set search_path='' as $$
begin
 if not pso_team_private.is_admin(p_admin_id) then return jsonb_build_object('status','denied');end if;
 return jsonb_build_object('members',(select coalesce(jsonb_agg(jsonb_build_object('id',device_id,'name',name,'role',role,'card',card) order by created_at,device_id),'[]'::jsonb) from pso_team_private.members where state='pending'));
end;
$$;
create or replace function public.pso_team_approve(p_admin_id text,p_device_id text)
returns text language plpgsql security invoker set search_path='' as $$
declare v_member pso_team_private.members%rowtype;
begin
 perform pg_catalog.pg_advisory_xact_lock(1347637077,1);
 if not pso_team_private.is_admin(p_admin_id) then return 'denied';end if;
 select * into v_member from pso_team_private.members where device_id=p_device_id;
 if not found or v_member.role='admin' or v_member.state='revoked' then return 'denied';end if;
 if v_member.state='active' then return 'active';end if;
 if v_member.role in ('cardiologist','bot') and exists(select 1 from pso_team_private.members where role=v_member.role and state='active') then return 'conflict';end if;
 if v_member.role='intensivist' and (select count(*) from pso_team_private.members where role='intensivist' and state='active')>=25 then return 'conflict';end if;
 update pso_team_private.members set state='active',approved_at=clock_timestamp() where device_id=p_device_id;
 return 'active';
end;
$$;
create or replace function public.pso_team_revoke(p_admin_id text,p_device_id text)
returns text language plpgsql security invoker set search_path='' as $$
begin
 perform pg_catalog.pg_advisory_xact_lock(1347637077,1);
 if not pso_team_private.is_admin(p_admin_id) then return 'denied';end if;
 if not exists(select 1 from pso_team_private.members where device_id=p_device_id and role<>'admin') then return 'denied';end if;
 update pso_team_private.members set state='revoked',revoked_at=coalesce(revoked_at,clock_timestamp()) where device_id=p_device_id;
 return 'revoked';
end;
$$;
create or replace function public.pso_team_create(p_sender_id text,p_id_hash text,p_request_hash text,p_group text,p_kind text,p_issued bigint,p_expires bigint,p_entries jsonb)
returns text language plpgsql security invoker set search_path='' as $$
declare v_now bigint;v_minute bigint;v_day bigint;v_role text;v_old pso_team_private.links%rowtype;v_received text[];v_expected text[];v_entry jsonb;
begin
 if pso_team_private.valid_id(p_sender_id) is distinct from true or pso_team_private.valid_hash(p_id_hash) is distinct from true or pso_team_private.valid_hash(p_request_hash) is distinct from true
 or p_group is null or p_group not in ('cardiology','orit') or p_kind is null or p_kind not in ('admission','review') or p_issued is null or p_expires is null or p_issued<=0 or p_expires<=p_issued or p_expires::numeric-p_issued::numeric>86400000
 or p_entries is null or jsonb_typeof(p_entries) is distinct from 'array' then return 'invalid';end if;
 if jsonb_array_length(p_entries) not between 1 and 25 or octet_length(p_entries::text)>24576 then return 'invalid';end if;
 for v_entry in select value from jsonb_array_elements(p_entries) loop
  if jsonb_typeof(v_entry) is distinct from 'object' or v_entry-array['recipientId','token']<>'{}'::jsonb or jsonb_typeof(v_entry->'recipientId') is distinct from 'string' or jsonb_typeof(v_entry->'token') is distinct from 'string'
  or pso_team_private.valid_id(v_entry->>'recipientId') is distinct from true or pso_team_private.valid_token(v_entry->>'token') is distinct from true
  or split_part(v_entry->>'token','.',2)<>v_entry->>'recipientId' or split_part(v_entry->>'token','.',3)<>p_sender_id then return 'invalid';end if;
 end loop;
 select array_agg(value->>'recipientId' order by value->>'recipientId') into v_received from jsonb_array_elements(p_entries);
 if cardinality(v_received)<>(select count(distinct s) from unnest(v_received) s) then return 'invalid';end if;
 perform pg_catalog.pg_advisory_xact_lock(1347637077,1);
 v_now:=floor(extract(epoch from clock_timestamp())*1000)::bigint;
 select role into v_role from pso_team_private.members where device_id=p_sender_id and state='active' and card is not null;
 if v_role is null or (p_kind='admission' and v_role<>'bot') or (p_kind='review' and v_role not in ('admin','neurologist')) then return 'denied';end if;
 if p_expires<=v_now then return 'invalid';end if;
 select * into v_old from pso_team_private.links where id_hash=p_id_hash;
 if found then
  if v_old.sender_id=p_sender_id and v_old.request_hash=p_request_hash and v_old.group_name=p_group and v_old.kind=p_kind and v_old.issued=p_issued and v_old.expires=p_expires
  and (select jsonb_agg(jsonb_build_object('recipientId',recipient_id,'token',token) order by recipient_id) from pso_team_private.entries where id_hash=p_id_hash)=(select jsonb_agg(value order by value->>'recipientId') from jsonb_array_elements(p_entries)) then return 'exists';end if;
  return 'conflict';
 end if;
 if exists(select 1 from pso_shortlink_private.links where id_hash=p_id_hash) then return 'conflict';end if;
 -- Fresh signed outer requests protect replay. The inner durable outbox payload
 -- may have been prepared earlier; preserve it while its bounded TTL is live.
 if p_issued>v_now+30000 then return 'invalid';end if;
 select array_agg(device_id order by device_id) into v_expected from pso_team_private.members where state='active' and card is not null and role=case p_group when 'cardiology' then 'cardiologist' else 'intensivist' end;
 if v_expected is null or v_received is distinct from v_expected then return 'roster_changed';end if;
 v_minute:=v_now/60000;v_day:=v_now/86400000;
 insert into pso_team_private.quotas values('global','create-day',v_day,0),(p_sender_id,'create-day',v_day,0),(p_sender_id,'create-minute',v_minute,0) on conflict do nothing;
 if exists(select 1 from pso_team_private.quotas where (subject='global' and period='create-day' and bucket=v_day and used>=5000) or (subject=p_sender_id and ((period='create-day' and bucket=v_day and used>=500) or (period='create-minute' and bucket=v_minute and used>=30)))) then return 'limited';end if;
 update pso_team_private.quotas set used=used+1 where (subject='global' and period='create-day' and bucket=v_day) or (subject=p_sender_id and ((period='create-day' and bucket=v_day) or (period='create-minute' and bucket=v_minute)));
 insert into pso_team_private.links(id_hash,request_hash,sender_id,group_name,kind,issued,expires) values(p_id_hash,p_request_hash,p_sender_id,p_group,p_kind,p_issued,p_expires);
 insert into pso_team_private.entries(id_hash,recipient_id,token) select p_id_hash,value->>'recipientId',value->>'token' from jsonb_array_elements(p_entries);
 return 'created';
end;
$$;
create or replace function public.pso_team_resolve(p_device_id text,p_id_hash text)
returns jsonb language plpgsql security invoker set search_path='' as $$
declare v_link pso_team_private.links%rowtype;v_token text;v_sender pso_team_private.members%rowtype;v_now bigint;
begin
 if pso_team_private.valid_id(p_device_id) is distinct from true or pso_team_private.valid_hash(p_id_hash) is distinct from true then return jsonb_build_object('status','missing');end if;
 perform pg_catalog.pg_advisory_xact_lock(1347637077,1);
 v_now:=floor(extract(epoch from clock_timestamp())*1000)::bigint;
 select * into v_link from pso_team_private.links where id_hash=p_id_hash and expires>v_now;
 if not found then return jsonb_build_object('status','missing');end if;
 if not exists(select 1 from pso_team_private.members where device_id=p_device_id and state='active' and role=case v_link.group_name when 'cardiology' then 'cardiologist' else 'intensivist' end) then return jsonb_build_object('status','denied');end if;
 select token into v_token from pso_team_private.entries where id_hash=p_id_hash and recipient_id=p_device_id;
 if not found then return jsonb_build_object('status','denied');end if;
 select * into v_sender from pso_team_private.members where device_id=v_link.sender_id;
 -- Existing messages remain verifiable after the sender leaves. Recipient
 -- revocation always denies new resolution; previously downloaded copies persist.
 return jsonb_build_object('status','ok','token',v_token,'expires',v_link.expires,'senderCard',v_sender.card,'senderName',v_sender.name);
end;
$$;
create or replace function public.pso_team_push_claim(p_sender_id text,p_id_hash text)
returns jsonb language plpgsql security invoker set search_path='' as $$
declare v_link pso_team_private.links%rowtype;v_target record;v_targets jsonb:='[]'::jsonb;v_now bigint;
begin
 if pso_team_private.valid_id(p_sender_id) is distinct from true or pso_team_private.valid_hash(p_id_hash) is distinct from true then return jsonb_build_object('targets',v_targets);end if;
 perform pg_catalog.pg_advisory_xact_lock(1347637077,1);
 perform pg_catalog.pg_advisory_xact_lock(1347637076,1);
 v_now:=floor(extract(epoch from clock_timestamp())*1000)::bigint;
 select * into v_link from pso_team_private.links where id_hash=p_id_hash and sender_id=p_sender_id and expires>v_now;
 if not found or not exists(select 1 from pso_team_private.members where device_id=p_sender_id and state='active' and ((v_link.kind='admission' and role='bot') or (v_link.kind='review' and role in ('admin','neurologist')))) then return jsonb_build_object('targets',v_targets);end if;
 for v_target in select e.recipient_id,s.endpoint_hash,s.subscription from pso_team_private.entries e join pso_team_private.members m on m.device_id=e.recipient_id join pso_push_private.subscriptions s on s.device_id=e.recipient_id
 where e.id_hash=p_id_hash and m.state='active' and m.role=case v_link.group_name when 'cardiology' then 'cardiologist' else 'intensivist' end
 and s.refreshed_at>=clock_timestamp()-interval '90 days' and p_sender_id=any(s.senders)
 and not exists(select 1 from pso_team_private.push_claims c where c.id_hash=p_id_hash and c.recipient_id=e.recipient_id)
 order by e.recipient_id loop
  insert into pso_team_private.push_claims(id_hash,recipient_id,endpoint_hash) values(p_id_hash,v_target.recipient_id,v_target.endpoint_hash);
  v_targets:=v_targets||jsonb_build_array(jsonb_build_object('recipientId',v_target.recipient_id,'subscription',v_target.subscription,'expires',v_link.expires));
 end loop;
 return jsonb_build_object('targets',v_targets);
end;
$$;
create or replace function public.pso_team_push_finish(p_id_hash text,p_recipient_id text,p_status text)
returns text language plpgsql security invoker set search_path='' as $$
declare v_claim pso_team_private.push_claims%rowtype;
begin
 if p_status is null or p_status not in ('accepted','gone','failed') then return 'invalid';end if;
 perform pg_catalog.pg_advisory_xact_lock(1347637077,1);
 perform pg_catalog.pg_advisory_xact_lock(1347637076,1);
 select * into v_claim from pso_team_private.push_claims where id_hash=p_id_hash and recipient_id=p_recipient_id and status='sending';
 if not found then return 'unchanged';end if;
 update pso_team_private.push_claims set status=p_status where id_hash=p_id_hash and recipient_id=p_recipient_id;
 if p_status='gone' then delete from pso_push_private.subscriptions where device_id=p_recipient_id and endpoint_hash=v_claim.endpoint_hash;end if;
 return 'ok';
end;
$$;
create or replace function pso_team_private.cleanup()
returns void language plpgsql security invoker set search_path='' as $$
declare v_now bigint:=floor(extract(epoch from clock_timestamp())*1000)::bigint;
begin
 perform pg_catalog.pg_advisory_xact_lock(1347637077,1);
 delete from pso_team_private.links where expires<=v_now;
 delete from pso_team_private.nonces where created_at<clock_timestamp()-interval '2 minutes';
 delete from pso_team_private.quotas where (period in ('minute','create-minute') and bucket<v_now/60000-2880) or (period in ('day','create-day','invite-day') and bucket<v_now/86400000-2);
 delete from pso_team_private.invites where expires<v_now-604800000;
end;
$$;

revoke all on all functions in schema pso_team_private from public,anon,authenticated;
grant execute on function pso_team_private.valid_id(text),pso_team_private.valid_nonce(text),pso_team_private.valid_hash(text),pso_team_private.valid_card(text),pso_team_private.valid_token(text),pso_team_private.is_admin(text) to service_role;
revoke all on function public.pso_team_accept(text,text,text,bigint,text,text),public.pso_team_status(text),public.pso_team_directory(text),public.pso_team_invite(text,text,text,text),public.pso_team_claim(text,text,text,text),public.pso_team_pending(text),public.pso_team_approve(text,text),public.pso_team_revoke(text,text),public.pso_team_create(text,text,text,text,text,bigint,bigint,jsonb),public.pso_team_resolve(text,text),public.pso_team_push_claim(text,text),public.pso_team_push_finish(text,text,text) from public,anon,authenticated;
grant execute on function public.pso_team_accept(text,text,text,bigint,text,text),public.pso_team_status(text),public.pso_team_directory(text),public.pso_team_invite(text,text,text,text),public.pso_team_claim(text,text,text,text),public.pso_team_pending(text),public.pso_team_approve(text,text),public.pso_team_revoke(text,text),public.pso_team_create(text,text,text,text,text,bigint,bigint,jsonb),public.pso_team_resolve(text,text),public.pso_team_push_claim(text,text),public.pso_team_push_finish(text,text,text) to service_role;
do $$ begin
 if not exists(select 1 from cron.job where jobname='pso-team-cleanup') then perform cron.schedule('pso-team-cleanup','* * * * *','select pso_team_private.cleanup()');end if;
end; $$;
commit;
