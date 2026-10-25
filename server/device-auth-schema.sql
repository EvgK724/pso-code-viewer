-- Optional device-holder verification for direct messages. No patient data here.
begin;
create schema if not exists pso_device_auth_private;
revoke all on schema pso_device_auth_private from public,anon,authenticated;
grant usage on schema pso_device_auth_private to service_role;
create table if not exists pso_device_auth_private.credentials (
 device_id text primary key references pso_team_private.members(device_id),
 credential_id text unique not null check(char_length(credential_id) between 16 and 4096 and credential_id ~ '^[A-Za-z0-9_-]+$'),
 public_key text not null check(char_length(public_key) between 32 and 8192 and public_key ~ '^[A-Za-z0-9_-]+$'),
 counter bigint not null check(counter>=0),
 transports jsonb not null check(jsonb_typeof(transports)='array' and jsonb_array_length(transports)<=10),
 created_at timestamptz not null default clock_timestamp()
);
create table if not exists pso_device_auth_private.challenges (
 device_id text not null references pso_team_private.members(device_id),
 purpose text not null check(purpose in ('enroll','unlock')),
 challenge text not null check(challenge ~ '^[A-Za-z0-9_-]{32,128}$'),
 expires bigint not null,
 primary key(device_id,purpose)
);
create table if not exists pso_device_auth_private.sessions (
 token_hash text primary key check(token_hash ~ '^[0-9a-f]{64}$'),
 device_id text not null references pso_device_auth_private.credentials(device_id) on delete cascade,
 expires bigint not null
);
create index if not exists pso_device_auth_sessions_device on pso_device_auth_private.sessions(device_id);
create index if not exists pso_device_auth_sessions_expires on pso_device_auth_private.sessions(expires);
alter table pso_device_auth_private.credentials enable row level security;
alter table pso_device_auth_private.challenges enable row level security;
alter table pso_device_auth_private.sessions enable row level security;
revoke all on all tables in schema pso_device_auth_private from public,anon,authenticated;
grant select,insert,update,delete on all tables in schema pso_device_auth_private to service_role;

create or replace function pso_device_auth_private.active(p_device_id text)
returns boolean language sql stable security invoker set search_path='' as $$
 select exists(select 1 from pso_team_private.members where device_id=p_device_id and state='active' and role<>'bot');
$$;
create or replace function public.pso_device_auth_accept(p_device_id text,p_nonce text,p_issued bigint,p_card text,p_signing_spki text)
returns text language plpgsql security invoker set search_path='' as $$
declare r text;
begin
 if not pso_device_auth_private.active(p_device_id) then return 'denied';end if;
 r:=public.pso_team_accept(p_device_id,p_nonce,'status',p_issued,p_card,p_signing_spki);
 return case when r='replay' then 'conflict' else r end;
end;$$;
create or replace function public.pso_device_auth_status(p_device_id text)
returns jsonb language sql stable security invoker set search_path='' as $$
 select case when pso_device_auth_private.active(p_device_id) then jsonb_build_object('enabled',exists(select 1 from pso_device_auth_private.credentials where device_id=p_device_id)) else null end;
$$;
create or replace function public.pso_device_auth_credential(p_device_id text)
returns jsonb language sql stable security invoker set search_path='' as $$
 select jsonb_build_object('id',credential_id,'publicKey',public_key,'counter',counter,'transports',transports) from pso_device_auth_private.credentials where device_id=p_device_id and pso_device_auth_private.active(p_device_id);
$$;
create or replace function public.pso_device_auth_challenge_put(p_device_id text,p_purpose text,p_challenge text,p_expires bigint)
returns text language plpgsql security invoker set search_path='' as $$
declare t bigint:=floor(extract(epoch from clock_timestamp())*1000)::bigint;
begin
 if not pso_device_auth_private.active(p_device_id) or p_purpose is null or p_purpose not in ('enroll','unlock') or p_challenge is null or p_challenge !~ '^[A-Za-z0-9_-]{32,128}$' or p_expires is null or p_expires<=t or p_expires>t+300000 then return 'denied';end if;
 if (p_purpose='enroll')=exists(select 1 from pso_device_auth_private.credentials where device_id=p_device_id) then return 'conflict';end if;
 delete from pso_device_auth_private.challenges where expires<=t;
 delete from pso_device_auth_private.sessions where expires<=t;
 insert into pso_device_auth_private.challenges values(p_device_id,p_purpose,p_challenge,p_expires) on conflict(device_id,purpose) do update set challenge=excluded.challenge,expires=excluded.expires;
 return 'ok';
end;$$;
create or replace function public.pso_device_auth_challenge_take(p_device_id text,p_purpose text)
returns text language plpgsql security invoker set search_path='' as $$
declare r pso_device_auth_private.challenges%rowtype;t bigint:=floor(extract(epoch from clock_timestamp())*1000)::bigint;
begin
 if not pso_device_auth_private.active(p_device_id) then return null;end if;
 delete from pso_device_auth_private.challenges where device_id=p_device_id and purpose=p_purpose returning * into r;
 if r.expires>t then return r.challenge;end if;return null;
end;$$;
create or replace function public.pso_device_auth_enroll(p_device_id text,p_credential jsonb,p_token_hash text,p_expires bigint)
returns text language plpgsql security invoker set search_path='' as $$
declare t bigint:=floor(extract(epoch from clock_timestamp())*1000)::bigint;
begin
 if not pso_device_auth_private.active(p_device_id) or p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$' or p_expires is null or p_expires<=t or p_expires>t+600000 then return 'denied';end if;
 if jsonb_typeof(p_credential) is distinct from 'object' or (select array_agg(k order by k) from jsonb_object_keys(p_credential) k) is distinct from array['counter','id','publicKey','transports'] then return 'denied';end if;
 insert into pso_device_auth_private.credentials(device_id,credential_id,public_key,counter,transports) values(p_device_id,p_credential->>'id',p_credential->>'publicKey',(p_credential->>'counter')::bigint,p_credential->'transports');
 insert into pso_device_auth_private.sessions values(p_token_hash,p_device_id,p_expires);
 return 'ok';
exception when unique_violation then return 'conflict';when check_violation or invalid_text_representation or not_null_violation then return 'denied';
end;$$;
create or replace function public.pso_device_auth_unlock(p_device_id text,p_credential_id text,p_old_counter bigint,p_new_counter bigint,p_token_hash text,p_expires bigint)
returns text language plpgsql security invoker set search_path='' as $$
declare r pso_device_auth_private.credentials%rowtype;t bigint:=floor(extract(epoch from clock_timestamp())*1000)::bigint;
begin
 if not pso_device_auth_private.active(p_device_id) or p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$' or p_expires is null or p_expires<=t or p_expires>t+600000 or p_old_counter is null or p_new_counter is null or p_old_counter<0 or p_new_counter<0 then return 'denied';end if;
 select * into r from pso_device_auth_private.credentials where device_id=p_device_id for update;
 if not found or r.credential_id<>p_credential_id or r.counter<>p_old_counter or ((r.counter>0 or p_new_counter>0) and p_new_counter<=r.counter) then return 'conflict';end if;
 update pso_device_auth_private.credentials set counter=p_new_counter where device_id=p_device_id;
 delete from pso_device_auth_private.sessions where device_id=p_device_id or expires<=t;
 insert into pso_device_auth_private.sessions values(p_token_hash,p_device_id,p_expires);
 return 'ok';
end;$$;
create or replace function public.pso_device_unlock_check(p_device_id text,p_token text)
returns boolean language plpgsql volatile security invoker set search_path='' as $$
declare t bigint:=floor(extract(epoch from clock_timestamp())*1000)::bigint;
begin
 if not pso_device_auth_private.active(p_device_id) then return false;end if;
 if not exists(select 1 from pso_device_auth_private.credentials where device_id=p_device_id) then return true;end if;
 if p_token is null or p_token !~ '^[A-Za-z0-9_-]{43}$' then return false;end if;
 return exists(select 1 from pso_device_auth_private.sessions where device_id=p_device_id and expires>t and token_hash=encode(sha256(convert_to(p_token,'UTF8')),'hex'));
end;$$;
create or replace function public.pso_device_unlock_reset(p_admin_id text,p_device_id text,p_token text)
returns text language plpgsql security invoker set search_path='' as $$
begin
 if not pso_team_private.is_admin(p_admin_id) then return 'denied';end if;
 if not public.pso_device_unlock_check(p_admin_id,p_token) then return 'locked';end if;
 if not exists(select 1 from pso_team_private.members where device_id=p_device_id and role<>'bot') then return 'denied';end if;
 delete from pso_device_auth_private.credentials where device_id=p_device_id;
 delete from pso_device_auth_private.challenges where device_id=p_device_id;
 return 'ok';
end;$$;
revoke all on all functions in schema pso_device_auth_private from public,anon,authenticated;
grant execute on all functions in schema pso_device_auth_private to service_role;
do $$declare r record;begin for r in select p.oid::regprocedure as signature from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='public' and (p.proname like 'pso_device_auth_%' or p.proname like 'pso_device_unlock_%') loop execute format('revoke all on function %s from public,anon,authenticated',r.signature);execute format('grant execute on function %s to service_role',r.signature);end loop;end;$$;
commit;
