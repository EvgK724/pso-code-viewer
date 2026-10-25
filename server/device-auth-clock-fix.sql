-- Check expiry and current membership at the gate invocation, not the start of
-- an earlier enclosing SQL statement. Keep the service-only function grants.
begin;
create or replace function public.pso_device_unlock_check(p_device_id text,p_token text)
returns boolean language plpgsql volatile security invoker set search_path='' as $$
declare t bigint:=floor(extract(epoch from clock_timestamp())*1000)::bigint;
begin
 if not pso_device_auth_private.active(p_device_id) then return false;end if;
 if not exists(select 1 from pso_device_auth_private.credentials where device_id=p_device_id) then return true;end if;
 if p_token is null or p_token !~ '^[A-Za-z0-9_-]{43}$' then return false;end if;
 return exists(select 1 from pso_device_auth_private.sessions where device_id=p_device_id and expires>t and token_hash=encode(sha256(convert_to(p_token,'UTF8')),'hex'));
end;$$;
revoke all on function public.pso_device_unlock_check(text,text) from public,anon,authenticated;
grant execute on function public.pso_device_unlock_check(text,text) to service_role;
commit;
