-- OPTIONAL FINAL CUTOVER. Apply only after the role-based frontend is published.
-- Existing legacy links/crypto/read access are unchanged. No new legacy links
-- may bypass role-based creation. Reverting requires the previous reviewed
-- function definition from supabase-schema.sql; do not delete existing data.
begin;
create or replace function public.pso_shortlink_put(
 p_id_hash text,p_request_hash text,p_sender_id text,p_token text,p_issued bigint,p_expires bigint
) returns text language sql security invoker set search_path='' as $$
 select 'denied'::text;
$$;
revoke all on function public.pso_shortlink_put(text,text,text,text,bigint,bigint) from public,anon,authenticated;
grant execute on function public.pso_shortlink_put(text,text,text,text,bigint,bigint) to service_role;
commit;
