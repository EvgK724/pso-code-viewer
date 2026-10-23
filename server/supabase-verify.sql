-- Execute only on the newly approved short-link project after schema setup.
-- Synthetic SQL-level fixtures. Crypto/API tests are separate.
-- Every mutation is rolled back; do not remove BEGIN/ROLLBACK.
begin;

create function pg_temp.pso_assert(p_ok boolean, p_label text)
returns void language plpgsql as $$
begin
  if p_ok is distinct from true then raise exception 'PSO test failed: %', p_label; end if;
end;
$$;
grant execute on function pg_temp.pso_assert(boolean,text) to service_role;

do $$
declare r text; t text; f text;
begin
  foreach r in array array['anon','authenticated'] loop
    perform pg_temp.pso_assert(not has_schema_privilege(r,'pso_shortlink_private','USAGE'), r || ' private schema denied');
    foreach t in array array['writers','links','quotas'] loop
      perform pg_temp.pso_assert(not has_table_privilege(r,'pso_shortlink_private.' || t,'SELECT,INSERT,UPDATE,DELETE'), r || ' table privileges denied ' || t);
    end loop;
    foreach f in array array[
      'public.pso_shortlink_writer(text)',
      'public.pso_shortlink_put(text,text,text,text,bigint,bigint)',
      'public.pso_shortlink_resolve(text)',
      'pso_shortlink_private.cleanup()'
    ] loop
      perform pg_temp.pso_assert(not has_function_privilege(r,f,'EXECUTE'), r || ' function denied ' || f);
    end loop;
  end loop;
  perform pg_temp.pso_assert((select bool_and(relrowsecurity) from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='pso_shortlink_private' and c.relname in ('writers','links','quotas')), 'RLS enabled');
  perform pg_temp.pso_assert((select bool_and(not prosecdef) from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='public' and p.proname like 'pso_shortlink_%'), 'RPC functions security invoker');
end;
$$;

set local role anon;
do $$ begin
  begin perform public.pso_shortlink_resolve(repeat('0',64)); raise exception 'PSO test failed: anon RPC allowed';
  exception when insufficient_privilege then null; end;
  begin perform 1 from pso_shortlink_private.links limit 1; raise exception 'PSO test failed: anon table read allowed';
  exception when insufficient_privilege then null; end;
end; $$;
reset role;

set local role authenticated;
do $$ begin
  begin perform public.pso_shortlink_writer(repeat('A',43)); raise exception 'PSO test failed: authenticated RPC allowed';
  exception when insufficient_privilege then null; end;
  begin perform 1 from pso_shortlink_private.writers limit 1; raise exception 'PSO test failed: authenticated table read allowed';
  exception when insufficient_privilege then null; end;
end; $$;
reset role;

-- Structurally valid fake values, never used as cryptographic public keys.
insert into pso_shortlink_private.writers(sender_id,signing_spki,enabled)
values(repeat('A',43),repeat('A',122),true);

set local role service_role;
do $$
declare
  v_now bigint := floor(extract(epoch from clock_timestamp()) * 1000)::bigint;
  v_sender text := repeat('A',43);
  v_token text := 'PSO1.' || repeat('B',43) || '.' || repeat('A',43) || '.' || repeat('C',512) || '.' || repeat('D',86);
  v_id text := repeat('1',64);
  v_request text := repeat('2',64);
begin
  perform pg_temp.pso_assert((public.pso_shortlink_writer(v_sender)->>'enabled')::boolean,'enabled writer lookup');
  perform pg_temp.pso_assert(public.pso_shortlink_writer(repeat('Z',43)) is null,'unknown writer lookup');
  perform pg_temp.pso_assert(public.pso_shortlink_put(v_id,v_request,v_sender,v_token,v_now,v_now+3600000)='created','service-role create');
  perform pg_temp.pso_assert(public.pso_shortlink_resolve(v_id)->>'token'=v_token,'service-role resolve');
  perform pg_temp.pso_assert(public.pso_shortlink_put(v_id,v_request,v_sender,v_token,v_now,v_now+3600000)='exists','idempotent retry');
  perform pg_temp.pso_assert((select sum(used)=3 from pso_shortlink_private.quotas where subject in ('global',v_sender)),'retry does not consume quota');
  perform pg_temp.pso_assert(public.pso_shortlink_put(v_id,repeat('3',64),v_sender,v_token,v_now,v_now+3600000)='conflict','changed request conflicts');
  perform pg_temp.pso_assert(public.pso_shortlink_put(v_id,v_request,v_sender,v_token,v_now,v_now+3600001)='conflict','expiry cannot be extended');
  perform pg_temp.pso_assert(public.pso_shortlink_put(repeat('4',64),v_request,v_sender,v_token,v_now-60001,v_now+3600000)='denied','stale request denied');
  perform pg_temp.pso_assert(public.pso_shortlink_put(repeat('4',64),v_request,v_sender,v_token,v_now+60000,v_now+3600000)='denied','future request denied');
  perform pg_temp.pso_assert(public.pso_shortlink_put(repeat('4',64),v_request,v_sender,v_token,v_now-60000,v_now-1)='denied','expired write denied');
  perform pg_temp.pso_assert(public.pso_shortlink_put(repeat('4',64),v_request,v_sender,v_token,v_now,v_now+86400001)='denied','TTL over 24 hours denied');

  update pso_shortlink_private.writers set enabled=false where sender_id=v_sender;
  perform pg_temp.pso_assert(public.pso_shortlink_writer(v_sender) is null,'disabled writer hidden');
  perform pg_temp.pso_assert(public.pso_shortlink_put(v_id,v_request,v_sender,v_token,v_now,v_now+3600000)='denied','disabled writer retry denied atomically');
  update pso_shortlink_private.writers set enabled=true where sender_id=v_sender;

  -- Include current/next bucket so boundary crossings do not weaken the test.
  insert into pso_shortlink_private.quotas values
    (v_sender,'minute',v_now/60000,10),(v_sender,'minute',v_now/60000+1,10)
  on conflict(subject,period,bucket) do update set used=excluded.used;
  perform pg_temp.pso_assert(public.pso_shortlink_put(repeat('4',64),v_request,v_sender,v_token,v_now,v_now+3600000)='limited','minute quota');
  update pso_shortlink_private.quotas set used=0 where subject=v_sender and period='minute';
  insert into pso_shortlink_private.quotas values
    (v_sender,'day',v_now/86400000,200),(v_sender,'day',v_now/86400000+1,200)
  on conflict(subject,period,bucket) do update set used=excluded.used;
  perform pg_temp.pso_assert(public.pso_shortlink_put(repeat('4',64),v_request,v_sender,v_token,v_now,v_now+3600000)='limited','writer day quota');
  update pso_shortlink_private.quotas set used=0 where subject=v_sender and period='day';
  insert into pso_shortlink_private.quotas values
    ('global','day',v_now/86400000,5000),('global','day',v_now/86400000+1,5000)
  on conflict(subject,period,bucket) do update set used=excluded.used;
  perform pg_temp.pso_assert(public.pso_shortlink_put(repeat('4',64),v_request,v_sender,v_token,v_now,v_now+3600000)='limited','global day quota');
  perform pg_temp.pso_assert((select count(*)=1 from pso_shortlink_private.links where sender_id=v_sender),'rejected writes create no records');
end;
$$;
reset role;

insert into pso_shortlink_private.links(id_hash,request_hash,sender_id,token,issued,expires)
select repeat('e',64),repeat('f',64),repeat('A',43),
  'PSO1.' || repeat('B',43) || '.' || repeat('A',43) || '.' || repeat('C',512) || '.' || repeat('D',86),
  floor(extract(epoch from clock_timestamp())*1000)::bigint-120000,
  floor(extract(epoch from clock_timestamp())*1000)::bigint-60000;

set local role service_role;
select pg_temp.pso_assert(public.pso_shortlink_resolve(repeat('e',64)) is null,'expired resolve denied by DB time');
reset role;

select pso_shortlink_private.cleanup();
select pg_temp.pso_assert(not exists(select 1 from pso_shortlink_private.links where id_hash=repeat('e',64)),'expired row removed');
select pg_temp.pso_assert(exists(select 1 from pso_shortlink_private.links where id_hash=repeat('1',64)),'unexpired row retained');

select 'SQL security, idempotency, quotas, disabled-writer and expiry tests passed; fixtures rolled back below' as result;
rollback;
