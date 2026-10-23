-- Synthetic, rollback-only integration tests after applying push-schema.sql.
-- Never remove BEGIN/ROLLBACK. No push-provider HTTP requests occur here.
-- Assertions never print private VAPID keys or real subscription endpoints.
begin;
create function pg_temp.pso_push_assert(p_ok boolean,p_label text)
returns void language plpgsql as $$ begin
  if p_ok is distinct from true then raise exception 'PSO push test failed: %',p_label; end if;
end; $$;
grant execute on function pg_temp.pso_push_assert(boolean,text) to service_role;

create function pg_temp.pso_push_sub(p_suffix text)
returns jsonb language sql as $$
  select jsonb_build_object('endpoint','https://web.push.apple.com/pso-sql-fixture-'||p_suffix,
    'keys',jsonb_build_object('p256dh','B'||repeat('A',86),'auth',repeat('A',22)));
$$;
grant execute on function pg_temp.pso_push_sub(text) to service_role;

do $$ declare r text; t text; f text; begin
  foreach r in array array['anon','authenticated'] loop
    perform pg_temp.pso_push_assert(not has_schema_privilege(r,'pso_push_private','USAGE'),r||' private schema denied');
    foreach t in array array['vapid','subscriptions','nonces','quotas','claims'] loop
      perform pg_temp.pso_push_assert(not has_table_privilege(r,'pso_push_private.'||t,'SELECT,INSERT,UPDATE,DELETE'),r||' private table denied '||t);
    end loop;
    foreach f in array array[
      'public.pso_push_keys(jsonb)','public.pso_push_accept(text,text,text,bigint)',
      'public.pso_push_register(text,jsonb,text[])','public.pso_push_unregister(text)',
      'public.pso_push_status(text)','public.pso_push_test_subscription(text)',
      'public.pso_push_claim(text,text)','public.pso_push_finish(text,text)',
      'pso_push_private.cleanup()','pso_push_private.valid_id(text)','pso_push_private.valid_nonce(text)'
    ] loop
      perform pg_temp.pso_push_assert(not has_function_privilege(r,f,'EXECUTE'),r||' RPC denied '||f);
    end loop;
  end loop;
  perform pg_temp.pso_push_assert((select bool_and(relrowsecurity) from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='pso_push_private' and c.relkind='r'),'RLS enabled on every private table');
  perform pg_temp.pso_push_assert((select bool_and(not prosecdef and proconfig @> array['search_path=""']) from pg_proc p join pg_namespace n on n.oid=p.pronamespace where (n.nspname='public' and p.proname like 'pso_push_%') or n.nspname='pso_push_private'),'functions invoker with fixed empty search path');
  perform pg_temp.pso_push_assert((select count(*)=1 and bool_and(active) from cron.job where jobname='pso-push-cleanup'),'one enabled cleanup job');
end; $$;

set local role anon;
do $$ begin
  begin perform public.pso_push_keys(); raise exception 'PSO push test failed: anon key RPC allowed'; exception when insufficient_privilege then null; end;
  begin perform public.pso_push_register(repeat('A',43),'{}',array[]::text[]); raise exception 'PSO push test failed: anon register allowed'; exception when insufficient_privilege then null; end;
  begin perform 1 from pso_push_private.vapid; raise exception 'PSO push test failed: anon table read allowed'; exception when insufficient_privilege then null; end;
end; $$;
reset role;
set local role authenticated;
do $$ begin
  begin perform public.pso_push_test_subscription(repeat('A',43)); raise exception 'PSO push test failed: authenticated subscription read allowed'; exception when insufficient_privilege then null; end;
  begin perform public.pso_push_claim(repeat('A',43),repeat('f',64)); raise exception 'PSO push test failed: authenticated notify allowed'; exception when insufficient_privilege then null; end;
  begin perform 1 from pso_push_private.subscriptions; raise exception 'PSO push test failed: authenticated table read allowed'; exception when insufficient_privilege then null; end;
end; $$;
reset role;

-- Fake valid-shape fixtures are never used for cryptography or real delivery.
insert into pso_shortlink_private.writers(sender_id,signing_spki,enabled)
  values(repeat('A',43),repeat('A',122),true),(repeat('C',42)||'A',repeat('A',122),true);
insert into pso_shortlink_private.links(id_hash,request_hash,sender_id,token,issued,expires)
select encode(sha256(convert_to('pso-push-sql-link-'||i,'UTF8')),'hex'),repeat('f',64),repeat('A',43),
  'PSO1.'||repeat('B',42)||'A.'||repeat('A',43)||'.'||repeat('C',512)||'.'||repeat('D',86),
  floor(extract(epoch from clock_timestamp())*1000)::bigint-1000,
  floor(extract(epoch from clock_timestamp())*1000)::bigint+3600000
from generate_series(1,12) i;

set local role service_role;
do $$
declare
  v_now bigint:=floor(extract(epoch from clock_timestamp())*1000)::bigint;
  a text:=repeat('A',43); b text:=repeat('B',42)||'A'; c text:=repeat('C',42)||'A';
  h text:=encode(sha256(convert_to('pso-push-sql-link-1','UTF8')),'hex');
  h2 text:=encode(sha256(convert_to('pso-push-sql-link-2','UTF8')),'hex');
  h3 text:=encode(sha256(convert_to('pso-push-sql-link-3','UTF8')),'hex');
  h4 text:=encode(sha256(convert_to('pso-push-sql-link-4','UTF8')),'hex');
  h5 text:=encode(sha256(convert_to('pso-push-sql-link-5','UTF8')),'hex');
  h6 text:=encode(sha256(convert_to('pso-push-sql-link-6','UTF8')),'hex');
  v_first jsonb; v_next jsonb; v_claim jsonb; i integer;
begin
  -- Canonical final bits prevent aliases of one byte sequence becoming IDs/nonces.
  perform pg_temp.pso_push_assert(pso_push_private.valid_id(a),'canonical ID accepted');
  perform pg_temp.pso_push_assert(not pso_push_private.valid_id(repeat('A',42)||'B'),'noncanonical ID denied');
  perform pg_temp.pso_push_assert(not pso_push_private.valid_nonce(repeat('A',21)||'B'),'noncanonical nonce denied');
  perform pg_temp.pso_push_assert(public.pso_push_accept(a,repeat('a',21)||'A','register',v_now)='ok','fresh nonce accepted');
  perform pg_temp.pso_push_assert(public.pso_push_accept(a,repeat('a',21)||'A','register',v_now)='replay','same nonce rejected');
  perform pg_temp.pso_push_assert(public.pso_push_accept(a,repeat('b',21)||'A','register',v_now-60001)='invalid','old request rejected');
  perform pg_temp.pso_push_assert(public.pso_push_accept(a,repeat('c',21)||'A','register',v_now+60000)='invalid','future request rejected');
  perform pg_temp.pso_push_assert(public.pso_push_accept(repeat('A',42)||'B',repeat('d',21)||'A','status',v_now)='invalid','bad device ID rejected');
  perform pg_temp.pso_push_assert(public.pso_push_accept(a,repeat('d',21)||'B','status',v_now)='invalid','bad nonce rejected');
  perform pg_temp.pso_push_assert(public.pso_push_accept(a,repeat('d',21)||'A','arbitrary',v_now)='invalid','unknown operation rejected');

  -- An initialized key cannot be overwritten by another initialization request.
  -- Only equality is asserted; key material never appears in test output.
  v_first:=public.pso_push_keys();
  if v_first is null then
    v_first:=public.pso_push_keys(jsonb_build_object('publicKey','B'||repeat('A',86),
      'privateKey',jsonb_build_object('kty','EC','crv','P-256','x',a,'y',a,'d',a)));
  end if;
  v_next:=public.pso_push_keys(jsonb_build_object('publicKey','B'||repeat('C',85)||'A',
    'privateKey',jsonb_build_object('kty','EC','crv','P-256','x',a,'y',a,'d',c)));
  perform pg_temp.pso_push_assert(v_first=v_next,'VAPID initialization is immutable');

  perform pg_temp.pso_push_assert(not public.pso_push_status(b),'unregistered recipient unavailable');
  perform pg_temp.pso_push_assert(public.pso_push_register(b,pg_temp.pso_push_sub('b'),array[]::text[])='ok','recipient can register without writer allowlist');
  perform pg_temp.pso_push_assert(public.pso_push_status(b),'registered recipient status');
  perform pg_temp.pso_push_assert(public.pso_push_test_subscription(b)=pg_temp.pso_push_sub('b'),'own test subscription');
  perform pg_temp.pso_push_assert((select senders=array[b] from pso_push_private.subscriptions where device_id=b),'self included in consent automatically');
  perform pg_temp.pso_push_assert(public.pso_push_register(c,pg_temp.pso_push_sub('b'),array[c])='conflict','endpoint cannot be rebound to another identity');
  perform pg_temp.pso_push_assert(public.pso_push_register(c,pg_temp.pso_push_sub('b')||'{"name":"private"}',array[c])='conflict','extra subscription fields denied');
  perform pg_temp.pso_push_assert(public.pso_push_register(c,jsonb_set(pg_temp.pso_push_sub('c'),'{endpoint}','"https://127.0.0.1/private"'),array[c])='conflict','private endpoint rejected');
  perform pg_temp.pso_push_assert(public.pso_push_register(c,jsonb_set(pg_temp.pso_push_sub('c'),'{endpoint}','"https://web.push.apple.com.evil.example/private"'),array[c])='conflict','lookalike endpoint rejected');
  perform pg_temp.pso_push_assert(public.pso_push_register(c,jsonb_set(pg_temp.pso_push_sub('c'),'{endpoint}','"https://web.push.apple.com:8443/private"'),array[c])='conflict','custom endpoint port rejected');
  perform pg_temp.pso_push_assert(public.pso_push_register(c,pg_temp.pso_push_sub('c'),array[null::text])='conflict','null sender denied');
  perform pg_temp.pso_push_assert(public.pso_push_register(c,pg_temp.pso_push_sub('c'),array_fill(a,array[101]))='conflict','oversized sender list denied');

  perform pg_temp.pso_push_assert(public.pso_push_claim(a,h)->>'status'='unavailable','unapproved sender cannot notify recipient');
  perform pg_temp.pso_push_assert(not exists(select 1 from pso_push_private.claims where id_hash=h),'unavailable does not consume claim');
  perform pg_temp.pso_push_assert(public.pso_push_register(b,pg_temp.pso_push_sub('b'),array[a])='ok','recipient consents to known sender');
  perform pg_temp.pso_push_assert(public.pso_push_claim(c,h)->>'status'='unavailable','different approved writer cannot notify someone else link');
  perform pg_temp.pso_push_assert(public.pso_push_claim(a,repeat('0',64))->>'status'='unavailable','unknown link denied');
  v_claim:=public.pso_push_claim(a,h);
  perform pg_temp.pso_push_assert(v_claim->>'status'='ready' and v_claim->>'recipient_id'=b and v_claim->'subscription'=pg_temp.pso_push_sub('b'),'claim binds ciphertext recipient and subscription');
  perform pg_temp.pso_push_assert((v_claim->>'expires')::bigint>v_now,'claim expiry is live');
  perform pg_temp.pso_push_assert(public.pso_push_claim(a,h)->>'status'='already','duplicate claim never re-sends');
  perform pg_temp.pso_push_assert(public.pso_push_finish(h,'accepted')='ok','accepted send completed');
  perform pg_temp.pso_push_assert(public.pso_push_claim(a,h)='{"status":"accepted"}'::jsonb,'repeat reports acceptance without endpoint');
  perform pg_temp.pso_push_assert(public.pso_push_finish(h,'gone')='unchanged','finished claim cannot change');

  perform pg_temp.pso_push_assert(public.pso_push_claim(a,h2)->>'status'='ready','second link separately claimed');
  perform pg_temp.pso_push_assert(public.pso_push_finish(h2,'failed')='ok','failed send completed');
  perform pg_temp.pso_push_assert(public.pso_push_claim(a,h2)='{"status":"failed"}'::jsonb,'failed send not duplicated');
  perform pg_temp.pso_push_assert(public.pso_push_finish(h3,'unexpected')='invalid','invalid result rejected');

  perform pg_temp.pso_push_assert(public.pso_push_claim(a,h3)->>'status'='ready','third link claim');
  perform pg_temp.pso_push_assert(public.pso_push_register(b,pg_temp.pso_push_sub('b-new'),array[a])='ok','recipient refreshes endpoint');
  perform pg_temp.pso_push_assert(public.pso_push_finish(h3,'gone')='ok','old endpoint gone');
  perform pg_temp.pso_push_assert(public.pso_push_test_subscription(b)=pg_temp.pso_push_sub('b-new'),'gone does not delete replacement endpoint');
  perform pg_temp.pso_push_assert(public.pso_push_claim(a,h4)->>'status'='ready','replacement endpoint used');
  perform pg_temp.pso_push_assert(public.pso_push_finish(h4,'gone')='ok','current endpoint gone');
  perform pg_temp.pso_push_assert(not public.pso_push_status(b),'gone current endpoint removed');

  perform pg_temp.pso_push_assert(public.pso_push_register(b,pg_temp.pso_push_sub('b-new'),array[a])='ok','resubscription possible');
  update pso_shortlink_private.writers set enabled=false where sender_id=a;
  perform pg_temp.pso_push_assert(public.pso_push_claim(a,h5)->>'status'='unavailable','disabled sender rejected at claim');
  update pso_shortlink_private.writers set enabled=true where sender_id=a;
  update pso_push_private.subscriptions set refreshed_at=clock_timestamp()-interval '91 days' where device_id=b;
  perform pg_temp.pso_push_assert(not public.pso_push_status(b) and public.pso_push_test_subscription(b) is null,'expired subscription not returned');
  perform pg_temp.pso_push_assert(public.pso_push_claim(a,h5)->>'status'='unavailable','expired subscription cannot receive');
  perform pg_temp.pso_push_assert(public.pso_push_register(b,pg_temp.pso_push_sub('b-new'),array[a])='ok','refresh expired subscription');
  perform pg_temp.pso_push_assert(public.pso_push_unregister(c)='ok' and public.pso_push_status(b),'other identity unregister does not remove recipient');
  perform pg_temp.pso_push_assert(public.pso_push_unregister(b)='ok' and not public.pso_push_status(b),'own unregister succeeds');
  perform pg_temp.pso_push_assert(public.pso_push_claim(a,h6)->>'status'='unavailable','unregistered recipient cannot receive');

  -- Dedicated test-notification quota is independent of ordinary minute usage.
  for i in 1..3 loop
    perform pg_temp.pso_push_assert(public.pso_push_accept(c,repeat(i::text,21)||'A','test',v_now)='ok','test quota admitted '||i);
  end loop;
  perform pg_temp.pso_push_assert(public.pso_push_accept(c,repeat('4',21)||'A','test',v_now)='limited','fourth test blocked');
  perform pg_temp.pso_push_assert(public.pso_push_accept(c,repeat('5',21)||'A','status',v_now)='ok','test quota does not block ordinary status');

  insert into pso_push_private.quotas values(a,'minute',v_now/60000,20),(a,'minute',v_now/60000+1,20)
    on conflict(subject,period,bucket) do update set used=excluded.used;
  perform pg_temp.pso_push_assert(public.pso_push_accept(a,repeat('e',21)||'A','notify',v_now)='limited','minute quota');
  update pso_push_private.quotas set used=0 where subject=a and period='minute';
  insert into pso_push_private.quotas values(a,'day',v_now/86400000,500),(a,'day',v_now/86400000+1,500)
    on conflict(subject,period,bucket) do update set used=excluded.used;
  perform pg_temp.pso_push_assert(public.pso_push_accept(a,repeat('e',21)||'A','notify',v_now)='limited','device daily quota');
  update pso_push_private.quotas set used=0 where subject=a and period='day';
  insert into pso_push_private.quotas values('global','day',v_now/86400000,10000),('global','day',v_now/86400000+1,10000)
    on conflict(subject,period,bucket) do update set used=excluded.used;
  perform pg_temp.pso_push_assert(public.pso_push_accept(a,repeat('e',21)||'A','notify',v_now)='limited','global daily quota');
  perform pg_temp.pso_push_assert(public.pso_push_accept(repeat('Z',42)||'A',repeat('e',21)||'A','register',v_now)='limited','global quota rejects a fresh identity');
  perform pg_temp.pso_push_assert(not exists(select 1 from pso_push_private.quotas where subject=repeat('Z',42)||'A'),'global exhaustion creates no fresh-identity quota rows');
  perform pg_temp.pso_push_assert(not exists(select 1 from pso_push_private.nonces where device_id=a and nonce=repeat('e',21)||'A'),'limited requests do not create nonces');
end; $$;
reset role;

-- Expired ciphertext is tested using DB time and without changing real records.
update pso_shortlink_private.links set issued=floor(extract(epoch from clock_timestamp())*1000)::bigint-120000,
  expires=floor(extract(epoch from clock_timestamp())*1000)::bigint-60000
  where id_hash=encode(sha256(convert_to('pso-push-sql-link-7','UTF8')),'hex');
set local role service_role;
select pg_temp.pso_push_assert(public.pso_push_register(repeat('B',42)||'A',pg_temp.pso_push_sub('b-expiry'),array[repeat('A',43)])='ok','setup expiry subscription');
select pg_temp.pso_push_assert(public.pso_push_claim(repeat('A',43),encode(sha256(convert_to('pso-push-sql-link-7','UTF8')),'hex'))->>'status'='unavailable','expired ciphertext cannot trigger notification');
reset role;

-- Subscriber-capacity guard; fake entries live only inside this transaction.
insert into pso_push_private.subscriptions(device_id,endpoint_hash,subscription,senders)
select rtrim(translate(encode(sha256(convert_to('pso-push-capacity-'||i,'UTF8')),'base64'),'+/','-_'),'='),
  encode(sha256(convert_to('pso-push-capacity-endpoint-'||i,'UTF8')),'hex'),
  pg_temp.pso_push_sub('capacity-'||i),array[repeat('A',43)] from generate_series(1,500) i;
set local role service_role;
select pg_temp.pso_push_assert(public.pso_push_register(repeat('D',42)||'A',pg_temp.pso_push_sub('over-capacity'),array[]::text[])='limited','subscriber count bounded');
select pg_temp.pso_push_assert(public.pso_push_register(repeat('B',42)||'A',pg_temp.pso_push_sub('b-refresh-full'),array[repeat('A',43)])='ok','existing subscription refresh works at capacity');
reset role;

update pso_push_private.nonces set created_at=clock_timestamp()-interval '3 minutes'
  where device_id=repeat('A',43) and nonce=repeat('a',21)||'A';
update pso_push_private.claims set created_at=clock_timestamp()-interval '3 days'
  where id_hash=encode(sha256(convert_to('pso-push-sql-link-2','UTF8')),'hex');
update pso_push_private.subscriptions set refreshed_at=clock_timestamp()-interval '91 days'
  where device_id=repeat('B',42)||'A';
insert into pso_push_private.quotas values('pso-fixture-expired','day',0,1);
select pso_push_private.cleanup();
select pg_temp.pso_push_assert(not exists(select 1 from pso_push_private.nonces where device_id=repeat('A',43) and nonce=repeat('a',21)||'A'),'old nonces removed');
select pg_temp.pso_push_assert(not exists(select 1 from pso_push_private.claims where id_hash=encode(sha256(convert_to('pso-push-sql-link-2','UTF8')),'hex')),'old claims removed');
select pg_temp.pso_push_assert(not exists(select 1 from pso_push_private.subscriptions where device_id=repeat('B',42)||'A'),'old subscriptions removed');
select pg_temp.pso_push_assert(not exists(select 1 from pso_push_private.quotas where subject='pso-fixture-expired'),'old quotas removed');
select pg_temp.pso_push_assert(exists(select 1 from pso_push_private.claims where id_hash=encode(sha256(convert_to('pso-push-sql-link-1','UTF8')),'hex')),'recent claim retained');

select 'Push SQL access, consent, ownership, replay, quotas, deduplication, expiry and cleanup assertions passed; fixtures rolled back below' as result;
rollback;
