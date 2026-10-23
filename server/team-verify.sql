-- Run after team-schema.sql inside this rollback transaction. No HTTP sends.
-- Fixtures deliberately use reserved-looking synthetic IDs/cards, not real staff.
begin;
create function pg_temp.team_assert(p_ok boolean,p_message text) returns void language plpgsql as $$
begin if p_ok is distinct from true then raise exception 'Team assertion failed: %',p_message;end if;end;$$;
create function pg_temp.team_token(p_recipient text,p_sender text) returns text language sql as $$
 select 'PSO1.'||p_recipient||'.'||p_sender||'.'||repeat('A',512)||'.'||repeat('A',86);
$$;

-- No browser role may use private tables or privileged RPCs.
set local role anon;
do $$ begin
 begin perform public.pso_team_status(repeat('A',43));raise exception 'anon RPC unexpectedly allowed';exception when insufficient_privilege then null;end;
 begin perform count(*) from pso_team_private.members;raise exception 'anon table unexpectedly allowed';exception when insufficient_privilege then null;end;
end;$$;
reset role;
set local role authenticated;
do $$ begin
 begin perform public.pso_team_invite(repeat('A',43),repeat('1',64),'Fixture','neurologist');raise exception 'authenticated RPC unexpectedly allowed';exception when insufficient_privilege then null;end;
 begin perform count(*) from pso_team_private.links;raise exception 'authenticated table unexpectedly allowed';exception when insufficient_privilege then null;end;
end;$$;
reset role;

do $$ begin
 perform pg_temp.team_assert(not exists(select 1 from pso_team_private.members where device_id in (repeat('A',43),repeat('B',42)||'A',repeat('C',42)||'A',repeat('D',42)||'A',repeat('E',42)||'A',repeat('F',42)||'A',repeat('G',42)||'A')),'fixture identities unused');
 insert into pso_team_private.members(device_id,name,role,state,signing_spki) values(repeat('A',43),'Synthetic administrator','admin','active',repeat('A',122));
end;$$;
set local role service_role;
do $$
declare
 a text:=repeat('A',43);n text:=repeat('B',42)||'A';c text:=repeat('C',42)||'A';i text:=repeat('D',42)||'A';j text:=repeat('E',42)||'A';b text:=repeat('F',42)||'A';x text:=repeat('G',42)||'A';
 ca text:='PSO-CARD1.'||repeat('A',150);sp text:=repeat('A',122);
 t bigint:=floor(extract(epoch from clock_timestamp())*1000)::bigint;
 r jsonb; entries jsonb;cardio jsonb;h text:=repeat('a',64);hc text:=repeat('b',64);requesthash text:=repeat('9',64);sub jsonb;
begin
 perform pg_temp.team_assert(public.pso_team_status(n)=jsonb_build_object('state','unregistered','role',null,'name',null),'unknown status');
 perform pg_temp.team_assert(public.pso_team_directory(n)->>'status'='denied','unknown directory denied');
 perform pg_temp.team_assert(public.pso_team_pending(n)->>'status'='denied','unknown pending denied');
 perform pg_temp.team_assert(public.pso_team_accept(a,repeat('A',22),'status',t,ca,repeat('A',121)||'Q')='denied','bootstrap signing key mismatch rejected');
 perform pg_temp.team_assert(public.pso_team_accept(a,repeat('A',22),'status',t,ca,sp)='ok','approved bootstrap binds first card');
 perform pg_temp.team_assert(public.pso_team_accept(a,repeat('A',22),'status',t,ca,sp)='replay','signed nonce replay denied');
 perform pg_temp.team_assert(public.pso_team_accept(a,repeat('B',21)||'A','status',t-60001,ca,sp)='denied','stale timestamp denied');
 perform pg_temp.team_assert(public.pso_team_accept(a,repeat('C',21)||'A','status',t+60001,ca,sp)='denied','future timestamp denied');
 perform pg_temp.team_assert((select card=ca from pso_team_private.members where device_id=a),'bound admin card');
 perform pg_temp.team_assert(public.pso_team_invite(n,repeat('1',64),'Synthetic neurologist','neurologist')->>'status'='denied','nonadmin cannot invite');
 perform pg_temp.team_assert(public.pso_team_invite(a,repeat('1',64),'Synthetic neurologist','admin')->>'status'='invalid','cannot invite admin role');
 r:=public.pso_team_invite(a,repeat('1',64),'Synthetic neurologist','neurologist');
 perform pg_temp.team_assert(r->>'status'='created' and (r->>'expires')::bigint>t,'admin invitation created');
 perform pg_temp.team_assert(public.pso_team_invite(a,repeat('1',64),'Synthetic neurologist','neurologist')->>'status'='exists','invite retry idempotent');
 perform pg_temp.team_assert(public.pso_team_invite(a,repeat('1',64),'Changed label','neurologist')->>'status'='conflict','invite reuse cannot change role/name');
 perform pg_temp.team_assert(public.pso_team_claim(n,repeat('1',64),ca,sp)='pending','invitation possession only creates pending');
 perform pg_temp.team_assert(public.pso_team_claim(n,repeat('1',64),ca,sp)='pending','same pending claim idempotent');
 perform pg_temp.team_assert(public.pso_team_claim(x,repeat('1',64),ca,sp)='denied','invite single-use');
 perform pg_temp.team_assert(public.pso_team_directory(n)->>'status'='denied','pending cannot read directory');
 perform pg_temp.team_assert(public.pso_team_approve(n,n)='denied','pending cannot approve self');
 perform pg_temp.team_assert(jsonb_array_length(public.pso_team_pending(a)->'members')>=1,'admin sees pending key');
 perform pg_temp.team_assert(public.pso_team_approve(a,n)='active','admin approves pending');
 perform pg_temp.team_assert(public.pso_team_claim(n,repeat('1',64),ca,sp)='active','same approved claim stable');
 perform pg_temp.team_assert(public.pso_team_revoke(a,a)='denied','admin self-revoke blocked');
 -- Recipient and bot enrollment use the same explicit approval path.
 perform public.pso_team_invite(a,repeat('2',64),'Synthetic cardiologist','cardiologist');
 perform pg_temp.team_assert(public.pso_team_claim(c,repeat('2',64),ca,sp)='pending','cardiologist pending');perform pg_temp.team_assert(public.pso_team_approve(a,c)='active','cardiologist approval');
 perform public.pso_team_invite(a,repeat('3',64),'Synthetic intensivist one','intensivist');perform public.pso_team_claim(i,repeat('3',64),ca,sp);perform pg_temp.team_assert(public.pso_team_approve(a,i)='active','intensivist one approval');
 perform public.pso_team_invite(a,repeat('4',64),'Synthetic intensivist two','intensivist');perform public.pso_team_claim(j,repeat('4',64),ca,sp);perform pg_temp.team_assert(public.pso_team_approve(a,j)='active','intensivist two approval');
 perform public.pso_team_invite(a,repeat('5',64),'Synthetic bot','bot');perform public.pso_team_claim(b,repeat('5',64),ca,sp);perform pg_temp.team_assert(public.pso_team_approve(a,b)='active','bot approval');
 perform public.pso_team_invite(a,repeat('6',64),'Synthetic second cardiologist','cardiologist');perform public.pso_team_claim(x,repeat('6',64),ca,sp);perform pg_temp.team_assert(public.pso_team_approve(a,x)='conflict','only one active cardiologist');
 perform pg_temp.team_assert(jsonb_array_length(public.pso_team_directory(n)->'members')>=6,'active directory includes senders and recipients');
 entries:=jsonb_build_array(jsonb_build_object('recipientId',i,'token',pg_temp.team_token(i,n)),jsonb_build_object('recipientId',j,'token',pg_temp.team_token(j,n)));
 cardio:=jsonb_build_array(jsonb_build_object('recipientId',c,'token',pg_temp.team_token(c,n)));
 perform pg_temp.team_assert(public.pso_team_create(n,h,requesthash,'orit','admission',t,t+3600000,entries)='denied','neurologist cannot create admission');
 perform pg_temp.team_assert(public.pso_team_create(c,h,requesthash,'orit','review',t,t+3600000,jsonb_build_array(jsonb_build_object('recipientId',i,'token',pg_temp.team_token(i,c))))='denied','recipient role cannot send review');
 perform pg_temp.team_assert(public.pso_team_create(b,h,requesthash,'orit','review',t,t+3600000,jsonb_build_array(jsonb_build_object('recipientId',i,'token',pg_temp.team_token(i,b))))='denied','bot cannot send review');
 perform pg_temp.team_assert(public.pso_team_create(n,h,requesthash,'orit','review',t,t+3600000,jsonb_build_array(entries->0))='roster_changed','missing recipient rejected');
 perform pg_temp.team_assert(public.pso_team_create(n,h,requesthash,'orit','review',t,t+3600000,entries||cardio)='roster_changed','cross-group extra recipient rejected');
 perform pg_temp.team_assert(public.pso_team_create(n,h,requesthash,'orit','review',t,t+3600000,entries||jsonb_build_array(entries->0))='invalid','duplicate recipient rejected');
 perform pg_temp.team_assert(public.pso_team_create(n,repeat('d',64),requesthash,'orit','review',t-120000,t+3600000,entries)='created','delayed first durable outbox creation stays valid');
 perform pg_temp.team_assert(public.pso_team_create(n,h,requesthash,'orit','review',t,t+3600000,entries)='created','group review accepted exact recipients');
 perform pg_temp.team_assert(public.pso_team_create(n,h,requesthash,'orit','review',t,t+3600000,entries)='exists','identical group retry');
 perform pg_temp.team_assert(public.pso_team_create(n,h,repeat('8',64),'orit','review',t,t+3600000,entries)='conflict','changed payload for same id rejected');
 perform pg_temp.team_assert(public.pso_team_create(n,hc,requesthash,'cardiology','review',t,t+3600000,cardio)='created','cardiology only designated recipient');
 perform pg_temp.team_assert(public.pso_team_resolve(i,h)->>'token'=pg_temp.team_token(i,n),'own first recipient token');
 perform pg_temp.team_assert(public.pso_team_resolve(j,h)->>'token'=pg_temp.team_token(j,n),'own second recipient token');
 perform pg_temp.team_assert(public.pso_team_resolve(c,h)->>'status'='denied','cardiologist cannot resolve ORIT');
 perform pg_temp.team_assert(public.pso_team_resolve(n,h)->>'status'='denied','neurologist not automatic recipient');
 perform pg_temp.team_assert(public.pso_team_resolve(a,h)->>'status'='denied','admin not automatic recipient');
 perform pg_temp.team_assert(public.pso_team_resolve(x,repeat('0',64))->>'status'='missing','unknown legacy ID permits fallback even before enrollment');
 perform pg_temp.team_assert(public.pso_team_resolve(c,hc)->>'senderCard'=ca,'approved sender card returned');
 -- Push requires current membership AND a sender-consented subscription.
 sub:=jsonb_build_object('endpoint','https://web.push.apple.com/synthetic-team-sql-one','keys',jsonb_build_object('p256dh','B'||repeat('A',86),'auth',repeat('A',22)));
 perform pg_temp.team_assert(public.pso_push_register(i,sub,array[i])='ok','synthetic self-only push subscription');
 perform pg_temp.team_assert(jsonb_array_length(public.pso_team_push_claim(n,h)->'targets')=0,'no consent means no push');
 perform pg_temp.team_assert(public.pso_push_register(i,sub,array[i,n])='ok','explicit sender consent');
 r:=public.pso_team_push_claim(n,h);
 perform pg_temp.team_assert(jsonb_array_length(r->'targets')=1 and r->'targets'->0->>'recipientId'=i,'push only consenting enrolled recipient');
 perform pg_temp.team_assert(jsonb_array_length(public.pso_team_push_claim(n,h)->'targets')=0,'push per-recipient dedup');
 perform pg_temp.team_assert(jsonb_array_length(public.pso_team_push_claim(b,h)->'targets')=0,'other writer cannot push link');
 sub:=jsonb_set(sub,'{endpoint}','"https://web.push.apple.com/synthetic-team-sql-new"');
 perform public.pso_push_register(i,sub,array[i,n]);
 perform pg_temp.team_assert(public.pso_team_push_finish(h,i,'gone')='ok','old endpoint delivery finish');
 perform pg_temp.team_assert(public.pso_push_status(i),'gone result leaves replacement subscription');
 perform pg_temp.team_assert(public.pso_team_push_finish(h,i,'accepted')='unchanged','delivery finish cannot be changed twice');
 -- Revocation rejects future reads and new stale roster sends, but cannot erase
 -- previously downloaded ciphertext. Identical saved retry is still idempotent.
 perform pg_temp.team_assert(public.pso_team_revoke(a,j)='revoked','revoke recipient');
 perform pg_temp.team_assert(public.pso_team_resolve(j,h)->>'status'='denied','revoked recipient cannot resolve');
 perform pg_temp.team_assert(public.pso_team_create(n,h,requesthash,'orit','review',t,t+3600000,entries)='exists','saved retry ignores later roster change');
 perform pg_temp.team_assert(public.pso_team_create(n,repeat('c',64),requesthash,'orit','review',t,t+3600000,entries)='roster_changed','new stale roster rejected');
 perform pg_temp.team_assert(public.pso_team_claim(j,repeat('4',64),ca,sp)='conflict','old invite cannot undo revocation');
 perform pg_temp.team_assert(public.pso_team_revoke(a,n)='revoked','revoke sender');
 perform pg_temp.team_assert(public.pso_team_create(n,h,requesthash,'orit','review',t,t+3600000,entries)='denied','revoked sender cannot retry');
 perform pg_temp.team_assert(public.pso_team_resolve(i,h)->>'status'='ok','existing recipient can verify former sender message');
 perform pg_temp.team_assert(jsonb_array_length(public.pso_team_push_claim(n,h)->'targets')=0,'revoked sender cannot push');
 -- Global and device quota bound unknown signed identities, independently of
 -- link cleanup. Raising counters here is solely within this rolled-back fixture.
 insert into pso_team_private.quotas(subject,period,bucket,used) values(x,'minute',t/60000,60) on conflict(subject,period,bucket) do update set used=60;
 perform pg_temp.team_assert(public.pso_team_accept(x,repeat('D',21)||'A','status',t,ca,sp)='limited','per-device request quota');
 update pso_team_private.quotas set used=20000 where subject='global' and period='day' and bucket=t/86400000;
 perform pg_temp.team_assert(public.pso_team_accept(repeat('H',42)||'A',repeat('E',21)||'A','status',t,ca,sp)='limited','global request quota');
 perform pg_temp.team_assert(not exists(select 1 from pso_team_private.quotas where subject=repeat('H',42)||'A'),'global cap prevents unlimited identity counter growth');
end;$$;
reset role;

-- Administrator-only fixture mutations to exercise expiry/cleanup and grants.
do $$
declare a text:=repeat('A',43);i text:=repeat('D',42)||'A';h text:=repeat('a',64);t bigint:=floor(extract(epoch from clock_timestamp())*1000)::bigint;
begin
 update pso_team_private.links set issued=t-120000,expires=t-1000 where id_hash=h;
 perform pg_temp.team_assert(public.pso_team_resolve(i,h)->>'status'='missing','server expiry denies read');
 update pso_team_private.nonces set created_at=clock_timestamp()-interval '3 minutes' where device_id=a;
 update pso_team_private.invites set expires=t-604800001 where id_hash=repeat('1',64);
 perform pso_team_private.cleanup();
 perform pg_temp.team_assert(not exists(select 1 from pso_team_private.links where id_hash=h),'expired link cleanup');
 perform pg_temp.team_assert(not exists(select 1 from pso_team_private.entries where id_hash=h),'ciphertext entries cascade cleanup');
 perform pg_temp.team_assert(not exists(select 1 from pso_team_private.push_claims where id_hash=h),'push claim cascade cleanup');
 perform pg_temp.team_assert(not exists(select 1 from pso_team_private.nonces where device_id=a),'replay row cleanup');
 perform pg_temp.team_assert(not exists(select 1 from pso_team_private.invites where id_hash=repeat('1',64)),'expired invitation cleanup');
 perform pg_temp.team_assert((select bool_and(relrowsecurity) from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='pso_team_private' and c.relkind='r'),'RLS enabled on all team tables');
 perform pg_temp.team_assert(not exists(select 1 from pg_proc p join pg_namespace n on n.oid=p.pronamespace where (n.nspname='pso_team_private' or (n.nspname='public' and p.proname like 'pso_team_%')) and p.prosecdef),'no security-definer functions');
 perform pg_temp.team_assert(not has_schema_privilege('anon','pso_team_private','USAGE') and not has_schema_privilege('authenticated','pso_team_private','USAGE'),'private schema hidden from browser roles');
end;$$;
select 'Team SQL roles, enrollment, exact recipients, idempotency, consent, push deduplication, revocation, quotas and cleanup assertions passed; all fixtures roll back.' as result;
rollback;
