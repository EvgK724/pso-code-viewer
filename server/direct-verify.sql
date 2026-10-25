-- Run after direct-schema.sql. Synthetic rows only, rolled back; NO network calls.
-- Execute on a test project or before real recipient enrollment.
begin;
create function pg_temp.direct_assert(ok boolean,label text) returns void language plpgsql as $$begin if ok is distinct from true then raise exception 'Direct assertion: %',label;end if;end;$$;
create function pg_temp.direct_proof(id text,n text,r text,a text,t bigint) returns jsonb language sql as $$select jsonb_build_object('grant',jsonb_build_object('v',1,'subjectId',id,'name',n,'role',r,'issued',t,'expires',t+86400000,'issuerId',a),'signature',repeat('A',86),'issuerCard','PSO-CARD1.'||repeat('A',150));$$;
-- HTTP handler verifies cryptographic signatures. SQL fixtures test access/state.
set local role anon;
do $$begin
 begin perform public.pso_direct_list(repeat('A',43),false,null);raise exception 'anon RPC unexpectedly allowed';exception when insufficient_privilege then null;end;
 begin perform count(*) from pso_direct_private.messages;raise exception 'anon table unexpectedly allowed';exception when insufficient_privilege then null;end;
end;$$;
reset role;
set local role authenticated;
do $$begin
 begin perform public.pso_direct_cleanup();raise exception 'authenticated cleanup unexpectedly allowed';exception when insufficient_privilege then null;end;
end;$$;
reset role;
do $$begin
 if exists(select 1 from pso_team_private.members where state='active' and role in ('cardiologist','intensivist')) then raise exception 'Use a test project: real active recipient enrollment exists';end if;
 if exists(select 1 from pso_team_private.members where device_id in (repeat('U',42)||'A',repeat('V',42)||'A',repeat('W',42)||'A',repeat('X',42)||'A',repeat('Y',42)||'A',repeat('Z',42)||'A',repeat('T',42)||'A')) then raise exception 'Fixture IDs occupied';end if;
 insert into pso_team_private.members(device_id,name,role,state,card,signing_spki) values
  (repeat('U',42)||'A','Synthetic organizer','admin','active','PSO-CARD1.'||repeat('A',150),repeat('A',122)),
  (repeat('V',42)||'A','Synthetic bot','bot','active','PSO-CARD1.'||repeat('A',150),repeat('A',122)),
  (repeat('W',42)||'A','Synthetic neurologist','neurologist','active','PSO-CARD1.'||repeat('A',150),repeat('A',122)),
  (repeat('X',42)||'A','Synthetic intensivist','intensivist','active','PSO-CARD1.'||repeat('A',150),repeat('A',122)),
  (repeat('Y',42)||'A','Synthetic new phone','intensivist','pending','PSO-CARD1.'||repeat('A',150),repeat('A',122)),
  (repeat('Z',42)||'A','Synthetic second bot','bot','pending','PSO-CARD1.'||repeat('A',150),repeat('A',122)),
  (repeat('T',42)||'A','Synthetic cardio','cardiologist','active','PSO-CARD1.'||repeat('A',150),repeat('A',122));
end;$$;
set local role service_role;
do $$
declare
 a text:=repeat('U',42)||'A';b text:=repeat('V',42)||'A';n text:=repeat('W',42)||'A';i text:=repeat('X',42)||'A';j text:=repeat('Y',42)||'A';b2 text:=repeat('Z',42)||'A';c text:=repeat('T',42)||'A';
 mid text:=repeat('K',21)||'A';t bigint:=floor(extract(epoch from clock_timestamp())*1000)::bigint;d jsonb;r jsonb;proof jsonb;lease integer;
begin
 perform pg_temp.direct_assert(public.pso_team_approve(a,b2)='active','second bot approval leaves first active');
 perform pg_temp.direct_assert((select count(*) from pso_team_private.members where device_id in (b,b2) and state='active')=2,'parallel bots');
 perform public.pso_direct_certify(a,b,pg_temp.direct_proof(b,'Synthetic bot','bot',a,t));
 perform public.pso_direct_certify(a,n,pg_temp.direct_proof(n,'Synthetic neurologist','neurologist',a,t));
 perform public.pso_direct_certify(a,i,pg_temp.direct_proof(i,'Synthetic intensivist','intensivist',a,t));
 perform public.pso_direct_certify(a,c,pg_temp.direct_proof(c,'Synthetic cardio','cardiologist',a,t));
 perform pg_temp.direct_assert(public.pso_direct_accept(b,repeat('A',22),'inbox',t,'PSO-CARD1.'||repeat('A',150),repeat('A',122))='ok','direct envelope nonce accepted');
 perform pg_temp.direct_assert(public.pso_direct_accept(b,repeat('A',22),'inbox',t,'PSO-CARD1.'||repeat('A',150),repeat('A',122))='replay','nonce replay denied');
 perform pg_temp.direct_assert(public.pso_direct_accept(j,repeat('B',21)||'A','inbox',t,'PSO-CARD1.'||repeat('A',150),repeat('A',122))='denied','pending device denied');
 d:=jsonb_build_object('id',mid,'group','orit','kind','admission','issued',t,'expires',t+3600000,'entries',jsonb_build_array(jsonb_build_object('recipientId',i,'token','PSO1.'||i||'.'||b||'.'||repeat('A',512)||'.'||repeat('A',86))));
 perform pg_temp.direct_assert(public.pso_direct_create(n,repeat('1',64),d)='denied','neurologist cannot create admission');
 perform pg_temp.direct_assert(public.pso_direct_create(b,repeat('1',64),d)='created','direct admission persisted');
 perform pg_temp.direct_assert(public.pso_direct_create(b,repeat('1',64),d)='exists','idempotent retry');
 perform pg_temp.direct_assert(public.pso_direct_create(b,repeat('2',64),d)='conflict','same id different content rejected');
 perform pg_temp.direct_assert(jsonb_array_length(public.pso_direct_list(i,false,null)->'items')=1,'recipient inbox');
 perform pg_temp.direct_assert(jsonb_array_length(public.pso_direct_list(c,false,null)->'items')=0,'other group sees no entry');
 perform pg_temp.direct_assert(public.pso_direct_open(c,mid,false)->>'status'='denied','other role cannot open');
 perform pg_temp.direct_assert(public.pso_direct_open(j,mid,false)->>'status'='denied','pending phone cannot open');
 perform pg_temp.direct_assert(public.pso_direct_open(i,mid,false)->'meta'->>'id'=mid,'recipient opens ciphertext');
 perform pg_temp.direct_assert((public.pso_direct_open(i,mid,true)->>'openedAt')::bigint>=t,'ack recorded');
 perform pg_temp.direct_assert((public.pso_direct_list(b,true,null)->'items'->0->>'openedCount')::int=1,'sender receipt count');
 insert into pso_push_private.subscriptions(device_id,endpoint_hash,subscription,senders) values(i,repeat('f',64),'{"endpoint":"https://unit.push.apple.com/synthetic","keys":{"auth":"not-real","p256dh":"not-real"}}',array[b,n]);
 r:=public.pso_direct_push_claim(b,null);perform pg_temp.direct_assert(jsonb_array_length(r->'targets')=1,'push lease claimed');lease:=(r->'targets'->0->>'lease')::int;
 perform pg_temp.direct_assert(jsonb_array_length(public.pso_direct_push_claim(b,null)->'targets')=0,'lease prevents concurrent duplicate');
 perform pg_temp.direct_assert(public.pso_direct_push_finish(mid,i,lease,'failed')='ok','failure persists');
 update pso_direct_private.entries set next_attempt=0 where message_id=mid;
 r:=public.pso_direct_push_claim(b,null);perform pg_temp.direct_assert((r->'targets'->0->>'lease')::int=lease+1,'failed lease retry');
 perform pg_temp.direct_assert(public.pso_direct_push_finish(mid,i,lease,'accepted')='stale','stale worker cannot finish new lease');
 perform public.pso_direct_push_finish(mid,i,lease+1,'accepted');
 perform pg_temp.direct_assert(jsonb_array_length(public.pso_direct_push_claim(b,null)->'targets')=0,'accepted notice not retried');
 perform pg_temp.direct_assert(public.pso_direct_update(n,i,'X','intensivist','revoked',null)->>'status'='denied','nonadmin cannot revoke');
 perform pg_temp.direct_assert(public.pso_direct_update(a,a,'X','neurologist','revoked',null)->>'status'='denied','admin self lockout denied');
 proof:=pg_temp.direct_proof(j,'Synthetic intensivist','intensivist',a,t);
 perform pg_temp.direct_assert(public.pso_direct_replace(a,i,j,proof)->>'state'='active','replacement active');
 perform pg_temp.direct_assert(public.pso_direct_open(i,mid,false)->>'status'='denied','old phone revoked');
 perform pg_temp.direct_assert(public.pso_direct_open(j,mid,false)->>'status'='denied','new key cannot access old encrypted copies');
 perform pg_temp.direct_assert(not exists(select 1 from pso_push_private.subscriptions where device_id=i),'old notification subscription removed');
 update pso_direct_private.messages set issued=t-7200000,expires=t-1 where id=mid;
 perform pg_temp.direct_assert(public.pso_direct_open(j,mid,false)->>'status'='missing','expired inaccessible');
 perform public.pso_direct_cleanup();
 perform pg_temp.direct_assert(not exists(select 1 from pso_direct_private.messages where id=mid),'expired payload removed');
 perform pg_temp.direct_assert(not exists(select 1 from pso_direct_private.entries where message_id=mid),'expired recipient copies cascaded');
end;$$;
reset role;
rollback;
