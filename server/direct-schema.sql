-- Direct encrypted inbox. No patient plaintext belongs in this schema.
-- Existing team membership and device signing keys are retained.
begin;
create schema if not exists pso_direct_private;
revoke all on schema pso_direct_private from public,anon,authenticated;
grant usage on schema pso_direct_private to service_role;
alter table pso_team_private.members add column if not exists approval_proof jsonb;
create table if not exists pso_direct_private.messages(
 id text primary key check(pso_team_private.valid_nonce(id)),
 request_hash text not null check(pso_team_private.valid_hash(request_hash)),
 sender_id text not null references pso_team_private.members(device_id),
 group_name text not null check(group_name in ('cardiology','orit')),
 kind text not null check(kind in ('admission','review')),
 issued bigint not null,expires bigint not null,
 payload jsonb,
 created_at timestamptz not null default clock_timestamp(),
 check(issued>0 and expires>issued and expires-issued<=86400000),
 check(payload is null or octet_length(payload::text)<=2000000)
);
create index if not exists pso_direct_expiry on pso_direct_private.messages(expires);
create index if not exists pso_direct_sender on pso_direct_private.messages(sender_id,issued desc,id desc);
create table if not exists pso_direct_private.entries(
 message_id text not null references pso_direct_private.messages(id) on delete cascade,
 recipient_id text not null references pso_team_private.members(device_id),
 token text not null check(octet_length(token)<=1000 and token ~ '^PSO[12]\.' and split_part(token,'.',2)=recipient_id),
 opened_at bigint,
 push_state text not null default 'queued' check(push_state in ('queued','sending','accepted','gone','failed')),
 push_attempts integer not null default 0,
 lease_until bigint not null default 0,next_attempt bigint not null default 0,
 endpoint_hash text,
 primary key(message_id,recipient_id)
);
create index if not exists pso_direct_recipient on pso_direct_private.entries(recipient_id,message_id);
create index if not exists pso_direct_push_due on pso_direct_private.entries(next_attempt) where push_state<>'accepted';
create table if not exists pso_direct_private.audit(
 id bigint generated always as identity primary key,
 actor_id text not null, action text not null,message_id text,target_id text,
 created_at timestamptz not null default clock_timestamp()
);
create index if not exists pso_direct_audit_created on pso_direct_private.audit(created_at);
alter table pso_direct_private.messages enable row level security;
alter table pso_direct_private.entries enable row level security;
alter table pso_direct_private.audit enable row level security;
revoke all on all tables in schema pso_direct_private from public,anon,authenticated;
grant select,insert,update,delete on all tables in schema pso_direct_private to service_role;
grant usage,select on all sequences in schema pso_direct_private to service_role;
-- Two independent bot identities may run alongside each other.
drop index if exists pso_team_private.pso_team_one_bot;
create or replace function public.pso_team_approve(p_admin_id text,p_device_id text)
returns text language plpgsql security invoker set search_path='' as $$
declare v_member pso_team_private.members%rowtype;
begin
 perform pg_catalog.pg_advisory_xact_lock(1347637077,1);
 if not pso_team_private.is_admin(p_admin_id) then return 'denied';end if;
 select * into v_member from pso_team_private.members where device_id=p_device_id;
 if not found or v_member.role='admin' or v_member.state='revoked' then return 'denied';end if;
 if v_member.state='active' then return 'active';end if;
 if v_member.role='cardiologist' and exists(select 1 from pso_team_private.members where role=v_member.role and state='active') then return 'conflict';end if;
 if v_member.role in ('intensivist','bot') and (select count(*) from pso_team_private.members where role=v_member.role and state='active')>=25 then return 'conflict';end if;
 update pso_team_private.members set state='active',approved_at=clock_timestamp() where device_id=p_device_id;
 return 'active';
end;
$$;
create or replace function public.pso_direct_accept(p_device_id text,p_nonce text,p_op text,p_issued bigint,p_card text,p_signing_spki text)
returns text language plpgsql security invoker set search_path='' as $$
begin
 if p_op is null or p_op not in ('create','inbox','outbox','open','ack','retry','admin_members','admin_update','admin_replace','directory','admin_certify') then return 'denied';end if;
 if not exists(select 1 from pso_team_private.members where device_id=p_device_id and state='active' and signing_spki=p_signing_spki) then return 'denied';end if;
 -- Outer signature contains the original operation. Reuse nonce/rate protection.
 return public.pso_team_accept(p_device_id,p_nonce,'status',p_issued,p_card,p_signing_spki);
end;
$$;
create or replace function pso_direct_private.valid_approval(p_id text)
returns boolean language sql stable security invoker set search_path='' as $$
 select coalesce((select m.role='admin' or (m.approval_proof->'grant'->>'subjectId'=m.device_id and m.approval_proof->'grant'->>'name'=m.name and m.approval_proof->'grant'->>'role'=m.role and case when coalesce(m.approval_proof->'grant'->>'expires','')~'^[0-9]{1,16}$' then (m.approval_proof->'grant'->>'expires')::numeric>extract(epoch from clock_timestamp())*1000 else false end and exists(select 1 from pso_team_private.members a where a.device_id=m.approval_proof->'grant'->>'issuerId' and a.role='admin' and a.state='active')) from pso_team_private.members m where m.device_id=p_id),false);
$$;
grant execute on function pso_direct_private.valid_approval(text) to service_role;
create or replace function public.pso_direct_directory(p_device_id text)
returns jsonb language plpgsql stable security invoker set search_path='' as $$
begin
 if not exists(select 1 from pso_team_private.members where device_id=p_device_id and state='active') then return jsonb_build_object('status','denied');end if;
 return jsonb_build_object('members',(select coalesce(jsonb_agg(jsonb_build_object('id',device_id,'name',name,'role',role,'card',card,'approvalProof',approval_proof) order by role,name,device_id),'[]'::jsonb) from pso_team_private.members where state='active' and card is not null));
end;
$$;
create or replace function public.pso_direct_certify(p_admin_id text,p_id text,p_proof jsonb)
returns jsonb language plpgsql security invoker set search_path='' as $$
declare v_target pso_team_private.members%rowtype;
begin
 perform pg_catalog.pg_advisory_xact_lock(1347637077,1);
 if not pso_team_private.is_admin(p_admin_id) then return jsonb_build_object('status','denied');end if;
 select * into v_target from pso_team_private.members where device_id=p_id and state='active' and role<>'admin';
 if not found then return jsonb_build_object('status','denied');end if;
 if p_proof is null or p_proof->'grant'->>'subjectId' is distinct from p_id or p_proof->'grant'->>'name' is distinct from v_target.name or p_proof->'grant'->>'role' is distinct from v_target.role or p_proof->'grant'->>'issuerId' is distinct from p_admin_id or octet_length(p_proof::text)>8000 then return jsonb_build_object('status','invalid');end if;
 update pso_team_private.members set approval_proof=p_proof where device_id=p_id;
 insert into pso_direct_private.audit(actor_id,action,target_id) values(p_admin_id,'certified',p_id);
 return jsonb_build_object('state','active');
end;
$$;
create or replace function public.pso_direct_create(p_sender_id text,p_request_hash text,p_data jsonb)
returns text language plpgsql security invoker set search_path='' as $$
declare v_now bigint;v_role text;v_old pso_direct_private.messages%rowtype;v_expected text[];v_received text[];v_entry jsonb;v_group text;v_kind text;v_id text;v_issued bigint;v_expires bigint;
begin
 if pso_team_private.valid_hash(p_request_hash) is distinct from true or p_data is null or jsonb_typeof(p_data)<>'object' then return 'invalid';end if;
 v_id:=p_data->>'id';v_group:=p_data->>'group';v_kind:=p_data->>'kind';
 if pso_team_private.valid_nonce(v_id) is distinct from true or v_group not in ('cardiology','orit') or v_kind not in ('admission','review') or jsonb_typeof(p_data->'entries') is distinct from 'array' then return 'invalid';end if;
 if not coalesce(p_data->>'issued','')~'^[0-9]{1,16}$' or not coalesce(p_data->>'expires','')~'^[0-9]{1,16}$' then return 'invalid';end if;
 v_issued:=(p_data->>'issued')::bigint;v_expires:=(p_data->>'expires')::bigint;
 if v_issued<=0 or v_expires<=v_issued or v_expires-v_issued>86400000 or jsonb_array_length(p_data->'entries') not between 1 and 25 or octet_length(p_data::text)>2050000 then return 'invalid';end if;
 perform pg_catalog.pg_advisory_xact_lock(1347637077,1);
 v_now:=floor(extract(epoch from clock_timestamp())*1000)::bigint;
 select role into v_role from pso_team_private.members where device_id=p_sender_id and state='active';
 if not found or not pso_direct_private.valid_approval(p_sender_id) or (v_kind='admission' and v_role<>'bot') or (v_kind='review' and v_role not in ('admin','neurologist')) then return 'denied';end if;
 if v_expires<=v_now or v_issued>v_now+30000 then return 'invalid';end if;
 select * into v_old from pso_direct_private.messages where id=v_id;
 if found then
  if v_old.sender_id=p_sender_id and v_old.request_hash=p_request_hash then return 'exists';end if;
  return 'conflict';
 end if;
 select array_agg(device_id order by device_id) into v_expected from pso_team_private.members where state='active' and role=case when v_group='cardiology' then 'cardiologist' else 'intensivist' end;
 select array_agg(value->>'recipientId' order by value->>'recipientId') into v_received from jsonb_array_elements(p_data->'entries');
 if v_expected is null or v_received is distinct from v_expected then return 'roster_changed';end if;
 if exists(select 1 from unnest(v_expected) id where not pso_direct_private.valid_approval(id)) then return 'denied';end if;
 if (select count(*) from pso_direct_private.messages where sender_id=p_sender_id and created_at>clock_timestamp()-interval '1 day')>=500 or (select count(*) from pso_direct_private.messages where created_at>clock_timestamp()-interval '1 day')>=5000 then return 'limited';end if;
 -- Ciphertext-only photo limits bound storage even for authenticated senders.
 if p_data ? 'payload' and ((select count(*) from pso_direct_private.messages where sender_id=p_sender_id and payload is not null and created_at>clock_timestamp()-interval '1 day')>=30 or (select coalesce(sum(octet_length(payload::text)),0) from pso_direct_private.messages)>250000000) then return 'limited';end if;
 for v_entry in select value from jsonb_array_elements(p_data->'entries') loop
  if pso_team_private.valid_id(v_entry->>'recipientId') is distinct from true or octet_length(v_entry->>'token')>1000 or split_part(v_entry->>'token','.',2)<>v_entry->>'recipientId' or split_part(v_entry->>'token','.',3)<>p_sender_id then return 'invalid';end if;
 end loop;
 insert into pso_direct_private.messages(id,request_hash,sender_id,group_name,kind,issued,expires,payload) values(v_id,p_request_hash,p_sender_id,v_group,v_kind,v_issued,v_expires,p_data->'payload');
 insert into pso_direct_private.entries(message_id,recipient_id,token) select v_id,value->>'recipientId',value->>'token' from jsonb_array_elements(p_data->'entries');
 insert into pso_direct_private.audit(actor_id,action,message_id) values(p_sender_id,'created',v_id);
 return 'created';
end;
$$;
create or replace function public.pso_direct_list(p_device_id text,p_outbox boolean,p_cursor jsonb default null)
returns jsonb language plpgsql stable security invoker set search_path='' as $$
declare v_now bigint;v_role text;v_rows jsonb;v_last jsonb;v_before bigint;v_id text;
begin
 select role into v_role from pso_team_private.members where device_id=p_device_id and state='active';
 if not found then return jsonb_build_object('status','denied');end if;
 v_now:=floor(extract(epoch from clock_timestamp())*1000)::bigint;
 if p_cursor is not null then
  if not coalesce(p_cursor->>'issued','')~'^[0-9]{1,16}$' or pso_team_private.valid_nonce(p_cursor->>'id') is distinct from true then return jsonb_build_object('status','invalid');end if;
  v_before:=(p_cursor->>'issued')::bigint;v_id:=p_cursor->>'id';
 end if;
 select coalesce(jsonb_agg(x.item order by x.issued desc,x.id desc),'[]'::jsonb) into v_rows from (
  select m.issued,m.id,jsonb_build_object('id',m.id,'group',m.group_name,'kind',m.kind,'issued',m.issued,'expires',m.expires,'senderId',m.sender_id,'senderName',s.name,'openedAt',e.opened_at,'recipientCount',(select count(*) from pso_direct_private.entries z where z.message_id=m.id),'openedCount',(select count(*) from pso_direct_private.entries z where z.message_id=m.id and z.opened_at is not null)) item
  from pso_direct_private.messages m join pso_team_private.members s on s.device_id=m.sender_id
  left join pso_direct_private.entries e on e.message_id=m.id and e.recipient_id=p_device_id
  where m.expires>v_now and (p_cursor is null or (m.issued,m.id)<(v_before,v_id))
   and ((p_outbox and m.sender_id=p_device_id) or (not p_outbox and e.recipient_id=p_device_id and ((v_role='cardiologist' and m.group_name='cardiology') or(v_role='intensivist' and m.group_name='orit'))))
  order by m.issued desc,m.id desc limit 51
 ) x;
 if jsonb_array_length(v_rows)>50 then v_rows:=v_rows-50;v_last:=v_rows->49;end if;
 return jsonb_build_object('items',v_rows,'next',case when v_last is null then null else jsonb_build_object('issued',v_last->'issued','id',v_last->'id') end);
end;
$$;
create or replace function public.pso_direct_open(p_device_id text,p_id text,p_ack boolean default false)
returns jsonb language plpgsql security invoker set search_path='' as $$
declare v_now bigint;v_role text;v_message pso_direct_private.messages%rowtype;v_entry pso_direct_private.entries%rowtype;v_sender pso_team_private.members%rowtype;
begin
 v_now:=floor(extract(epoch from clock_timestamp())*1000)::bigint;
 select role into v_role from pso_team_private.members where device_id=p_device_id and state='active';
 if not found then return jsonb_build_object('status','denied');end if;
 select * into v_message from pso_direct_private.messages where id=p_id and expires>v_now;
 if not found then return jsonb_build_object('status','missing');end if;
 if (v_message.group_name='cardiology' and v_role<>'cardiologist') or (v_message.group_name='orit' and v_role<>'intensivist') then return jsonb_build_object('status','denied');end if;
 select * into v_entry from pso_direct_private.entries where message_id=p_id and recipient_id=p_device_id;
 if not found then return jsonb_build_object('status','denied');end if;
 select * into v_sender from pso_team_private.members where device_id=v_message.sender_id;
 if p_ack then
  update pso_direct_private.entries set opened_at=coalesce(opened_at,v_now) where message_id=p_id and recipient_id=p_device_id returning opened_at into v_entry.opened_at;
  if v_entry.opened_at=v_now then insert into pso_direct_private.audit(actor_id,action,message_id) values(p_device_id,'opened',p_id);end if;
  return jsonb_build_object('openedAt',v_entry.opened_at);
 end if;
 insert into pso_direct_private.audit(actor_id,action,message_id) values(p_device_id,'retrieved',p_id);
 return jsonb_build_object('token',v_entry.token,'payload',v_message.payload,'senderCard',v_sender.card,'senderName',v_sender.name,'senderRole',v_sender.role,'senderApprovalProof',v_sender.approval_proof,'meta',jsonb_build_object('id',v_message.id,'group',v_message.group_name,'kind',v_message.kind,'issued',v_message.issued,'expires',v_message.expires));
end;
$$;
create or replace function public.pso_direct_members(p_admin_id text)
returns jsonb language plpgsql stable security invoker set search_path='' as $$
begin
 if not pso_team_private.is_admin(p_admin_id) then return jsonb_build_object('status','denied');end if;
 return jsonb_build_object('members',(select coalesce(jsonb_agg(jsonb_build_object('id',device_id,'name',name,'role',role,'state',state,'card',card,'createdAt',floor(extract(epoch from created_at)*1000)::bigint,'approvedAt',floor(extract(epoch from approved_at)*1000)::bigint,'revokedAt',floor(extract(epoch from revoked_at)*1000)::bigint,'approvalProof',approval_proof) order by state,name,device_id),'[]'::jsonb) from pso_team_private.members));
end;
$$;
create or replace function public.pso_direct_update(p_admin_id text,p_id text,p_name text,p_role text,p_state text,p_proof jsonb default null)
returns jsonb language plpgsql security invoker set search_path='' as $$
declare v_old pso_team_private.members%rowtype;
begin
 perform pg_catalog.pg_advisory_xact_lock(1347637077,1);
 if not pso_team_private.is_admin(p_admin_id) or p_id=p_admin_id then return jsonb_build_object('status','denied');end if;
 select * into v_old from pso_team_private.members where device_id=p_id;
 if not found or v_old.role='admin' or v_old.state<>'active' then return jsonb_build_object('status','denied');end if;
 if p_name is null or char_length(p_name) not between 1 and 60 or p_name~'[[:cntrl:]]' or p_name !~ '[^[:space:]]' or p_role not in ('neurologist','cardiologist','intensivist','bot') or p_state not in ('active','revoked') then return jsonb_build_object('status','invalid');end if;
 if p_state='active' and p_role='cardiologist' and exists(select 1 from pso_team_private.members where device_id<>p_id and state='active' and role='cardiologist') then return jsonb_build_object('status','conflict');end if;
 if p_state='active' and p_role in ('bot','intensivist') and (select count(*) from pso_team_private.members where device_id<>p_id and state='active' and role=p_role)>=25 then return jsonb_build_object('status','conflict');end if;
 if p_state='active' and (p_proof is null or p_proof->'grant'->>'subjectId' is distinct from p_id or p_proof->'grant'->>'role' is distinct from p_role or p_proof->'grant'->>'name' is distinct from p_name or p_proof->'grant'->>'issuerId' is distinct from p_admin_id) then return jsonb_build_object('status','invalid');end if;
 update pso_team_private.members set name=p_name,role=p_role,state=p_state,approval_proof=case when p_state='active' then p_proof else null end,revoked_at=case when p_state='revoked' then clock_timestamp() else revoked_at end where device_id=p_id;
 if p_state='revoked' then delete from pso_push_private.subscriptions where device_id=p_id;end if;
 insert into pso_direct_private.audit(actor_id,action,target_id) values(p_admin_id,case when p_state='revoked' then 'revoked' else 'updated' end,p_id);
 return jsonb_build_object('state',p_state);
end;
$$;
create or replace function public.pso_direct_replace(p_admin_id text,p_old_id text,p_new_id text,p_proof jsonb)
returns jsonb language plpgsql security invoker set search_path='' as $$
declare v_old pso_team_private.members%rowtype;v_new pso_team_private.members%rowtype;
begin
 perform pg_catalog.pg_advisory_xact_lock(1347637077,1);
 if not pso_team_private.is_admin(p_admin_id) or p_old_id=p_new_id or p_old_id=p_admin_id then return jsonb_build_object('status','denied');end if;
 select * into v_old from pso_team_private.members where device_id=p_old_id;
 if not found or v_old.role='admin' or v_old.state not in ('active','revoked') then return jsonb_build_object('status','denied');end if;
 select * into v_new from pso_team_private.members where device_id=p_new_id;
 if not found or v_new.role='admin' or v_new.state<>'pending' then return jsonb_build_object('status','denied');end if;
 if v_old.role='cardiologist' and exists(select 1 from pso_team_private.members where device_id<>p_old_id and state='active' and role='cardiologist') then return jsonb_build_object('status','conflict');end if;
 if v_old.state='revoked' and v_old.role in ('bot','intensivist') and (select count(*) from pso_team_private.members where state='active' and role=v_old.role)>=25 then return jsonb_build_object('status','conflict');end if;
 if p_proof is null or p_proof->'grant'->>'subjectId' is distinct from p_new_id or p_proof->'grant'->>'name' is distinct from v_old.name or p_proof->'grant'->>'role' is distinct from v_old.role or p_proof->'grant'->>'issuerId' is distinct from p_admin_id then return jsonb_build_object('status','invalid');end if;
 update pso_team_private.members set state='revoked',approval_proof=null,revoked_at=coalesce(revoked_at,clock_timestamp()) where device_id=p_old_id;
 delete from pso_push_private.subscriptions where device_id=p_old_id;
 update pso_team_private.members set state='active',name=v_old.name,role=v_old.role,approval_proof=p_proof,approved_at=clock_timestamp() where device_id=p_new_id;
 insert into pso_direct_private.audit(actor_id,action,target_id) values(p_admin_id,'replaced_old',p_old_id),(p_admin_id,'replaced_new',p_new_id);
 return jsonb_build_object('state','active');
end;
$$;
create or replace function public.pso_direct_push_claim(p_actor_id text,p_message_id text default null)
returns jsonb language plpgsql security invoker set search_path='' as $$
declare v_now bigint;v_role text;v_row record;v_targets jsonb:='[]'::jsonb;v_lease integer;
begin
 select role into v_role from pso_team_private.members where device_id=p_actor_id and state='active';
 if not found then return jsonb_build_object('status','denied');end if;
 v_now:=floor(extract(epoch from clock_timestamp())*1000)::bigint;
 for v_row in select e.message_id,e.recipient_id,m.expires,s.subscription,s.endpoint_hash
  from pso_direct_private.entries e join pso_direct_private.messages m on m.id=e.message_id
  join pso_team_private.members r on r.device_id=e.recipient_id and r.state='active'
  join pso_team_private.members sender on sender.device_id=m.sender_id and sender.state='active'
  join pso_push_private.subscriptions s on s.device_id=e.recipient_id
  where m.expires>v_now and e.push_state<>'accepted' and e.push_attempts<8 and e.lease_until<=v_now and e.next_attempt<=v_now
   and (p_message_id is null or m.id=p_message_id)
   and (v_role in ('bot','admin') or m.sender_id=p_actor_id)
   and ((m.group_name='cardiology' and r.role='cardiologist') or (m.group_name='orit' and r.role='intensivist'))
   and ((m.kind='admission' and sender.role='bot') or(m.kind='review' and sender.role in ('admin','neurologist')))
  order by e.next_attempt,m.issued limit 20 for update of e skip locked
 loop
  update pso_direct_private.entries set push_state='sending',push_attempts=push_attempts+1,lease_until=v_now+60000,endpoint_hash=v_row.endpoint_hash where message_id=v_row.message_id and recipient_id=v_row.recipient_id returning push_attempts into v_lease;
  v_targets:=v_targets||jsonb_build_array(jsonb_build_object('id',v_row.message_id,'recipientId',v_row.recipient_id,'expires',v_row.expires,'subscription',v_row.subscription,'lease',v_lease));
 end loop;
 return jsonb_build_object('targets',v_targets);
end;
$$;
create or replace function public.pso_direct_push_finish(p_id text,p_recipient_id text,p_lease integer,p_status text)
returns text language plpgsql security invoker set search_path='' as $$
declare v_now bigint;v_hash text;
begin
 if p_status not in ('accepted','gone','failed') then return 'invalid';end if;
 v_now:=floor(extract(epoch from clock_timestamp())*1000)::bigint;
 update pso_direct_private.entries set push_state=p_status,lease_until=0,next_attempt=v_now+(least(3600000,30000*power(2,least(push_attempts,6)))::bigint)
  where message_id=p_id and recipient_id=p_recipient_id and push_attempts=p_lease and push_state='sending' returning endpoint_hash into v_hash;
 if not found then return 'stale';end if;
 if p_status='gone' then delete from pso_push_private.subscriptions where device_id=p_recipient_id and endpoint_hash=v_hash;end if;
 return 'ok';
end;
$$;
create or replace function public.pso_direct_cleanup()
returns void language plpgsql security invoker set search_path='' as $$
begin
 delete from pso_direct_private.messages where expires<=floor(extract(epoch from clock_timestamp())*1000)::bigint;
 delete from pso_direct_private.audit where created_at<clock_timestamp()-interval '7 days';
end;
$$;
-- These RPCs are reachable only by the authenticated edge service role.
do $$ declare r record;begin
 for r in select p.oid::regprocedure as f from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='public' and p.proname like 'pso_direct_%' loop
  execute format('revoke all on function %s from public,anon,authenticated',r.f);
  execute format('grant execute on function %s to service_role',r.f);
 end loop;
end;$$;
-- pg_cron is already used by this project; no network secret is required.
do $$begin
 if exists(select 1 from pg_namespace where nspname='cron') then
  if not exists(select 1 from cron.job where jobname='pso-direct-expiry') then perform cron.schedule('pso-direct-expiry','*/5 * * * *','select public.pso_direct_cleanup()');end if;
 end if;
end;$$;
commit;
