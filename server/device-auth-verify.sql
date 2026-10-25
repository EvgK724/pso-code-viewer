-- Synthetic rollback-only gate verification. Never uses patient or physician data.
begin;
do $$
declare
 physician text:=repeat('U',42)||'A'; admin_id text:=repeat('V',42)||'A'; stranger text:=repeat('W',42)||'A';
 token text:=repeat('A',43); token_hash text; t bigint; credential jsonb; c text; result text;
begin
 if exists(select 1 from pso_team_private.members where device_id in (physician,admin_id,stranger)) then raise exception 'Synthetic test IDs already exist; choose different IDs';end if;
 t:=floor(extract(epoch from clock_timestamp())*1000)::bigint;
 token_hash:=encode(sha256(convert_to(token,'UTF8')),'hex');
 insert into pso_team_private.members(device_id,name,role,state,card,signing_spki) values
 (physician,'Synthetic unlock test','intensivist','active','PSO-CARD1.'||repeat('A',100),repeat('A',122)),
 (admin_id,'Synthetic unlock administrator','admin','active','PSO-CARD1.'||repeat('A',100),repeat('A',122)),
 (stranger,'Synthetic revoked device','intensivist','revoked','PSO-CARD1.'||repeat('A',100),repeat('A',122));
 if not public.pso_device_unlock_check(physician,'') then raise exception 'Unenrolled active device unexpectedly blocked';end if;
 if public.pso_device_unlock_check(stranger,'') then raise exception 'Revoked device allowed';end if;
 if public.pso_device_auth_challenge_put(physician,'enroll',repeat('A',43),t+290000)<>'ok' then raise exception 'Challenge was not stored';end if;
 c:=public.pso_device_auth_challenge_take(physician,'enroll');if c is distinct from repeat('A',43) then raise exception 'Challenge unavailable';end if;
 if public.pso_device_auth_challenge_take(physician,'enroll') is not null then raise exception 'Challenge replay allowed';end if;
 credential:=jsonb_build_object('id',repeat('A',43),'publicKey',repeat('A',100),'counter',0,'transports',jsonb_build_array('internal'));
 if public.pso_device_auth_enroll(physician,credential,token_hash,t+590000)<>'ok' then raise exception 'Enrollment failed';end if;
 if public.pso_device_auth_enroll(physician,credential,token_hash,t+590000)<>'conflict' then raise exception 'Existing passkey could be overwritten';end if;
 if public.pso_device_unlock_check(physician,'') then raise exception 'Enabled gate accepted missing session';end if;
 if not public.pso_device_unlock_check(physician,token) then raise exception 'Valid session rejected';end if;
 if public.pso_device_unlock_check(stranger,token) then raise exception 'Session crossed device boundary';end if;
 update pso_device_auth_private.sessions set expires=0 where device_id=physician;
 if public.pso_device_unlock_check(physician,token) then raise exception 'Expired session allowed';end if;
 if public.pso_device_auth_unlock(physician,repeat('A',43),0,1,token_hash,t+590000)<>'ok' then raise exception 'Valid authentication state not saved';end if;
 if public.pso_device_auth_unlock(physician,repeat('A',43),0,1,token_hash,t+590000)<>'conflict' then raise exception 'Counter race/replay accepted';end if;
 if public.pso_device_unlock_reset(physician,physician,token)<>'denied' then raise exception 'Nonadmin reset allowed';end if;
 update pso_team_private.members set state='revoked' where device_id=physician;
 if public.pso_device_unlock_check(physician,token) then raise exception 'Revocation did not invalidate session';end if;
 if public.pso_device_unlock_reset(admin_id,physician,'')<>'ok' then raise exception 'Admin could not reset revoked device';end if;
 if exists(select 1 from pso_device_auth_private.sessions where device_id=physician) then raise exception 'Reset left sessions active';end if;
end $$;
rollback;
