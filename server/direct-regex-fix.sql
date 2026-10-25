-- PostgreSQL bounds a regex repetition count at 255. Keep the same limits
-- using length checks and an unbounded character-class expression instead.
begin;
alter table pso_device_auth_private.credentials
 drop constraint if exists credentials_credential_id_check,
 drop constraint if exists credentials_public_key_check;
alter table pso_device_auth_private.credentials
 add constraint credentials_credential_id_check check(char_length(credential_id) between 16 and 4096 and credential_id ~ '^[A-Za-z0-9_-]+$'),
 add constraint credentials_public_key_check check(char_length(public_key) between 32 and 8192 and public_key ~ '^[A-Za-z0-9_-]+$');
commit;
