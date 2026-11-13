-- Privacidad de datos financieros en Supabase:
-- Los nombres de ingresos, obligaciones e historial de pagos se almacenan truncados a los primeros
-- 5 caracteres + "***" y los montos en 0 dentro de las columnas visibles de las tablas.
-- Los valores reales se guardan cifrados en `encrypted_payload` (formato v1:<nonce>:<tag>:<cipher>)
-- para que la app del usuario (y su grupo familiar) pueda reconstruirlos localmente sin exponer
-- en qué ni cuánto gastan los usuarios en la base de datos.

create extension if not exists pgcrypto with schema extensions;

alter table public.incomes
  add column if not exists encrypted_payload text;

alter table public.obligations
  add column if not exists encrypted_payload text;

alter table public.payment_history
  add column if not exists encrypted_payload text;

create or replace function public.mask_sensitive_text(p_text text)
returns text
language sql
immutable
set search_path = ''
as $$
  select case
    when p_text is null or p_text = '' then '***'
    when right(p_text, 3) = '***' and char_length(p_text) <= 8 then p_text
    else left(p_text, 5) || '***'
  end;
$$;

create or replace function public.encrypt_sensitive_payload(p_row_id uuid, p_json text)
returns text
language plpgsql
immutable
set search_path = ''
as $$
declare
  v_key constant text := 'inariko-privacy-v1-9f4b2c8e1a7d6f3052b8e4c1d9a07f63';
  v_id text := lower(p_row_id::text);
  v_plain bytea := convert_to(p_json, 'UTF8');
  v_len int := octet_length(v_plain);
  v_blocks int := ceil(v_len::numeric / 32.0)::int;
  v_nonce_hex text;
  v_keystream bytea;
  v_cipher bytea := ''::bytea;
  v_cipher_hex text;
  v_tag_hex text;
  v_block int;
  v_i int;
  v_offset int;
  v_limit int;
begin
  v_nonce_hex := substr(
    encode(extensions.digest(convert_to(v_key || ':nonce:' || v_id || ':' || p_json, 'UTF8'), 'sha256'), 'hex'),
    1,
    16
  );

  for v_block in 0 .. greatest(v_blocks - 1, 0) loop
    exit when v_len = 0;
    v_keystream := extensions.digest(
      convert_to(v_key || ':enc:' || v_id || ':' || v_nonce_hex || ':' || v_block::text, 'UTF8'),
      'sha256'
    );
    v_offset := v_block * 32;
    v_limit := least(32, v_len - v_offset);
    for v_i in 0 .. (v_limit - 1) loop
      v_cipher := v_cipher || set_byte(
        '\x00'::bytea,
        0,
        get_byte(v_plain, v_offset + v_i) # get_byte(v_keystream, v_i)
      );
    end loop;
  end loop;

  v_cipher_hex := encode(v_cipher, 'hex');
  v_tag_hex := substr(
    encode(
      extensions.digest(
        convert_to(v_key || ':mac:' || v_id || ':' || v_nonce_hex || ':' || v_cipher_hex, 'UTF8'),
        'sha256'
      ),
      'hex'
    ),
    1,
    32
  );

  return 'v1:' || v_nonce_hex || ':' || v_tag_hex || ':' || v_cipher_hex;
end;
$$;

create or replace function public.privacy_mask_incomes()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if tg_op = 'UPDATE' and new.encrypted_payload is null then
    new.encrypted_payload := old.encrypted_payload;
  end if;
  if new.encrypted_payload is null or new.amount > 0 or right(new.name, 3) <> '***' then
    new.encrypted_payload := public.encrypt_sensitive_payload(
      new.id,
      json_build_object('n', new.name, 'a', new.amount)::text
    );
  end if;
  new.name := public.mask_sensitive_text(new.name);
  new.amount := 0;
  return new;
end;
$$;

create or replace function public.privacy_mask_obligations()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if tg_op = 'UPDATE' and new.encrypted_payload is null then
    new.encrypted_payload := old.encrypted_payload;
  end if;
  if new.encrypted_payload is null or new.amount > 0 or right(new.name, 3) <> '***' then
    new.encrypted_payload := public.encrypt_sensitive_payload(
      new.id,
      json_build_object('n', new.name, 'a', new.amount, 'r', new.reference, 'no', new.notes)::text
    );
  end if;
  new.name := public.mask_sensitive_text(new.name);
  new.amount := 0;
  if new.reference is not null and new.reference <> '' then
    new.reference := public.mask_sensitive_text(new.reference);
  end if;
  if new.notes is not null and new.notes <> '' then
    new.notes := '***';
  end if;
  return new;
end;
$$;

create or replace function public.privacy_mask_payment_history()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if tg_op = 'UPDATE' and new.encrypted_payload is null then
    new.encrypted_payload := old.encrypted_payload;
  end if;
  if new.encrypted_payload is null or new.amount > 0 or right(new.obligation_name, 3) <> '***' then
    new.encrypted_payload := public.encrypt_sensitive_payload(
      new.id,
      json_build_object('n', new.obligation_name, 'a', new.amount)::text
    );
  end if;
  new.obligation_name := public.mask_sensitive_text(new.obligation_name);
  new.amount := 0;
  return new;
end;
$$;

drop trigger if exists a_privacy_mask_before_write on public.incomes;
create trigger a_privacy_mask_before_write
  before insert or update on public.incomes
  for each row execute function public.privacy_mask_incomes();

drop trigger if exists a_privacy_mask_before_write on public.obligations;
create trigger a_privacy_mask_before_write
  before insert or update on public.obligations
  for each row execute function public.privacy_mask_obligations();

drop trigger if exists a_privacy_mask_before_write on public.payment_history;
create trigger a_privacy_mask_before_write
  before insert or update on public.payment_history
  for each row execute function public.privacy_mask_payment_history();

-- Enmascarar y cifrar todas las filas existentes conservando server_updated_at para no pisar cachés locales previas.
alter table public.incomes disable trigger sync_before_write;
alter table public.obligations disable trigger sync_before_write;
alter table public.payment_history disable trigger sync_before_write;

update public.incomes
set
  encrypted_payload = coalesce(
    encrypted_payload,
    public.encrypt_sensitive_payload(id, json_build_object('n', name, 'a', amount)::text)
  ),
  name = public.mask_sensitive_text(name),
  amount = 0
where encrypted_payload is null or amount > 0 or right(name, 3) <> '***';

update public.obligations
set
  encrypted_payload = coalesce(
    encrypted_payload,
    public.encrypt_sensitive_payload(id, json_build_object('n', name, 'a', amount, 'r', reference, 'no', notes)::text)
  ),
  name = public.mask_sensitive_text(name),
  amount = 0,
  reference = case when reference is not null and reference <> '' then public.mask_sensitive_text(reference) else reference end,
  notes = case when notes is not null and notes <> '' then '***' else notes end
where encrypted_payload is null or amount > 0 or right(name, 3) <> '***';

update public.payment_history
set
  encrypted_payload = coalesce(
    encrypted_payload,
    public.encrypt_sensitive_payload(id, json_build_object('n', obligation_name, 'a', amount)::text)
  ),
  obligation_name = public.mask_sensitive_text(obligation_name),
  amount = 0
where encrypted_payload is null or amount > 0 or right(obligation_name, 3) <> '***';

alter table public.incomes enable trigger sync_before_write;
alter table public.obligations enable trigger sync_before_write;
alter table public.payment_history enable trigger sync_before_write;
