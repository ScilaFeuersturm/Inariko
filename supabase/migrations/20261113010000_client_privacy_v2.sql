-- La clave privada vive en el dispositivo; los únicos respaldos son sobres cifrados.
-- La clave privada de soporte NO se instala en Supabase, EAS ni en funciones.
create table public.privacy_vaults (
  user_id uuid primary key references auth.users(id) on delete cascade,
  public_key text not null check (public_key ~ '^[0-9a-f]{64}$'),
  password_box jsonb not null,
  recovery_box jsonb not null,
  recovery_key_id text not null,
  created_at timestamptz not null default clock_timestamp()
);
alter table public.privacy_vaults enable row level security;
revoke all on public.privacy_vaults from anon, authenticated;
grant select, insert on public.privacy_vaults to authenticated;
grant update (password_box) on public.privacy_vaults to authenticated;
create policy vault_read on public.privacy_vaults for select to authenticated using (user_id = (select auth.uid()));
create policy vault_create on public.privacy_vaults for insert to authenticated with check (user_id = (select auth.uid()));
create policy vault_rewrap on public.privacy_vaults for update to authenticated
  using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));

-- No expone los respaldos ajenos. Incluye integrantes sin clave para impedir compartir a medias.
create function public.privacy_recipients()
returns table (user_id uuid, public_key text)
language sql stable security definer set search_path = '' as $$
  select users.id, v.public_key
  from (
    select (select auth.uid()) as id
    union
    select m.user_id from public.household_members m
    where m.household_id = (select public.my_household_id())
  ) users
  left join public.privacy_vaults v on v.user_id = users.id
  where users.id is not null;
$$;
revoke execute on function public.privacy_recipients() from public, anon;
grant execute on function public.privacy_recipients() to authenticated;

-- El servidor no cifra ni recibe importes reales. Permite cambios de metadatos sobre filas v1
-- existentes para no romper las salidas del grupo durante la migración. Rechaza nuevos cifrados v1.
create function public.privacy_require_client_ciphertext()
returns trigger language plpgsql set search_path = '' as $$
begin
  if tg_op = 'UPDATE' then
    if new.id is distinct from old.id or new.user_id is distinct from old.user_id then
      raise exception 'No se puede cambiar la identidad de un dato financiero';
    end if;
    if new.encrypted_payload is not distinct from old.encrypted_payload then
      -- Incluye actualizaciones del sistema al salir/disolver un grupo.
      if to_jsonb(new) - array['household_id','updated_at','server_updated_at','deleted','is_paid','paid_date']
         = to_jsonb(old) - array['household_id','updated_at','server_updated_at','deleted','is_paid','paid_date'] then
        return new;
      end if;
    elsif new.encrypted_payload is null or left(new.encrypted_payload, 3) <> 'v2:' then
      raise exception 'Actualizá la app para sincronizar datos protegidos';
    end if;
  elsif new.encrypted_payload is null or left(new.encrypted_payload, 3) <> 'v2:' then
    raise exception 'Actualizá la app para sincronizar datos protegidos';
  end if;
  if new.amount <> 0 then raise exception 'El servidor no acepta importes sin cifrar'; end if;
  if tg_table_name = 'payment_history' then
    if new.obligation_name <> '***' then raise exception 'El servidor no acepta nombres sin cifrar'; end if;
  else
    if new.name <> '***' then raise exception 'El servidor no acepta nombres sin cifrar'; end if;
    if tg_table_name = 'obligations' then
      if (new.reference is not null and new.reference <> '***')
         or (new.notes is not null and new.notes <> '***') then
        raise exception 'El servidor no acepta referencias ni notas sin cifrar';
      end if;
    end if;
  end if;
  return new;
end;
$$;

-- Reemplaza los triggers con clave global por un validador sin secretos.
drop trigger a_privacy_mask_before_write on public.incomes;
drop trigger a_privacy_mask_before_write on public.obligations;
drop trigger a_privacy_mask_before_write on public.payment_history;
drop function public.privacy_mask_incomes();
drop function public.privacy_mask_obligations();
drop function public.privacy_mask_payment_history();
drop function public.encrypt_sensitive_payload(uuid, text);

do $$ declare t text; begin
  foreach t in array array['incomes','obligations','payment_history'] loop
    execute format('create trigger a_privacy_mask_before_write before insert or update on public.%I
      for each row execute function public.privacy_require_client_ciphertext()', t);
  end loop;
end $$;
