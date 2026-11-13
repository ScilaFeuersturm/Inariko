-- =============================================================================
-- Testers pre-aprobados con 3 meses de Inariko Premium (individual y familiar)
-- =============================================================================
-- 1. Guarda los 20 emails y las 3 parejas familiares.
-- 2. Si el usuario ya existe hoy en auth.users, le activa / extiende los 3 meses
--    desde ahora mismo y arma su grupo familiar si ambos integrantes existen.
-- 3. Cuando cualquiera de los testers que faltan se registre en la app, el
--    trigger en auth.users le activa automáticamente sus 3 meses de Premium
--    y, si su pareja ya está registrada, los une automáticamente en su grupo.

create table if not exists public.tester_grants (
  email text primary key,
  plan text not null check (plan in ('individual', 'family')),
  pair_key text,
  pair_role text check (pair_role in ('owner', 'member')),
  created_at timestamptz not null default clock_timestamp()
);

alter table public.tester_grants enable row level security;
revoke all on public.tester_grants from public, anon, authenticated;

insert into public.tester_grants (email, plan, pair_key, pair_role) values
  -- 14 Testers Plan Individual
  ('lucasm.sain@gmail.com', 'individual', null, null),
  ('michaeldavidsg@gmail.com', 'individual', null, null),
  ('necro.business@gmail.com', 'individual', null, null),
  ('m.davidsg11@gmail.com', 'individual', null, null),
  ('lesmeisterakll@gmail.com', 'individual', null, null),
  ('lesmeisterakl@gmail.com', 'individual', null, null),
  ('rocksaveyoursoul3@gmail.com', 'individual', null, null),
  ('francisco.gg.gimenes@gmail.com', 'individual', null, null),
  ('sonianancygomez@gmail.com', 'individual', null, null),
  ('ezequielgimenez432@gmail.com', 'individual', null, null),
  ('miguelchirinoprogramer@gmail.com', 'individual', null, null),
  ('micaela.salerno.ms@gmail.com', 'individual', null, null),
  ('duloneliseo@gmail.com', 'individual', null, null),
  ('agustincabrerabrian563@gmail.com', 'individual', null, null),
  ('gigic2002@hotmail.com', 'individual', null, null),
  ('mrominaovejero@gmail.com', 'individual', null, null),
  -- Pareja Familiar 1: Nidia Mónica Romero + Daniel Carlos Aranda
  ('romeronidiamonica@gmail.com', 'family', 'pair_1', 'owner'),
  ('arandadanielcarlos@gmail.com', 'family', 'pair_1', 'member'),
  -- Pareja Familiar 2: Pablo Russo + Clausia Dahiana
  ('pablorusso2016@hotmail.com', 'family', 'pair_2', 'member'),
  ('clausiadahiana@hotmail.com', 'family', 'pair_2', 'owner'),
  -- Pareja Familiar 3: Eric Rodríguez + Gheo Ponce
  ('ericrodrigueza123@gmail.com', 'family', 'pair_3', 'owner'),
  ('gheoponce@gmail.com', 'family', 'pair_3', 'member')
on conflict (email) do update
set
  plan = excluded.plan,
  pair_key = excluded.pair_key,
  pair_role = excluded.pair_role;

create or replace function public.apply_tester_grant_for_user(p_user_id uuid, p_email text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  g public.tester_grants;
  owner_uid uuid;
  member_uid uuid;
  hid uuid;
begin
  select * into g from public.tester_grants where email = lower(trim(p_email));
  if g.email is null then
    return;
  end if;

  -- Activar 3 meses de Premium desde hoy (o mantener si ya tenía una fecha mayor)
  insert into public.entitlements (user_id, premium_until, source, product_id, plan, updated_at)
  values (
    p_user_id,
    clock_timestamp() + interval '3 months',
    'manual',
    case when g.plan = 'family' then 'tester-familiar-3m' else 'tester-individual-3m' end,
    g.plan,
    clock_timestamp()
  )
  on conflict (user_id) do update
  set
    premium_until = greatest(public.entitlements.premium_until, clock_timestamp() + interval '3 months'),
    source = 'manual',
    product_id = excluded.product_id,
    plan = excluded.plan,
    updated_at = clock_timestamp();

  -- Si pertenece a una pareja familiar, verificar si ambos usuarios ya existen para vincular su grupo
  if g.pair_key is not null then
    select u.id into owner_uid
    from public.tester_grants tg
    join auth.users u on lower(u.email) = tg.email
    where tg.pair_key = g.pair_key and tg.pair_role = 'owner'
    limit 1;

    select u.id into member_uid
    from public.tester_grants tg
    join auth.users u on lower(u.email) = tg.email
    where tg.pair_key = g.pair_key and tg.pair_role = 'member'
    limit 1;

    if owner_uid is not null then
      -- Asegurar que el owner tenga su household creado
      select id into hid from public.households where owner_id = owner_uid;
      if hid is null and not exists (select 1 from public.household_members where user_id = owner_uid) then
        insert into public.households (owner_id, name)
        values (owner_uid, 'Mi casa')
        returning id into hid;

        insert into public.household_members (user_id, household_id, role)
        values (owner_uid, hid, 'owner')
        on conflict (user_id) do nothing;
      end if;

      -- Si el segundo integrante también existe y aún no está en un grupo, sumarlo automáticamente
      if hid is not null and member_uid is not null and not exists (select 1 from public.household_members where user_id = member_uid) then
        insert into public.household_members (user_id, household_id, role)
        values (member_uid, hid, 'member')
        on conflict (user_id) do nothing;
      end if;
    end if;
  end if;
end;
$$;

revoke execute on function public.apply_tester_grant_for_user(uuid, text) from public, anon, authenticated;

create or replace function public.on_auth_user_tester_grant()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform public.apply_tester_grant_for_user(new.id, new.email);
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_tester_grant on auth.users;
create trigger on_auth_user_created_tester_grant
  after insert on auth.users
  for each row execute function public.on_auth_user_tester_grant();

-- Aplicar inmediatamente a cualquier usuario de la lista que ya esté registrado hoy
do $$
declare
  r record;
begin
  for r in
    select u.id, u.email
    from auth.users u
    join public.tester_grants tg on lower(u.email) = tg.email
  loop
    perform public.apply_tester_grant_for_user(r.id, r.email);
  end loop;
end;
$$;
