-- =============================================================================
-- Seguridad: los testers ya no se unen solos al grupo familiar de su pareja
-- =============================================================================
-- La versión anterior (20261112000000_tester_grants.sql) sumaba automáticamente al segundo
-- integrante de cada pareja al grupo del primero apenas se registraba una cuenta con su email.
-- Como no se verifica que el email sea de quien se registra, cualquiera que se anotara con el email
-- de un tester todavía no registrado quedaba dentro del grupo y veía los datos compartidos de la otra
-- persona. Ahora el trigger solo activa los 3 meses de Premium (lo peor que consigue un impostor es
-- Premium gratis) y las parejas se unen con el flujo normal de invitación de la app.
--
-- No deshace grupos ya armados: antes de aplicarla, revisar las membresías existentes con la consulta
-- de auditoría que acompaña al release y sacar a quien no corresponda.

create or replace function public.apply_tester_grant_for_user(p_user_id uuid, p_email text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  g public.tester_grants;
begin
  select * into g from public.tester_grants where email = lower(trim(p_email));
  if g.email is null then
    return;
  end if;

  -- Activar 3 meses de Premium desde hoy (o mantener si ya tenía una fecha mayor).
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
end;
$$;

revoke execute on function public.apply_tester_grant_for_user(uuid, text) from public, anon, authenticated;
