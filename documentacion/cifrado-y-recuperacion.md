# Cifrado de datos financieros v2 y recuperación por soporte

## Qué cambia

Cada cuenta tiene una clave privada X25519 aleatoria de 256 bits creada en el teléfono.
Se guarda en Keychain/Keystore, con acceso solo en el dispositivo desbloqueado, y se borra
al cerrar sesión o reinstalar. SQLite sigue cifrada con SQLCipher y conserva nombres e
importes completos para mostrarlos sin conexión.

Los ingresos, obligaciones e historial de pagos se cifran **antes** de enviarse a Supabase.
Cada destinatario obtiene un sobre X25519 + HKDF-SHA256 + XChaCha20-Poly1305, con una clave
efímera y nonce nuevos. El contexto autenticado incluye tabla, ID, dueño y destinatario:
trasladar un sobre a otra fila o modificarlo impide descifrarlo.

Las columnas visibles tienen nombre `***`, importe `0` y referencia/notas ocultas.
Ya no se envían las primeras cinco letras del nombre. Siguen visibles los metadatos
necesarios para sincronización y permisos: propietarios, grupos, fechas, monedas,
categorías, estado de pago y marcas de tiempo. El nombre del perfil tampoco es un dato
financiero cifrado.

La clave privada de cada cuenta tiene dos respaldos cifrados en `privacy_vaults`:

- Un sobre con una clave derivada de la contraseña: PBKDF2-HMAC-SHA256, 600.000 iteraciones,
  sal aleatoria de 16 bytes y XChaCha20-Poly1305. Permite entrar desde otro dispositivo.
- Un sobre cifrado para la clave pública de soporte. Permite recuperar los datos si se
  pierde el dispositivo y se restablece la contraseña.

La clave privada de soporte NO va en Supabase, EAS, variables de entorno, funciones,
repositorios, builds ni tickets. La app contiene solo su clave pública y su identificador.
Quien custodie la privada de soporte puede recuperar las cuentas: no es un esquema en
el que únicamente el usuario pueda descifrar.

## Custodia de soporte

Se generó el par `support-2026-11`. El archivo privado inicial se entregó por separado,
fuera del repositorio. Guardarlo en una bóveda externa con acceso restringido y una copia
de respaldo; comprobar que se puede restaurar antes de publicar. No sustituir este par
tras empezar a crear cuentas: las copias antiguas necesitan su privada original.

Para crear un par nuevo en una estación de soporte (Node 22.18 o posterior), desde `mobile`:

```sh
node scripts/privacy-support.mjs generate /ruta/externa/privada.json /ruta/externa/publica.json
```

El generador no sobrescribe archivos existentes y no imprime secretos. Si se configura
otro par antes del lanzamiento, copiar solo la pública y su ID a
`mobile/src/privacy/supportPublicKey.ts`. Para una rotación real después del lanzamiento,
conservar las claves anteriores y planificar el recifrado de los sobres de recuperación;
no basta con reemplazar la constante.

## Recuperación de una cuenta

1. Verificar la identidad por un procedimiento de soporte independiente; no alcanza
   con recibir un UUID o tener una sesión de recuperación de contraseña.
2. Exportar **solo** la fila de `privacy_vaults` correspondiente a esa cuenta como un
   objeto JSON. No hace falta descargar todos sus gastos.
3. En la estación de soporte, con la privada fuera del backend:

   ```sh
   node scripts/privacy-support.mjs recover /boveda/privada.json /seguro/vault.json /seguro/recuperacion.json
   ```

4. El programa verifica el ID de la clave de soporte, autentica el sobre y comprueba
   que la clave recuperada corresponde a la clave pública de la cuenta. El resultado
   es un archivo privado y no se imprime en consola.
5. Entregar `recoverySecret` por un canal seguro a la persona verificada. En la app,
   después de iniciar sesión con la contraseña actual, elegir “Tengo una clave de
   soporte” y pegarla. Se mantiene la identidad y se recifra el respaldo con la
   contraseña actual. No crea otra cuenta ni reemplaza los datos por valores vacíos.
6. Borrar de la estación de trabajo los archivos temporales según el procedimiento de
   soporte. Esa clave recuperada es un secreto duradero de la cuenta, no un código de
   un solo uso: no debe quedar en chats, logs o tickets.

## Plan familiar

Los datos privados solo incluyen el sobre del dueño. Los compartidos incluyen sobres
para los integrantes actuales. Los respaldos privados de otra persona no se exponen a
los demás: el RPC `privacy_recipients` devuelve únicamente claves públicas del propio
usuario y su grupo. Los clientes no pueden modificar esas claves públicas ni el sobre
de soporte una vez creados.

Cuando cambia el grupo, se vuelven a descargar las filas y cada dueño vuelve a cifrar
las suyas para los destinatarios actuales aunque no haya cambiado el importe. Los nuevos
integrantes pueden necesitar que los dueños abran y sincronicen la app. Todos deben
actualizar y activar su protección antes de subir datos compartidos. Al perder acceso al
grupo se eliminan las copias locales ajenas; quien ya leyó un dato legítimamente pudo
conservarlo, algo que ningún recifrado puede revertir.

## Migración y lanzamiento

Este cambio está preparado localmente; no aplica migraciones remotas ni publica builds.

1. Probar en un Supabase de ensayo con cuentas existentes, otra instalación y un grupo
   familiar. Arrancar Docker y ejecutar `npx supabase start` desde la raíz del repo.
   Correr los tests de backend y plan familiar indicados en el README.
2. Custodiar y probar la clave externa de soporte. Confirmar que su pública coincide con
   la incluida en la app.
3. Coordinar una actualización obligatoria: la migración
   `20261113010000_client_privacy_v2.sql` quita del servidor los triggers con la clave
   global y rechaza nuevas escrituras v1 o datos financieros sin cifrar. Las apps viejas
   dejarán de sincronizar hasta actualizarse. La app nueva necesita esa migración para
   activar su protección; planificar el orden del lanzamiento y la ventana de servicio.
4. La app lee v1 **solo para migrar** en el dispositivo. Recupera primero los datos reales
   y luego sube v2; nunca vuelve a cifrar `Sueld***` y `0` como originales. Si no puede
   descifrar, conserva la copia local, falla la sincronización y no avanza el cursor.
5. Medir la migración desde el servidor, sin leer ni descifrar importes:

   ```sql
   select 'incomes' as tabla, count(*) as pendientes from public.incomes
     where encrypted_payload is null or left(encrypted_payload, 3) <> 'v2:'
   union all
   select 'obligations', count(*) from public.obligations
     where encrypted_payload is null or left(encrypted_payload, 3) <> 'v2:'
   union all
   select 'payment_history', count(*) from public.payment_history
     where encrypted_payload is null or left(encrypted_payload, 3) <> 'v2:';
   ```

   Las cuentas inactivas siguen en v1 hasta migrar; no se borran ni se finge que están
   protegidas con v2. También deben migrar las filas borradas lógicamente.
6. Las copias de seguridad, el historial SQL y los datos v1 previos pueden conservar
   datos descifrables con la clave antigua. El nuevo esquema no protege retroactivamente
   esas copias. Después de completar la migración y la retención, se podrá retirar el
   lector legado en otra versión.

La protección es frente al acceso a las tablas/respaldos del backend sin claves privadas.
No cubre un teléfono comprometido, una clave de soporte filtrada, contraseñas débiles
adivinadas, ni un servidor activo malicioso que capture contraseñas al autenticar o
sustituya claves públicas en el primer contacto de un grupo. Para cubrir también ese
último escenario se necesitan verificaciones de identidad independientes del servidor.

## Validación realizada

56 pruebas aprobadas, TypeScript y lint sin errores ni advertencias. Metro exportó
correctamente los bundles Hermes de iOS y Android; esto no instala ni publica la app.
La herramienta offline también se probó con el par de soporte configurado en la app.

- Pruebas de cifrado, manipulación, aislamiento entre cuentas, acceso familiar y soporte.
- Recuperación en otra instalación, contraseña incorrecta y cambio de contraseña.
- Integración del motor con SQLite real: recuperación de una máscara v1, migración a v2,
  incorporación de un nuevo integrante sin cambio de importe y rechazo de una fila corrupta.
- Migración SQL aplicada en PostgreSQL embebido con el esquema base y las políticas reales;
  se verificaron RLS, claves inmutables, acceso del grupo, rechazo de texto/importes reales,
  rechazo de downgrade y eliminación de la función con la clave global. El formato v1 se
  simuló porque ese entorno no incorpora pgcrypto.

La prueba completa contra Supabase local y las pruebas físicas en iOS/Android siguen
pendientes: Docker no estaba iniciado durante esta sesión.

Referencias: [noble-ciphers](https://github.com/paulmillr/noble-ciphers),
[noble-curves](https://github.com/paulmillr/noble-curves),
[SecureStore SDK 57](https://docs.expo.dev/versions/v57.0.0/sdk/securestore/),
[RLS de Supabase](https://supabase.com/docs/guides/database/postgres/row-level-security).
