import { epochDayOf, toParts } from '@/domain/dates';

import { type PrivacyContext, decryptSensitivePayload, encryptSensitivePayload, isMaskedText, maskSensitiveText } from './privacy';

/**
 * Qué se sincroniza y cómo se convierte cada columna entre la base local (SQLite) y Supabase (Postgres).
 * Los nombres de columna son iguales en los dos lados; cambian los tipos:
 *   bool  0/1 en SQLite        ↔ boolean en Postgres
 *   date  días desde 1970      ↔ 'YYYY-MM-DD'
 */
type ColumnType = 'text' | 'int' | 'bool' | 'date';

export type SyncTable = {
  local: string;
  remote: string;
  primaryKey: string;
  columns: Record<string, ColumnType>;
};

const SYNC_COLUMNS = { updated_at: 'int', deleted: 'bool' } as const;

/**
 * Tablas cuyas filas se pueden compartir con el grupo del plan familiar: se bajan todas las que el
 * servidor deja ver (las propias y las compartidas), no solo las del usuario.
 */
export const SHARED_TABLES = ['incomes', 'obligations', 'payment_history'];

export const SYNC_TABLES: SyncTable[] = [
  {
    local: 'profile',
    remote: 'profiles',
    primaryKey: 'user_id',
    columns: { user_id: 'text', name: 'text', ...SYNC_COLUMNS },
  },
  {
    local: 'budget_plan',
    remote: 'budget_plans',
    primaryKey: 'user_id',
    columns: {
      user_id: 'text',
      model_type: 'text',
      necesidades_percent: 'int',
      deseos_percent: 'int',
      ahorro_percent: 'int',
      reminder_days_before: 'int',
      display_currency: 'text',
      onboarding_completed: 'bool',
      ...SYNC_COLUMNS,
    },
  },
  {
    local: 'incomes',
    remote: 'incomes',
    primaryKey: 'id',
    columns: {
      id: 'text',
      user_id: 'text',
      name: 'text',
      amount: 'int',
      currency: 'text',
      day_of_month: 'int',
      is_recurring: 'bool',
      household_id: 'text',
      ...SYNC_COLUMNS,
    },
  },
  {
    local: 'obligations',
    remote: 'obligations',
    primaryKey: 'id',
    columns: {
      id: 'text',
      user_id: 'text',
      name: 'text',
      reference: 'text',
      amount: 'int',
      currency: 'text',
      due_date: 'date',
      category: 'text',
      is_recurring: 'bool',
      is_paid: 'bool',
      paid_date: 'date',
      notes: 'text',
      created_from_ocr: 'bool',
      created_on: 'date',
      household_id: 'text',
      ...SYNC_COLUMNS,
    },
  },
  {
    local: 'payment_history',
    remote: 'payment_history',
    primaryKey: 'id',
    columns: {
      id: 'text',
      user_id: 'text',
      obligation_id: 'text',
      obligation_name: 'text',
      category: 'text',
      amount: 'int',
      currency: 'text',
      paid_date: 'date',
      household_id: 'text',
      ...SYNC_COLUMNS,
    },
  },
];

export type Row = Record<string, unknown>;

export function epochDayToIso(day: number): string {
  const { year, month, day: d } = toParts(day);
  return `${String(year).padStart(4, '0')}-${String(month).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
}

export function isoToEpochDay(iso: string): number {
  const [year, month, day] = iso.slice(0, 10).split('-').map(Number);
  return epochDayOf(year, month, day);
}

/**
 * Milisegundos de una marca de tiempo de Postgres ("2026-10-12T21:40:00.123456+00:00").
 * Se recortan los microsegundos: no todos los motores de JavaScript los aceptan.
 */
export function parseServerTimestamp(value: string): number {
  const normalized = value.replace(' ', 'T').replace(/(\.\d{3})\d+/, '$1').replace(/\+00(:?00)?$/, 'Z');
  const millis = Date.parse(normalized);
  if (Number.isNaN(millis)) throw new Error(`Marca de tiempo inválida: ${value}`);
  return millis;
}

/** Fila local → fila para Supabase (sin columnas solo-locales como dirty o email). */
export function toRemote(table: SyncTable, local: Row, privacy?: PrivacyContext): Row {
  const out: Row = {};
  for (const [column, type] of Object.entries(table.columns)) {
    const value = local[column];
    if (value == null) out[column] = null;
    else if (type === 'bool') out[column] = !!value;
    else if (type === 'date') out[column] = epochDayToIso(Number(value));
    else if (type === 'int') out[column] = Number(value);
    else out[column] = value;
  }

  // Una máscara de una versión antigua debe recuperarse antes de subir: nunca cifrarla como original.
  if (isLocallyMasked(table, local)) throw new Error('Este dato debe recuperarse del servidor antes de volver a subirlo.');

  if (table.local === 'incomes') {
    const name = String(local.name ?? '');
    const amount = Number(local.amount ?? 0);
    out.encrypted_payload = encryptSensitivePayload({ table: table.local, id: String(local.id), owner: String(local.user_id), shared: local.household_id != null }, { n: name, a: amount }, privacy);
    out.name = maskSensitiveText(name);
    out.amount = 0;
  } else if (table.local === 'obligations') {
    const name = String(local.name ?? '');
    const amount = Number(local.amount ?? 0);
    const reference = local.reference != null ? String(local.reference) : null;
    const notes = local.notes != null ? String(local.notes) : null;
    out.encrypted_payload = encryptSensitivePayload({ table: table.local, id: String(local.id), owner: String(local.user_id), shared: local.household_id != null }, {
      n: name,
      a: amount,
      r: reference,
      no: notes,
    }, privacy);
    out.name = maskSensitiveText(name);
    out.amount = 0;
    out.reference = reference ? maskSensitiveText(reference) : null;
    out.notes = notes ? '***' : null;
  } else if (table.local === 'payment_history') {
    const obligationName = String(local.obligation_name ?? '');
    const amount = Number(local.amount ?? 0);
    out.encrypted_payload = encryptSensitivePayload({ table: table.local, id: String(local.id), owner: String(local.user_id), shared: local.household_id != null }, { n: obligationName, a: amount }, privacy);
    out.obligation_name = maskSensitiveText(obligationName);
    out.amount = 0;
  }

  return out;
}

/** Tablas con nombre y monto enmascarados en el servidor. */
export function isSensitiveTable(table: SyncTable): boolean {
  return table.local === 'incomes' || table.local === 'obligations' || table.local === 'payment_history';
}

/** Columnas que en el servidor están enmascaradas y solo se recuperan descifrando. */
export function sensitiveColumnsOf(table: SyncTable): string[] {
  if (table.local === 'payment_history') return ['obligation_name', 'amount'];
  if (table.local === 'obligations') return ['name', 'amount', 'reference', 'notes'];
  if (table.local === 'incomes') return ['name', 'amount'];
  return [];
}

function isLocallyMasked(table: SyncTable, local: Row): boolean {
  if (!isSensitiveTable(table)) return false;
  const name = table.local === 'payment_history' ? local.obligation_name : local.name;
  return isMaskedText(name) && Number(local.amount ?? 0) === 0;
}

/** Fila de Supabase → valores para la base local. */
export function fromRemote(table: SyncTable, remote: Row, privacy?: PrivacyContext): Row {
  return fromRemoteWithStatus(table, remote, privacy).values;
}

/**
 * Como `fromRemote`, pero avisa si las columnas sensibles se pudieron descifrar. Si no (`decrypted`
 * false), los valores de esas columnas son los enmascarados del servidor y no deben pisar los locales.
 */
export function fromRemoteWithStatus(table: SyncTable, remote: Row, privacy?: PrivacyContext): { values: Row; decrypted: boolean } {
  const out: Row = {};
  for (const [column, type] of Object.entries(table.columns)) {
    const value = remote[column];
    if (value == null) out[column] = null;
    else if (type === 'bool') out[column] = value ? 1 : 0;
    else if (type === 'date') out[column] = isoToEpochDay(String(value));
    else if (type === 'int') out[column] = Number(value);
    else out[column] = value;
  }

  let ok = true;
  if (isSensitiveTable(table)) {
    const decrypted = decryptSensitivePayload({ table: table.local, id: String(remote.id ?? ''), owner: String(remote.user_id), shared: remote.household_id != null }, remote.encrypted_payload as string | null, privacy);
    ok = decrypted != null;
    if (decrypted) {
      if (table.local === 'payment_history') {
        out.obligation_name = decrypted.n;
      } else {
        out.name = decrypted.n;
      }
      out.amount = decrypted.a;
      if (table.local === 'obligations') {
        out.reference = decrypted.r ?? null;
        out.notes = decrypted.no ?? null;
      }
    }
  }

  return { values: out, decrypted: ok };
}

/**
 * Regla de conflictos ("gana el último"): un cambio del servidor se aplica salvo que en este teléfono
 * haya un cambio más nuevo todavía sin subir.
 */
export function shouldApplyRemote(local: { updated_at: number; dirty: number } | null, remoteUpdatedAt: number): boolean {
  if (!local) return true;
  if (!local.dirty) return true;
  return remoteUpdatedAt >= local.updated_at;
}
