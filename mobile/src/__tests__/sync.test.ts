import { epochDayOf } from '@/domain/dates';
import {
  epochDayToIso,
  fromRemote,
  fromRemoteWithStatus,
  isoToEpochDay,
  parseServerTimestamp,
  sensitiveColumnsOf,
  shouldApplyRemote,
  SYNC_TABLES,
  toRemote,
} from '@/sync/tables';
import { utf8Decode, utf8Encode } from '@/sync/privacy';
import { sha256 } from '@noble/hashes/sha2.js';

const obligations = SYNC_TABLES.find((t) => t.local === 'obligations')!;

test('fechas: días desde 1970 ↔ YYYY-MM-DD', () => {
  expect(epochDayToIso(epochDayOf(2026, 10, 9))).toBe('2026-10-09');
  expect(isoToEpochDay('2026-10-09')).toBe(epochDayOf(2026, 10, 9));
  expect(isoToEpochDay('2024-02-29')).toBe(epochDayOf(2024, 2, 29));
});

test('marcas de tiempo de Postgres con microsegundos', () => {
  expect(parseServerTimestamp('2026-10-12T21:40:00.123456+00:00')).toBe(Date.UTC(2026, 9, 12, 21, 40, 0, 123));
  expect(parseServerTimestamp('2026-10-12 21:40:00+00')).toBe(Date.UTC(2026, 9, 12, 21, 40, 0));
  expect(() => parseServerTimestamp('basura')).toThrow();
});

test('una factura local se convierte al formato del servidor y vuelve igual', () => {
  const local = {
    id: '6f0c2a52-1111-4a6b-9d0b-2f0f6a6b0001',
    user_id: 'b3f1c1d2-2222-4c3d-8e4f-5a6b7c8d0002',
    name: 'Luz',
    reference: null,
    amount: 350000,
    currency: 'PYG',
    due_date: epochDayOf(2026, 10, 20),
    category: 'SERVICIOS',
    is_recurring: 1,
    is_paid: 0,
    paid_date: null,
    notes: null,
    created_from_ocr: 0,
    created_on: epochDayOf(2026, 10, 12),
    // Compartida con el grupo del plan familiar: el id del grupo viaja tal cual.
    household_id: '9a8b7c6d-3333-4e5f-8a9b-0c1d2e3f0003',
    updated_at: 1_791_000_000_000,
    deleted: 0,
    dirty: 1,
  };
  const remote = toRemote(obligations, local);
  expect(remote.household_id).toBe(local.household_id);
  expect(remote).toMatchObject({
    name: 'Luz***',
    amount: 0,
    due_date: '2026-10-20',
    is_recurring: true,
    is_paid: false,
    created_on: '2026-10-12',
  });
  expect(typeof remote.encrypted_payload).toBe('string');
  expect(remote).not.toHaveProperty('dirty');

  const { dirty: _dirty, ...expected } = local;
  expect(fromRemote(obligations, { ...remote, server_updated_at: '2026-10-12T00:00:00+00:00' })).toEqual(expected);
});

test('privacidad: trunca a 5 caracteres + *** en el servidor y recupera el original al bajar', () => {
  const local = {
    id: '6f0c2a52-1111-4a6b-9d0b-2f0f6a6b0099',
    user_id: 'b3f1c1d2-2222-4c3d-8e4f-5a6b7c8d0002',
    name: 'Supermercado mensual',
    reference: 'FACT-998877',
    amount: 12500000,
    currency: 'ARS',
    due_date: epochDayOf(2026, 11, 15),
    category: 'ALIMENTACION',
    is_recurring: 1,
    is_paid: 1,
    paid_date: epochDayOf(2026, 11, 10),
    notes: 'Compra grande del mes',
    created_from_ocr: 0,
    created_on: epochDayOf(2026, 11, 1),
    household_id: null,
    updated_at: 1_794_000_000_000,
    deleted: 0,
    dirty: 1,
  };
  const remote = toRemote(obligations, local);
  expect(remote.name).toBe('Super***');
  expect(remote.reference).toBe('FACT-***');
  expect(remote.notes).toBe('***');
  expect(remote.amount).toBe(0);

  const restored = fromRemote(obligations, remote);
  expect(restored.name).toBe('Supermercado mensual');
  expect(restored.reference).toBe('FACT-998877');
  expect(restored.notes).toBe('Compra grande del mes');
  expect(restored.amount).toBe(12500000);
});

test('conflictos: gana el cambio más reciente', () => {
  // Sin la fila en el teléfono, o sin cambios locales pendientes: se aplica lo del servidor.
  expect(shouldApplyRemote(null, 100)).toBe(true);
  expect(shouldApplyRemote({ updated_at: 500, dirty: 0 }, 100)).toBe(true);
  // Con un cambio local pendiente, solo se pisa si el del servidor es igual o más nuevo.
  expect(shouldApplyRemote({ updated_at: 500, dirty: 1 }, 100)).toBe(false);
  expect(shouldApplyRemote({ updated_at: 500, dirty: 1 }, 900)).toBe(true);
});

test('todas las tablas sincronizadas tienen dueño y columnas de sincronización', () => {
  for (const table of SYNC_TABLES) {
    expect(table.columns).toHaveProperty('user_id');
    expect(table.columns).toHaveProperty('updated_at', 'int');
    expect(table.columns).toHaveProperty('deleted', 'bool');
  }
});

const incomes = SYNC_TABLES.find((t) => t.local === 'incomes')!;
const INCOME_ID = '0a1b2c3d-4444-4e5f-9a0b-1c2d3e4f0004';
const USER_ID = 'b3f1c1d2-2222-4c3d-8e4f-5a6b7c8d0002';

/**
 * Cifrado tal como lo hace el trigger de Postgres (privacy_mask_incomes), reimplementado con el
 * mismo algoritmo: sirve para comprobar que la app descifra filas cifradas en el servidor, cuyo JSON
 * tiene otro formato ('{"n" : ..., "a" : ...}').
 */
function encryptLikePostgres(rowId: string, json: string): string {
  const key = 'inariko-privacy-v1-9f4b2c8e1a7d6f3052b8e4c1d9a07f63';
  const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  const sha = (text: string) => sha256(utf8Encode(text));
  const id = rowId.toLowerCase();
  const nonce = hex(sha(`${key}:nonce:${id}:${json}`)).slice(0, 16);
  const plain = utf8Encode(json);
  const cipher = plain.map((byte, i) => byte ^ sha(`${key}:enc:${id}:${nonce}:${Math.floor(i / 32)}`)[i % 32]);
  const cipherHex = hex(cipher);
  const tag = hex(sha(`${key}:mac:${id}:${nonce}:${cipherHex}`)).slice(0, 32);
  return `v1:${nonce}:${tag}:${cipherHex}`;
}

const remoteIncome = (encrypted_payload: string | null) => ({
  id: INCOME_ID,
  user_id: USER_ID,
  name: 'Sueld***',
  amount: 0,
  currency: 'ARS',
  day_of_month: 5,
  is_recurring: true,
  household_id: null,
  updated_at: 1_794_000_000_000,
  deleted: false,
  encrypted_payload,
});

test('privacidad: la app descifra sin TextEncoder/TextDecoder (Hermes)', () => {
  const g = globalThis as { TextEncoder?: unknown; TextDecoder?: unknown };
  const saved = { TextEncoder: g.TextEncoder, TextDecoder: g.TextDecoder };
  delete g.TextEncoder;
  delete g.TextDecoder;
  try {
    const local = { id: INCOME_ID, user_id: USER_ID, name: 'Sueldo de Muñoz 💼', amount: 85000000, currency: 'ARS',
      day_of_month: 5, is_recurring: 1, household_id: null, updated_at: 1, deleted: 0 };
    const { values, decrypted } = fromRemoteWithStatus(incomes, toRemote(incomes, local));
    expect(decrypted).toBe(true);
    expect(values.name).toBe('Sueldo de Muñoz 💼');
    expect(values.amount).toBe(85000000);
  } finally {
    Object.assign(g, saved);
  }
});

test('privacidad: descifra filas cifradas por el trigger del servidor (json_build_object)', () => {
  const payload = encryptLikePostgres(INCOME_ID, '{"n" : "Sueldo de Peña", "a" : 500000}');
  const { values, decrypted } = fromRemoteWithStatus(incomes, remoteIncome(payload));
  expect(decrypted).toBe(true);
  expect(values.name).toBe('Sueldo de Peña');
  expect(values.amount).toBe(500000);
});

test('privacidad: si no se puede descifrar, se avisa para no pisar los datos locales', () => {
  expect(fromRemoteWithStatus(incomes, remoteIncome(null)).decrypted).toBe(false);
  expect(fromRemoteWithStatus(incomes, remoteIncome('v1:basura')).decrypted).toBe(false);
  expect(sensitiveColumnsOf(incomes)).toEqual(['name', 'amount']);
});

test('privacidad: una copia local ya enmascarada no reemplaza el cifrado real del servidor', () => {
  const masked = { id: INCOME_ID, user_id: USER_ID, name: 'Sueld***', amount: 0, currency: 'ARS',
    day_of_month: 5, is_recurring: 1, household_id: null, updated_at: 1, deleted: 0 };
  expect(toRemote(incomes, masked)).not.toHaveProperty('encrypted_payload');
  expect(toRemote(incomes, { ...masked, name: 'Sueldo', amount: 100 })).toHaveProperty('encrypted_payload');
});

test('utf8: codifica acentos, símbolos y emojis como UTF-8 estándar y vuelve igual', () => {
  const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  expect(hex(utf8Encode('Luz'))).toBe('4c757a');
  expect(hex(utf8Encode('ñ'))).toBe('c3b1');
  expect(hex(utf8Encode('₲'))).toBe('e282b2');
  expect(hex(utf8Encode('💼'))).toBe('f09f92bc');
  for (const text of ['', 'Luz', 'Señora Muñoz', 'Café ☕', 'Gs. ₲ 💼🏠']) {
    expect(utf8Decode(utf8Encode(text))).toBe(text);
  }
});
