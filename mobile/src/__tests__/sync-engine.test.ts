import { runSync } from '@/sync/engine';
import { SYNC_TABLES, toRemote } from '@/sync/tables';
import { getDb } from '@/data/db';
import { privacyContext } from '@/data/privacyVault';
import { publicKey } from '@/privacy/crypto';
import { supabase } from '@/data/supabase';

jest.mock('expo-crypto', () => ({ getRandomBytes: (n: number) => new Uint8Array(jest.requireActual('node:crypto').randomBytes(n)) }));
jest.mock('@/data/privacyVault', () => ({ privacyContext: jest.fn() }));
jest.mock('@/data/db', () => ({ getDb: jest.fn() }));
jest.mock('@/data/supabase', () => ({ supabase: { from: jest.fn() } }));

const privacy = () => { const secret = new Uint8Array(32).fill(7); return { userId: 'user-1', secret, recipients: { 'user-1': publicKey(secret) } }; };
const income = SYNC_TABLES.find((table) => table.local === 'incomes')!;
const local = { id: 'income-1', user_id: 'user-1', name: 'Sueldo', amount: 850000,
  currency: 'ARS', day_of_month: 1, is_recurring: 1, household_id: null, updated_at: 10, deleted: 0 };

function setup(payload: string | null, existing: boolean) {
  jest.mocked(privacyContext).mockResolvedValue(privacy());
  const db = {
    getAllAsync: jest.fn().mockResolvedValue([]),
    getFirstAsync: jest.fn(async (sql: string) => sql.startsWith('SELECT updated_at') && existing
      ? { updated_at: 10, dirty: 0 } : null),
    runAsync: jest.fn().mockResolvedValue(undefined),
    withTransactionAsync: jest.fn(async (callback: () => Promise<void>) => callback()),
  };
  jest.mocked(getDb).mockReturnValue(db as unknown as ReturnType<typeof getDb>);
  jest.mocked(supabase.from).mockImplementation(((table: string) => {
    const result = { data: table === 'incomes'
      ? [{ ...toRemote(income, local, privacy()), encrypted_payload: payload, server_updated_at: '2026-11-13T00:00:00Z' }] : [], error: null };
    const query = { select: () => query, order: () => query, limit: () => query,
      eq: () => query, then: (resolve: (value: typeof result) => unknown) => Promise.resolve(result).then(resolve) };
    return query;
  }) as unknown as typeof supabase.from);
  return db;
}

test.each([false, true])('un ingreso ilegible no se inserta ni reemplaza datos ni avanza su cursor (existente: %s)', async (existing) => {
  const db = setup(null, existing);
  await expect(runSync('user-1')).rejects.toThrow('No se pudieron recuperar los datos financieros');
  expect(db.runAsync.mock.calls.some(([sql]) => /INSERT INTO incomes/.test(sql))).toBe(false);
  expect(db.runAsync.mock.calls.some(([sql, , table]) => /INSERT.*sync_state/.test(sql) && table === 'incomes')).toBe(false);
});

test('un ingreso recuperable se guarda completo en el dispositivo', async () => {
  const db = setup(toRemote(income, local, privacy()).encrypted_payload as string, false);
  await runSync('user-1');
  const insert = db.runAsync.mock.calls.find(([sql]) => /INSERT INTO incomes/.test(sql));
  expect(insert).toBeDefined();
  expect(insert).toContain('Sueldo');
  expect(insert).toContain(850000);
  expect(insert).not.toContain('Sueld***');
});
