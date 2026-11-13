import { sha256 } from '@noble/hashes/sha2.js';
import { getDb } from '@/data/db';
import { privacyContext } from '@/data/privacyVault';
import { supabase } from '@/data/supabase';
import { bytesToHex, publicKey } from '@/privacy/crypto';
import { runSync } from '@/sync/engine';
import { fromRemoteWithStatus, SYNC_TABLES, toRemote, type Row } from '@/sync/tables';
import { utf8Encode, type PrivacyContext } from '@/sync/privacy';

// Node 22: SQLite real sin cargar el módulo nativo de Expo en Jest.
const { DatabaseSync } = jest.requireActual('node:sqlite');

jest.mock('expo-crypto', () => ({ getRandomBytes: (n: number) => new Uint8Array(jest.requireActual('node:crypto').randomBytes(n)) }));
jest.mock('@/data/db', () => ({ getDb: jest.fn() }));
jest.mock('@/data/privacyVault', () => ({ privacyContext: jest.fn() }));
jest.mock('@/data/supabase', () => ({ supabase: { from: jest.fn() } }));
const income = SYNC_TABLES.find(t => t.local === 'incomes')!;
const alice = new Uint8Array(32).fill(1), bob = new Uint8Array(32).fill(2);
const ownContext = (): PrivacyContext => ({ userId: 'alice', secret: alice.slice(), recipients: { alice: publicKey(alice) } });
const sharedContext = (): PrivacyContext => ({ ...ownContext(), recipients: { alice: publicKey(alice), bob: publicKey(bob) } });
const local = { id: 'income-1', user_id: 'alice', name: 'Sueldo', amount: 880000, currency: 'ARS', day_of_month: 5,
  is_recurring: 1, household_id: null, updated_at: 100, deleted: 0 };
let db: InstanceType<typeof DatabaseSync>;
let remote: Map<string, Row[]>;
let timestamp = 0;

beforeEach(() => {
  db = new DatabaseSync(':memory:');
  for (const table of SYNC_TABLES) {
    db.exec(`CREATE TABLE ${table.local} (${Object.entries(table.columns).map(([name, type]) =>
      `${name} ${type === 'text' ? 'TEXT' : 'INTEGER'} ${name === table.primaryKey ? 'PRIMARY KEY' : ''}`).join(', ')}, dirty INTEGER NOT NULL DEFAULT 0)`);
  }
  db.exec('CREATE TABLE sync_state (user_id TEXT, table_name TEXT, cursor TEXT, PRIMARY KEY(user_id, table_name)); CREATE TABLE privacy_sync_state (user_id TEXT PRIMARY KEY, recipients TEXT);');
  const adapter = {
    getAllAsync: async (sql: string, ...args: any[]) => db.prepare(sql).all(...args),
    getFirstAsync: async (sql: string, ...args: any[]) => db.prepare(sql).get(...args) ?? null,
    runAsync: async (sql: string, ...args: any[]) => db.prepare(sql).run(...args),
    withTransactionAsync: async (callback: () => Promise<void>) => {
      db.exec('BEGIN');
      try { await callback(); db.exec('COMMIT'); } catch (error) { db.exec('ROLLBACK'); throw error; }
    },
  };
  jest.mocked(getDb).mockReturnValue(adapter as unknown as ReturnType<typeof getDb>);
  remote = new Map(SYNC_TABLES.map(t => [t.remote, []]));
  jest.mocked(privacyContext).mockImplementation(async () => ownContext());
  jest.mocked(supabase.from).mockImplementation(((name: string) => {
    let filter = (_row: Row) => true;
    const result = () => ({ data: remote.get(name)!.filter(filter), error: null });
    const query = {
      select: () => query, order: () => query, limit: () => query, gte: () => query,
      eq: (key: string, value: unknown) => { const before = filter; filter = row => before(row) && row[key] === value; return query; },
      in: (key: string, ids: unknown[]) => { filter = row => ids.includes(row[key]); return query; },
      then: (resolve: (value: ReturnType<typeof result>) => unknown) => Promise.resolve(result()).then(resolve),
      upsert: async (rows: Row[]) => {
        const table = SYNC_TABLES.find(t => t.remote === name)!;
        for (const row of rows) {
          const saved = { ...row, server_updated_at: new Date(1_800_000_000_000 + timestamp++).toISOString() };
          const all = remote.get(name)!;
          const index = all.findIndex(r => r[table.primaryKey] === row[table.primaryKey]);
          if (index < 0) all.push(saved); else all[index] = saved;
        }
        return { error: null };
      },
    };
    return query;
  }) as unknown as typeof supabase.from);
});
afterEach(() => db.close());

function insertLocal(row: Row, dirty = 0) {
  const names = Object.keys(row);
  db.prepare(`INSERT INTO incomes (${names.join(',')},dirty) VALUES (${names.map(()=>'?').join(',')},?)`).run(...Object.values(row) as any[], dirty);
}

function legacyToken(): string {
  const key = 'inariko-privacy-v1-9f4b2c8e1a7d6f3052b8e4c1d9a07f63';
  const json = JSON.stringify({ n: local.name, a: local.amount });
  const sha = (text: string) => sha256(utf8Encode(text));
  const nonce = bytesToHex(sha(`${key}:nonce:${local.id}:${json}`)).slice(0,16);
  const cipher = bytesToHex(utf8Encode(json).map((b,i)=>b ^ sha(`${key}:enc:${local.id}:${nonce}:${Math.floor(i/32)}`)[i%32]));
  const tag = bytesToHex(sha(`${key}:mac:${local.id}:${nonce}:${cipher}`)).slice(0,32);
  return `v1:${nonce}:${tag}:${cipher}`;
}

test('SQLite real: una copia local ofuscada se recupera y migra sin subir la máscara como dato', async () => {
  insertLocal({ ...local, name: 'Sueld***', amount: 0 }, 1);
  remote.get('incomes')!.push({ ...local, name: 'Sueld***', amount: 0, is_recurring: true, deleted: false,
    encrypted_payload: legacyToken(), server_updated_at: '2026-11-13T00:00:00Z' });
  await runSync('alice');
  expect(db.prepare('SELECT name,amount,dirty FROM incomes').get()).toMatchObject({ name: 'Sueldo', amount: 880000, dirty: 0 });
  const saved = remote.get('incomes')![0];
  expect(saved).toMatchObject({ name: '***', amount: 0 });
  expect(String(saved.encrypted_payload)).toMatch(/^v2:/);
  expect(fromRemoteWithStatus(income, saved, ownContext()).values.amount).toBe(880000);
});

test('SQLite real: un integrante nuevo recibe un sobre aunque el importe y updated_at no cambien', async () => {
  const shared = { ...local, household_id: 'house-1' };
  insertLocal(shared);
  remote.get('incomes')!.push({ ...toRemote(income, shared, ownContext()), server_updated_at: '2026-11-13T00:00:00Z' });
  db.prepare('INSERT INTO privacy_sync_state VALUES (?,?)').run('alice', JSON.stringify(Object.entries(ownContext().recipients)));
  jest.mocked(privacyContext).mockImplementation(async () => sharedContext());
  await runSync('alice');
  const recipient = { ...sharedContext(), userId: 'bob', secret: bob.slice() };
  expect(fromRemoteWithStatus(income, remote.get('incomes')![0], recipient)).toMatchObject({ decrypted: true, values: { name: 'Sueldo', amount: 880000, updated_at: 100 } });
});

test('SQLite real: una fila corrupta no borra datos ni confirma su cursor', async () => {
  insertLocal(local);
  remote.get('incomes')!.push({ ...toRemote(income, local, ownContext()), encrypted_payload: 'v2:corrupt', server_updated_at: '2026-11-13T00:00:00Z' });
  await expect(runSync('alice')).rejects.toThrow('No se pudieron recuperar');
  expect(db.prepare('SELECT name,amount FROM incomes').get()).toMatchObject({ name: 'Sueldo', amount: 880000 });
  expect(db.prepare("SELECT * FROM sync_state WHERE table_name='incomes'").get()).toBeUndefined();
});
