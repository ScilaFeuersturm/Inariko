import { unlockPrivacy, readPrivacySecret, clearPrivacySecret, queuePrivacyPassword, flushPrivacyOutbox, privacyContext } from '@/data/privacyVault';
import { bytesToHex, open, publicKey } from '@/privacy/crypto';
import { supabase } from '@/data/supabase';

jest.mock('expo-crypto', () => ({ getRandomBytes: (n: number) => new Uint8Array(jest.requireActual('node:crypto').randomBytes(n)) }));
jest.mock('@/privacy/supportPublicKey', () => ({ SUPPORT_KEY_ID: 'support-test',
  SUPPORT_PUBLIC_KEY: jest.requireActual('@/privacy/crypto').publicKey(new Uint8Array(32).fill(9)) }));
jest.mock('@/data/passwordHasher', () => ({ deriveVaultPasswordKey: async (password: string, salt: Uint8Array) =>
  new Uint8Array(jest.requireActual('node:crypto').pbkdf2Sync(password, salt, 600_000, 32, 'sha256')) }));
jest.mock('@/data/secureStorage', () => {
  const items = new Map();
  return { getSecureItem: (key: string) => items.get(key) ?? null,
    setSecureItem: (key: string, value: string) => items.set(key, value), deleteSecureItem: async (key: string) => items.delete(key) };
});
jest.mock('@/data/db', () => {
  const outbox = new Map();
  return { notifyDataChanged: jest.fn(), getDb: () => ({
    runAsync: async (sql: string, userId: string, box: string) => {
      if (sql.startsWith('INSERT')) outbox.set(userId, { box });
      else if (sql.startsWith('DELETE')) outbox.delete(userId);
    }, getFirstAsync: async (_sql: string, userId: string) => outbox.get(userId) ?? null,
  }) };
});
jest.mock('@/data/supabase', () => ({ supabase: { from: jest.fn(), rpc: jest.fn() } }));

const vaults = new Map<string, Record<string, any>>();
beforeEach(async () => {
  vaults.clear();
  await clearPrivacySecret();
  jest.mocked(supabase.from).mockImplementation((() => ({
    select: () => ({ eq: (_field: string, userId: string) => ({ maybeSingle: async () => ({ data: vaults.get(userId) ?? null, error: null }) }) }),
    insert: async (row: Record<string, any>) => { vaults.set(row.user_id, structuredClone(row)); return { error: null }; },
    update: (patch: object) => ({ eq: async (_field: string, userId: string) => { Object.assign(vaults.get(userId)!, structuredClone(patch)); return { error: null }; } }),
  })) as unknown as typeof supabase.from);
  jest.mocked(supabase.rpc).mockImplementation((async () => ({ data: [...vaults.values()].map((v) => ({ user_id: v.user_id, public_key: v.public_key })), error: null })) as unknown as typeof supabase.rpc);
});

test('otra instalación abre con contraseña; una contraseña equivocada no crea otra identidad', async () => {
  await unlockPrivacy('alice', 'Password123');
  const original = readPrivacySecret('alice')!;
  expect(readPrivacySecret('bob')).toBeNull();
  expect(JSON.stringify(vaults.get('alice'))).not.toContain(bytesToHex(original));
  await clearPrivacySecret();
  await expect(unlockPrivacy('alice', 'Incorrecta123')).rejects.toThrow('soporte');
  expect(readPrivacySecret('alice')).toBeNull();
  await unlockPrivacy('alice', 'Password123');
  expect(readPrivacySecret('alice')).toEqual(original);
});

test('soporte recupera la misma identidad tras resetear la contraseña; una clave ajena falla', async () => {
  await unlockPrivacy('alice', 'Password123');
  const vault = vaults.get('alice')!;
  const originalPublicKey = vault.public_key;
  const recovered = open(vault.recovery_box, new Uint8Array(32).fill(9), 'inariko:recovery:v2:alice:support-test');
  await clearPrivacySecret();
  await expect(unlockPrivacy('alice', 'Nueva1234', 'aa'.repeat(32))).rejects.toThrow('no corresponde');
  await unlockPrivacy('alice', 'Nueva1234', bytesToHex(recovered));
  expect(vaults.get('alice')!.public_key).toBe(originalPublicKey);
  await clearPrivacySecret();
  await unlockPrivacy('alice', 'Nueva1234');
  expect(publicKey(readPrivacySecret('alice')!)).toBe(originalPublicKey);
});

test('el respaldo pendiente de cambio de contraseña se reintenta sin guardar la contraseña', async () => {
  await unlockPrivacy('alice', 'Password123');
  const before = readPrivacySecret('alice');
  await queuePrivacyPassword('alice', 'Nueva1234');
  await flushPrivacyOutbox('alice');
  await clearPrivacySecret();
  await unlockPrivacy('alice', 'Nueva1234');
  expect(readPrivacySecret('alice')).toEqual(before);
});

test('una sustitución de la clave pública del usuario bloquea la sincronización', async () => {
  await unlockPrivacy('alice', 'Password123');
  vaults.get('alice')!.public_key = publicKey(new Uint8Array(32).fill(2));
  await expect(privacyContext('alice')).rejects.toThrow('no coincide');
});
