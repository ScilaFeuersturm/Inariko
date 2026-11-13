import { bytesToHex, hexToBytes, open, passwordOpen, passwordSeal, publicKey, seal } from '@/privacy/crypto';
import { decryptSensitivePayload, encryptSensitivePayload, type PrivacyContext } from '@/sync/privacy';

jest.mock('expo-crypto', () => ({ getRandomBytes: (n: number) => new Uint8Array(jest.requireActual('node:crypto').randomBytes(n)) }));
const random = (n: number): Uint8Array => new Uint8Array(jest.requireActual('node:crypto').randomBytes(n));
const alice = new Uint8Array(32).fill(1);
const bob = new Uint8Array(32).fill(2);
const outsider = new Uint8Array(32).fill(3);
const recipients = { alice: publicKey(alice), bob: publicKey(bob) };
const context = (userId: string, secret: Uint8Array): PrivacyContext => ({ userId, secret, recipients });
const row = { table: 'incomes', id: 'salary-1', owner: 'alice', shared: false };
const payload = { n: 'Sueldo de Peña 💼', a: 980000 };

test('v2: dos cifrados del mismo dato son distintos; solo su dueño abre un dato privado', () => {
  const token = encryptSensitivePayload(row, payload, context('alice', alice));
  expect(token).not.toContain(payload.n);
  expect(token).not.toBe(encryptSensitivePayload(row, payload, context('alice', alice)));
  expect(decryptSensitivePayload(row, token, context('alice', alice))).toEqual(payload);
  expect(decryptSensitivePayload(row, token, context('bob', bob))).toBeNull();
  expect(decryptSensitivePayload(row, token, context('alice', outsider))).toBeNull();
  expect(() => encryptSensitivePayload(row, payload)).toThrow('Desbloqueá');
});

test('v2: un dato compartido abre para ambos; al dejar de compartir el nuevo cifrado solo abre para su dueño', () => {
  const shared = { ...row, shared: true };
  const token = encryptSensitivePayload(shared, payload, context('alice', alice));
  expect(decryptSensitivePayload(shared, token, context('bob', bob))).toEqual(payload);
  const privateToken = encryptSensitivePayload(row, payload, context('alice', alice));
  expect(decryptSensitivePayload(row, privateToken, context('bob', bob))).toBeNull();
  expect(() => encryptSensitivePayload(shared, payload, { ...context('alice', alice), recipients: { alice: publicKey(alice), bob: null } })).toThrow('actualizar');
});

test('v2: rechaza sustitución de fila, tabla, dueño, destinatario y contenido', () => {
  const token = encryptSensitivePayload(row, payload, context('alice', alice));
  for (const changed of [{ ...row, id: 'other' }, { ...row, table: 'obligations' }, { ...row, owner: 'bob' }]) {
    expect(decryptSensitivePayload(changed, token, context('alice', alice))).toBeNull();
  }
  const boxes = JSON.parse(token.slice(3));
  boxes.alice.ciphertext = (boxes.alice.ciphertext[0] === '0' ? '1' : '0') + boxes.alice.ciphertext.slice(1);
  expect(decryptSensitivePayload(row, 'v2:' + JSON.stringify(boxes), context('alice', alice))).toBeNull();
});

test('soporte: se recupera con la privada externa y no con la pública ni con otra privada', () => {
  const support = random(32);
  const label = 'inariko:recovery:v2:alice:support-test';
  const box = seal(alice, publicKey(support), label, random);
  expect(open(box, support, label)).toEqual(alice);
  expect(() => open(box, hexToBytes(publicKey(support)), label)).toThrow();
  expect(() => open(box, outsider, label)).toThrow();
  expect(() => open(box, support, label.replace('alice', 'bob'))).toThrow();
});

test('respaldo por contraseña: otra clave o cuenta no abre; la rotación conserva la identidad', () => {
  const oldKey = random(32), newKey = random(32), nonce = random(24);
  const box = passwordSeal(alice, oldKey, 'alice', nonce);
  expect(bytesToHex(passwordOpen(box, oldKey, 'alice', nonce))).toBe(bytesToHex(alice));
  expect(() => passwordOpen(box, newKey, 'alice', nonce)).toThrow();
  expect(() => passwordOpen(box, oldKey, 'bob', nonce)).toThrow();
  const newBox = passwordSeal(alice, newKey, 'alice', random(24));
  expect(newBox).not.toBe(box);
});
