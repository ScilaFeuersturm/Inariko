// Formato de cliente real para los tests del backend. Node 22 ejecuta el núcleo TypeScript puro.
import { randomBytes } from 'node:crypto';
import { open, publicKey, seal } from '../../../mobile/src/privacy/crypto.ts';
const keys = new Map();
const secretFor = (userId) => { if (!keys.has(userId)) keys.set(userId, randomBytes(32)); return keys.get(userId); };
const label = (row) => `inariko:row:v2:obligations:${row.id.toLowerCase()}:${row.user_id}:${row.user_id}`;
export function protectedBill(row) {
  const secret = secretFor(row.user_id);
  const box = seal(new TextEncoder().encode(JSON.stringify({ n: row.name, a: row.amount })), publicKey(secret), label(row), randomBytes);
  return { ...row, name: row.name === '' ? '' : '***', amount: row.amount < 0 ? row.amount : 0,
    encrypted_payload: `v2:${JSON.stringify({ [row.user_id]: box })}` };
}
export function readBill(row) {
  const box = JSON.parse(row.encrypted_payload.slice(3))[row.user_id];
  return JSON.parse(new TextDecoder().decode(open(box, secretFor(row.user_id), label(row))));
}
