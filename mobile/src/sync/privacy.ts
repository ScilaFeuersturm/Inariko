import { getRandomBytes } from 'expo-crypto';

import { open, seal, utf8Encode } from '../privacy/crypto';
import { decryptLegacyPayload, utf8Decode } from '../privacy/legacy';
import type { SensitivePayload } from '../privacy/legacy';

export { isMaskedText, utf8Encode, utf8Decode } from '../privacy/legacy';
export type { SensitivePayload } from '../privacy/legacy';

export type PrivacyContext = {
  userId: string;
  secret: Uint8Array;
  recipients: Record<string, string | null>;
};

type RowIdentity = { table: string; id: string; owner: string; shared: boolean };
const contextOf = (row: RowIdentity) => `inariko:row:v2:${row.table}:${row.id.toLowerCase()}:${row.owner}`;

export function encryptSensitivePayload(row: RowIdentity, payload: SensitivePayload, privacy?: PrivacyContext): string {
  if (!privacy) throw new Error('Desbloqueá la protección de tus datos antes de sincronizar.');
  const recipients = row.shared ? Object.keys(privacy.recipients) : [row.owner];
  if (!recipients.includes(row.owner)) throw new Error('Falta la clave de quien creó el dato.');
  const plain = utf8Encode(JSON.stringify(payload));
  try {
    const boxes = Object.fromEntries(recipients.map((userId) => {
      const key = privacy.recipients[userId];
      if (!key) throw new Error('Todas las personas del grupo deben actualizar la app y activar la protección de datos.');
      return [userId, seal(plain, key, `${contextOf(row)}:${userId}`, getRandomBytes)];
    }));
    return `v2:${JSON.stringify(boxes)}`;
  } finally { plain.fill(0); }
}

export function decryptSensitivePayload(row: RowIdentity, token: string | null | undefined, privacy?: PrivacyContext): SensitivePayload | null {
  if (token?.startsWith('v1:')) return decryptLegacyPayload(row.id, token);
  if (!token?.startsWith('v2:') || !privacy || token.length > 1_000_000) return null;
  try {
    const boxes = JSON.parse(token.slice(3));
    const bytes = open(boxes[privacy.userId], privacy.secret, `${contextOf(row)}:${privacy.userId}`);
    try {
      const parsed = JSON.parse(utf8Decode(bytes));
      if (typeof parsed?.n !== 'string' || !Number.isSafeInteger(parsed.a) || parsed.a < 0) return null;
      if (parsed.r != null && typeof parsed.r !== 'string') return null;
      if (parsed.no != null && typeof parsed.no !== 'string') return null;
      return parsed;
    } finally { bytes.fill(0); }
  } catch { return null; }
}

/** Ningún prefijo del nombre real se envía al backend en v2. */
export function maskSensitiveText(_value: string): string { return '***'; }
