import { sha256 } from '@noble/hashes/sha2.js';

/**
 * Privacidad de datos financieros en la nube:
 * En Supabase los nombres de gastos/ingresos se guardan truncados a los primeros 5 caracteres + "***"
 * y los montos en 0, mientras que los valores reales viajan cifrados en `encrypted_payload` para que
 * solo la app del usuario (y su grupo familiar) pueda reconstruirlos localmente.
 */
const PRIVACY_KEY = 'inariko-privacy-v1-9f4b2c8e1a7d6f3052b8e4c1d9a07f63';
const PREFIX = 'v1';

export type SensitivePayload = {
  n: string;
  a: number;
  r?: string | null;
  no?: string | null;
};

/** Deja solo los primeros 5 caracteres (puntos de código Unicode) y reemplaza el resto por "***". */
export function maskSensitiveText(value: string): string {
  const text = String(value ?? '');
  if (!text) return '***';
  if (text.endsWith('***') && Array.from(text).length <= 8) return text;
  const firstFive = Array.from(text).slice(0, 5).join('');
  return `${firstFive}***`;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) return new Uint8Array(0);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function digestUtf8(input: string): Uint8Array {
  return sha256(new TextEncoder().encode(input));
}

function xorStream(data: Uint8Array, rowId: string, nonceHex: string): Uint8Array {
  const out = new Uint8Array(data.length);
  const blocks = Math.ceil(data.length / 32);
  for (let b = 0; b < blocks; b++) {
    const keystream = digestUtf8(`${PRIVACY_KEY}:enc:${rowId}:${nonceHex}:${b}`);
    const offset = b * 32;
    const limit = Math.min(32, data.length - offset);
    for (let i = 0; i < limit; i++) {
      out[offset + i] = data[offset + i] ^ keystream[i];
    }
  }
  return out;
}

function computeTag(rowId: string, nonceHex: string, cipherHex: string): string {
  return bytesToHex(digestUtf8(`${PRIVACY_KEY}:mac:${rowId}:${nonceHex}:${cipherHex}`)).slice(0, 32);
}

export function encryptSensitivePayload(rowId: string, payload: SensitivePayload): string {
  const id = rowId.toLowerCase();
  const jsonBytes = new TextEncoder().encode(JSON.stringify(payload));
  // Nonce determinístico derivado del contenido y el id para no requerir generador asíncrono.
  const nonceHex = bytesToHex(digestUtf8(`${PRIVACY_KEY}:nonce:${id}:${ JSON.stringify(payload) }`)).slice(0, 16);
  const cipherBytes = xorStream(jsonBytes, id, nonceHex);
  const cipherHex = bytesToHex(cipherBytes);
  const tagHex = computeTag(id, nonceHex, cipherHex);
  return `${PREFIX}:${nonceHex}:${tagHex}:${cipherHex}`;
}

export function decryptSensitivePayload(rowId: string, token: string | null | undefined): SensitivePayload | null {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split(':');
  if (parts.length !== 4 || parts[0] !== PREFIX) return null;
  const [, nonceHex, tagHex, cipherHex] = parts;
  if (nonceHex.length !== 16 || tagHex.length !== 32) return null;
  const id = rowId.toLowerCase();
  const expectedTag = computeTag(id, nonceHex, cipherHex);
  if (expectedTag !== tagHex) return null;
  try {
    const cipherBytes = hexToBytes(cipherHex);
    const plainBytes = xorStream(cipherBytes, id, nonceHex);
    const parsed = JSON.parse(new TextDecoder().decode(plainBytes)) as SensitivePayload;
    if (typeof parsed?.n !== 'string' || typeof parsed?.a !== 'number') return null;
    return parsed;
  } catch {
    return null;
  }
}
