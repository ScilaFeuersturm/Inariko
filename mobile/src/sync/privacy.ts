import { sha256 } from '@noble/hashes/sha2.js';

/**
 * Privacidad de datos financieros en la nube:
 * En Supabase los nombres de gastos/ingresos se guardan truncados a los primeros 5 caracteres + "***"
 * y los montos en 0, mientras que los valores reales viajan cifrados en `encrypted_payload` para que
 * solo la app del usuario (y su grupo familiar) pueda reconstruirlos localmente. En el teléfono los
 * datos se guardan y se muestran completos: el enmascarado es solo del lado del servidor.
 */
const PRIVACY_KEY = 'inariko-privacy-v1-9f4b2c8e1a7d6f3052b8e4c1d9a07f63';
const PREFIX = 'v1';

export type SensitivePayload = {
  n: string;
  a: number;
  r?: string | null;
  no?: string | null;
};

/** true si el texto ya tiene la forma enmascarada del servidor ("Sueld***"). */
export function isMaskedText(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  return value.endsWith('***') && Array.from(value).length <= 8;
}

/** Deja solo los primeros 5 caracteres (puntos de código Unicode) y reemplaza el resto por "***". */
export function maskSensitiveText(value: string): string {
  const text = String(value ?? '');
  if (!text) return '***';
  if (isMaskedText(text)) return text;
  const firstFive = Array.from(text).slice(0, 5).join('');
  return `${firstFive}***`;
}

/*
 * UTF-8 propio en vez de TextEncoder/TextDecoder: Hermes (el motor de JavaScript de la app) no
 * garantiza TextDecoder. Cuando faltaba, el descifrado fallaba en silencio y la app mostraba los
 * valores enmascarados del servidor ("Sueld***", $0) en lugar de los reales.
 */
export function utf8Encode(input: string): Uint8Array {
  const bytes: number[] = [];
  for (const char of input) {
    const cp = char.codePointAt(0)!;
    if (cp < 0x80) bytes.push(cp);
    else if (cp < 0x800) bytes.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
    else if (cp < 0x10000) bytes.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    else bytes.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
  }
  return Uint8Array.from(bytes);
}

export function utf8Decode(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  const next = () => {
    const b = bytes[i++];
    if (b === undefined || (b & 0xc0) !== 0x80) throw new Error('UTF-8 inválido');
    return b & 0x3f;
  };
  while (i < bytes.length) {
    const b0 = bytes[i++];
    let cp: number;
    if (b0 < 0x80) cp = b0;
    else if (b0 >= 0xc2 && b0 < 0xe0) cp = ((b0 & 0x1f) << 6) | next();
    else if (b0 >= 0xe0 && b0 < 0xf0) cp = ((b0 & 0x0f) << 12) | (next() << 6) | next();
    else if (b0 >= 0xf0 && b0 < 0xf5) cp = ((b0 & 0x07) << 18) | (next() << 12) | (next() << 6) | next();
    else throw new Error('UTF-8 inválido');
    out += String.fromCodePoint(cp);
  }
  return out;
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
  return sha256(utf8Encode(input));
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
  const json = JSON.stringify(payload);
  // Nonce determinístico derivado del contenido y el id para no requerir generador asíncrono.
  const nonceHex = bytesToHex(digestUtf8(`${PRIVACY_KEY}:nonce:${id}:${json}`)).slice(0, 16);
  const cipherHex = bytesToHex(xorStream(utf8Encode(json), id, nonceHex));
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
  const expectedTag = computeTag(id, nonceHex, cipherHex.toLowerCase());
  if (expectedTag !== tagHex.toLowerCase()) return null;
  try {
    const plainBytes = xorStream(hexToBytes(cipherHex), id, nonceHex.toLowerCase());
    const parsed = JSON.parse(utf8Decode(plainBytes)) as SensitivePayload;
    if (typeof parsed?.n !== 'string' || typeof parsed?.a !== 'number') return null;
    return parsed;
  } catch (error) {
    if (__DEV__) console.warn('[privacy] no se pudo descifrar la fila', rowId, error);
    return null;
  }
}
