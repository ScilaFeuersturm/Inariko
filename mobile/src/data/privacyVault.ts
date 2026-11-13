import { getRandomBytes } from 'expo-crypto';

import { bytesToHex, hexToBytes, passwordOpen, passwordSeal, publicKey, seal, type SealedBox } from '../privacy/crypto';
import { SUPPORT_KEY_ID, SUPPORT_PUBLIC_KEY } from '../privacy/supportPublicKey';
import type { PrivacyContext } from '../sync/privacy';
import { getDb, notifyDataChanged } from './db';
import { deriveVaultPasswordKey } from './passwordHasher';
import { deleteSecureItem, getSecureItem, setSecureItem } from './secureStorage';
import { supabase } from './supabase';

const CACHE_KEY = 'privacy_vault_v2';
export type PasswordBox = { salt: string; nonce: string; ciphertext: string };
export type Vault = { user_id: string; public_key: string; password_box: PasswordBox; recovery_box: SealedBox; recovery_key_id: string };

export function readPrivacySecret(userId: string): Uint8Array | null {
  try {
    const cached = JSON.parse(getSecureItem(CACHE_KEY) ?? 'null');
    if (cached?.userId !== userId) return null;
    const secret = hexToBytes(cached.secret);
    return secret.length === 32 ? secret : null;
  } catch { return null; }
}

export async function clearPrivacySecret(): Promise<void> {
  await deleteSecureItem(CACHE_KEY);
}

async function wrapPassword(userId: string, secret: Uint8Array, password: string): Promise<PasswordBox> {
  const salt = getRandomBytes(16);
  const nonce = getRandomBytes(24);
  const key = await deriveVaultPasswordKey(password, salt);
  try { return { salt: bytesToHex(salt), nonce: bytesToHex(nonce), ciphertext: passwordSeal(secret, key, userId, nonce) }; }
  finally { key.fill(0); }
}

async function unwrapPassword(userId: string, box: PasswordBox, password: string): Promise<Uint8Array> {
  const key = await deriveVaultPasswordKey(password, hexToBytes(box.salt));
  try { return passwordOpen(box.ciphertext, key, userId, hexToBytes(box.nonce)); }
  finally { key.fill(0); }
}

/** El backend solo recibe la clave pública y dos sobres cifrados, nunca la privada. */
export async function unlockPrivacy(userId: string, password: string, recoverySecret?: string): Promise<void> {
  const { data, error } = await supabase.from('privacy_vaults').select('*').eq('user_id', userId).maybeSingle();
  if (error) throw new Error('No se pudo abrir la protección de datos. Revisá tu conexión y volvé a intentar.');
  const vault = data as Vault | null;
  let secret = readPrivacySecret(userId);
  try {
    if (recoverySecret) secret = hexToBytes(recoverySecret.trim());
    if (!vault) {
      if (recoverySecret) throw new Error('Esta cuenta todavía no tiene una clave para recuperar.');
      if (!SUPPORT_PUBLIC_KEY) throw new Error('Falta configurar la recuperación de soporte.');
      secret ??= getRandomBytes(32);
      const next: Vault = { user_id: userId, public_key: publicKey(secret),
        password_box: await wrapPassword(userId, secret, password),
        recovery_box: seal(secret, SUPPORT_PUBLIC_KEY, `inariko:recovery:v2:${userId}:${SUPPORT_KEY_ID}`, getRandomBytes),
        recovery_key_id: SUPPORT_KEY_ID };
      const { error: insertError } = await supabase.from('privacy_vaults').insert(next);
      if (insertError) throw new Error('No se pudo activar la protección. Volvé a intentar.');
    } else {
      if (!secret) {
        try { secret = await unwrapPassword(userId, vault.password_box, password); }
        catch { throw new Error('Para recuperar tus datos en este dispositivo, pedí ayuda a soporte. No crees otra clave.'); }
      }
      if (publicKey(secret) !== vault.public_key) throw new Error('La clave de recuperación no corresponde a esta cuenta.');
      // Repara también el respaldo al entrar después de un cambio o recuperación de contraseña.
      const { error: updateError } = await supabase.from('privacy_vaults')
        .update({ password_box: await wrapPassword(userId, secret, password) }).eq('user_id', userId);
      if (updateError) throw new Error('No se pudo actualizar el respaldo protegido. Volvé a intentar.');
    }
    setSecureItem(CACHE_KEY, JSON.stringify({ userId, secret: bytesToHex(secret!) }));
    await getDb().runAsync('DELETE FROM privacy_password_outbox WHERE user_id = ?', userId);
    notifyDataChanged();
  } finally { secret?.fill(0); }
}

/** Respaldo pendiente: contiene solo un sobre cifrado, nunca la contraseña ni la clave privada. */
export async function queuePrivacyPassword(userId: string, password: string): Promise<void> {
  const secret = readPrivacySecret(userId);
  if (!secret) return; // Recuperación por email sin clave local: luego se requiere soporte.
  try {
    const box = await wrapPassword(userId, secret, password);
    await getDb().runAsync('INSERT OR REPLACE INTO privacy_password_outbox (user_id, box) VALUES (?, ?)', userId, JSON.stringify(box));
  } finally { secret.fill(0); }
}

export async function flushPrivacyOutbox(userId: string): Promise<void> {
  const pending = await getDb().getFirstAsync<{ box: string }>('SELECT box FROM privacy_password_outbox WHERE user_id = ?', userId);
  if (!pending) return;
  const { error } = await supabase.from('privacy_vaults').update({ password_box: JSON.parse(pending.box) }).eq('user_id', userId);
  if (error) throw new Error('Falta sincronizar el respaldo protegido de tu contraseña.');
  await getDb().runAsync('DELETE FROM privacy_password_outbox WHERE user_id = ? AND box = ?', userId, pending.box);
}

export async function privacyContext(userId: string): Promise<PrivacyContext> {
  const secret = readPrivacySecret(userId);
  if (!secret) throw new Error('Desbloqueá la protección de tus datos antes de sincronizar.');
  try {
    await flushPrivacyOutbox(userId);
    const { data, error } = await supabase.rpc('privacy_recipients');
    if (error) throw new Error('No se pudieron verificar las claves del grupo.');
    const recipients = Object.fromEntries((data as { user_id: string; public_key: string | null }[]).map((row) => [row.user_id, row.public_key]));
    if (recipients[userId] !== publicKey(secret)) throw new Error('La clave de esta cuenta no coincide. Pedí ayuda a soporte.');
    return { userId, secret, recipients };
  } catch (error) { secret.fill(0); throw error; }
}
