// Run on an offline support workstation. Never deploy this workstation's private key to a server.
import { randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { bytesToHex, hexToBytes, open, publicKey } from '../src/privacy/crypto.ts';

const [command, ...args] = process.argv.slice(2);
const save = (path, value) => writeFileSync(path, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
if (command === 'generate' && args.length === 2) {
  const secret = randomBytes(32);
  try {
    const key = { id: 'support-2026-11', publicKey: publicKey(secret), privateKey: bytesToHex(secret) };
    save(args[0], key);
    save(args[1], { id: key.id, publicKey: key.publicKey });
    console.log('Par de soporte guardado. La clave privada no se imprime.');
  } finally { secret.fill(0); }
} else if (command === 'recover' && args.length === 3) {
  const key = JSON.parse(readFileSync(args[0], 'utf8'));
  const vault = JSON.parse(readFileSync(args[1], 'utf8'));
  if (vault.recovery_key_id !== key.id) throw new Error('Esta copia requiere otra clave de soporte.');
  const supportSecret = hexToBytes(key.privateKey);
  try {
    if (publicKey(supportSecret) !== key.publicKey) throw new Error('Clave de soporte inválida.');
    const secret = open(vault.recovery_box, supportSecret, `inariko:recovery:v2:${vault.user_id}:${key.id}`);
    try {
      if (publicKey(secret) !== vault.public_key) throw new Error('El respaldo no corresponde a la cuenta.');
      save(args[2], { userId: vault.user_id, recoverySecret: bytesToHex(secret) });
      console.log('Recuperación guardada en archivo privado. No enviarla por canales públicos.');
    } finally { secret.fill(0); }
  } finally { supportSecret.fill(0); }
} else {
  console.error('Uso: node scripts/privacy-support.mjs generate PRIVADA.json PUBLICA.json\n     node scripts/privacy-support.mjs recover PRIVADA.json VAULT.json RECUPERACION.json');
  process.exitCode = 1;
}
