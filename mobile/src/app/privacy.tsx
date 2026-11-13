import { useState } from 'react';

import { logout } from '@/data/auth';
import { hashPassword } from '@/data/passwordHasher';
import { unlockPrivacy } from '@/data/privacyVault';
import { setSecureItem } from '@/data/secureStorage';
import { currentUserId } from '@/data/session';
import { supabase } from '@/data/supabase';
import { useAppData } from '@/state/AppDataProvider';
import { PasswordField, TextField } from '@/ui/form';
import { AlertBanner, PrimaryButton, Text, TextButton } from '@/ui/primitives';
import { ScreenScroll } from '@/ui/Screen';

export default function PrivacyScreen() {
  const { user } = useAppData();
  const [password, setPassword] = useState('');
  const [recovery, setRecovery] = useState('');
  const [recovering, setRecovering] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const unlock = async () => {
    if (busy || !user) return;
    setBusy(true);
    setError(null);
    try {
      const userId = currentUserId();
      const { data, error: authError } = await supabase.auth.signInWithPassword({ email: user.email, password });
      if (authError || data.user?.id !== userId || !userId) throw new Error('Revisá tu contraseña e intentá de nuevo.');
      await unlockPrivacy(userId, password, recovering ? recovery : undefined);
      setSecureItem('unlock_verifier', await hashPassword(password));
      setPassword('');
      setRecovery('');
    } catch (err) { setError(err instanceof Error ? err.message : 'No se pudieron recuperar los datos.'); }
    finally { setBusy(false); }
  };

  return (
    <ScreenScroll safeTop>
      <Text variant="headlineSmall" header>Protegé tus datos</Text>
      <Text>Confirmá tu contraseña para abrir tus gastos e ingresos en este dispositivo. La base del servidor guarda los importes y nombres cifrados.</Text>
      <Text>Si recuperaste la contraseña y no tenés otro dispositivo con tus datos, soporte puede ayudarte a recuperarlos después de verificar tu identidad.</Text>
      <PasswordField label="Contraseña actual" value={password} onChangeText={setPassword} autoComplete="current-password" />
      {recovering && (
        <TextField label="Clave de recuperación entregada por soporte" value={recovery} onChangeText={setRecovery}
          autoCapitalize="none" autoCorrect={false} secure textContentType="none" />
      )}
      {error && <AlertBanner message={error} critical />}
      <PrimaryButton text={recovering ? 'Recuperar mis datos' : 'Continuar'} onPress={unlock}
        loading={busy} disabled={busy || !password || (recovering && !/^[0-9a-fA-F]{64}$/.test(recovery.trim()))} />
      <TextButton text={recovering ? 'Volver' : 'Tengo una clave de soporte'} onPress={() => { if (!busy) setRecovering((value) => !value); }} />
      <TextButton text="Cerrar sesión" onPress={async () => {
        if (busy) return;
        const result = await logout();
        if (!result.ok) setError('Hay cambios guardados solo en este teléfono. Recuperá la protección antes de cerrar sesión.');
      }} />
    </ScreenScroll>
  );
}
