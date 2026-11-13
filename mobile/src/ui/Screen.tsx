import { router } from 'expo-router';
import type { ReactNode } from 'react';
import { KeyboardAvoidingView, Platform, ScrollView, View, type StyleProp, type ViewStyle } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { IconButton, ScreenPadding, Text } from './primitives';
import { useTheme } from './theme';

/** Barra superior de pantallas secundarias: volver, título y acciones (equivalente a TopAppBar). */
export function ScreenHeader({ title, actions }: { title: string; actions?: ReactNode }) {
  const { colors } = useTheme();
  const insets = useSafeAreaInsets();
  return (
    <View
      style={{
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: colors.background,
        paddingTop: insets.top + 4,
        paddingHorizontal: 4,
        paddingBottom: 4,
        minHeight: 56 + insets.top,
      }}
    >
      <IconButton icon="arrow-back" label="Volver" onPress={() => router.back()} color={colors.onBackground} />
      <Text variant="titleLarge" weight="bold" color={colors.onBackground} style={{ flex: 1, marginLeft: 8 }} numberOfLines={2} header>
        {title}
      </Text>
      {actions}
    </View>
  );
}

/**
 * Contenido desplazable con el padding estándar y manejo del teclado. Con `withHeader` muestra
 * una ScreenHeader; sin ella respeta el área segura superior (pantallas de sesión/onboarding).
 */
export function ScreenScroll({
  children,
  title,
  actions,
  safeTop,
  contentStyle,
}: {
  children: ReactNode;
  title?: string;
  actions?: ReactNode;
  safeTop?: boolean;
  contentStyle?: StyleProp<ViewStyle>;
}) {
  const { colors } = useTheme();
  const insets = useSafeAreaInsets();
  // Sin barra superior, la franja de la hora/batería (y la isla dinámica) queda reservada fuera del
  // scroll: así ni un `paddingTop` de `contentStyle` ni el contenido al desplazarse la tapan.
  const reserveTop = title == null && safeTop;
  return (
    <View style={{ flex: 1, backgroundColor: colors.background, paddingTop: reserveTop ? insets.top : 0 }}>
      {title != null && <ScreenHeader title={title} actions={actions} />}
      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
        <ScrollView
          keyboardShouldPersistTaps="handled"
          keyboardDismissMode="on-drag"
          contentContainerStyle={[
            {
              padding: ScreenPadding,
              paddingBottom: (title != null || safeTop ? insets.bottom : 0) + ScreenPadding,
              gap: 16,
            },
            contentStyle,
          ]}
        >
          {children}
        </ScrollView>
      </KeyboardAvoidingView>
    </View>
  );
}
