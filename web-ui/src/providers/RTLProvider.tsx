import React, { useMemo, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { prefixer } from 'stylis';
import rtlPlugin from 'stylis-plugin-rtl';
import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';
import { isRTLLanguage } from '../i18n/config';

interface RTLProviderProps {
  children: React.ReactNode;
  baseTheme: any;
}

const RTLProvider: React.FC<RTLProviderProps> = ({ children, baseTheme }) => {
  const { i18n } = useTranslation();
  const isRTL = isRTLLanguage(i18n.language);

  // Create RTL cache for emotion
  const cacheRTL = useMemo(
    () =>
      createCache({
        key: 'muirtl',
        stylisPlugins: [prefixer, rtlPlugin],
      }),
    []
  );

  // Create LTR cache for emotion
  const cacheLTR = useMemo(
    () =>
      createCache({
        key: 'muiltr',
        stylisPlugins: [prefixer],
      }),
    []
  );

  // Create theme with RTL support
  const theme = useMemo(
    () =>
      createTheme({
        ...baseTheme,
        direction: isRTL ? 'rtl' : 'ltr',
        typography: {
          ...baseTheme.typography,
          fontFamily: isRTL
            ? '"Vazirmatn", "Noto Sans Arabic", "Segoe UI", "Roboto", "Arial", sans-serif'
            : baseTheme.typography.fontFamily,
        },
        components: {
          ...baseTheme.components,
          MuiAppBar: {
            ...baseTheme.components?.MuiAppBar,
            styleOverrides: {
              ...baseTheme.components?.MuiAppBar?.styleOverrides,
              root: {
                ...(baseTheme.components?.MuiAppBar?.styleOverrides?.root || {}),
                direction: isRTL ? 'rtl' : 'ltr',
              },
            },
          },
          MuiDrawer: {
            ...baseTheme.components?.MuiDrawer,
            styleOverrides: {
              ...baseTheme.components?.MuiDrawer?.styleOverrides,
              paper: {
                ...(baseTheme.components?.MuiDrawer?.styleOverrides?.paper || {}),
                direction: isRTL ? 'rtl' : 'ltr',
              },
            },
          },
        },
      }),
    [baseTheme, isRTL]
  );

  // Update body direction
  useEffect(() => {
    document.body.dir = isRTL ? 'rtl' : 'ltr';
    document.documentElement.dir = isRTL ? 'rtl' : 'ltr';
  }, [isRTL]);

  return (
    <CacheProvider value={isRTL ? cacheRTL : cacheLTR}>
      <ThemeProvider theme={theme}>
        {children}
      </ThemeProvider>
    </CacheProvider>
  );
};

export default RTLProvider;