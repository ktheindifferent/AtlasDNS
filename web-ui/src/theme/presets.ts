import { CustomThemeConfig } from './types';

export const defaultThemes: Record<string, CustomThemeConfig> = {
  light: {
    id: 'default-light',
    name: 'Default Light',
    description: 'Clean and modern light theme',
    author: 'System',
    version: '1.0.0',
    mode: 'light',
    colors: {
      primary: {
        main: '#1976d2',
        light: '#42a5f5',
        dark: '#1565c0',
        contrastText: '#ffffff',
      },
      secondary: {
        main: '#dc004e',
        light: '#f06292',
        dark: '#c51162',
        contrastText: '#ffffff',
      },
      error: {
        main: '#f44336',
        light: '#e57373',
        dark: '#d32f2f',
        contrastText: '#ffffff',
      },
      warning: {
        main: '#ff9800',
        light: '#ffb74d',
        dark: '#f57c00',
        contrastText: '#000000',
      },
      info: {
        main: '#2196f3',
        light: '#64b5f6',
        dark: '#1976d2',
        contrastText: '#ffffff',
      },
      success: {
        main: '#4caf50',
        light: '#81c784',
        dark: '#388e3c',
        contrastText: '#ffffff',
      },
      background: {
        default: '#fafafa',
        paper: '#ffffff',
        elevated: '#f5f5f5',
      },
      text: {
        primary: 'rgba(0, 0, 0, 0.87)',
        secondary: 'rgba(0, 0, 0, 0.6)',
        disabled: 'rgba(0, 0, 0, 0.38)',
      },
      divider: 'rgba(0, 0, 0, 0.12)',
    },
    typography: {
      fontFamily: {
        primary: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
        secondary: '"Roboto Slab", serif',
        monospace: '"Fira Code", "Courier New", monospace',
      },
      fontSize: {
        base: 14,
        scale: 1.25,
      },
      fontWeight: {
        light: 300,
        regular: 400,
        medium: 500,
        semibold: 600,
        bold: 700,
      },
      lineHeight: {
        tight: 1.2,
        normal: 1.5,
        relaxed: 1.75,
      },
      letterSpacing: {
        tight: -0.05,
        normal: 0,
        wide: 0.1,
      },
    },
    density: {
      level: 'comfortable',
      spacing: {
        base: 8,
        scale: 1.5,
      },
      borderRadius: {
        small: 4,
        medium: 8,
        large: 12,
      },
      componentSize: {
        small: 32,
        medium: 40,
        large: 48,
      },
    },
    accessibility: {
      contrastRatio: {
        AA: true,
        AAA: false,
      },
      fontSize: {
        minimum: 12,
        readable: true,
      },
      focusIndicator: {
        visible: true,
        style: 'outline',
      },
      reducedMotion: false,
      highContrast: false,
    },
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
  },
  dark: {
    id: 'default-dark',
    name: 'Default Dark',
    description: 'Comfortable dark theme for reduced eye strain',
    author: 'System',
    version: '1.0.0',
    mode: 'dark',
    colors: {
      primary: {
        main: '#90caf9',
        light: '#e3f2fd',
        dark: '#42a5f5',
        contrastText: '#000000',
      },
      secondary: {
        main: '#f48fb1',
        light: '#ffc1e3',
        dark: '#bf5f82',
        contrastText: '#000000',
      },
      error: {
        main: '#f44336',
        light: '#e57373',
        dark: '#d32f2f',
        contrastText: '#ffffff',
      },
      warning: {
        main: '#ffa726',
        light: '#ffb74d',
        dark: '#f57c00',
        contrastText: '#000000',
      },
      info: {
        main: '#29b6f6',
        light: '#4fc3f7',
        dark: '#0288d1',
        contrastText: '#000000',
      },
      success: {
        main: '#66bb6a',
        light: '#81c784',
        dark: '#388e3c',
        contrastText: '#000000',
      },
      background: {
        default: '#121212',
        paper: '#1e1e1e',
        elevated: '#2a2a2a',
      },
      text: {
        primary: '#ffffff',
        secondary: 'rgba(255, 255, 255, 0.7)',
        disabled: 'rgba(255, 255, 255, 0.5)',
      },
      divider: 'rgba(255, 255, 255, 0.12)',
    },
    typography: {
      fontFamily: {
        primary: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
        secondary: '"Roboto Slab", serif',
        monospace: '"Fira Code", "Courier New", monospace',
      },
      fontSize: {
        base: 14,
        scale: 1.25,
      },
      fontWeight: {
        light: 300,
        regular: 400,
        medium: 500,
        semibold: 600,
        bold: 700,
      },
      lineHeight: {
        tight: 1.2,
        normal: 1.5,
        relaxed: 1.75,
      },
      letterSpacing: {
        tight: -0.05,
        normal: 0,
        wide: 0.1,
      },
    },
    density: {
      level: 'comfortable',
      spacing: {
        base: 8,
        scale: 1.5,
      },
      borderRadius: {
        small: 4,
        medium: 8,
        large: 12,
      },
      componentSize: {
        small: 32,
        medium: 40,
        large: 48,
      },
    },
    accessibility: {
      contrastRatio: {
        AA: true,
        AAA: false,
      },
      fontSize: {
        minimum: 12,
        readable: true,
      },
      focusIndicator: {
        visible: true,
        style: 'outline',
      },
      reducedMotion: false,
      highContrast: false,
    },
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
  },
  ocean: {
    id: 'preset-ocean',
    name: 'Ocean Breeze',
    description: 'Cool blue tones inspired by the ocean',
    author: 'System',
    version: '1.0.0',
    mode: 'light',
    colors: {
      primary: {
        main: '#006064',
        light: '#428e92',
        dark: '#00363a',
        contrastText: '#ffffff',
      },
      secondary: {
        main: '#00acc1',
        light: '#5ddef4',
        dark: '#007c91',
        contrastText: '#000000',
      },
      error: {
        main: '#d32f2f',
        light: '#ef5350',
        dark: '#c62828',
        contrastText: '#ffffff',
      },
      warning: {
        main: '#f57c00',
        light: '#ff9800',
        dark: '#e65100',
        contrastText: '#000000',
      },
      info: {
        main: '#0288d1',
        light: '#03a9f4',
        dark: '#01579b',
        contrastText: '#ffffff',
      },
      success: {
        main: '#00897b',
        light: '#4db6ac',
        dark: '#00695c',
        contrastText: '#ffffff',
      },
      background: {
        default: '#e0f7fa',
        paper: '#ffffff',
        elevated: '#b2ebf2',
      },
      text: {
        primary: '#004d40',
        secondary: '#00695c',
        disabled: 'rgba(0, 0, 0, 0.38)',
      },
      divider: 'rgba(0, 150, 136, 0.12)',
    },
    typography: {
      fontFamily: {
        primary: '"Nunito", "Roboto", sans-serif',
        secondary: '"Merriweather", serif',
        monospace: '"Source Code Pro", monospace',
      },
      fontSize: {
        base: 14,
        scale: 1.2,
      },
      fontWeight: {
        light: 300,
        regular: 400,
        medium: 500,
        semibold: 600,
        bold: 700,
      },
      lineHeight: {
        tight: 1.3,
        normal: 1.6,
        relaxed: 1.8,
      },
      letterSpacing: {
        tight: -0.02,
        normal: 0,
        wide: 0.05,
      },
    },
    density: {
      level: 'comfortable',
      spacing: {
        base: 8,
        scale: 1.5,
      },
      borderRadius: {
        small: 8,
        medium: 12,
        large: 20,
      },
      componentSize: {
        small: 32,
        medium: 40,
        large: 48,
      },
    },
    accessibility: {
      contrastRatio: {
        AA: true,
        AAA: false,
      },
      fontSize: {
        minimum: 12,
        readable: true,
      },
      focusIndicator: {
        visible: true,
        style: 'glow',
      },
      reducedMotion: false,
      highContrast: false,
    },
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
  },
  forest: {
    id: 'preset-forest',
    name: 'Forest',
    description: 'Natural green tones for a calming experience',
    author: 'System',
    version: '1.0.0',
    mode: 'dark',
    colors: {
      primary: {
        main: '#4caf50',
        light: '#80e27e',
        dark: '#087f23',
        contrastText: '#000000',
      },
      secondary: {
        main: '#8bc34a',
        light: '#bef67a',
        dark: '#5a9216',
        contrastText: '#000000',
      },
      error: {
        main: '#f44336',
        light: '#ff7961',
        dark: '#ba000d',
        contrastText: '#ffffff',
      },
      warning: {
        main: '#ff9800',
        light: '#ffc947',
        dark: '#c66900',
        contrastText: '#000000',
      },
      info: {
        main: '#00bcd4',
        light: '#62efff',
        dark: '#008ba3',
        contrastText: '#000000',
      },
      success: {
        main: '#4caf50',
        light: '#80e27e',
        dark: '#087f23',
        contrastText: '#000000',
      },
      background: {
        default: '#1a1a1a',
        paper: '#2d2d2d',
        elevated: '#3a3a3a',
      },
      text: {
        primary: '#e0f2f1',
        secondary: '#a7c0a4',
        disabled: 'rgba(255, 255, 255, 0.38)',
      },
      divider: 'rgba(76, 175, 80, 0.12)',
    },
    typography: {
      fontFamily: {
        primary: '"Poppins", "Roboto", sans-serif',
        secondary: '"Playfair Display", serif',
        monospace: '"JetBrains Mono", monospace',
      },
      fontSize: {
        base: 15,
        scale: 1.25,
      },
      fontWeight: {
        light: 300,
        regular: 400,
        medium: 500,
        semibold: 600,
        bold: 700,
      },
      lineHeight: {
        tight: 1.25,
        normal: 1.55,
        relaxed: 1.75,
      },
      letterSpacing: {
        tight: -0.03,
        normal: 0,
        wide: 0.08,
      },
    },
    density: {
      level: 'spacious',
      spacing: {
        base: 10,
        scale: 1.6,
      },
      borderRadius: {
        small: 6,
        medium: 10,
        large: 16,
      },
      componentSize: {
        small: 36,
        medium: 44,
        large: 52,
      },
    },
    accessibility: {
      contrastRatio: {
        AA: true,
        AAA: false,
      },
      fontSize: {
        minimum: 13,
        readable: true,
      },
      focusIndicator: {
        visible: true,
        style: 'outline',
      },
      reducedMotion: false,
      highContrast: false,
    },
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
  },
};