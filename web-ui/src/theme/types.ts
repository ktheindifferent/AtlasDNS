import { PaletteMode, ThemeOptions } from '@mui/material';

export interface CustomThemeConfig {
  id: string;
  name: string;
  description?: string;
  author?: string;
  version: string;
  mode: PaletteMode;
  colors: ColorConfig;
  typography: TypographyConfig;
  density: DensityConfig;
  customCSS?: string;
  accessibility: AccessibilityConfig;
  createdAt: string;
  updatedAt: string;
  isPublic?: boolean;
  downloads?: number;
  rating?: number;
}

export interface ColorConfig {
  primary: ColorPalette;
  secondary: ColorPalette;
  error: ColorPalette;
  warning: ColorPalette;
  info: ColorPalette;
  success: ColorPalette;
  background: {
    default: string;
    paper: string;
    elevated?: string;
  };
  text: {
    primary: string;
    secondary: string;
    disabled: string;
  };
  divider: string;
  custom?: Record<string, string>;
}

export interface ColorPalette {
  main: string;
  light?: string;
  dark?: string;
  contrastText?: string;
}

export interface TypographyConfig {
  fontFamily: {
    primary: string;
    secondary?: string;
    monospace?: string;
  };
  fontSize: {
    base: number;
    scale: number;
  };
  fontWeight: {
    light: number;
    regular: number;
    medium: number;
    semibold: number;
    bold: number;
  };
  lineHeight: {
    tight: number;
    normal: number;
    relaxed: number;
  };
  letterSpacing: {
    tight: number;
    normal: number;
    wide: number;
  };
}

export type DensityLevel = 'compact' | 'comfortable' | 'spacious';

export interface DensityConfig {
  level: DensityLevel;
  spacing: {
    base: number;
    scale: number;
  };
  borderRadius: {
    small: number;
    medium: number;
    large: number;
  };
  componentSize: {
    small: number;
    medium: number;
    large: number;
  };
}

export interface AccessibilityConfig {
  contrastRatio: {
    AA: boolean;
    AAA: boolean;
  };
  fontSize: {
    minimum: number;
    readable: boolean;
  };
  focusIndicator: {
    visible: boolean;
    style: 'outline' | 'glow' | 'underline';
  };
  reducedMotion: boolean;
  highContrast: boolean;
}

export interface ThemePreset {
  id: string;
  name: string;
  thumbnail?: string;
  config: Partial<CustomThemeConfig>;
}

export interface ThemeMarketplaceItem {
  theme: CustomThemeConfig;
  stats: {
    downloads: number;
    likes: number;
    rating: number;
    reviews: number;
  };
  tags: string[];
  screenshots?: string[];
}

export interface ThemeExport {
  version: string;
  theme: CustomThemeConfig;
  metadata: {
    exportedAt: string;
    exportedBy?: string;
    application: string;
  };
}