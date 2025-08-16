import { ColorPalette } from '../types';

export function hexToRgb(hex: string): { r: number; g: number; b: number } | null {
  const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  return result
    ? {
        r: parseInt(result[1], 16),
        g: parseInt(result[2], 16),
        b: parseInt(result[3], 16),
      }
    : null;
}

export function rgbToHex(r: number, g: number, b: number): string {
  return '#' + ((1 << 24) + (r << 16) + (g << 8) + b).toString(16).slice(1);
}

export function getLuminance(hex: string): number {
  const rgb = hexToRgb(hex);
  if (!rgb) return 0;

  const { r, g, b } = rgb;
  const sRGB = [r, g, b].map((val) => {
    val = val / 255;
    return val <= 0.03928 ? val / 12.92 : Math.pow((val + 0.055) / 1.055, 2.4);
  });

  return 0.2126 * sRGB[0] + 0.7152 * sRGB[1] + 0.0722 * sRGB[2];
}

export function getContrastRatio(color1: string, color2: string): number {
  const lum1 = getLuminance(color1);
  const lum2 = getLuminance(color2);
  const brightest = Math.max(lum1, lum2);
  const darkest = Math.min(lum1, lum2);
  return (brightest + 0.05) / (darkest + 0.05);
}

export function isAccessibleColor(
  foreground: string,
  background: string,
  level: 'AA' | 'AAA' = 'AA'
): boolean {
  const ratio = getContrastRatio(foreground, background);
  return level === 'AA' ? ratio >= 4.5 : ratio >= 7;
}

export function generateColorPalette(baseColor: string): ColorPalette {
  const rgb = hexToRgb(baseColor);
  if (!rgb) {
    return { main: baseColor };
  }

  const lighten = (color: { r: number; g: number; b: number }, amount: number) => {
    return {
      r: Math.min(255, color.r + amount),
      g: Math.min(255, color.g + amount),
      b: Math.min(255, color.b + amount),
    };
  };

  const darken = (color: { r: number; g: number; b: number }, amount: number) => {
    return {
      r: Math.max(0, color.r - amount),
      g: Math.max(0, color.g - amount),
      b: Math.max(0, color.b - amount),
    };
  };

  const light = lighten(rgb, 40);
  const dark = darken(rgb, 40);

  const luminance = getLuminance(baseColor);
  const contrastText = luminance > 0.5 ? '#000000' : '#ffffff';

  return {
    main: baseColor,
    light: rgbToHex(light.r, light.g, light.b),
    dark: rgbToHex(dark.r, dark.g, dark.b),
    contrastText,
  };
}

export function generateComplementaryColor(hex: string): string {
  const rgb = hexToRgb(hex);
  if (!rgb) return hex;

  return rgbToHex(255 - rgb.r, 255 - rgb.g, 255 - rgb.b);
}

export function generateAnalogousColors(hex: string): string[] {
  const rgb = hexToRgb(hex);
  if (!rgb) return [hex];

  const hsl = rgbToHsl(rgb.r, rgb.g, rgb.b);
  const analogous1 = hslToRgb((hsl.h + 30) % 360, hsl.s, hsl.l);
  const analogous2 = hslToRgb((hsl.h - 30 + 360) % 360, hsl.s, hsl.l);

  return [
    rgbToHex(analogous1.r, analogous1.g, analogous1.b),
    hex,
    rgbToHex(analogous2.r, analogous2.g, analogous2.b),
  ];
}

export function generateTriadicColors(hex: string): string[] {
  const rgb = hexToRgb(hex);
  if (!rgb) return [hex];

  const hsl = rgbToHsl(rgb.r, rgb.g, rgb.b);
  const triadic1 = hslToRgb((hsl.h + 120) % 360, hsl.s, hsl.l);
  const triadic2 = hslToRgb((hsl.h + 240) % 360, hsl.s, hsl.l);

  return [
    hex,
    rgbToHex(triadic1.r, triadic1.g, triadic1.b),
    rgbToHex(triadic2.r, triadic2.g, triadic2.b),
  ];
}

function rgbToHsl(r: number, g: number, b: number) {
  r /= 255;
  g /= 255;
  b /= 255;

  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  let h = 0;
  let s = 0;
  const l = (max + min) / 2;

  if (max !== min) {
    const d = max - min;
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
    switch (max) {
      case r:
        h = ((g - b) / d + (g < b ? 6 : 0)) / 6;
        break;
      case g:
        h = ((b - r) / d + 2) / 6;
        break;
      case b:
        h = ((r - g) / d + 4) / 6;
        break;
    }
  }

  return { h: h * 360, s, l };
}

function hslToRgb(h: number, s: number, l: number) {
  h /= 360;
  let r, g, b;

  if (s === 0) {
    r = g = b = l;
  } else {
    const hue2rgb = (p: number, q: number, t: number) => {
      if (t < 0) t += 1;
      if (t > 1) t -= 1;
      if (t < 1 / 6) return p + (q - p) * 6 * t;
      if (t < 1 / 2) return q;
      if (t < 2 / 3) return p + (q - p) * (2 / 3 - t) * 6;
      return p;
    };

    const q = l < 0.5 ? l * (1 + s) : l + s - l * s;
    const p = 2 * l - q;
    r = hue2rgb(p, q, h + 1 / 3);
    g = hue2rgb(p, q, h);
    b = hue2rgb(p, q, h - 1 / 3);
  }

  return {
    r: Math.round(r * 255),
    g: Math.round(g * 255),
    b: Math.round(b * 255),
  };
}

export function generateColorSchemeFromBrand(
  brandColor: string,
  scheme: 'monochromatic' | 'complementary' | 'analogous' | 'triadic' = 'analogous'
): Record<string, string> {
  const baseColors: Record<string, string> = {
    primary: brandColor,
  };

  switch (scheme) {
    case 'monochromatic': {
      const rgb = hexToRgb(brandColor);
      if (rgb) {
        baseColors.secondary = rgbToHex(
          Math.round(rgb.r * 0.8),
          Math.round(rgb.g * 0.8),
          Math.round(rgb.b * 0.8)
        );
        baseColors.tertiary = rgbToHex(
          Math.round(rgb.r * 0.6),
          Math.round(rgb.g * 0.6),
          Math.round(rgb.b * 0.6)
        );
      }
      break;
    }
    case 'complementary':
      baseColors.secondary = generateComplementaryColor(brandColor);
      break;
    case 'analogous': {
      const analogous = generateAnalogousColors(brandColor);
      baseColors.secondary = analogous[0];
      baseColors.tertiary = analogous[2];
      break;
    }
    case 'triadic': {
      const triadic = generateTriadicColors(brandColor);
      baseColors.secondary = triadic[1];
      baseColors.tertiary = triadic[2];
      break;
    }
  }

  return baseColors;
}