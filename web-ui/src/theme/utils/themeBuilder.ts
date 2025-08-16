import { createTheme, ThemeOptions } from '@mui/material/styles';
import { CustomThemeConfig, DensityLevel } from '../types';

export function buildMuiTheme(config: CustomThemeConfig): ThemeOptions {
  const densitySpacing = getDensitySpacing(config.density.level);
  const densitySize = getDensityComponentSize(config.density.level);

  return createTheme({
    palette: {
      mode: config.mode,
      primary: config.colors.primary,
      secondary: config.colors.secondary,
      error: config.colors.error,
      warning: config.colors.warning,
      info: config.colors.info,
      success: config.colors.success,
      background: config.colors.background,
      text: config.colors.text,
      divider: config.colors.divider,
    },
    typography: {
      fontFamily: config.typography.fontFamily.primary,
      fontSize: config.typography.fontSize.base,
      h1: {
        fontSize: `${config.typography.fontSize.base * 2.5}px`,
        fontWeight: config.typography.fontWeight.bold,
        lineHeight: config.typography.lineHeight.tight,
        letterSpacing: config.typography.letterSpacing.tight,
      },
      h2: {
        fontSize: `${config.typography.fontSize.base * 2}px`,
        fontWeight: config.typography.fontWeight.semibold,
        lineHeight: config.typography.lineHeight.tight,
        letterSpacing: config.typography.letterSpacing.normal,
      },
      h3: {
        fontSize: `${config.typography.fontSize.base * 1.75}px`,
        fontWeight: config.typography.fontWeight.semibold,
        lineHeight: config.typography.lineHeight.normal,
        letterSpacing: config.typography.letterSpacing.normal,
      },
      h4: {
        fontSize: `${config.typography.fontSize.base * 1.5}px`,
        fontWeight: config.typography.fontWeight.medium,
        lineHeight: config.typography.lineHeight.normal,
        letterSpacing: config.typography.letterSpacing.normal,
      },
      h5: {
        fontSize: `${config.typography.fontSize.base * 1.25}px`,
        fontWeight: config.typography.fontWeight.medium,
        lineHeight: config.typography.lineHeight.normal,
        letterSpacing: config.typography.letterSpacing.normal,
      },
      h6: {
        fontSize: `${config.typography.fontSize.base * 1.1}px`,
        fontWeight: config.typography.fontWeight.medium,
        lineHeight: config.typography.lineHeight.normal,
        letterSpacing: config.typography.letterSpacing.wide,
      },
      body1: {
        fontSize: `${config.typography.fontSize.base}px`,
        fontWeight: config.typography.fontWeight.regular,
        lineHeight: config.typography.lineHeight.relaxed,
        letterSpacing: config.typography.letterSpacing.normal,
      },
      body2: {
        fontSize: `${config.typography.fontSize.base * 0.875}px`,
        fontWeight: config.typography.fontWeight.regular,
        lineHeight: config.typography.lineHeight.relaxed,
        letterSpacing: config.typography.letterSpacing.normal,
      },
      button: {
        fontSize: `${config.typography.fontSize.base * 0.875}px`,
        fontWeight: config.typography.fontWeight.medium,
        letterSpacing: config.typography.letterSpacing.wide,
        textTransform: 'none',
      },
      caption: {
        fontSize: `${config.typography.fontSize.base * 0.75}px`,
        fontWeight: config.typography.fontWeight.regular,
        lineHeight: config.typography.lineHeight.normal,
        letterSpacing: config.typography.letterSpacing.wide,
      },
      overline: {
        fontSize: `${config.typography.fontSize.base * 0.75}px`,
        fontWeight: config.typography.fontWeight.medium,
        lineHeight: config.typography.lineHeight.normal,
        letterSpacing: config.typography.letterSpacing.wide,
        textTransform: 'uppercase',
      },
    },
    spacing: densitySpacing,
    shape: {
      borderRadius: config.density.borderRadius.medium,
    },
    components: {
      MuiButton: {
        styleOverrides: {
          root: {
            borderRadius: config.density.borderRadius.medium,
            padding: `${densitySize.button.paddingY}px ${densitySize.button.paddingX}px`,
            fontSize: `${densitySize.button.fontSize}px`,
            minHeight: `${densitySize.button.height}px`,
          },
          sizeSmall: {
            padding: `${densitySize.button.paddingY * 0.75}px ${densitySize.button.paddingX * 0.75}px`,
            fontSize: `${densitySize.button.fontSize * 0.875}px`,
            minHeight: `${densitySize.button.height * 0.875}px`,
          },
          sizeLarge: {
            padding: `${densitySize.button.paddingY * 1.25}px ${densitySize.button.paddingX * 1.25}px`,
            fontSize: `${densitySize.button.fontSize * 1.125}px`,
            minHeight: `${densitySize.button.height * 1.25}px`,
          },
        },
      },
      MuiTextField: {
        styleOverrides: {
          root: {
            '& .MuiInputBase-root': {
              borderRadius: config.density.borderRadius.small,
            },
            '& .MuiInputBase-input': {
              padding: `${densitySize.input.paddingY}px ${densitySize.input.paddingX}px`,
              fontSize: `${densitySize.input.fontSize}px`,
            },
          },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: {
            borderRadius: config.density.borderRadius.large,
            padding: densitySpacing * 2,
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: {
            borderRadius: config.density.borderRadius.medium,
          },
        },
      },
      MuiChip: {
        styleOverrides: {
          root: {
            borderRadius: config.density.borderRadius.small,
            height: `${densitySize.chip.height}px`,
            fontSize: `${densitySize.chip.fontSize}px`,
          },
        },
      },
      MuiIconButton: {
        styleOverrides: {
          root: {
            padding: `${densitySize.iconButton.padding}px`,
          },
          sizeSmall: {
            padding: `${densitySize.iconButton.padding * 0.75}px`,
          },
          sizeLarge: {
            padding: `${densitySize.iconButton.padding * 1.25}px`,
          },
        },
      },
      MuiListItem: {
        styleOverrides: {
          root: {
            paddingTop: `${densitySize.listItem.paddingY}px`,
            paddingBottom: `${densitySize.listItem.paddingY}px`,
          },
        },
      },
      MuiTableCell: {
        styleOverrides: {
          root: {
            padding: `${densitySize.tableCell.padding}px`,
          },
          sizeSmall: {
            padding: `${densitySize.tableCell.padding * 0.75}px`,
          },
        },
      },
    },
  });
}

function getDensitySpacing(level: DensityLevel): number {
  switch (level) {
    case 'compact':
      return 4;
    case 'comfortable':
      return 8;
    case 'spacious':
      return 12;
    default:
      return 8;
  }
}

function getDensityComponentSize(level: DensityLevel) {
  const sizes = {
    compact: {
      button: { height: 32, paddingX: 12, paddingY: 6, fontSize: 13 },
      input: { paddingX: 10, paddingY: 8, fontSize: 13 },
      chip: { height: 24, fontSize: 12 },
      iconButton: { padding: 6 },
      listItem: { paddingY: 6 },
      tableCell: { padding: 8 },
    },
    comfortable: {
      button: { height: 40, paddingX: 16, paddingY: 8, fontSize: 14 },
      input: { paddingX: 12, paddingY: 10, fontSize: 14 },
      chip: { height: 32, fontSize: 13 },
      iconButton: { padding: 8 },
      listItem: { paddingY: 8 },
      tableCell: { padding: 12 },
    },
    spacious: {
      button: { height: 48, paddingX: 20, paddingY: 10, fontSize: 15 },
      input: { paddingX: 14, paddingY: 12, fontSize: 15 },
      chip: { height: 36, fontSize: 14 },
      iconButton: { padding: 10 },
      listItem: { paddingY: 10 },
      tableCell: { padding: 16 },
    },
  };

  return sizes[level] || sizes.comfortable;
}

export function applyCustomCSS(css: string): void {
  const styleId = 'custom-theme-css';
  let styleElement = document.getElementById(styleId) as HTMLStyleElement;

  if (!styleElement) {
    styleElement = document.createElement('style');
    styleElement.id = styleId;
    document.head.appendChild(styleElement);
  }

  styleElement.textContent = css;
}

export function removeCustomCSS(): void {
  const styleElement = document.getElementById('custom-theme-css');
  if (styleElement) {
    styleElement.remove();
  }
}

export function generateCSSVariables(config: CustomThemeConfig): string {
  const variables: string[] = [':root {'];

  variables.push(`  --primary-main: ${config.colors.primary.main};`);
  variables.push(`  --primary-light: ${config.colors.primary.light};`);
  variables.push(`  --primary-dark: ${config.colors.primary.dark};`);
  variables.push(`  --primary-contrast: ${config.colors.primary.contrastText};`);

  variables.push(`  --secondary-main: ${config.colors.secondary.main};`);
  variables.push(`  --secondary-light: ${config.colors.secondary.light};`);
  variables.push(`  --secondary-dark: ${config.colors.secondary.dark};`);
  variables.push(`  --secondary-contrast: ${config.colors.secondary.contrastText};`);

  variables.push(`  --error-main: ${config.colors.error.main};`);
  variables.push(`  --warning-main: ${config.colors.warning.main};`);
  variables.push(`  --info-main: ${config.colors.info.main};`);
  variables.push(`  --success-main: ${config.colors.success.main};`);

  variables.push(`  --bg-default: ${config.colors.background.default};`);
  variables.push(`  --bg-paper: ${config.colors.background.paper};`);

  variables.push(`  --text-primary: ${config.colors.text.primary};`);
  variables.push(`  --text-secondary: ${config.colors.text.secondary};`);
  variables.push(`  --text-disabled: ${config.colors.text.disabled};`);

  variables.push(`  --divider: ${config.colors.divider};`);

  variables.push(`  --font-family: ${config.typography.fontFamily.primary};`);
  variables.push(`  --font-size-base: ${config.typography.fontSize.base}px;`);

  variables.push(`  --spacing-unit: ${config.density.spacing.base}px;`);
  variables.push(`  --border-radius-sm: ${config.density.borderRadius.small}px;`);
  variables.push(`  --border-radius-md: ${config.density.borderRadius.medium}px;`);
  variables.push(`  --border-radius-lg: ${config.density.borderRadius.large}px;`);

  if (config.colors.custom) {
    Object.entries(config.colors.custom).forEach(([key, value]) => {
      variables.push(`  --custom-${key}: ${value};`);
    });
  }

  variables.push('}');

  return variables.join('\n');
}