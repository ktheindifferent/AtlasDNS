import React, { createContext, useContext, useState, useEffect, useCallback, useMemo } from 'react';
import { ThemeProvider as MuiThemeProvider, createTheme } from '@mui/material/styles';
import { CustomThemeConfig, ThemePreset } from './types';
import { buildMuiTheme, applyCustomCSS, removeCustomCSS, generateCSSVariables } from './utils/themeBuilder';
import { defaultThemes } from './presets';

interface ThemeContextValue {
  currentTheme: CustomThemeConfig;
  setTheme: (theme: CustomThemeConfig) => void;
  presets: ThemePreset[];
  isDarkMode: boolean;
  toggleDarkMode: () => void;
  saveTheme: (theme: CustomThemeConfig) => Promise<void>;
  loadTheme: (themeId: string) => Promise<CustomThemeConfig | null>;
  deleteTheme: (themeId: string) => Promise<void>;
  exportTheme: (theme: CustomThemeConfig) => string;
  importTheme: (themeData: string) => CustomThemeConfig | null;
  applyPreset: (presetId: string) => void;
  resetToDefault: () => void;
}

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined);

export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};

interface ThemeProviderProps {
  children: React.ReactNode;
  initialTheme?: CustomThemeConfig;
}

export const CustomThemeProvider: React.FC<ThemeProviderProps> = ({ children, initialTheme }) => {
  const [currentTheme, setCurrentTheme] = useState<CustomThemeConfig>(
    initialTheme || defaultThemes.light
  );
  const [presets] = useState<ThemePreset[]>(Object.values(defaultThemes));

  const muiTheme = useMemo(() => {
    return createTheme(buildMuiTheme(currentTheme));
  }, [currentTheme]);

  useEffect(() => {
    const cssVariables = generateCSSVariables(currentTheme);
    const styleElement = document.createElement('style');
    styleElement.id = 'theme-css-variables';
    styleElement.textContent = cssVariables;
    
    const existingElement = document.getElementById('theme-css-variables');
    if (existingElement) {
      existingElement.remove();
    }
    document.head.appendChild(styleElement);

    if (currentTheme.customCSS) {
      applyCustomCSS(currentTheme.customCSS);
    } else {
      removeCustomCSS();
    }

    return () => {
      removeCustomCSS();
    };
  }, [currentTheme]);

  useEffect(() => {
    const savedThemeId = localStorage.getItem('selectedThemeId');
    if (savedThemeId) {
      loadTheme(savedThemeId).then((theme) => {
        if (theme) {
          setCurrentTheme(theme);
        }
      });
    }
  }, []);

  const setTheme = useCallback((theme: CustomThemeConfig) => {
    setCurrentTheme(theme);
    localStorage.setItem('selectedThemeId', theme.id);
  }, []);

  const isDarkMode = currentTheme.mode === 'dark';

  const toggleDarkMode = useCallback(() => {
    setCurrentTheme((prev) => ({
      ...prev,
      mode: prev.mode === 'dark' ? 'light' : 'dark',
    }));
  }, []);

  const saveTheme = useCallback(async (theme: CustomThemeConfig) => {
    try {
      const response = await fetch('/api/themes', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`,
        },
        body: JSON.stringify(theme),
      });

      if (!response.ok) {
        throw new Error('Failed to save theme');
      }

      const savedTheme = await response.json();
      
      const savedThemes = JSON.parse(localStorage.getItem('customThemes') || '[]');
      const updatedThemes = [...savedThemes.filter((t: CustomThemeConfig) => t.id !== theme.id), savedTheme];
      localStorage.setItem('customThemes', JSON.stringify(updatedThemes));
      
      return savedTheme;
    } catch (error) {
      console.error('Error saving theme:', error);
      
      const savedThemes = JSON.parse(localStorage.getItem('customThemes') || '[]');
      const updatedThemes = [...savedThemes.filter((t: CustomThemeConfig) => t.id !== theme.id), theme];
      localStorage.setItem('customThemes', JSON.stringify(updatedThemes));
      
      throw error;
    }
  }, []);

  const loadTheme = useCallback(async (themeId: string): Promise<CustomThemeConfig | null> => {
    try {
      const response = await fetch(`/api/themes/${themeId}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`,
        },
      });

      if (!response.ok) {
        throw new Error('Failed to load theme');
      }

      return await response.json();
    } catch (error) {
      console.error('Error loading theme:', error);
      
      const savedThemes = JSON.parse(localStorage.getItem('customThemes') || '[]');
      const theme = savedThemes.find((t: CustomThemeConfig) => t.id === themeId);
      
      if (!theme) {
        const preset = Object.values(defaultThemes).find(t => t.id === themeId);
        return preset || null;
      }
      
      return theme;
    }
  }, []);

  const deleteTheme = useCallback(async (themeId: string) => {
    try {
      const response = await fetch(`/api/themes/${themeId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`,
        },
      });

      if (!response.ok) {
        throw new Error('Failed to delete theme');
      }
      
      const savedThemes = JSON.parse(localStorage.getItem('customThemes') || '[]');
      const updatedThemes = savedThemes.filter((t: CustomThemeConfig) => t.id !== themeId);
      localStorage.setItem('customThemes', JSON.stringify(updatedThemes));
      
      if (currentTheme.id === themeId) {
        setCurrentTheme(defaultThemes.light);
      }
    } catch (error) {
      console.error('Error deleting theme:', error);
      throw error;
    }
  }, [currentTheme]);

  const exportTheme = useCallback((theme: CustomThemeConfig): string => {
    const exportData = {
      version: '1.0.0',
      theme,
      metadata: {
        exportedAt: new Date().toISOString(),
        application: 'Atlas DNS UI',
      },
    };
    return JSON.stringify(exportData, null, 2);
  }, []);

  const importTheme = useCallback((themeData: string): CustomThemeConfig | null => {
    try {
      const parsed = JSON.parse(themeData);
      if (parsed.version && parsed.theme) {
        const importedTheme = {
          ...parsed.theme,
          id: `imported-${Date.now()}`,
          updatedAt: new Date().toISOString(),
        };
        return importedTheme;
      }
      return null;
    } catch (error) {
      console.error('Error importing theme:', error);
      return null;
    }
  }, []);

  const applyPreset = useCallback((presetId: string) => {
    const preset = Object.values(defaultThemes).find(t => t.id === presetId);
    if (preset) {
      setTheme(preset);
    }
  }, [setTheme]);

  const resetToDefault = useCallback(() => {
    setTheme(defaultThemes.light);
  }, [setTheme]);

  const value: ThemeContextValue = {
    currentTheme,
    setTheme,
    presets,
    isDarkMode,
    toggleDarkMode,
    saveTheme,
    loadTheme,
    deleteTheme,
    exportTheme,
    importTheme,
    applyPreset,
    resetToDefault,
  };

  return (
    <ThemeContext.Provider value={value}>
      <MuiThemeProvider theme={muiTheme}>
        {children}
      </MuiThemeProvider>
    </ThemeContext.Provider>
  );
};