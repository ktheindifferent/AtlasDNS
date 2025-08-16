import React, { useState, useEffect, useMemo } from 'react';
import {
  Box,
  Paper,
  Grid,
  Typography,
  Button,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Tabs,
  Tab,
  Slider,
  Switch,
  FormControlLabel,
  IconButton,
  Tooltip,
  Divider,
  Chip,
  Alert,
  Snackbar,
} from '@mui/material';
import {
  Palette as PaletteIcon,
  TextFields as TextFieldsIcon,
  Dashboard as DashboardIcon,
  Code as CodeIcon,
  Accessibility as AccessibilityIcon,
  Save as SaveIcon,
  Download as DownloadIcon,
  Upload as UploadIcon,
  Refresh as RefreshIcon,
  Preview as PreviewIcon,
  Share as ShareIcon,
} from '@mui/icons-material';
import { CustomThemeConfig, DensityLevel } from '../../theme/types';
import { useTheme } from '../../theme/ThemeContext';
import ColorPicker from './ColorPicker';
import TypographySettings from './TypographySettings';
import DensitySettings from './DensitySettings';
import CustomCSSEditor from './CustomCSSEditor';
import AccessibilityChecker from './AccessibilityChecker';
import ThemePreview from './ThemePreview';
import { generateColorPalette, generateColorSchemeFromBrand } from '../../theme/utils/colorUtils';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`theme-tabpanel-${index}`}
      aria-labelledby={`theme-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

export default function ThemeBuilder() {
  const {
    currentTheme,
    setTheme,
    saveTheme,
    exportTheme,
    importTheme,
    applyPreset,
    resetToDefault,
    presets,
  } = useTheme();

  const [editingTheme, setEditingTheme] = useState<CustomThemeConfig>(currentTheme);
  const [activeTab, setActiveTab] = useState(0);
  const [showPreview, setShowPreview] = useState(true);
  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success',
  });

  useEffect(() => {
    setEditingTheme(currentTheme);
  }, [currentTheme]);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setActiveTab(newValue);
  };

  const handleColorChange = (colorPath: string, value: string) => {
    const paths = colorPath.split('.');
    setEditingTheme((prev) => {
      const newTheme = { ...prev };
      let obj: any = newTheme;
      for (let i = 0; i < paths.length - 1; i++) {
        obj = obj[paths[i]];
      }
      obj[paths[paths.length - 1]] = value;
      return newTheme;
    });
  };

  const handleGeneratePalette = (baseColor: string, scheme: 'monochromatic' | 'complementary' | 'analogous' | 'triadic') => {
    const colorScheme = generateColorSchemeFromBrand(baseColor, scheme);
    const primary = generateColorPalette(colorScheme.primary);
    const secondary = generateColorPalette(colorScheme.secondary || colorScheme.primary);

    setEditingTheme((prev) => ({
      ...prev,
      colors: {
        ...prev.colors,
        primary,
        secondary,
      },
    }));

    setSnackbar({
      open: true,
      message: `Generated ${scheme} color palette`,
      severity: 'success',
    });
  };

  const handleTypographyChange = (settings: any) => {
    setEditingTheme((prev) => ({
      ...prev,
      typography: {
        ...prev.typography,
        ...settings,
      },
    }));
  };

  const handleDensityChange = (density: DensityLevel) => {
    setEditingTheme((prev) => ({
      ...prev,
      density: {
        ...prev.density,
        level: density,
      },
    }));
  };

  const handleCustomCSSChange = (css: string) => {
    setEditingTheme((prev) => ({
      ...prev,
      customCSS: css,
    }));
  };

  const handleApplyTheme = () => {
    setTheme(editingTheme);
    setSnackbar({
      open: true,
      message: 'Theme applied successfully',
      severity: 'success',
    });
  };

  const handleSaveTheme = async () => {
    setSaveStatus('saving');
    try {
      await saveTheme(editingTheme);
      setSaveStatus('saved');
      setSnackbar({
        open: true,
        message: 'Theme saved successfully',
        severity: 'success',
      });
    } catch (error) {
      setSaveStatus('error');
      setSnackbar({
        open: true,
        message: 'Failed to save theme',
        severity: 'error',
      });
    }
  };

  const handleExportTheme = () => {
    const themeData = exportTheme(editingTheme);
    const blob = new Blob([themeData], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${editingTheme.name.replace(/\s+/g, '-').toLowerCase()}-theme.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    setSnackbar({
      open: true,
      message: 'Theme exported successfully',
      severity: 'success',
    });
  };

  const handleImportTheme = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;
        const imported = importTheme(content);
        if (imported) {
          setEditingTheme(imported);
          setSnackbar({
            open: true,
            message: 'Theme imported successfully',
            severity: 'success',
          });
        } else {
          setSnackbar({
            open: true,
            message: 'Failed to import theme',
            severity: 'error',
          });
        }
      };
      reader.readAsText(file);
    }
  };

  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <Paper sx={{ mb: 2, p: 2 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs>
            <Typography variant="h5" component="h1">
              Theme Builder
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Customize your application theme with live preview
            </Typography>
          </Grid>
          <Grid item>
            <FormControlLabel
              control={
                <Switch
                  checked={showPreview}
                  onChange={(e) => setShowPreview(e.target.checked)}
                />
              }
              label="Show Preview"
            />
          </Grid>
          <Grid item>
            <Button
              variant="outlined"
              startIcon={<RefreshIcon />}
              onClick={resetToDefault}
              sx={{ mr: 1 }}
            >
              Reset
            </Button>
            <Button
              variant="contained"
              startIcon={<SaveIcon />}
              onClick={handleApplyTheme}
              sx={{ mr: 1 }}
            >
              Apply
            </Button>
            <Button
              variant="contained"
              color="success"
              startIcon={<SaveIcon />}
              onClick={handleSaveTheme}
              disabled={saveStatus === 'saving'}
            >
              Save
            </Button>
          </Grid>
        </Grid>
      </Paper>

      <Box sx={{ flex: 1, display: 'flex', gap: 2, overflow: 'hidden' }}>
        <Paper sx={{ flex: showPreview ? '0 0 60%' : '1', display: 'flex', flexDirection: 'column' }}>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs value={activeTab} onChange={handleTabChange} variant="scrollable">
              <Tab icon={<PaletteIcon />} label="Colors" />
              <Tab icon={<TextFieldsIcon />} label="Typography" />
              <Tab icon={<DashboardIcon />} label="Density" />
              <Tab icon={<CodeIcon />} label="Custom CSS" />
              <Tab icon={<AccessibilityIcon />} label="Accessibility" />
            </Tabs>
          </Box>

          <Box sx={{ flex: 1, overflow: 'auto' }}>
            <TabPanel value={activeTab} index={0}>
              <ColorPicker
                theme={editingTheme}
                onChange={handleColorChange}
                onGeneratePalette={handleGeneratePalette}
              />
            </TabPanel>
            <TabPanel value={activeTab} index={1}>
              <TypographySettings
                typography={editingTheme.typography}
                onChange={handleTypographyChange}
              />
            </TabPanel>
            <TabPanel value={activeTab} index={2}>
              <DensitySettings
                density={editingTheme.density}
                onChange={handleDensityChange}
              />
            </TabPanel>
            <TabPanel value={activeTab} index={3}>
              <CustomCSSEditor
                css={editingTheme.customCSS || ''}
                onChange={handleCustomCSSChange}
              />
            </TabPanel>
            <TabPanel value={activeTab} index={4}>
              <AccessibilityChecker
                theme={editingTheme}
                onFix={(fixes) => setEditingTheme({ ...editingTheme, ...fixes })}
              />
            </TabPanel>
          </Box>

          <Box sx={{ p: 2, borderTop: 1, borderColor: 'divider' }}>
            <Grid container spacing={2}>
              <Grid item>
                <input
                  accept="application/json"
                  style={{ display: 'none' }}
                  id="import-theme-file"
                  type="file"
                  onChange={handleImportTheme}
                />
                <label htmlFor="import-theme-file">
                  <Button variant="outlined" component="span" startIcon={<UploadIcon />}>
                    Import
                  </Button>
                </label>
              </Grid>
              <Grid item>
                <Button
                  variant="outlined"
                  startIcon={<DownloadIcon />}
                  onClick={handleExportTheme}
                >
                  Export
                </Button>
              </Grid>
              <Grid item>
                <Button variant="outlined" startIcon={<ShareIcon />}>
                  Share to Marketplace
                </Button>
              </Grid>
            </Grid>
          </Box>
        </Paper>

        {showPreview && (
          <Paper sx={{ flex: '0 0 40%', overflow: 'auto' }}>
            <ThemePreview theme={editingTheme} />
          </Paper>
        )}
      </Box>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert severity={snackbar.severity} onClose={() => setSnackbar({ ...snackbar, open: false })}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
}