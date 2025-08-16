import React, { useState } from 'react';
import {
  Box,
  Grid,
  Typography,
  TextField,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Paper,
  Chip,
  IconButton,
  Tooltip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  AutoFixHigh as AutoFixHighIcon,
  ContentCopy as ContentCopyIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { CustomThemeConfig } from '../../theme/types';
import { generateColorPalette, getContrastRatio } from '../../theme/utils/colorUtils';

interface ColorPickerProps {
  theme: CustomThemeConfig;
  onChange: (path: string, value: string) => void;
  onGeneratePalette: (baseColor: string, scheme: 'monochromatic' | 'complementary' | 'analogous' | 'triadic') => void;
}

export default function ColorPicker({ theme, onChange, onGeneratePalette }: ColorPickerProps) {
  const [brandColor, setBrandColor] = useState('#1976d2');
  const [colorScheme, setColorScheme] = useState<'monochromatic' | 'complementary' | 'analogous' | 'triadic'>('analogous');

  const handleColorChange = (path: string, value: string) => {
    onChange(`colors.${path}`, value);
  };

  const handleGenerateFromBrand = () => {
    onGeneratePalette(brandColor, colorScheme);
  };

  const copyToClipboard = (color: string) => {
    navigator.clipboard.writeText(color);
  };

  const ColorInput = ({ label, path, value }: { label: string; path: string; value: string }) => (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
      <Box
        sx={{
          width: 40,
          height: 40,
          backgroundColor: value,
          border: '1px solid',
          borderColor: 'divider',
          borderRadius: 1,
          cursor: 'pointer',
        }}
        onClick={() => {
          const input = document.createElement('input');
          input.type = 'color';
          input.value = value;
          input.onchange = (e) => {
            handleColorChange(path, (e.target as HTMLInputElement).value);
          };
          input.click();
        }}
      />
      <TextField
        label={label}
        value={value}
        onChange={(e) => handleColorChange(path, e.target.value)}
        size="small"
        sx={{ flex: 1 }}
      />
      <Tooltip title="Copy color">
        <IconButton size="small" onClick={() => copyToClipboard(value)}>
          <ContentCopyIcon fontSize="small" />
        </IconButton>
      </Tooltip>
    </Box>
  );

  return (
    <Box>
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Generate from Brand Color
        </Typography>
        <Grid container spacing={2} alignItems="flex-end">
          <Grid item xs={12} md={4}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Box
                sx={{
                  width: 40,
                  height: 40,
                  backgroundColor: brandColor,
                  border: '1px solid',
                  borderColor: 'divider',
                  borderRadius: 1,
                  cursor: 'pointer',
                }}
                onClick={() => {
                  const input = document.createElement('input');
                  input.type = 'color';
                  input.value = brandColor;
                  input.onchange = (e) => {
                    setBrandColor((e.target as HTMLInputElement).value);
                  };
                  input.click();
                }}
              />
              <TextField
                label="Brand Color"
                value={brandColor}
                onChange={(e) => setBrandColor(e.target.value)}
                size="small"
                fullWidth
              />
            </Box>
          </Grid>
          <Grid item xs={12} md={4}>
            <FormControl fullWidth size="small">
              <InputLabel>Color Scheme</InputLabel>
              <Select
                value={colorScheme}
                label="Color Scheme"
                onChange={(e) => setColorScheme(e.target.value as typeof colorScheme)}
              >
                <MenuItem value="monochromatic">Monochromatic</MenuItem>
                <MenuItem value="complementary">Complementary</MenuItem>
                <MenuItem value="analogous">Analogous</MenuItem>
                <MenuItem value="triadic">Triadic</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} md={4}>
            <Button
              variant="contained"
              startIcon={<AutoFixHighIcon />}
              onClick={handleGenerateFromBrand}
              fullWidth
            >
              Generate Palette
            </Button>
          </Grid>
        </Grid>
      </Paper>

      <Accordion defaultExpanded>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="subtitle1">Primary Colors</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <ColorInput label="Main" path="primary.main" value={theme.colors.primary.main} />
          <ColorInput label="Light" path="primary.light" value={theme.colors.primary.light || ''} />
          <ColorInput label="Dark" path="primary.dark" value={theme.colors.primary.dark || ''} />
          <ColorInput label="Contrast Text" path="primary.contrastText" value={theme.colors.primary.contrastText || ''} />
        </AccordionDetails>
      </Accordion>

      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="subtitle1">Secondary Colors</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <ColorInput label="Main" path="secondary.main" value={theme.colors.secondary.main} />
          <ColorInput label="Light" path="secondary.light" value={theme.colors.secondary.light || ''} />
          <ColorInput label="Dark" path="secondary.dark" value={theme.colors.secondary.dark || ''} />
          <ColorInput label="Contrast Text" path="secondary.contrastText" value={theme.colors.secondary.contrastText || ''} />
        </AccordionDetails>
      </Accordion>

      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="subtitle1">Status Colors</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <ColorInput label="Error" path="error.main" value={theme.colors.error.main} />
            </Grid>
            <Grid item xs={12} md={6}>
              <ColorInput label="Warning" path="warning.main" value={theme.colors.warning.main} />
            </Grid>
            <Grid item xs={12} md={6}>
              <ColorInput label="Info" path="info.main" value={theme.colors.info.main} />
            </Grid>
            <Grid item xs={12} md={6}>
              <ColorInput label="Success" path="success.main" value={theme.colors.success.main} />
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>

      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="subtitle1">Background & Text</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Typography variant="subtitle2" gutterBottom>
            Background
          </Typography>
          <ColorInput label="Default" path="background.default" value={theme.colors.background.default} />
          <ColorInput label="Paper" path="background.paper" value={theme.colors.background.paper} />
          {theme.colors.background.elevated && (
            <ColorInput label="Elevated" path="background.elevated" value={theme.colors.background.elevated} />
          )}

          <Typography variant="subtitle2" gutterBottom sx={{ mt: 2 }}>
            Text
          </Typography>
          <ColorInput label="Primary" path="text.primary" value={theme.colors.text.primary} />
          <ColorInput label="Secondary" path="text.secondary" value={theme.colors.text.secondary} />
          <ColorInput label="Disabled" path="text.disabled" value={theme.colors.text.disabled} />

          <Typography variant="subtitle2" gutterBottom sx={{ mt: 2 }}>
            Other
          </Typography>
          <ColorInput label="Divider" path="divider" value={theme.colors.divider} />
        </AccordionDetails>
      </Accordion>

      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="subtitle1">Custom Colors</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Button variant="outlined" fullWidth>
            Add Custom Color Variable
          </Button>
        </AccordionDetails>
      </Accordion>
    </Box>
  );
}