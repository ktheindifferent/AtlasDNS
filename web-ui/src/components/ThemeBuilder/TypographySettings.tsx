import React from 'react';
import {
  Box,
  Grid,
  Typography,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Slider,
  Paper,
  Divider,
} from '@mui/material';
import { TypographyConfig } from '../../theme/types';

interface TypographySettingsProps {
  typography: TypographyConfig;
  onChange: (settings: Partial<TypographyConfig>) => void;
}

const fontFamilies = [
  'Inter, sans-serif',
  'Roboto, sans-serif',
  'Open Sans, sans-serif',
  'Lato, sans-serif',
  'Poppins, sans-serif',
  'Nunito, sans-serif',
  'Montserrat, sans-serif',
  'Raleway, sans-serif',
  'Playfair Display, serif',
  'Merriweather, serif',
  'Georgia, serif',
  'Times New Roman, serif',
  'Fira Code, monospace',
  'Source Code Pro, monospace',
  'JetBrains Mono, monospace',
  'Courier New, monospace',
];

export default function TypographySettings({ typography, onChange }: TypographySettingsProps) {
  const handleFontFamilyChange = (type: 'primary' | 'secondary' | 'monospace', value: string) => {
    onChange({
      fontFamily: {
        ...typography.fontFamily,
        [type]: value,
      },
    });
  };

  const handleFontSizeChange = (field: 'base' | 'scale', value: number) => {
    onChange({
      fontSize: {
        ...typography.fontSize,
        [field]: value,
      },
    });
  };

  const handleFontWeightChange = (weight: keyof typeof typography.fontWeight, value: number) => {
    onChange({
      fontWeight: {
        ...typography.fontWeight,
        [weight]: value,
      },
    });
  };

  const handleLineHeightChange = (type: keyof typeof typography.lineHeight, value: number) => {
    onChange({
      lineHeight: {
        ...typography.lineHeight,
        [type]: value,
      },
    });
  };

  const handleLetterSpacingChange = (type: keyof typeof typography.letterSpacing, value: number) => {
    onChange({
      letterSpacing: {
        ...typography.letterSpacing,
        [type]: value,
      },
    });
  };

  return (
    <Box>
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Font Families
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12}>
            <FormControl fullWidth>
              <InputLabel>Primary Font</InputLabel>
              <Select
                value={typography.fontFamily.primary}
                label="Primary Font"
                onChange={(e) => handleFontFamilyChange('primary', e.target.value)}
              >
                {fontFamilies.map((font) => (
                  <MenuItem key={font} value={font}>
                    <span style={{ fontFamily: font }}>{font}</span>
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} md={6}>
            <FormControl fullWidth>
              <InputLabel>Secondary Font</InputLabel>
              <Select
                value={typography.fontFamily.secondary || ''}
                label="Secondary Font"
                onChange={(e) => handleFontFamilyChange('secondary', e.target.value)}
              >
                <MenuItem value="">None</MenuItem>
                {fontFamilies.map((font) => (
                  <MenuItem key={font} value={font}>
                    <span style={{ fontFamily: font }}>{font}</span>
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} md={6}>
            <FormControl fullWidth>
              <InputLabel>Monospace Font</InputLabel>
              <Select
                value={typography.fontFamily.monospace || ''}
                label="Monospace Font"
                onChange={(e) => handleFontFamilyChange('monospace', e.target.value)}
              >
                <MenuItem value="">None</MenuItem>
                {fontFamilies.filter((f) => f.includes('mono') || f.includes('Courier')).map((font) => (
                  <MenuItem key={font} value={font}>
                    <span style={{ fontFamily: font }}>{font}</span>
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
        </Grid>
      </Paper>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Font Sizes
        </Typography>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Typography gutterBottom>Base Size: {typography.fontSize.base}px</Typography>
            <Slider
              value={typography.fontSize.base}
              onChange={(e, value) => handleFontSizeChange('base', value as number)}
              min={10}
              max={20}
              step={1}
              marks
              valueLabelDisplay="auto"
            />
          </Grid>
          <Grid item xs={12} md={6}>
            <Typography gutterBottom>Scale Factor: {typography.fontSize.scale.toFixed(2)}</Typography>
            <Slider
              value={typography.fontSize.scale}
              onChange={(e, value) => handleFontSizeChange('scale', value as number)}
              min={1.1}
              max={1.5}
              step={0.05}
              marks
              valueLabelDisplay="auto"
            />
          </Grid>
        </Grid>

        <Box sx={{ mt: 3 }}>
          <Typography variant="caption" color="text.secondary">
            Preview:
          </Typography>
          <Box sx={{ mt: 1 }}>
            <Typography style={{ fontSize: typography.fontSize.base * Math.pow(typography.fontSize.scale, 4) }}>
              Heading 1
            </Typography>
            <Typography style={{ fontSize: typography.fontSize.base * Math.pow(typography.fontSize.scale, 3) }}>
              Heading 2
            </Typography>
            <Typography style={{ fontSize: typography.fontSize.base * Math.pow(typography.fontSize.scale, 2) }}>
              Heading 3
            </Typography>
            <Typography style={{ fontSize: typography.fontSize.base * typography.fontSize.scale }}>
              Heading 4
            </Typography>
            <Typography style={{ fontSize: typography.fontSize.base }}>
              Body text
            </Typography>
            <Typography style={{ fontSize: typography.fontSize.base * 0.875 }}>
              Caption text
            </Typography>
          </Box>
        </Box>
      </Paper>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Font Weights
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} md={4}>
            <Typography gutterBottom>Light: {typography.fontWeight.light}</Typography>
            <Slider
              value={typography.fontWeight.light}
              onChange={(e, value) => handleFontWeightChange('light', value as number)}
              min={100}
              max={400}
              step={100}
              marks
              valueLabelDisplay="auto"
            />
          </Grid>
          <Grid item xs={12} md={4}>
            <Typography gutterBottom>Regular: {typography.fontWeight.regular}</Typography>
            <Slider
              value={typography.fontWeight.regular}
              onChange={(e, value) => handleFontWeightChange('regular', value as number)}
              min={300}
              max={500}
              step={100}
              marks
              valueLabelDisplay="auto"
            />
          </Grid>
          <Grid item xs={12} md={4}>
            <Typography gutterBottom>Medium: {typography.fontWeight.medium}</Typography>
            <Slider
              value={typography.fontWeight.medium}
              onChange={(e, value) => handleFontWeightChange('medium', value as number)}
              min={400}
              max={600}
              step={100}
              marks
              valueLabelDisplay="auto"
            />
          </Grid>
          <Grid item xs={12} md={6}>
            <Typography gutterBottom>Semibold: {typography.fontWeight.semibold}</Typography>
            <Slider
              value={typography.fontWeight.semibold}
              onChange={(e, value) => handleFontWeightChange('semibold', value as number)}
              min={500}
              max={700}
              step={100}
              marks
              valueLabelDisplay="auto"
            />
          </Grid>
          <Grid item xs={12} md={6}>
            <Typography gutterBottom>Bold: {typography.fontWeight.bold}</Typography>
            <Slider
              value={typography.fontWeight.bold}
              onChange={(e, value) => handleFontWeightChange('bold', value as number)}
              min={600}
              max={900}
              step={100}
              marks
              valueLabelDisplay="auto"
            />
          </Grid>
        </Grid>
      </Paper>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Line Height
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} md={4}>
            <Typography gutterBottom>Tight: {typography.lineHeight.tight.toFixed(2)}</Typography>
            <Slider
              value={typography.lineHeight.tight}
              onChange={(e, value) => handleLineHeightChange('tight', value as number)}
              min={1}
              max={1.5}
              step={0.05}
              marks
              valueLabelDisplay="auto"
            />
          </Grid>
          <Grid item xs={12} md={4}>
            <Typography gutterBottom>Normal: {typography.lineHeight.normal.toFixed(2)}</Typography>
            <Slider
              value={typography.lineHeight.normal}
              onChange={(e, value) => handleLineHeightChange('normal', value as number)}
              min={1.2}
              max={1.8}
              step={0.05}
              marks
              valueLabelDisplay="auto"
            />
          </Grid>
          <Grid item xs={12} md={4}>
            <Typography gutterBottom>Relaxed: {typography.lineHeight.relaxed.toFixed(2)}</Typography>
            <Slider
              value={typography.lineHeight.relaxed}
              onChange={(e, value) => handleLineHeightChange('relaxed', value as number)}
              min={1.5}
              max={2.2}
              step={0.05}
              marks
              valueLabelDisplay="auto"
            />
          </Grid>
        </Grid>
      </Paper>

      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" gutterBottom>
          Letter Spacing
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} md={4}>
            <Typography gutterBottom>Tight: {typography.letterSpacing.tight.toFixed(3)}em</Typography>
            <Slider
              value={typography.letterSpacing.tight}
              onChange={(e, value) => handleLetterSpacingChange('tight', value as number)}
              min={-0.1}
              max={0}
              step={0.01}
              marks
              valueLabelDisplay="auto"
            />
          </Grid>
          <Grid item xs={12} md={4}>
            <Typography gutterBottom>Normal: {typography.letterSpacing.normal.toFixed(3)}em</Typography>
            <Slider
              value={typography.letterSpacing.normal}
              onChange={(e, value) => handleLetterSpacingChange('normal', value as number)}
              min={-0.05}
              max={0.05}
              step={0.01}
              marks
              valueLabelDisplay="auto"
            />
          </Grid>
          <Grid item xs={12} md={4}>
            <Typography gutterBottom>Wide: {typography.letterSpacing.wide.toFixed(3)}em</Typography>
            <Slider
              value={typography.letterSpacing.wide}
              onChange={(e, value) => handleLetterSpacingChange('wide', value as number)}
              min={0}
              max={0.2}
              step={0.01}
              marks
              valueLabelDisplay="auto"
            />
          </Grid>
        </Grid>
      </Paper>
    </Box>
  );
}