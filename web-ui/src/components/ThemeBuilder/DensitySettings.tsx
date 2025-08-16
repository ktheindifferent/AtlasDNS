import React from 'react';
import {
  Box,
  Grid,
  Typography,
  RadioGroup,
  FormControlLabel,
  Radio,
  Slider,
  Paper,
  Button,
  Card,
  TextField,
  Chip,
} from '@mui/material';
import { DensityConfig, DensityLevel } from '../../theme/types';

interface DensitySettingsProps {
  density: DensityConfig;
  onChange: (level: DensityLevel) => void;
}

export default function DensitySettings({ density, onChange }: DensitySettingsProps) {
  const handleDensityChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    onChange(event.target.value as DensityLevel);
  };

  const getDensityDescription = (level: DensityLevel) => {
    switch (level) {
      case 'compact':
        return 'Minimal spacing, smaller components. Best for data-dense interfaces.';
      case 'comfortable':
        return 'Balanced spacing and sizing. Suitable for most applications.';
      case 'spacious':
        return 'Generous spacing, larger touch targets. Great for touch interfaces.';
      default:
        return '';
    }
  };

  const getDensityMetrics = (level: DensityLevel) => {
    switch (level) {
      case 'compact':
        return {
          spacing: 4,
          buttonHeight: 32,
          inputPadding: 8,
          borderRadius: 4,
        };
      case 'comfortable':
        return {
          spacing: 8,
          buttonHeight: 40,
          inputPadding: 12,
          borderRadius: 8,
        };
      case 'spacious':
        return {
          spacing: 12,
          buttonHeight: 48,
          inputPadding: 16,
          borderRadius: 12,
        };
      default:
        return {
          spacing: 8,
          buttonHeight: 40,
          inputPadding: 12,
          borderRadius: 8,
        };
    }
  };

  const metrics = getDensityMetrics(density.level);

  return (
    <Box>
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Density Level
        </Typography>
        <RadioGroup value={density.level} onChange={handleDensityChange}>
          <Grid container spacing={2}>
            {(['compact', 'comfortable', 'spacious'] as DensityLevel[]).map((level) => (
              <Grid item xs={12} key={level}>
                <Card
                  sx={{
                    p: 2,
                    border: 2,
                    borderColor: density.level === level ? 'primary.main' : 'transparent',
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                    '&:hover': {
                      borderColor: density.level === level ? 'primary.main' : 'divider',
                    },
                  }}
                  onClick={() => onChange(level)}
                >
                  <FormControlLabel
                    value={level}
                    control={<Radio />}
                    label={
                      <Box>
                        <Typography variant="subtitle1" sx={{ textTransform: 'capitalize' }}>
                          {level}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          {getDensityDescription(level)}
                        </Typography>
                      </Box>
                    }
                  />
                </Card>
              </Grid>
            ))}
          </Grid>
        </RadioGroup>
      </Paper>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Current Metrics
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={6} md={3}>
            <Typography variant="body2" color="text.secondary">
              Base Spacing
            </Typography>
            <Typography variant="h4">{metrics.spacing}px</Typography>
          </Grid>
          <Grid item xs={6} md={3}>
            <Typography variant="body2" color="text.secondary">
              Button Height
            </Typography>
            <Typography variant="h4">{metrics.buttonHeight}px</Typography>
          </Grid>
          <Grid item xs={6} md={3}>
            <Typography variant="body2" color="text.secondary">
              Input Padding
            </Typography>
            <Typography variant="h4">{metrics.inputPadding}px</Typography>
          </Grid>
          <Grid item xs={6} md={3}>
            <Typography variant="body2" color="text.secondary">
              Border Radius
            </Typography>
            <Typography variant="h4">{metrics.borderRadius}px</Typography>
          </Grid>
        </Grid>
      </Paper>

      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" gutterBottom>
          Component Preview
        </Typography>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          See how components look with current density settings
        </Typography>

        <Box sx={{ mt: 3 }}>
          <Grid container spacing={metrics.spacing / 4}>
            <Grid item xs={12}>
              <Typography variant="subtitle2" gutterBottom>
                Buttons
              </Typography>
              <Box sx={{ display: 'flex', gap: metrics.spacing / 4, flexWrap: 'wrap' }}>
                <Button
                  variant="contained"
                  sx={{
                    minHeight: metrics.buttonHeight,
                    px: metrics.inputPadding / 4,
                    borderRadius: `${metrics.borderRadius}px`,
                  }}
                >
                  Primary Button
                </Button>
                <Button
                  variant="outlined"
                  sx={{
                    minHeight: metrics.buttonHeight,
                    px: metrics.inputPadding / 4,
                    borderRadius: `${metrics.borderRadius}px`,
                  }}
                >
                  Outlined Button
                </Button>
                <Button
                  variant="text"
                  sx={{
                    minHeight: metrics.buttonHeight,
                    px: metrics.inputPadding / 4,
                  }}
                >
                  Text Button
                </Button>
              </Box>
            </Grid>

            <Grid item xs={12}>
              <Typography variant="subtitle2" gutterBottom>
                Inputs
              </Typography>
              <Box sx={{ display: 'flex', gap: metrics.spacing / 4, flexWrap: 'wrap' }}>
                <TextField
                  label="Text Field"
                  variant="outlined"
                  size={density.level === 'compact' ? 'small' : 'medium'}
                  sx={{
                    '& .MuiInputBase-root': {
                      borderRadius: `${metrics.borderRadius}px`,
                    },
                    '& .MuiInputBase-input': {
                      py: `${metrics.inputPadding}px`,
                    },
                  }}
                />
                <TextField
                  label="Filled Field"
                  variant="filled"
                  size={density.level === 'compact' ? 'small' : 'medium'}
                  sx={{
                    '& .MuiInputBase-root': {
                      borderRadius: `${metrics.borderRadius}px ${metrics.borderRadius}px 0 0`,
                    },
                    '& .MuiInputBase-input': {
                      py: `${metrics.inputPadding}px`,
                    },
                  }}
                />
              </Box>
            </Grid>

            <Grid item xs={12}>
              <Typography variant="subtitle2" gutterBottom>
                Chips
              </Typography>
              <Box sx={{ display: 'flex', gap: metrics.spacing / 8, flexWrap: 'wrap' }}>
                <Chip
                  label="Default Chip"
                  sx={{
                    height: metrics.buttonHeight * 0.8,
                    borderRadius: `${metrics.borderRadius / 2}px`,
                  }}
                />
                <Chip
                  label="Outlined Chip"
                  variant="outlined"
                  sx={{
                    height: metrics.buttonHeight * 0.8,
                    borderRadius: `${metrics.borderRadius / 2}px`,
                  }}
                />
                <Chip
                  label="Deletable"
                  onDelete={() => {}}
                  sx={{
                    height: metrics.buttonHeight * 0.8,
                    borderRadius: `${metrics.borderRadius / 2}px`,
                  }}
                />
              </Box>
            </Grid>

            <Grid item xs={12}>
              <Typography variant="subtitle2" gutterBottom>
                Cards
              </Typography>
              <Card
                sx={{
                  p: metrics.spacing / 4,
                  borderRadius: `${metrics.borderRadius * 1.5}px`,
                }}
              >
                <Typography variant="body1">Card Content</Typography>
                <Typography variant="body2" color="text.secondary">
                  This card demonstrates the current padding and border radius settings.
                </Typography>
                <Box sx={{ mt: metrics.spacing / 4 }}>
                  <Button
                    size="small"
                    sx={{
                      minHeight: metrics.buttonHeight * 0.8,
                      borderRadius: `${metrics.borderRadius}px`,
                    }}
                  >
                    Action
                  </Button>
                </Box>
              </Card>
            </Grid>
          </Grid>
        </Box>
      </Paper>
    </Box>
  );
}