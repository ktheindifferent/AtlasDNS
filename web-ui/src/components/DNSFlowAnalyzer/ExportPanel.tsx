import React, { useState } from 'react';
import {
  Box,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  Typography,
  Slider,
  FormControlLabel,
  Switch,
  CircularProgress,
  Alert,
  SelectChangeEvent,
} from '@mui/material';
import { Download, Image, Movie, Code } from '@mui/icons-material';
import * as htmlToImage from 'html-to-image';
import html2canvas from 'html2canvas';

interface ExportPanelProps {
  onExport: (format: 'png' | 'svg' | 'mp4', element: HTMLElement) => void;
}

type ExportFormat = 'png' | 'svg' | 'mp4' | 'gif' | 'json';
type Quality = 'low' | 'medium' | 'high';

interface ExportOptions {
  format: ExportFormat;
  quality: Quality;
  width: number;
  height: number;
  fps: number;
  duration: number;
  includeTimestamp: boolean;
  includeWatermark: boolean;
}

const ExportPanel: React.FC<ExportPanelProps> = ({ onExport }) => {
  const [open, setOpen] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [options, setOptions] = useState<ExportOptions>({
    format: 'png',
    quality: 'high',
    width: 1920,
    height: 1080,
    fps: 30,
    duration: 10,
    includeTimestamp: true,
    includeWatermark: false,
  });

  const handleOpen = () => {
    setOpen(true);
    setExportError(null);
  };

  const handleClose = () => {
    setOpen(false);
    setIsExporting(false);
    setExportError(null);
  };

  const handleFormatChange = (event: SelectChangeEvent) => {
    setOptions({
      ...options,
      format: event.target.value as ExportFormat,
    });
  };

  const handleQualityChange = (event: SelectChangeEvent) => {
    setOptions({
      ...options,
      quality: event.target.value as Quality,
    });
  };

  const getQualitySettings = (quality: Quality) => {
    switch (quality) {
      case 'low':
        return { pixelRatio: 1, quality: 0.6 };
      case 'medium':
        return { pixelRatio: 2, quality: 0.8 };
      case 'high':
        return { pixelRatio: 3, quality: 1.0 };
    }
  };

  const exportAsPNG = async (element: HTMLElement) => {
    try {
      const qualitySettings = getQualitySettings(options.quality);
      const dataUrl = await htmlToImage.toPng(element, {
        width: options.width,
        height: options.height,
        pixelRatio: qualitySettings.pixelRatio,
        quality: qualitySettings.quality,
      });

      const link = document.createElement('a');
      link.href = dataUrl;
      link.download = `dns-flow-analysis-${Date.now()}.png`;
      link.click();
    } catch (error) {
      throw new Error(`Failed to export PNG: ${error}`);
    }
  };

  const exportAsSVG = async (element: HTMLElement) => {
    try {
      const dataUrl = await htmlToImage.toSvg(element, {
        width: options.width,
        height: options.height,
      });

      const link = document.createElement('a');
      link.href = dataUrl;
      link.download = `dns-flow-analysis-${Date.now()}.svg`;
      link.click();
    } catch (error) {
      throw new Error(`Failed to export SVG: ${error}`);
    }
  };

  const exportAsVideo = async (element: HTMLElement) => {
    // This would require a more complex implementation with a library like FFmpeg.js
    // For now, we'll create a series of images that could be assembled into a video
    try {
      setExportError('Video export requires server-side processing. Creating image sequence instead...');
      
      const frames = options.fps * options.duration;
      const images: string[] = [];
      
      for (let i = 0; i < frames; i++) {
        // Simulate frame capture
        const dataUrl = await htmlToImage.toPng(element, {
          width: options.width,
          height: options.height,
        });
        images.push(dataUrl);
        
        // Update progress
        if (i % 10 === 0) {
          console.log(`Captured frame ${i + 1}/${frames}`);
        }
      }
      
      // In a real implementation, these frames would be sent to a server
      // or processed with FFmpeg.js to create an MP4
      console.log(`Captured ${images.length} frames for video export`);
      
      // For now, just download the first frame as a sample
      const link = document.createElement('a');
      link.href = images[0];
      link.download = `dns-flow-frame-000.png`;
      link.click();
      
    } catch (error) {
      throw new Error(`Failed to export video: ${error}`);
    }
  };

  const exportAsGIF = async (element: HTMLElement) => {
    // Similar to video export, this would require additional libraries
    setExportError('GIF export is not yet implemented. Try PNG or SVG format.');
  };

  const exportAsJSON = () => {
    // Export the data as JSON
    const exportData = {
      timestamp: new Date().toISOString(),
      options: options,
      // Add actual query data here
      data: {
        message: 'Query data would be exported here',
      },
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `dns-flow-data-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleExport = async () => {
    setIsExporting(true);
    setExportError(null);

    try {
      // Get the visualization container
      const element = document.querySelector('.dns-flow-visualization') as HTMLElement;
      if (!element) {
        throw new Error('Visualization element not found');
      }

      // Add watermark if requested
      if (options.includeWatermark) {
        const watermark = document.createElement('div');
        watermark.style.position = 'absolute';
        watermark.style.bottom = '10px';
        watermark.style.right = '10px';
        watermark.style.opacity = '0.5';
        watermark.style.fontSize = '12px';
        watermark.textContent = 'DNS Flow Analyzer';
        element.appendChild(watermark);
      }

      // Add timestamp if requested
      if (options.includeTimestamp) {
        const timestamp = document.createElement('div');
        timestamp.style.position = 'absolute';
        timestamp.style.top = '10px';
        timestamp.style.right = '10px';
        timestamp.style.fontSize = '10px';
        timestamp.textContent = new Date().toLocaleString();
        element.appendChild(timestamp);
      }

      switch (options.format) {
        case 'png':
          await exportAsPNG(element);
          break;
        case 'svg':
          await exportAsSVG(element);
          break;
        case 'mp4':
          await exportAsVideo(element);
          break;
        case 'gif':
          await exportAsGIF(element);
          break;
        case 'json':
          exportAsJSON();
          break;
      }

      handleClose();
    } catch (error: any) {
      setExportError(error.message || 'Export failed');
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <>
      <Button
        variant="outlined"
        startIcon={<Download />}
        onClick={handleOpen}
      >
        Export
      </Button>

      <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
        <DialogTitle>Export Visualization</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2 }}>
            {exportError && (
              <Alert severity="error" sx={{ mb: 2 }}>
                {exportError}
              </Alert>
            )}

            {/* Format Selection */}
            <FormControl fullWidth sx={{ mb: 3 }}>
              <InputLabel>Export Format</InputLabel>
              <Select
                value={options.format}
                onChange={handleFormatChange}
                label="Export Format"
              >
                <MenuItem value="png">
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Image fontSize="small" />
                    PNG Image
                  </Box>
                </MenuItem>
                <MenuItem value="svg">
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Code fontSize="small" />
                    SVG Vector
                  </Box>
                </MenuItem>
                <MenuItem value="mp4" disabled>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Movie fontSize="small" />
                    MP4 Video (Coming Soon)
                  </Box>
                </MenuItem>
                <MenuItem value="gif" disabled>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Image fontSize="small" />
                    GIF Animation (Coming Soon)
                  </Box>
                </MenuItem>
                <MenuItem value="json">
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Code fontSize="small" />
                    JSON Data
                  </Box>
                </MenuItem>
              </Select>
            </FormControl>

            {/* Quality Selection */}
            {['png', 'mp4', 'gif'].includes(options.format) && (
              <FormControl fullWidth sx={{ mb: 3 }}>
                <InputLabel>Quality</InputLabel>
                <Select
                  value={options.quality}
                  onChange={handleQualityChange}
                  label="Quality"
                >
                  <MenuItem value="low">Low (Fast)</MenuItem>
                  <MenuItem value="medium">Medium</MenuItem>
                  <MenuItem value="high">High (Slow)</MenuItem>
                </Select>
              </FormControl>
            )}

            {/* Resolution */}
            {['png', 'svg', 'mp4', 'gif'].includes(options.format) && (
              <Box sx={{ mb: 3 }}>
                <Typography gutterBottom>Resolution</Typography>
                <Box sx={{ display: 'flex', gap: 2 }}>
                  <TextField
                    label="Width"
                    type="number"
                    value={options.width}
                    onChange={(e) => setOptions({ ...options, width: parseInt(e.target.value) })}
                    sx={{ flex: 1 }}
                  />
                  <TextField
                    label="Height"
                    type="number"
                    value={options.height}
                    onChange={(e) => setOptions({ ...options, height: parseInt(e.target.value) })}
                    sx={{ flex: 1 }}
                  />
                </Box>
              </Box>
            )}

            {/* Video/GIF Options */}
            {['mp4', 'gif'].includes(options.format) && (
              <>
                <Box sx={{ mb: 3 }}>
                  <Typography gutterBottom>
                    Frame Rate: {options.fps} FPS
                  </Typography>
                  <Slider
                    value={options.fps}
                    onChange={(e, value) => setOptions({ ...options, fps: value as number })}
                    min={15}
                    max={60}
                    step={15}
                    marks
                    valueLabelDisplay="auto"
                  />
                </Box>

                <Box sx={{ mb: 3 }}>
                  <Typography gutterBottom>
                    Duration: {options.duration} seconds
                  </Typography>
                  <Slider
                    value={options.duration}
                    onChange={(e, value) => setOptions({ ...options, duration: value as number })}
                    min={5}
                    max={30}
                    step={5}
                    marks
                    valueLabelDisplay="auto"
                  />
                </Box>
              </>
            )}

            {/* Additional Options */}
            <Box sx={{ mb: 2 }}>
              <FormControlLabel
                control={
                  <Switch
                    checked={options.includeTimestamp}
                    onChange={(e) => setOptions({ ...options, includeTimestamp: e.target.checked })}
                  />
                }
                label="Include Timestamp"
              />
            </Box>

            <Box>
              <FormControlLabel
                control={
                  <Switch
                    checked={options.includeWatermark}
                    onChange={(e) => setOptions({ ...options, includeWatermark: e.target.checked })}
                  />
                }
                label="Include Watermark"
              />
            </Box>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleClose} disabled={isExporting}>
            Cancel
          </Button>
          <Button
            onClick={handleExport}
            variant="contained"
            disabled={isExporting}
            startIcon={isExporting ? <CircularProgress size={20} /> : <Download />}
          >
            {isExporting ? 'Exporting...' : 'Export'}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default ExportPanel;