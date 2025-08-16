import React, { useState } from 'react';
import { Box, Paper, Typography, Button, Grid, FormControl, InputLabel, Select, MenuItem, TextField, Card, CardContent } from '@mui/material';
import { DocumentArrowDownIcon, ShareIcon, ClipboardDocumentIcon } from '@heroicons/react/24/outline';
import { useSnackbar } from 'notistack';

const ExportManager: React.FC = () => {
  const { enqueueSnackbar } = useSnackbar();
  const [exportFormat, setExportFormat] = useState('json');
  const [shareUrl, setShareUrl] = useState('');

  const handleExport = () => {
    enqueueSnackbar(`Exporting results as ${exportFormat.toUpperCase()}`, { variant: 'success' });
  };

  const generateShareLink = () => {
    const url = `https://dns-playground.example.com/share/${Date.now()}`;
    setShareUrl(url);
    enqueueSnackbar('Share link generated', { variant: 'success' });
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(shareUrl);
    enqueueSnackbar('Link copied to clipboard', { variant: 'success' });
  };

  return (
    <Box>
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Export Test Results
            </Typography>
            <FormControl fullWidth sx={{ mt: 2 }}>
              <InputLabel>Export Format</InputLabel>
              <Select
                value={exportFormat}
                onChange={(e) => setExportFormat(e.target.value)}
                label="Export Format"
              >
                <MenuItem value="json">JSON</MenuItem>
                <MenuItem value="csv">CSV</MenuItem>
                <MenuItem value="pdf">PDF Report</MenuItem>
                <MenuItem value="html">HTML Report</MenuItem>
              </Select>
            </FormControl>
            <Button
              fullWidth
              variant="contained"
              startIcon={<DocumentArrowDownIcon style={{ width: 20, height: 20 }} />}
              onClick={handleExport}
              sx={{ mt: 2 }}
            >
              Export Results
            </Button>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Share Test Cases
            </Typography>
            <Button
              fullWidth
              variant="outlined"
              startIcon={<ShareIcon style={{ width: 20, height: 20 }} />}
              onClick={generateShareLink}
              sx={{ mt: 2 }}
            >
              Generate Share Link
            </Button>
            {shareUrl && (
              <Card sx={{ mt: 2 }}>
                <CardContent>
                  <TextField
                    fullWidth
                    value={shareUrl}
                    InputProps={{
                      readOnly: true,
                      endAdornment: (
                        <Button
                          startIcon={<ClipboardDocumentIcon style={{ width: 16, height: 16 }} />}
                          onClick={copyToClipboard}
                          size="small"
                        >
                          Copy
                        </Button>
                      ),
                    }}
                  />
                </CardContent>
              </Card>
            )}
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default ExportManager;