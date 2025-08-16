import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Box,
  Typography,
  Alert,
  LinearProgress,
  Tab,
  Tabs,
} from '@mui/material';
import { CloudUpload, ContentPaste } from '@mui/icons-material';
import { useDispatch } from 'react-redux';
import { AppDispatch } from '../../store';
import { zoneApi } from '../../services/api';
import { fetchZones } from '../../store/slices/zonesSlice';
import { useSnackbar } from 'notistack';

interface ZoneImportDialogProps {
  open: boolean;
  onClose: () => void;
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index }) => {
  return (
    <div hidden={value !== index}>
      {value === index && <Box sx={{ pt: 3 }}>{children}</Box>}
    </div>
  );
};

const ZoneImportDialog: React.FC<ZoneImportDialogProps> = ({ open, onClose }) => {
  const dispatch = useDispatch<AppDispatch>();
  const { enqueueSnackbar } = useSnackbar();
  const [tabValue, setTabValue] = useState(0);
  const [zoneContent, setZoneContent] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleTabChange = (_: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
    setError(null);
  };

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = event.target.files?.[0];
    if (selectedFile) {
      if (selectedFile.size > 10 * 1024 * 1024) {
        setError('File size must be less than 10MB');
        return;
      }
      setFile(selectedFile);
      setError(null);
      
      // Read file content for preview
      const reader = new FileReader();
      reader.onload = (e) => {
        setZoneContent(e.target?.result as string);
      };
      reader.readAsText(selectedFile);
    }
  };

  const handleImport = async () => {
    setLoading(true);
    setError(null);

    try {
      let importData: any;
      
      if (tabValue === 0) {
        // Text import
        if (!zoneContent.trim()) {
          setError('Please enter zone file content');
          setLoading(false);
          return;
        }
        importData = { content: zoneContent, format: 'bind' };
      } else {
        // File import
        if (!file) {
          setError('Please select a file');
          setLoading(false);
          return;
        }
        const formData = new FormData();
        formData.append('file', file);
        importData = formData;
      }

      await zoneApi.import(importData);
      enqueueSnackbar('Zone imported successfully', { variant: 'success' });
      dispatch(fetchZones());
      handleClose();
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to import zone');
      enqueueSnackbar('Failed to import zone', { variant: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    setZoneContent('');
    setFile(null);
    setError(null);
    setTabValue(0);
    onClose();
  };

  const sampleZoneFile = `; Zone file for example.com
$ORIGIN example.com.
$TTL 86400
@   IN  SOA ns1.example.com. admin.example.com. (
            2024010101  ; Serial
            10800       ; Refresh
            3600        ; Retry
            604800      ; Expire
            86400       ; Minimum TTL
)
@   IN  NS  ns1.example.com.
@   IN  NS  ns2.example.com.
@   IN  A   192.0.2.1
www IN  A   192.0.2.2
mail IN  A   192.0.2.3
@   IN  MX  10 mail.example.com.`;

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="md" fullWidth>
      <DialogTitle>Import Zone</DialogTitle>
      <DialogContent>
        <Tabs value={tabValue} onChange={handleTabChange}>
          <Tab icon={<ContentPaste />} label="Paste Zone File" />
          <Tab icon={<CloudUpload />} label="Upload File" />
        </Tabs>

        {error && (
          <Alert severity="error" sx={{ mt: 2 }}>
            {error}
          </Alert>
        )}

        <TabPanel value={tabValue} index={0}>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            Paste your BIND zone file content below:
          </Typography>
          <TextField
            multiline
            rows={15}
            fullWidth
            variant="outlined"
            placeholder={sampleZoneFile}
            value={zoneContent}
            onChange={(e) => setZoneContent(e.target.value)}
            sx={{ fontFamily: 'monospace' }}
          />
          <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
            Supported formats: BIND zone file format
          </Typography>
        </TabPanel>

        <TabPanel value={tabValue} index={1}>
          <Box
            sx={{
              border: '2px dashed',
              borderColor: 'divider',
              borderRadius: 2,
              p: 4,
              textAlign: 'center',
              bgcolor: 'background.default',
            }}
          >
            <CloudUpload sx={{ fontSize: 48, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" gutterBottom>
              {file ? file.name : 'Select Zone File'}
            </Typography>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              Drag and drop a zone file here or click to browse
            </Typography>
            <Button
              variant="contained"
              component="label"
              sx={{ mt: 2 }}
            >
              Choose File
              <input
                type="file"
                hidden
                accept=".zone,.txt,.db"
                onChange={handleFileSelect}
              />
            </Button>
            {file && (
              <Box sx={{ mt: 2 }}>
                <Typography variant="body2">
                  File size: {(file.size / 1024).toFixed(2)} KB
                </Typography>
              </Box>
            )}
          </Box>
        </TabPanel>

        {loading && <LinearProgress sx={{ mt: 2 }} />}
      </DialogContent>
      <DialogActions>
        <Button onClick={handleClose} disabled={loading}>
          Cancel
        </Button>
        <Button
          onClick={handleImport}
          variant="contained"
          disabled={loading || (!zoneContent && !file)}
        >
          Import
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ZoneImportDialog;