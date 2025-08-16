import React, { useState, useCallback } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Box,
  Typography,
  Button,
  TextField,
  Alert,
  AlertTitle,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  IconButton,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  LinearProgress,
  useTheme,
  alpha,
} from '@mui/material';
import {
  Upload,
  FileUpload,
  CheckCircle,
  Error as ErrorIcon,
  Warning,
  Delete,
  Edit,
  Download,
  ContentPaste,
  TableChart,
  Code,
} from '@mui/icons-material';
import { useDropzone } from 'react-dropzone';
import Papa from 'papaparse';

interface DNSRecord {
  type: string;
  name: string;
  value: string;
  ttl: number;
  priority?: number;
  weight?: number;
  port?: number;
  isValid?: boolean;
  error?: string;
}

interface BatchImportProps {
  open: boolean;
  onClose: () => void;
  onImport: (records: DNSRecord[]) => void;
}

const sampleCSV = `type,name,value,ttl,priority
A,@,192.0.2.1,3600,
A,www,192.0.2.1,3600,
MX,@,mail.example.com,3600,10
TXT,@,v=spf1 include:_spf.google.com ~all,3600,
CNAME,blog,blog.example.com,3600,`;

const sampleJSON = `[
  {
    "type": "A",
    "name": "@",
    "value": "192.0.2.1",
    "ttl": 3600
  },
  {
    "type": "A",
    "name": "www",
    "value": "192.0.2.1",
    "ttl": 3600
  },
  {
    "type": "MX",
    "name": "@",
    "value": "mail.example.com",
    "ttl": 3600,
    "priority": 10
  }
]`;

const sampleBIND = `@       IN  A       192.0.2.1
www     IN  A       192.0.2.1
@       IN  MX  10  mail.example.com
@       IN  TXT     "v=spf1 include:_spf.google.com ~all"
blog    IN  CNAME   blog.example.com.`;

export const BatchImport: React.FC<BatchImportProps> = ({
  open,
  onClose,
  onImport,
}) => {
  const theme = useTheme();
  const [activeStep, setActiveStep] = useState(0);
  const [importFormat, setImportFormat] = useState<'csv' | 'json' | 'bind'>('csv');
  const [importText, setImportText] = useState('');
  const [parsedRecords, setParsedRecords] = useState<DNSRecord[]>([]);
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [parsing, setParsing] = useState(false);

  const onDrop = useCallback((acceptedFiles: File[]) => {
    const file = acceptedFiles[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        const text = e.target?.result as string;
        setImportText(text);
        parseImportData(text);
      };
      reader.readAsText(file);
    }
  }, [importFormat]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'text/csv': ['.csv'],
      'application/json': ['.json'],
      'text/plain': ['.txt', '.zone'],
    },
    maxFiles: 1,
  });

  const parseImportData = (data: string) => {
    setParsing(true);
    setValidationErrors([]);
    
    try {
      let records: DNSRecord[] = [];
      
      switch (importFormat) {
        case 'csv':
          Papa.parse(data, {
            header: true,
            complete: (results) => {
              records = results.data.map((row: any) => ({
                type: row.type?.toUpperCase(),
                name: row.name || '@',
                value: row.value,
                ttl: parseInt(row.ttl) || 3600,
                priority: row.priority ? parseInt(row.priority) : undefined,
                weight: row.weight ? parseInt(row.weight) : undefined,
                port: row.port ? parseInt(row.port) : undefined,
              }));
              validateAndSetRecords(records);
            },
            error: (error) => {
              setValidationErrors([`CSV parsing error: ${error.message}`]);
            },
          });
          break;
          
        case 'json':
          try {
            const jsonData = JSON.parse(data);
            if (Array.isArray(jsonData)) {
              records = jsonData.map(record => ({
                type: record.type?.toUpperCase(),
                name: record.name || '@',
                value: record.value,
                ttl: record.ttl || 3600,
                priority: record.priority,
                weight: record.weight,
                port: record.port,
              }));
              validateAndSetRecords(records);
            } else {
              setValidationErrors(['JSON data must be an array of records']);
            }
          } catch (error: any) {
            setValidationErrors([`JSON parsing error: ${error.message}`]);
          }
          break;
          
        case 'bind':
          records = parseBINDFormat(data);
          validateAndSetRecords(records);
          break;
      }
    } finally {
      setParsing(false);
    }
  };

  const parseBINDFormat = (data: string): DNSRecord[] => {
    const records: DNSRecord[] = [];
    const lines = data.split('\n').filter(line => line.trim() && !line.startsWith(';'));
    
    lines.forEach(line => {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 4) {
        const [name, , type, ...rest] = parts;
        
        let value = rest.join(' ');
        let priority: number | undefined;
        
        if (type === 'MX' && rest.length >= 2) {
          priority = parseInt(rest[0]);
          value = rest.slice(1).join(' ');
        }
        
        // Remove quotes from TXT records
        if (type === 'TXT') {
          value = value.replace(/^"|"$/g, '');
        }
        
        // Remove trailing dot from domains
        value = value.replace(/\.$/, '');
        
        records.push({
          type: type.toUpperCase(),
          name: name === '@' ? '@' : name,
          value,
          ttl: 3600,
          priority,
        });
      }
    });
    
    return records;
  };

  const validateAndSetRecords = (records: DNSRecord[]) => {
    const errors: string[] = [];
    const validatedRecords = records.map((record, index) => {
      const validated = { ...record, isValid: true };
      
      // Basic validation
      if (!record.type) {
        errors.push(`Row ${index + 1}: Missing record type`);
        validated.isValid = false;
        validated.error = 'Missing type';
      }
      
      if (!record.value) {
        errors.push(`Row ${index + 1}: Missing record value`);
        validated.isValid = false;
        validated.error = 'Missing value';
      }
      
      // Type-specific validation
      if (record.type === 'A') {
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipv4Regex.test(record.value)) {
          errors.push(`Row ${index + 1}: Invalid IPv4 address`);
          validated.isValid = false;
          validated.error = 'Invalid IPv4';
        }
      }
      
      if (record.type === 'AAAA') {
        const ipv6Regex = /^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$/;
        if (!ipv6Regex.test(record.value)) {
          errors.push(`Row ${index + 1}: Invalid IPv6 address`);
          validated.isValid = false;
          validated.error = 'Invalid IPv6';
        }
      }
      
      if (record.type === 'MX' && !record.priority) {
        errors.push(`Row ${index + 1}: MX record missing priority`);
        validated.isValid = false;
        validated.error = 'Missing priority';
      }
      
      return validated;
    });
    
    setValidationErrors(errors);
    setParsedRecords(validatedRecords);
    
    if (errors.length === 0 && records.length > 0) {
      setActiveStep(2);
    }
  };

  const handleImport = () => {
    const validRecords = parsedRecords.filter(record => record.isValid);
    onImport(validRecords);
    handleClose();
  };

  const handleClose = () => {
    setActiveStep(0);
    setImportText('');
    setParsedRecords([]);
    setValidationErrors([]);
    onClose();
  };

  const loadSample = () => {
    let sample = '';
    switch (importFormat) {
      case 'csv':
        sample = sampleCSV;
        break;
      case 'json':
        sample = sampleJSON;
        break;
      case 'bind':
        sample = sampleBIND;
        break;
    }
    setImportText(sample);
    parseImportData(sample);
  };

  const steps = [
    'Select Format',
    'Import Data',
    'Review & Validate',
  ];

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="lg" fullWidth>
      <DialogTitle>
        <Box display="flex" alignItems="center" gap={1}>
          <Upload color="primary" />
          <Typography variant="h6">Batch Import DNS Records</Typography>
        </Box>
      </DialogTitle>
      
      <DialogContent>
        <Stepper activeStep={activeStep} orientation="vertical">
          {/* Step 1: Select Format */}
          <Step>
            <StepLabel>Select Import Format</StepLabel>
            <StepContent>
              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel>Import Format</InputLabel>
                <Select
                  value={importFormat}
                  onChange={(e) => setImportFormat(e.target.value as any)}
                  label="Import Format"
                >
                  <MenuItem value="csv">
                    <Box display="flex" alignItems="center" gap={1}>
                      <TableChart />
                      CSV (Comma-Separated Values)
                    </Box>
                  </MenuItem>
                  <MenuItem value="json">
                    <Box display="flex" alignItems="center" gap={1}>
                      <Code />
                      JSON
                    </Box>
                  </MenuItem>
                  <MenuItem value="bind">
                    <Box display="flex" alignItems="center" gap={1}>
                      <Code />
                      BIND Zone File
                    </Box>
                  </MenuItem>
                </Select>
              </FormControl>
              
              <Alert severity="info">
                <AlertTitle>Format: {importFormat.toUpperCase()}</AlertTitle>
                {importFormat === 'csv' && 'CSV files should have headers: type, name, value, ttl, priority (optional)'}
                {importFormat === 'json' && 'JSON should be an array of record objects'}
                {importFormat === 'bind' && 'Standard BIND zone file format'}
              </Alert>
              
              <Box mt={2}>
                <Button
                  variant="contained"
                  onClick={() => setActiveStep(1)}
                >
                  Next
                </Button>
              </Box>
            </StepContent>
          </Step>

          {/* Step 2: Import Data */}
          <Step>
            <StepLabel>Import Data</StepLabel>
            <StepContent>
              <Box
                {...getRootProps()}
                sx={{
                  border: `2px dashed ${isDragActive ? theme.palette.primary.main : theme.palette.divider}`,
                  borderRadius: 2,
                  p: 3,
                  textAlign: 'center',
                  backgroundColor: isDragActive ? alpha(theme.palette.primary.main, 0.05) : 'transparent',
                  cursor: 'pointer',
                  mb: 2,
                }}
              >
                <input {...getInputProps()} />
                <FileUpload sx={{ fontSize: 48, color: theme.palette.action.disabled, mb: 1 }} />
                <Typography variant="body1" gutterBottom>
                  {isDragActive ? 'Drop the file here' : 'Drag & drop a file here, or click to select'}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Supported formats: {importFormat.toUpperCase()}
                </Typography>
              </Box>
              
              <Typography variant="body2" gutterBottom>
                Or paste your data directly:
              </Typography>
              
              <TextField
                fullWidth
                multiline
                rows={10}
                value={importText}
                onChange={(e) => setImportText(e.target.value)}
                placeholder={`Paste your ${importFormat.toUpperCase()} data here...`}
                sx={{ mb: 2, fontFamily: 'monospace' }}
              />
              
              <Box display="flex" gap={1}>
                <Button
                  variant="outlined"
                  startIcon={<ContentPaste />}
                  onClick={loadSample}
                >
                  Load Sample
                </Button>
                <Button
                  variant="contained"
                  onClick={() => parseImportData(importText)}
                  disabled={!importText || parsing}
                >
                  {parsing ? 'Parsing...' : 'Parse Data'}
                </Button>
              </Box>
              
              {validationErrors.length > 0 && (
                <Alert severity="error" sx={{ mt: 2 }}>
                  <AlertTitle>Validation Errors</AlertTitle>
                  <ul style={{ margin: 0, paddingLeft: 20 }}>
                    {validationErrors.map((error, idx) => (
                      <li key={idx}>{error}</li>
                    ))}
                  </ul>
                </Alert>
              )}
            </StepContent>
          </Step>

          {/* Step 3: Review & Validate */}
          <Step>
            <StepLabel>Review & Validate</StepLabel>
            <StepContent>
              <Alert severity="success" sx={{ mb: 2 }}>
                <AlertTitle>Validation Complete</AlertTitle>
                {parsedRecords.filter(r => r.isValid).length} of {parsedRecords.length} records are valid and ready to import.
              </Alert>
              
              <TableContainer component={Paper} sx={{ maxHeight: 400 }}>
                <Table stickyHeader size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Status</TableCell>
                      <TableCell>Type</TableCell>
                      <TableCell>Name</TableCell>
                      <TableCell>Value</TableCell>
                      <TableCell>TTL</TableCell>
                      <TableCell>Priority</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {parsedRecords.map((record, index) => (
                      <TableRow 
                        key={index}
                        sx={{
                          backgroundColor: record.isValid ? 'transparent' : alpha(theme.palette.error.main, 0.05),
                        }}
                      >
                        <TableCell>
                          {record.isValid ? (
                            <CheckCircle color="success" fontSize="small" />
                          ) : (
                            <ErrorIcon color="error" fontSize="small" />
                          )}
                        </TableCell>
                        <TableCell>
                          <Chip label={record.type} size="small" />
                        </TableCell>
                        <TableCell>{record.name}</TableCell>
                        <TableCell>{record.value}</TableCell>
                        <TableCell>{record.ttl}</TableCell>
                        <TableCell>{record.priority || '-'}</TableCell>
                        <TableCell>
                          {!record.isValid && (
                            <Chip 
                              label={record.error} 
                              size="small" 
                              color="error" 
                              variant="outlined"
                            />
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </StepContent>
          </Step>
        </Stepper>
      </DialogContent>
      
      <DialogActions>
        <Button onClick={handleClose}>Cancel</Button>
        {activeStep === 2 && (
          <Button
            variant="contained"
            startIcon={<CheckCircle />}
            onClick={handleImport}
            disabled={parsedRecords.filter(r => r.isValid).length === 0}
          >
            Import {parsedRecords.filter(r => r.isValid).length} Records
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
};