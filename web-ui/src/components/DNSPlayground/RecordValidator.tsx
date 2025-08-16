import React, { useState, useCallback, useEffect } from 'react';
import {
  Box,
  Paper,
  TextField,
  Button,
  Typography,
  Grid,
  Card,
  CardContent,
  Chip,
  Alert,
  AlertTitle,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  IconButton,
  Tooltip,
  LinearProgress,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from '@mui/material';
import {
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon,
  InformationCircleIcon,
  DocumentTextIcon,
  ShieldCheckIcon,
  ClockIcon,
  ChevronDownIcon,
  ArrowPathIcon,
  LightBulbIcon,
} from '@heroicons/react/24/outline';
import { useSnackbar } from 'notistack';
import { dnsPlaygroundApi } from '../../services/dnsPlaygroundApi';

interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  warnings: ValidationWarning[];
  suggestions: string[];
  recordType: string;
  recordValue: string;
  timestamp: Date;
}

interface ValidationError {
  field: string;
  message: string;
  severity: 'critical' | 'error';
  rule: string;
}

interface ValidationWarning {
  field: string;
  message: string;
  suggestion?: string;
}

interface RecordTemplate {
  type: string;
  example: string;
  fields: RecordField[];
  description: string;
}

interface RecordField {
  name: string;
  type: string;
  required: boolean;
  validation: string;
  description: string;
}

const RECORD_TEMPLATES: RecordTemplate[] = [
  {
    type: 'A',
    example: 'example.com. 300 IN A 192.168.1.1',
    fields: [
      { name: 'hostname', type: 'string', required: true, validation: 'FQDN', description: 'Fully qualified domain name' },
      { name: 'ttl', type: 'number', required: false, validation: '0-2147483647', description: 'Time to live in seconds' },
      { name: 'address', type: 'string', required: true, validation: 'IPv4', description: 'IPv4 address' },
    ],
    description: 'Maps a domain name to an IPv4 address',
  },
  {
    type: 'AAAA',
    example: 'example.com. 300 IN AAAA 2001:db8::1',
    fields: [
      { name: 'hostname', type: 'string', required: true, validation: 'FQDN', description: 'Fully qualified domain name' },
      { name: 'ttl', type: 'number', required: false, validation: '0-2147483647', description: 'Time to live in seconds' },
      { name: 'address', type: 'string', required: true, validation: 'IPv6', description: 'IPv6 address' },
    ],
    description: 'Maps a domain name to an IPv6 address',
  },
  {
    type: 'MX',
    example: 'example.com. 300 IN MX 10 mail.example.com.',
    fields: [
      { name: 'hostname', type: 'string', required: true, validation: 'FQDN', description: 'Domain name' },
      { name: 'ttl', type: 'number', required: false, validation: '0-2147483647', description: 'Time to live' },
      { name: 'priority', type: 'number', required: true, validation: '0-65535', description: 'Mail server priority' },
      { name: 'exchange', type: 'string', required: true, validation: 'FQDN', description: 'Mail server hostname' },
    ],
    description: 'Mail exchange record for email routing',
  },
  {
    type: 'TXT',
    example: 'example.com. 300 IN TXT "v=spf1 include:_spf.example.com ~all"',
    fields: [
      { name: 'hostname', type: 'string', required: true, validation: 'FQDN', description: 'Domain name' },
      { name: 'ttl', type: 'number', required: false, validation: '0-2147483647', description: 'Time to live' },
      { name: 'text', type: 'string', required: true, validation: 'max 255 chars per string', description: 'Text content' },
    ],
    description: 'Text record for various purposes (SPF, DKIM, etc.)',
  },
  {
    type: 'CNAME',
    example: 'www.example.com. 300 IN CNAME example.com.',
    fields: [
      { name: 'alias', type: 'string', required: true, validation: 'FQDN', description: 'Alias domain name' },
      { name: 'ttl', type: 'number', required: false, validation: '0-2147483647', description: 'Time to live' },
      { name: 'canonical', type: 'string', required: true, validation: 'FQDN', description: 'Canonical domain name' },
    ],
    description: 'Canonical name record (alias)',
  },
  {
    type: 'SRV',
    example: '_service._tcp.example.com. 300 IN SRV 10 60 5060 server.example.com.',
    fields: [
      { name: 'service', type: 'string', required: true, validation: '_service._protocol.name', description: 'Service name' },
      { name: 'ttl', type: 'number', required: false, validation: '0-2147483647', description: 'Time to live' },
      { name: 'priority', type: 'number', required: true, validation: '0-65535', description: 'Priority' },
      { name: 'weight', type: 'number', required: true, validation: '0-65535', description: 'Weight for load balancing' },
      { name: 'port', type: 'number', required: true, validation: '0-65535', description: 'Port number' },
      { name: 'target', type: 'string', required: true, validation: 'FQDN', description: 'Target hostname' },
    ],
    description: 'Service locator record',
  },
  {
    type: 'CAA',
    example: 'example.com. 300 IN CAA 0 issue "letsencrypt.org"',
    fields: [
      { name: 'hostname', type: 'string', required: true, validation: 'FQDN', description: 'Domain name' },
      { name: 'ttl', type: 'number', required: false, validation: '0-2147483647', description: 'Time to live' },
      { name: 'flags', type: 'number', required: true, validation: '0-255', description: 'CAA flags' },
      { name: 'tag', type: 'string', required: true, validation: 'issue|issuewild|iodef', description: 'CAA tag' },
      { name: 'value', type: 'string', required: true, validation: 'domain or email', description: 'Tag value' },
    ],
    description: 'Certification Authority Authorization',
  },
];

const RecordValidator: React.FC = () => {
  const { enqueueSnackbar } = useSnackbar();
  const [recordType, setRecordType] = useState('A');
  const [recordValue, setRecordValue] = useState('');
  const [validating, setValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<ValidationResult | null>(null);
  const [liveValidation, setLiveValidation] = useState(true);
  const [selectedTemplate, setSelectedTemplate] = useState<RecordTemplate | null>(null);

  useEffect(() => {
    const template = RECORD_TEMPLATES.find(t => t.type === recordType);
    setSelectedTemplate(template || null);
    if (template) {
      setRecordValue(template.example);
    }
  }, [recordType]);

  useEffect(() => {
    if (liveValidation && recordValue.trim()) {
      const timer = setTimeout(() => {
        validateRecord(true);
      }, 500);
      return () => clearTimeout(timer);
    }
  }, [recordValue, recordType, liveValidation]);

  const validateRecord = useCallback(async (silent = false) => {
    if (!recordValue.trim()) {
      if (!silent) {
        enqueueSnackbar('Please enter a DNS record', { variant: 'warning' });
      }
      return;
    }

    setValidating(true);

    try {
      const response = await dnsPlaygroundApi.validateRecord({
        type: recordType,
        value: recordValue.trim(),
      });

      const result: ValidationResult = {
        valid: response.data.valid,
        errors: response.data.errors || [],
        warnings: response.data.warnings || [],
        suggestions: response.data.suggestions || [],
        recordType,
        recordValue: recordValue.trim(),
        timestamp: new Date(),
      };

      setValidationResult(result);

      if (!silent) {
        if (result.valid) {
          enqueueSnackbar('Record is valid!', { variant: 'success' });
        } else {
          enqueueSnackbar(`Found ${result.errors.length} error(s)`, { variant: 'error' });
        }
      }
    } catch (error: any) {
      if (!silent) {
        enqueueSnackbar(error.message || 'Validation failed', { variant: 'error' });
      }
    } finally {
      setValidating(false);
    }
  }, [recordType, recordValue, enqueueSnackbar]);

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
      case 'error':
        return <XCircleIcon style={{ width: 20, height: 20, color: '#f44336' }} />;
      case 'warning':
        return <ExclamationTriangleIcon style={{ width: 20, height: 20, color: '#ff9800' }} />;
      case 'info':
        return <InformationCircleIcon style={{ width: 20, height: 20, color: '#2196f3' }} />;
      case 'success':
        return <CheckCircleIcon style={{ width: 20, height: 20, color: '#4caf50' }} />;
      default:
        return <InformationCircleIcon style={{ width: 20, height: 20 }} />;
    }
  };

  const applyQuickFix = (suggestion: string) => {
    setRecordValue(suggestion);
    enqueueSnackbar('Quick fix applied', { variant: 'info' });
  };

  return (
    <Box>
      <Grid container spacing={3}>
        <Grid item xs={12} md={8}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              DNS Record Validator
            </Typography>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              Validate DNS records with real-time syntax and semantic checking
            </Typography>

            <Grid container spacing={2} sx={{ mt: 2 }}>
              <Grid item xs={12} md={4}>
                <FormControl fullWidth>
                  <InputLabel>Record Type</InputLabel>
                  <Select
                    value={recordType}
                    onChange={(e) => setRecordType(e.target.value)}
                    label="Record Type"
                  >
                    {RECORD_TEMPLATES.map(template => (
                      <MenuItem key={template.type} value={template.type}>
                        {template.type}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={8}>
                <Box sx={{ display: 'flex', gap: 1 }}>
                  <Button
                    variant="contained"
                    onClick={() => validateRecord(false)}
                    disabled={validating}
                  >
                    Validate
                  </Button>
                  <Button
                    variant="outlined"
                    startIcon={<ArrowPathIcon style={{ width: 20, height: 20 }} />}
                    onClick={() => {
                      setRecordValue('');
                      setValidationResult(null);
                    }}
                  >
                    Clear
                  </Button>
                  <Tooltip title="Live validation">
                    <IconButton
                      color={liveValidation ? 'primary' : 'default'}
                      onClick={() => setLiveValidation(!liveValidation)}
                    >
                      <ClockIcon style={{ width: 20, height: 20 }} />
                    </IconButton>
                  </Tooltip>
                </Box>
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  multiline
                  rows={3}
                  label="DNS Record"
                  value={recordValue}
                  onChange={(e) => setRecordValue(e.target.value)}
                  placeholder={selectedTemplate?.example || 'Enter DNS record...'}
                  helperText={selectedTemplate?.description}
                />
              </Grid>
            </Grid>

            {validating && <LinearProgress sx={{ mt: 2 }} />}

            {validationResult && (
              <Box sx={{ mt: 3 }}>
                <Alert
                  severity={validationResult.valid ? 'success' : 'error'}
                  icon={validationResult.valid ? 
                    <CheckCircleIcon style={{ width: 20, height: 20 }} /> : 
                    <XCircleIcon style={{ width: 20, height: 20 }} />
                  }
                >
                  <AlertTitle>
                    {validationResult.valid ? 'Valid Record' : 'Invalid Record'}
                  </AlertTitle>
                  {validationResult.valid ? 
                    'This DNS record is syntactically and semantically correct.' :
                    `Found ${validationResult.errors.length} error(s) and ${validationResult.warnings.length} warning(s).`
                  }
                </Alert>

                {validationResult.errors.length > 0 && (
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="subtitle2" gutterBottom>
                      Errors
                    </Typography>
                    <List>
                      {validationResult.errors.map((error, idx) => (
                        <ListItem key={idx}>
                          <ListItemIcon>
                            {getSeverityIcon(error.severity)}
                          </ListItemIcon>
                          <ListItemText
                            primary={error.message}
                            secondary={`Field: ${error.field} | Rule: ${error.rule}`}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </Box>
                )}

                {validationResult.warnings.length > 0 && (
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="subtitle2" gutterBottom>
                      Warnings
                    </Typography>
                    <List>
                      {validationResult.warnings.map((warning, idx) => (
                        <ListItem key={idx}>
                          <ListItemIcon>
                            <ExclamationTriangleIcon style={{ width: 20, height: 20, color: '#ff9800' }} />
                          </ListItemIcon>
                          <ListItemText
                            primary={warning.message}
                            secondary={warning.suggestion}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </Box>
                )}

                {validationResult.suggestions.length > 0 && (
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="subtitle2" gutterBottom>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <LightBulbIcon style={{ width: 20, height: 20 }} />
                        Suggestions
                      </Box>
                    </Typography>
                    <List>
                      {validationResult.suggestions.map((suggestion, idx) => (
                        <ListItem key={idx}>
                          <ListItemText primary={suggestion} />
                          <Button
                            size="small"
                            onClick={() => applyQuickFix(suggestion)}
                          >
                            Apply
                          </Button>
                        </ListItem>
                      ))}
                    </List>
                  </Box>
                )}
              </Box>
            )}
          </Paper>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Record Format Guide
              </Typography>
              
              {selectedTemplate && (
                <Box>
                  <Alert severity="info" sx={{ mb: 2 }}>
                    <AlertTitle>{selectedTemplate.type} Record</AlertTitle>
                    {selectedTemplate.description}
                  </Alert>

                  <Typography variant="subtitle2" gutterBottom>
                    Example:
                  </Typography>
                  <Paper variant="outlined" sx={{ p: 1, mb: 2 }}>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                      {selectedTemplate.example}
                    </Typography>
                  </Paper>

                  <Typography variant="subtitle2" gutterBottom>
                    Fields:
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>Field</TableCell>
                          <TableCell>Type</TableCell>
                          <TableCell>Required</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {selectedTemplate.fields.map((field) => (
                          <TableRow key={field.name}>
                            <TableCell>
                              <Tooltip title={field.description}>
                                <Typography variant="body2">
                                  {field.name}
                                </Typography>
                              </Tooltip>
                            </TableCell>
                            <TableCell>
                              <Chip label={field.type} size="small" />
                            </TableCell>
                            <TableCell>
                              {field.required ? (
                                <CheckCircleIcon style={{ width: 16, height: 16, color: '#4caf50' }} />
                              ) : (
                                <Typography variant="body2" color="text.secondary">
                                  Optional
                                </Typography>
                              )}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Box>
              )}

              <Accordion sx={{ mt: 2 }}>
                <AccordionSummary expandIcon={<ChevronDownIcon style={{ width: 20, height: 20 }} />}>
                  <Typography>Common Issues</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    <ListItem>
                      <ListItemIcon>
                        <DocumentTextIcon style={{ width: 16, height: 16 }} />
                      </ListItemIcon>
                      <ListItemText
                        primary="Missing trailing dot"
                        secondary="FQDNs should end with a dot"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <DocumentTextIcon style={{ width: 16, height: 16 }} />
                      </ListItemIcon>
                      <ListItemText
                        primary="Invalid TTL values"
                        secondary="TTL must be 0-2147483647"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <DocumentTextIcon style={{ width: 16, height: 16 }} />
                      </ListItemIcon>
                      <ListItemText
                        primary="CNAME conflicts"
                        secondary="CNAME cannot coexist with other records"
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <DocumentTextIcon style={{ width: 16, height: 16 }} />
                      </ListItemIcon>
                      <ListItemText
                        primary="TXT record length"
                        secondary="Max 255 characters per string"
                      />
                    </ListItem>
                  </List>
                </AccordionDetails>
              </Accordion>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default RecordValidator;