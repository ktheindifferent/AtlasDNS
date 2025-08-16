import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Card,
  CardContent,
  Grid,
  Typography,
  TextField,
  Button,
  Chip,
  IconButton,
  Tooltip,
  Alert,
  Tabs,
  Tab,
  Paper,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Autocomplete,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Collapse,
  Divider,
  Badge,
  useTheme,
  alpha,
  CircularProgress,
} from '@mui/material';
import {
  AutoAwesome,
  CheckCircle,
  Warning,
  Error as ErrorIcon,
  Info,
  Add,
  Delete,
  Edit,
  ContentCopy,
  Upload,
  Download,
  Preview,
  DragIndicator,
  Lightbulb,
  Speed,
  Security,
  Cloud,
  Email,
  Web,
  Storage,
  Settings,
  Timeline,
  AccountTree,
  Visibility,
  VisibilityOff,
  PlayArrow,
  Undo,
  Redo,
  Save,
  ImportExport,
  LibraryBooks,
  Google,
  Microsoft,
  CloudQueue,
} from '@mui/icons-material';
import { Formik, Form, Field, FieldArray } from 'formik';
import * as Yup from 'yup';
import { DragDropContext, Droppable, Draggable } from 'react-beautiful-dnd';
import { useSnackbar } from 'notistack';
import { dnsApi } from '../../services/api';
import { AIAssistant } from './AIAssistant';
import { RecordTemplates } from './RecordTemplates';
import { RecordPreview } from './RecordPreview';
import { ConflictResolver } from './ConflictResolver';
import { BatchImport } from './BatchImport';
import { DependencyVisualizer } from './DependencyVisualizer';
import { ServiceIntegrations } from './ServiceIntegrations';

interface DNSRecord {
  id: string;
  type: 'A' | 'AAAA' | 'CNAME' | 'MX' | 'TXT' | 'NS' | 'SOA' | 'PTR' | 'SRV' | 'CAA';
  name: string;
  value: string;
  ttl: number;
  priority?: number;
  weight?: number;
  port?: number;
  target?: string;
  flags?: number;
  tag?: string;
  validation?: {
    status: 'valid' | 'warning' | 'error';
    message?: string;
  };
  aiSuggested?: boolean;
  dependencies?: string[];
}

interface SmartDNSRecordBuilderProps {
  domain: string;
  existingRecords?: DNSRecord[];
  onSave?: (records: DNSRecord[]) => void;
}

const recordTypeInfo = {
  A: { icon: Web, color: '#4caf50', description: 'Maps domain to IPv4 address' },
  AAAA: { icon: Web, color: '#2196f3', description: 'Maps domain to IPv6 address' },
  CNAME: { icon: AccountTree, color: '#ff9800', description: 'Alias to another domain' },
  MX: { icon: Email, color: '#9c27b0', description: 'Mail server configuration' },
  TXT: { icon: Storage, color: '#607d8b', description: 'Text records for verification' },
  NS: { icon: Cloud, color: '#00bcd4', description: 'Nameserver delegation' },
  SOA: { icon: Settings, color: '#795548', description: 'Start of Authority' },
  PTR: { icon: Timeline, color: '#e91e63', description: 'Reverse DNS lookup' },
  SRV: { icon: CloudQueue, color: '#3f51b5', description: 'Service location' },
  CAA: { icon: Security, color: '#f44336', description: 'Certificate authority authorization' },
};

const validationSchemas = {
  A: Yup.object({
    name: Yup.string().required('Name is required'),
    value: Yup.string()
      .matches(/^(\d{1,3}\.){3}\d{1,3}$/, 'Invalid IPv4 address')
      .required('IP address is required'),
    ttl: Yup.number().min(60).max(86400).required('TTL is required'),
  }),
  AAAA: Yup.object({
    name: Yup.string().required('Name is required'),
    value: Yup.string()
      .matches(/^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$/, 'Invalid IPv6 address')
      .required('IPv6 address is required'),
    ttl: Yup.number().min(60).max(86400).required('TTL is required'),
  }),
  CNAME: Yup.object({
    name: Yup.string().required('Name is required'),
    value: Yup.string()
      .matches(/^[a-zA-Z0-9][a-zA-Z0-9-_.]*[a-zA-Z0-9]$/, 'Invalid domain name')
      .required('Target domain is required'),
    ttl: Yup.number().min(60).max(86400).required('TTL is required'),
  }),
  MX: Yup.object({
    name: Yup.string().required('Name is required'),
    value: Yup.string()
      .matches(/^[a-zA-Z0-9][a-zA-Z0-9-_.]*[a-zA-Z0-9]$/, 'Invalid mail server')
      .required('Mail server is required'),
    priority: Yup.number().min(0).max(65535).required('Priority is required'),
    ttl: Yup.number().min(60).max(86400).required('TTL is required'),
  }),
  TXT: Yup.object({
    name: Yup.string().required('Name is required'),
    value: Yup.string().max(255, 'TXT record too long').required('Value is required'),
    ttl: Yup.number().min(60).max(86400).required('TTL is required'),
  }),
};

export const SmartDNSRecordBuilder: React.FC<SmartDNSRecordBuilderProps> = ({
  domain,
  existingRecords = [],
  onSave,
}) => {
  const theme = useTheme();
  const { enqueueSnackbar } = useSnackbar();
  const [records, setRecords] = useState<DNSRecord[]>(existingRecords);
  const [activeTab, setActiveTab] = useState(0);
  const [showAIAssistant, setShowAIAssistant] = useState(false);
  const [showTemplates, setShowTemplates] = useState(false);
  const [showPreview, setShowPreview] = useState(false);
  const [showBatchImport, setShowBatchImport] = useState(false);
  const [conflicts, setConflicts] = useState<any[]>([]);
  const [aiSuggestions, setAiSuggestions] = useState<DNSRecord[]>([]);
  const [selectedRecord, setSelectedRecord] = useState<DNSRecord | null>(null);
  const [validationErrors, setValidationErrors] = useState<Map<string, string>>(new Map());
  const [undoStack, setUndoStack] = useState<DNSRecord[][]>([]);
  const [redoStack, setRedoStack] = useState<DNSRecord[][]>([]);

  // AI-powered suggestions
  useEffect(() => {
    generateAISuggestions();
  }, [domain]);

  const generateAISuggestions = async () => {
    try {
      const response = await dnsApi.getAISuggestions(domain);
      setAiSuggestions(response.data.suggestions);
    } catch (error) {
      console.error('Failed to get AI suggestions:', error);
    }
  };

  // Real-time validation
  const validateRecord = useCallback((record: DNSRecord) => {
    const schema = validationSchemas[record.type];
    if (!schema) return { status: 'valid' };

    try {
      schema.validateSync(record);
      
      // Additional conflict detection
      const conflicts = detectConflicts(record, records);
      if (conflicts.length > 0) {
        return {
          status: 'warning',
          message: `Potential conflict with ${conflicts.length} existing record(s)`,
        };
      }

      return { status: 'valid' };
    } catch (error: any) {
      return {
        status: 'error',
        message: error.message,
      };
    }
  }, [records]);

  const detectConflicts = (newRecord: DNSRecord, existingRecords: DNSRecord[]) => {
    const conflicts = [];
    
    for (const record of existingRecords) {
      if (record.id === newRecord.id) continue;
      
      // CNAME conflicts
      if (newRecord.type === 'CNAME' && record.name === newRecord.name) {
        conflicts.push(record);
      }
      
      // Same name and type conflicts (except for multiple A/AAAA/MX/TXT)
      if (
        record.name === newRecord.name &&
        record.type === newRecord.type &&
        !['A', 'AAAA', 'MX', 'TXT'].includes(record.type)
      ) {
        conflicts.push(record);
      }
    }
    
    return conflicts;
  };

  const handleDragEnd = (result: any) => {
    if (!result.destination) return;

    const items = Array.from(records);
    const [reorderedItem] = items.splice(result.source.index, 1);
    items.splice(result.destination.index, 0, reorderedItem);

    saveToUndoStack();
    setRecords(items);
  };

  const saveToUndoStack = () => {
    setUndoStack([...undoStack, [...records]]);
    setRedoStack([]);
  };

  const handleUndo = () => {
    if (undoStack.length === 0) return;
    
    const previousState = undoStack[undoStack.length - 1];
    setRedoStack([...redoStack, [...records]]);
    setRecords(previousState);
    setUndoStack(undoStack.slice(0, -1));
  };

  const handleRedo = () => {
    if (redoStack.length === 0) return;
    
    const nextState = redoStack[redoStack.length - 1];
    saveToUndoStack();
    setRecords(nextState);
    setRedoStack(redoStack.slice(0, -1));
  };

  const addRecord = (record: Partial<DNSRecord>) => {
    const newRecord: DNSRecord = {
      id: `record-${Date.now()}`,
      type: 'A',
      name: '@',
      value: '',
      ttl: 3600,
      ...record,
    };

    const validation = validateRecord(newRecord);
    newRecord.validation = validation;

    saveToUndoStack();
    setRecords([...records, newRecord]);
    enqueueSnackbar('Record added', { variant: 'success' });
  };

  const updateRecord = (id: string, updates: Partial<DNSRecord>) => {
    saveToUndoStack();
    setRecords(records.map(record => {
      if (record.id === id) {
        const updated = { ...record, ...updates };
        updated.validation = validateRecord(updated);
        return updated;
      }
      return record;
    }));
  };

  const deleteRecord = (id: string) => {
    saveToUndoStack();
    setRecords(records.filter(record => record.id !== id));
    enqueueSnackbar('Record deleted', { variant: 'info' });
  };

  const applyTemplate = (template: any) => {
    saveToUndoStack();
    const templateRecords = template.records.map((record: any) => ({
      ...record,
      id: `record-${Date.now()}-${Math.random()}`,
      validation: validateRecord(record),
    }));
    setRecords([...records, ...templateRecords]);
    setShowTemplates(false);
    enqueueSnackbar(`Applied ${template.name} template`, { variant: 'success' });
  };

  const handleBatchImport = (importedRecords: DNSRecord[]) => {
    saveToUndoStack();
    const validatedRecords = importedRecords.map(record => ({
      ...record,
      id: `record-${Date.now()}-${Math.random()}`,
      validation: validateRecord(record),
    }));
    setRecords([...records, ...validatedRecords]);
    setShowBatchImport(false);
    enqueueSnackbar(`Imported ${importedRecords.length} records`, { variant: 'success' });
  };

  const handleSave = async () => {
    // Validate all records
    const hasErrors = records.some(record => record.validation?.status === 'error');
    if (hasErrors) {
      enqueueSnackbar('Please fix validation errors before saving', { variant: 'error' });
      return;
    }

    try {
      await dnsApi.saveRecords(domain, records);
      onSave?.(records);
      enqueueSnackbar('DNS records saved successfully', { variant: 'success' });
    } catch (error) {
      enqueueSnackbar('Failed to save DNS records', { variant: 'error' });
    }
  };

  return (
    <Box>
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Typography variant="h5" display="flex" alignItems="center" gap={1}>
              <AutoAwesome color="primary" />
              Smart DNS Record Builder
              <Chip 
                label={domain} 
                color="primary" 
                variant="outlined" 
                size="small" 
              />
            </Typography>
            <Box display="flex" gap={1}>
              <Tooltip title="Undo (Ctrl+Z)">
                <IconButton 
                  onClick={handleUndo} 
                  disabled={undoStack.length === 0}
                  size="small"
                >
                  <Undo />
                </IconButton>
              </Tooltip>
              <Tooltip title="Redo (Ctrl+Y)">
                <IconButton 
                  onClick={handleRedo} 
                  disabled={redoStack.length === 0}
                  size="small"
                >
                  <Redo />
                </IconButton>
              </Tooltip>
              <Divider orientation="vertical" flexItem />
              <Button
                startIcon={<Lightbulb />}
                variant="outlined"
                size="small"
                onClick={() => setShowAIAssistant(true)}
              >
                AI Assistant
              </Button>
              <Button
                startIcon={<LibraryBooks />}
                variant="outlined"
                size="small"
                onClick={() => setShowTemplates(true)}
              >
                Templates
              </Button>
              <Button
                startIcon={<Upload />}
                variant="outlined"
                size="small"
                onClick={() => setShowBatchImport(true)}
              >
                Import
              </Button>
              <Button
                startIcon={<Preview />}
                variant="outlined"
                size="small"
                onClick={() => setShowPreview(true)}
              >
                Preview
              </Button>
            </Box>
          </Box>

          {/* AI Suggestions Banner */}
          {aiSuggestions.length > 0 && (
            <Alert
              severity="info"
              icon={<AutoAwesome />}
              action={
                <Button size="small" onClick={() => setShowAIAssistant(true)}>
                  View All
                </Button>
              }
              sx={{ mb: 2 }}
            >
              AI detected {aiSuggestions.length} recommended records for your domain
            </Alert>
          )}

          {/* Quick Actions */}
          <Box display="flex" gap={1} flexWrap="wrap" mb={2}>
            {Object.entries(recordTypeInfo).map(([type, info]) => {
              const Icon = info.icon;
              return (
                <Tooltip key={type} title={info.description}>
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<Icon />}
                    onClick={() => addRecord({ type: type as DNSRecord['type'] })}
                    sx={{
                      borderColor: info.color,
                      color: info.color,
                      '&:hover': {
                        borderColor: info.color,
                        backgroundColor: alpha(info.color, 0.08),
                      },
                    }}
                  >
                    Add {type}
                  </Button>
                </Tooltip>
              );
            })}
          </Box>

          <Tabs value={activeTab} onChange={(_, v) => setActiveTab(v)}>
            <Tab label={`Records (${records.length})`} />
            <Tab label="Visual Builder" />
            <Tab label="Dependencies" />
            <Tab label="Validation" />
          </Tabs>
        </CardContent>
      </Card>

      {/* Records List */}
      {activeTab === 0 && (
        <DragDropContext onDragEnd={handleDragEnd}>
          <Droppable droppableId="records">
            {(provided) => (
              <Box {...provided.droppableProps} ref={provided.innerRef}>
                {records.map((record, index) => {
                  const TypeIcon = recordTypeInfo[record.type].icon;
                  return (
                    <Draggable key={record.id} draggableId={record.id} index={index}>
                      {(provided, snapshot) => (
                        <Card
                          ref={provided.innerRef}
                          {...provided.draggableProps}
                          sx={{
                            mb: 2,
                            backgroundColor: snapshot.isDragging ? 
                              alpha(theme.palette.primary.main, 0.08) : 
                              'background.paper',
                            border: record.validation?.status === 'error' ? 
                              `2px solid ${theme.palette.error.main}` :
                              record.validation?.status === 'warning' ?
                              `2px solid ${theme.palette.warning.main}` :
                              record.aiSuggested ?
                              `2px solid ${theme.palette.info.main}` :
                              'none',
                          }}
                        >
                          <CardContent>
                            <Box display="flex" alignItems="center" gap={2}>
                              <Box {...provided.dragHandleProps}>
                                <DragIndicator sx={{ cursor: 'grab' }} />
                              </Box>
                              
                              <TypeIcon sx={{ 
                                color: recordTypeInfo[record.type].color,
                                fontSize: 28,
                              }} />
                              
                              <Box flex={1}>
                                <Grid container spacing={2}>
                                  <Grid item xs={12} md={2}>
                                    <TextField
                                      label="Type"
                                      value={record.type}
                                      size="small"
                                      fullWidth
                                      select
                                      onChange={(e) => updateRecord(record.id, { 
                                        type: e.target.value as DNSRecord['type'] 
                                      })}
                                    >
                                      {Object.keys(recordTypeInfo).map(type => (
                                        <MenuItem key={type} value={type}>
                                          {type}
                                        </MenuItem>
                                      ))}
                                    </TextField>
                                  </Grid>
                                  
                                  <Grid item xs={12} md={3}>
                                    <TextField
                                      label="Name"
                                      value={record.name}
                                      size="small"
                                      fullWidth
                                      onChange={(e) => updateRecord(record.id, { 
                                        name: e.target.value 
                                      })}
                                      error={record.validation?.status === 'error' && record.validation.message?.includes('Name')}
                                    />
                                  </Grid>
                                  
                                  <Grid item xs={12} md={4}>
                                    <TextField
                                      label="Value"
                                      value={record.value}
                                      size="small"
                                      fullWidth
                                      onChange={(e) => updateRecord(record.id, { 
                                        value: e.target.value 
                                      })}
                                      error={record.validation?.status === 'error' && record.validation.message?.includes('value')}
                                    />
                                  </Grid>
                                  
                                  <Grid item xs={12} md={2}>
                                    <TextField
                                      label="TTL"
                                      value={record.ttl}
                                      size="small"
                                      fullWidth
                                      type="number"
                                      onChange={(e) => updateRecord(record.id, { 
                                        ttl: parseInt(e.target.value) 
                                      })}
                                    />
                                  </Grid>
                                  
                                  {record.type === 'MX' && (
                                    <Grid item xs={12} md={2}>
                                      <TextField
                                        label="Priority"
                                        value={record.priority || ''}
                                        size="small"
                                        fullWidth
                                        type="number"
                                        onChange={(e) => updateRecord(record.id, { 
                                          priority: parseInt(e.target.value) 
                                        })}
                                      />
                                    </Grid>
                                  )}
                                </Grid>
                                
                                {record.validation?.message && (
                                  <Alert 
                                    severity={record.validation.status as any}
                                    sx={{ mt: 1 }}
                                  >
                                    {record.validation.message}
                                  </Alert>
                                )}
                                
                                {record.aiSuggested && (
                                  <Chip
                                    icon={<AutoAwesome />}
                                    label="AI Suggested"
                                    color="info"
                                    size="small"
                                    sx={{ mt: 1 }}
                                  />
                                )}
                              </Box>
                              
                              <Box>
                                <IconButton
                                  size="small"
                                  onClick={() => deleteRecord(record.id)}
                                  color="error"
                                >
                                  <Delete />
                                </IconButton>
                              </Box>
                            </Box>
                          </CardContent>
                        </Card>
                      )}
                    </Draggable>
                  );
                })}
                {provided.placeholder}
              </Box>
            )}
          </Droppable>
        </DragDropContext>
      )}

      {/* Visual Builder Tab */}
      {activeTab === 1 && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Visual DNS Record Builder
            </Typography>
            <Alert severity="info" sx={{ mb: 2 }}>
              Drag and drop record types to build your DNS configuration visually
            </Alert>
            {/* Visual builder implementation */}
          </CardContent>
        </Card>
      )}

      {/* Dependencies Tab */}
      {activeTab === 2 && (
        <DependencyVisualizer records={records} />
      )}

      {/* Validation Tab */}
      {activeTab === 3 && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Validation Summary
            </Typography>
            <Box display="flex" gap={2} mb={2}>
              <Chip 
                icon={<CheckCircle />}
                label={`Valid: ${records.filter(r => r.validation?.status === 'valid').length}`}
                color="success"
              />
              <Chip 
                icon={<Warning />}
                label={`Warnings: ${records.filter(r => r.validation?.status === 'warning').length}`}
                color="warning"
              />
              <Chip 
                icon={<ErrorIcon />}
                label={`Errors: ${records.filter(r => r.validation?.status === 'error').length}`}
                color="error"
              />
            </Box>
            
            {conflicts.length > 0 && (
              <ConflictResolver 
                conflicts={conflicts}
                onResolve={(resolved) => {
                  setRecords(resolved);
                  setConflicts([]);
                }}
              />
            )}
          </CardContent>
        </Card>
      )}

      {/* Save Button */}
      <Box display="flex" justifyContent="flex-end" mt={3} gap={2}>
        <Button
          variant="outlined"
          startIcon={<Download />}
          onClick={() => {
            const dataStr = JSON.stringify(records, null, 2);
            const dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr);
            const exportFileDefaultName = `${domain}-dns-records.json`;
            const linkElement = document.createElement('a');
            linkElement.setAttribute('href', dataUri);
            linkElement.setAttribute('download', exportFileDefaultName);
            linkElement.click();
          }}
        >
          Export
        </Button>
        <Button
          variant="contained"
          startIcon={<Save />}
          onClick={handleSave}
          disabled={records.some(r => r.validation?.status === 'error')}
        >
          Save Records
        </Button>
      </Box>

      {/* Dialogs */}
      <AIAssistant
        open={showAIAssistant}
        onClose={() => setShowAIAssistant(false)}
        domain={domain}
        suggestions={aiSuggestions}
        onApply={(suggested) => {
          saveToUndoStack();
          setRecords([...records, ...suggested]);
          setShowAIAssistant(false);
        }}
      />

      <RecordTemplates
        open={showTemplates}
        onClose={() => setShowTemplates(false)}
        onApply={applyTemplate}
      />

      <RecordPreview
        open={showPreview}
        onClose={() => setShowPreview(false)}
        records={records}
        domain={domain}
      />

      <BatchImport
        open={showBatchImport}
        onClose={() => setShowBatchImport(false)}
        onImport={handleBatchImport}
      />
    </Box>
  );
};

export default SmartDNSRecordBuilder;