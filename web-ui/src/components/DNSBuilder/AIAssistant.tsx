import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Box,
  Typography,
  Button,
  Card,
  CardContent,
  Chip,
  TextField,
  Alert,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  CircularProgress,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Tooltip,
  Grid,
  useTheme,
  alpha,
} from '@mui/material';
import {
  AutoAwesome,
  CheckCircle,
  Add,
  Info,
  ExpandMore,
  Lightbulb,
  Security,
  Speed,
  Email,
  Web,
  Cloud,
  Business,
  School,
  ShoppingCart,
  Article,
  Forum,
  Games,
} from '@mui/icons-material';
import { dnsApi } from '../../services/api';

interface DNSRecord {
  id: string;
  type: string;
  name: string;
  value: string;
  ttl: number;
  priority?: number;
  aiSuggested?: boolean;
  reason?: string;
  confidence?: number;
}

interface AIAssistantProps {
  open: boolean;
  onClose: () => void;
  domain: string;
  suggestions: DNSRecord[];
  onApply: (records: DNSRecord[]) => void;
}

const domainCategories = {
  business: { icon: Business, label: 'Business Website', color: '#2196f3' },
  ecommerce: { icon: ShoppingCart, label: 'E-commerce', color: '#4caf50' },
  blog: { icon: Article, label: 'Blog/Personal', color: '#ff9800' },
  education: { icon: School, label: 'Educational', color: '#9c27b0' },
  forum: { icon: Forum, label: 'Community/Forum', color: '#00bcd4' },
  gaming: { icon: Games, label: 'Gaming', color: '#f44336' },
};

const servicePlatforms = [
  { id: 'google', name: 'Google Workspace', icon: '🔷' },
  { id: 'microsoft', name: 'Microsoft 365', icon: '🔶' },
  { id: 'cloudflare', name: 'Cloudflare', icon: '☁️' },
  { id: 'aws', name: 'AWS', icon: '⚡' },
  { id: 'vercel', name: 'Vercel', icon: '▲' },
  { id: 'netlify', name: 'Netlify', icon: '🔺' },
  { id: 'github', name: 'GitHub Pages', icon: '🐙' },
  { id: 'sendgrid', name: 'SendGrid', icon: '📧' },
  { id: 'mailgun', name: 'Mailgun', icon: '📮' },
];

export const AIAssistant: React.FC<AIAssistantProps> = ({
  open,
  onClose,
  domain,
  suggestions: initialSuggestions,
  onApply,
}) => {
  const theme = useTheme();
  const [loading, setLoading] = useState(false);
  const [category, setCategory] = useState<string>('business');
  const [services, setServices] = useState<string[]>([]);
  const [purpose, setPurpose] = useState('');
  const [suggestions, setSuggestions] = useState<DNSRecord[]>(initialSuggestions);
  const [selectedRecords, setSelectedRecords] = useState<Set<string>>(new Set());
  const [analyzing, setAnalyzing] = useState(false);
  const [analysis, setAnalysis] = useState<any>(null);

  useEffect(() => {
    if (open && !analysis) {
      analyzeDomain();
    }
  }, [open]);

  const analyzeDomain = async () => {
    setAnalyzing(true);
    try {
      const response = await dnsApi.analyzeDomain(domain);
      setAnalysis(response.data);
      
      // Auto-detect category based on analysis
      if (response.data.detectedCategory) {
        setCategory(response.data.detectedCategory);
      }
      
      // Generate initial suggestions based on analysis
      generateSuggestions();
    } catch (error) {
      console.error('Failed to analyze domain:', error);
    } finally {
      setAnalyzing(false);
    }
  };

  const generateSuggestions = async () => {
    setLoading(true);
    try {
      const response = await dnsApi.generateDNSSuggestions({
        domain,
        category,
        services,
        purpose,
        existingRecords: [],
      });
      
      const suggestedRecords = response.data.suggestions.map((record: any) => ({
        ...record,
        id: `ai-${Date.now()}-${Math.random()}`,
        aiSuggested: true,
      }));
      
      setSuggestions(suggestedRecords);
      
      // Auto-select high confidence suggestions
      const highConfidence = suggestedRecords
        .filter((r: DNSRecord) => (r.confidence || 0) > 0.8)
        .map((r: DNSRecord) => r.id);
      setSelectedRecords(new Set(highConfidence));
    } catch (error) {
      console.error('Failed to generate suggestions:', error);
    } finally {
      setLoading(false);
    }
  };

  const toggleRecordSelection = (recordId: string) => {
    const newSelection = new Set(selectedRecords);
    if (newSelection.has(recordId)) {
      newSelection.delete(recordId);
    } else {
      newSelection.add(recordId);
    }
    setSelectedRecords(newSelection);
  };

  const applySuggestions = () => {
    const recordsToApply = suggestions.filter(r => selectedRecords.has(r.id));
    onApply(recordsToApply);
  };

  const getRecordTypeIcon = (type: string) => {
    switch (type) {
      case 'A':
      case 'AAAA':
        return <Web />;
      case 'MX':
        return <Email />;
      case 'CNAME':
        return <Cloud />;
      case 'TXT':
        return <Security />;
      default:
        return <Info />;
    }
  };

  const groupedSuggestions = suggestions.reduce((acc, record) => {
    const group = record.reason?.split(':')[0] || 'General';
    if (!acc[group]) acc[group] = [];
    acc[group].push(record);
    return acc;
  }, {} as Record<string, DNSRecord[]>);

  return (
    <Dialog open={open} onClose={onClose} maxWidth="lg" fullWidth>
      <DialogTitle>
        <Box display="flex" alignItems="center" gap={1}>
          <AutoAwesome color="primary" />
          <Typography variant="h6">AI DNS Configuration Assistant</Typography>
        </Box>
      </DialogTitle>
      
      <DialogContent>
        {analyzing ? (
          <Box display="flex" flexDirection="column" alignItems="center" py={4}>
            <CircularProgress />
            <Typography variant="body2" color="text.secondary" mt={2}>
              Analyzing domain {domain}...
            </Typography>
          </Box>
        ) : (
          <>
            {/* Domain Analysis Results */}
            {analysis && (
              <Alert severity="info" sx={{ mb: 3 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Domain Analysis Results
                </Typography>
                <Box display="flex" gap={1} flexWrap="wrap" mt={1}>
                  {analysis.hasWebsite && (
                    <Chip size="small" label="Website Detected" color="success" />
                  )}
                  {analysis.hasMail && (
                    <Chip size="small" label="Mail Server Configured" color="primary" />
                  )}
                  {analysis.hasSSL && (
                    <Chip size="small" label="SSL Certificate" color="success" />
                  )}
                  {analysis.provider && (
                    <Chip size="small" label={`Hosted on ${analysis.provider}`} />
                  )}
                </Box>
              </Alert>
            )}

            {/* Configuration Options */}
            <Card sx={{ mb: 3 }}>
              <CardContent>
                <Typography variant="subtitle1" gutterBottom>
                  Tell us about your domain
                </Typography>
                
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <FormControl fullWidth size="small">
                      <InputLabel>Domain Purpose</InputLabel>
                      <Select
                        value={category}
                        onChange={(e) => setCategory(e.target.value)}
                        label="Domain Purpose"
                      >
                        {Object.entries(domainCategories).map(([key, cat]) => {
                          const Icon = cat.icon;
                          return (
                            <MenuItem key={key} value={key}>
                              <Box display="flex" alignItems="center" gap={1}>
                                <Icon sx={{ fontSize: 20, color: cat.color }} />
                                {cat.label}
                              </Box>
                            </MenuItem>
                          );
                        })}
                      </Select>
                    </FormControl>
                  </Grid>
                  
                  <Grid item xs={12} md={6}>
                    <FormControl fullWidth size="small">
                      <InputLabel>Services to Configure</InputLabel>
                      <Select
                        multiple
                        value={services}
                        onChange={(e) => setServices(e.target.value as string[])}
                        label="Services to Configure"
                      >
                        {servicePlatforms.map(platform => (
                          <MenuItem key={platform.id} value={platform.id}>
                            <Box display="flex" alignItems="center" gap={1}>
                              <span>{platform.icon}</span>
                              {platform.name}
                            </Box>
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Grid>
                  
                  <Grid item xs={12}>
                    <TextField
                      fullWidth
                      size="small"
                      label="Additional Requirements (Optional)"
                      placeholder="e.g., Need subdomain for API, staging environment, CDN setup..."
                      value={purpose}
                      onChange={(e) => setPurpose(e.target.value)}
                      multiline
                      rows={2}
                    />
                  </Grid>
                  
                  <Grid item xs={12}>
                    <Button
                      variant="contained"
                      startIcon={<AutoAwesome />}
                      onClick={generateSuggestions}
                      disabled={loading}
                      fullWidth
                    >
                      {loading ? 'Generating Suggestions...' : 'Generate AI Suggestions'}
                    </Button>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>

            {/* Suggestions */}
            {suggestions.length > 0 && (
              <Box>
                <Typography variant="subtitle1" gutterBottom>
                  Recommended DNS Records
                </Typography>
                
                <Alert severity="success" sx={{ mb: 2 }}>
                  Found {suggestions.length} recommended records. 
                  {selectedRecords.size} selected for import.
                </Alert>
                
                {Object.entries(groupedSuggestions).map(([group, records]) => (
                  <Accordion key={group} defaultExpanded>
                    <AccordionSummary expandIcon={<ExpandMore />}>
                      <Box display="flex" alignItems="center" gap={1}>
                        <Lightbulb sx={{ color: theme.palette.warning.main }} />
                        <Typography>{group}</Typography>
                        <Chip 
                          size="small" 
                          label={`${records.length} records`}
                          color="primary"
                        />
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <List>
                        {records.map(record => (
                          <ListItem
                            key={record.id}
                            sx={{
                              borderRadius: 1,
                              mb: 1,
                              backgroundColor: selectedRecords.has(record.id) ?
                                alpha(theme.palette.primary.main, 0.08) :
                                'transparent',
                            }}
                          >
                            <ListItemIcon>
                              {getRecordTypeIcon(record.type)}
                            </ListItemIcon>
                            <ListItemText
                              primary={
                                <Box display="flex" alignItems="center" gap={1}>
                                  <Chip 
                                    label={record.type} 
                                    size="small" 
                                    color="primary"
                                    variant="outlined"
                                  />
                                  <Typography variant="body2">
                                    {record.name} → {record.value}
                                  </Typography>
                                  {record.confidence && record.confidence > 0.8 && (
                                    <Chip 
                                      icon={<CheckCircle />}
                                      label="High Confidence"
                                      size="small"
                                      color="success"
                                    />
                                  )}
                                </Box>
                              }
                              secondary={
                                <Box>
                                  <Typography variant="caption" color="text.secondary">
                                    {record.reason}
                                  </Typography>
                                  <Typography variant="caption" display="block">
                                    TTL: {record.ttl}s
                                    {record.priority && ` | Priority: ${record.priority}`}
                                  </Typography>
                                </Box>
                              }
                            />
                            <ListItemSecondaryAction>
                              <IconButton
                                edge="end"
                                onClick={() => toggleRecordSelection(record.id)}
                                color={selectedRecords.has(record.id) ? 'primary' : 'default'}
                              >
                                {selectedRecords.has(record.id) ? 
                                  <CheckCircle /> : 
                                  <Add />
                                }
                              </IconButton>
                            </ListItemSecondaryAction>
                          </ListItem>
                        ))}
                      </List>
                    </AccordionDetails>
                  </Accordion>
                ))}
              </Box>
            )}
          </>
        )}
      </DialogContent>
      
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          variant="contained"
          startIcon={<CheckCircle />}
          onClick={applySuggestions}
          disabled={selectedRecords.size === 0}
        >
          Apply {selectedRecords.size} Selected Records
        </Button>
      </DialogActions>
    </Dialog>
  );
};