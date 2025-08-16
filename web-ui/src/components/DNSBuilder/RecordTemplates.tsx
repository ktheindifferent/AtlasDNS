import React, { useState } from 'react';
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
  CardActions,
  Grid,
  Chip,
  TextField,
  InputAdornment,
  IconButton,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Alert,
  useTheme,
  alpha,
} from '@mui/material';
import {
  LibraryBooks,
  Search,
  Email,
  Web,
  Cloud,
  Security,
  Business,
  School,
  ShoppingCart,
  ExpandMore,
  CheckCircle,
  ContentCopy,
  Favorite,
  FavoriteBorder,
  Star,
  Google,
  Microsoft,
} from '@mui/icons-material';

interface DNSTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  icon: React.ElementType;
  popularity: number;
  records: Array<{
    type: string;
    name: string;
    value: string;
    ttl: number;
    priority?: number;
  }>;
  tags: string[];
  provider?: string;
}

interface RecordTemplatesProps {
  open: boolean;
  onClose: () => void;
  onApply: (template: DNSTemplate) => void;
}

const templates: DNSTemplate[] = [
  {
    id: 'google-workspace',
    name: 'Google Workspace',
    description: 'Complete setup for Google Workspace (Gmail, Drive, Calendar)',
    category: 'Email & Productivity',
    icon: Google,
    popularity: 95,
    provider: 'Google',
    tags: ['email', 'productivity', 'collaboration'],
    records: [
      { type: 'MX', name: '@', value: 'aspmx.l.google.com', ttl: 3600, priority: 1 },
      { type: 'MX', name: '@', value: 'alt1.aspmx.l.google.com', ttl: 3600, priority: 5 },
      { type: 'MX', name: '@', value: 'alt2.aspmx.l.google.com', ttl: 3600, priority: 5 },
      { type: 'MX', name: '@', value: 'alt3.aspmx.l.google.com', ttl: 3600, priority: 10 },
      { type: 'MX', name: '@', value: 'alt4.aspmx.l.google.com', ttl: 3600, priority: 10 },
      { type: 'TXT', name: '@', value: 'v=spf1 include:_spf.google.com ~all', ttl: 3600 },
      { type: 'TXT', name: '_dmarc', value: 'v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com', ttl: 3600 },
      { type: 'CNAME', name: 'calendar', value: 'ghs.googlehosted.com', ttl: 3600 },
      { type: 'CNAME', name: 'drive', value: 'ghs.googlehosted.com', ttl: 3600 },
      { type: 'CNAME', name: 'mail', value: 'ghs.googlehosted.com', ttl: 3600 },
    ],
  },
  {
    id: 'office365',
    name: 'Microsoft 365',
    description: 'Complete setup for Microsoft 365 (Outlook, Teams, OneDrive)',
    category: 'Email & Productivity',
    icon: Microsoft,
    popularity: 90,
    provider: 'Microsoft',
    tags: ['email', 'productivity', 'teams'],
    records: [
      { type: 'MX', name: '@', value: 'example-com.mail.protection.outlook.com', ttl: 3600, priority: 0 },
      { type: 'TXT', name: '@', value: 'v=spf1 include:spf.protection.outlook.com -all', ttl: 3600 },
      { type: 'CNAME', name: 'autodiscover', value: 'autodiscover.outlook.com', ttl: 3600 },
      { type: 'CNAME', name: 'sip', value: 'sipdir.online.lync.com', ttl: 3600 },
      { type: 'CNAME', name: 'lyncdiscover', value: 'webdir.online.lync.com', ttl: 3600 },
      { type: 'CNAME', name: 'msoid', value: 'clientconfig.microsoftonline-p.net', ttl: 3600 },
      { type: 'CNAME', name: 'enterpriseregistration', value: 'enterpriseregistration.windows.net', ttl: 3600 },
      { type: 'CNAME', name: 'enterpriseenrollment', value: 'enterpriseenrollment.manage.microsoft.com', ttl: 3600 },
      { type: 'SRV', name: '_sip._tls', value: 'sipdir.online.lync.com', ttl: 3600, priority: 100, port: 443, weight: 1 },
      { type: 'SRV', name: '_sipfederationtls._tcp', value: 'sipfed.online.lync.com', ttl: 3600, priority: 100, port: 5061, weight: 1 },
    ],
  },
  {
    id: 'cloudflare-cdn',
    name: 'Cloudflare CDN & Security',
    description: 'Optimize website performance with Cloudflare CDN and security',
    category: 'CDN & Performance',
    icon: Cloud,
    popularity: 88,
    provider: 'Cloudflare',
    tags: ['cdn', 'performance', 'security', 'ddos'],
    records: [
      { type: 'A', name: '@', value: '192.0.2.1', ttl: 300 },
      { type: 'A', name: 'www', value: '192.0.2.1', ttl: 300 },
      { type: 'AAAA', name: '@', value: '2001:db8::1', ttl: 300 },
      { type: 'AAAA', name: 'www', value: '2001:db8::1', ttl: 300 },
      { type: 'TXT', name: '@', value: 'v=spf1 include:_spf.cloudflare.com ~all', ttl: 3600 },
      { type: 'CAA', name: '@', value: '0 issue "letsencrypt.org"', ttl: 3600 },
      { type: 'CAA', name: '@', value: '0 issuewild "letsencrypt.org"', ttl: 3600 },
    ],
  },
  {
    id: 'basic-website',
    name: 'Basic Website',
    description: 'Essential records for a simple website',
    category: 'Website',
    icon: Web,
    popularity: 85,
    tags: ['website', 'basic', 'simple'],
    records: [
      { type: 'A', name: '@', value: '192.0.2.1', ttl: 3600 },
      { type: 'A', name: 'www', value: '192.0.2.1', ttl: 3600 },
      { type: 'AAAA', name: '@', value: '2001:db8::1', ttl: 3600 },
      { type: 'AAAA', name: 'www', value: '2001:db8::1', ttl: 3600 },
    ],
  },
  {
    id: 'ecommerce',
    name: 'E-commerce Site',
    description: 'Comprehensive setup for online stores',
    category: 'E-commerce',
    icon: ShoppingCart,
    popularity: 82,
    tags: ['ecommerce', 'shop', 'store', 'payment'],
    records: [
      { type: 'A', name: '@', value: '192.0.2.1', ttl: 300 },
      { type: 'A', name: 'www', value: '192.0.2.1', ttl: 300 },
      { type: 'A', name: 'shop', value: '192.0.2.2', ttl: 300 },
      { type: 'A', name: 'api', value: '192.0.2.3', ttl: 300 },
      { type: 'CNAME', name: 'cdn', value: 'cdn.cloudflare.com', ttl: 300 },
      { type: 'TXT', name: '@', value: 'v=spf1 include:sendgrid.net ~all', ttl: 3600 },
      { type: 'MX', name: '@', value: 'mx.sendgrid.net', ttl: 3600, priority: 10 },
    ],
  },
  {
    id: 'development',
    name: 'Development Environment',
    description: 'Setup for development and staging environments',
    category: 'Development',
    icon: Business,
    popularity: 75,
    tags: ['dev', 'staging', 'test', 'development'],
    records: [
      { type: 'A', name: 'dev', value: '192.0.2.10', ttl: 300 },
      { type: 'A', name: 'staging', value: '192.0.2.11', ttl: 300 },
      { type: 'A', name: 'api-dev', value: '192.0.2.12', ttl: 300 },
      { type: 'A', name: 'api-staging', value: '192.0.2.13', ttl: 300 },
      { type: 'CNAME', name: 'preview', value: 'preview.vercel.app', ttl: 300 },
    ],
  },
  {
    id: 'email-security',
    name: 'Email Security Suite',
    description: 'Advanced email security with SPF, DKIM, and DMARC',
    category: 'Security',
    icon: Security,
    popularity: 80,
    tags: ['email', 'security', 'spf', 'dkim', 'dmarc'],
    records: [
      { type: 'TXT', name: '@', value: 'v=spf1 mx a include:_spf.example.com -all', ttl: 3600 },
      { type: 'TXT', name: 'default._domainkey', value: 'v=DKIM1; k=rsa; p=MIGfMA0GCS...', ttl: 3600 },
      { type: 'TXT', name: '_dmarc', value: 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:forensics@example.com; pct=100', ttl: 3600 },
      { type: 'TXT', name: '_mta-sts', value: 'v=STSv1; id=20240101000000', ttl: 3600 },
      { type: 'CNAME', name: 'mta-sts', value: 'mta-sts.example.com', ttl: 3600 },
    ],
  },
  {
    id: 'subdomain-delegation',
    name: 'Subdomain Delegation',
    description: 'Delegate subdomains to different nameservers',
    category: 'Advanced',
    icon: Cloud,
    popularity: 70,
    tags: ['subdomain', 'delegation', 'nameserver'],
    records: [
      { type: 'NS', name: 'api', value: 'ns1.provider.com', ttl: 3600 },
      { type: 'NS', name: 'api', value: 'ns2.provider.com', ttl: 3600 },
      { type: 'NS', name: 'blog', value: 'ns1.blogger.com', ttl: 3600 },
      { type: 'NS', name: 'blog', value: 'ns2.blogger.com', ttl: 3600 },
    ],
  },
];

const categories = [
  'All',
  'Email & Productivity',
  'CDN & Performance',
  'Website',
  'E-commerce',
  'Development',
  'Security',
  'Advanced',
];

export const RecordTemplates: React.FC<RecordTemplatesProps> = ({
  open,
  onClose,
  onApply,
}) => {
  const theme = useTheme();
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('All');
  const [expandedTemplate, setExpandedTemplate] = useState<string | null>(null);
  const [favorites, setFavorites] = useState<Set<string>>(new Set());

  const filteredTemplates = templates.filter(template => {
    const matchesSearch = template.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         template.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         template.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()));
    
    const matchesCategory = selectedCategory === 'All' || template.category === selectedCategory;
    
    return matchesSearch && matchesCategory;
  });

  const toggleFavorite = (templateId: string) => {
    const newFavorites = new Set(favorites);
    if (newFavorites.has(templateId)) {
      newFavorites.delete(templateId);
    } else {
      newFavorites.add(templateId);
    }
    setFavorites(newFavorites);
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="lg" fullWidth>
      <DialogTitle>
        <Box display="flex" alignItems="center" gap={1}>
          <LibraryBooks color="primary" />
          <Typography variant="h6">DNS Configuration Templates</Typography>
        </Box>
      </DialogTitle>
      
      <DialogContent>
        {/* Search and Filter */}
        <Box mb={3}>
          <TextField
            fullWidth
            placeholder="Search templates..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <Search />
                </InputAdornment>
              ),
            }}
            sx={{ mb: 2 }}
          />
          
          <Box display="flex" gap={1} flexWrap="wrap">
            {categories.map(category => (
              <Chip
                key={category}
                label={category}
                onClick={() => setSelectedCategory(category)}
                color={selectedCategory === category ? 'primary' : 'default'}
                variant={selectedCategory === category ? 'filled' : 'outlined'}
              />
            ))}
          </Box>
        </Box>

        {/* Templates Grid */}
        <Grid container spacing={2}>
          {filteredTemplates.map(template => {
            const Icon = template.icon;
            const isFavorite = favorites.has(template.id);
            const isExpanded = expandedTemplate === template.id;
            
            return (
              <Grid item xs={12} key={template.id}>
                <Card
                  sx={{
                    border: isExpanded ? `2px solid ${theme.palette.primary.main}` : 'none',
                    transition: 'all 0.3s',
                  }}
                >
                  <CardContent>
                    <Box display="flex" justifyContent="space-between" alignItems="start">
                      <Box display="flex" gap={2}>
                        <Icon sx={{ fontSize: 40, color: theme.palette.primary.main }} />
                        <Box>
                          <Typography variant="h6" gutterBottom>
                            {template.name}
                            {template.provider && (
                              <Chip
                                label={template.provider}
                                size="small"
                                sx={{ ml: 1 }}
                                variant="outlined"
                              />
                            )}
                          </Typography>
                          <Typography variant="body2" color="text.secondary" gutterBottom>
                            {template.description}
                          </Typography>
                          <Box display="flex" gap={1} mt={1}>
                            {template.tags.map(tag => (
                              <Chip key={tag} label={tag} size="small" />
                            ))}
                          </Box>
                        </Box>
                      </Box>
                      
                      <Box display="flex" alignItems="center" gap={1}>
                        <Box display="flex" alignItems="center">
                          <Star sx={{ color: theme.palette.warning.main, fontSize: 18 }} />
                          <Typography variant="body2" color="text.secondary">
                            {template.popularity}%
                          </Typography>
                        </Box>
                        <IconButton
                          size="small"
                          onClick={() => toggleFavorite(template.id)}
                        >
                          {isFavorite ? <Favorite color="error" /> : <FavoriteBorder />}
                        </IconButton>
                      </Box>
                    </Box>

                    {/* Expandable Records Preview */}
                    <Accordion
                      expanded={isExpanded}
                      onChange={() => setExpandedTemplate(isExpanded ? null : template.id)}
                      sx={{ mt: 2, boxShadow: 'none' }}
                    >
                      <AccordionSummary expandIcon={<ExpandMore />}>
                        <Typography variant="body2">
                          View {template.records.length} DNS records
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        <List dense>
                          {template.records.map((record, idx) => (
                            <ListItem key={idx}>
                              <ListItemText
                                primary={
                                  <Typography variant="body2" fontFamily="monospace">
                                    {record.type} {record.name} → {record.value}
                                  </Typography>
                                }
                                secondary={
                                  <Typography variant="caption">
                                    TTL: {record.ttl}s
                                    {record.priority && ` | Priority: ${record.priority}`}
                                  </Typography>
                                }
                              />
                            </ListItem>
                          ))}
                        </List>
                      </AccordionDetails>
                    </Accordion>
                  </CardContent>
                  
                  <CardActions>
                    <Button
                      variant="contained"
                      startIcon={<CheckCircle />}
                      onClick={() => onApply(template)}
                      fullWidth
                    >
                      Apply Template
                    </Button>
                  </CardActions>
                </Card>
              </Grid>
            );
          })}
        </Grid>

        {filteredTemplates.length === 0 && (
          <Alert severity="info">
            No templates found matching your search criteria.
          </Alert>
        )}
      </DialogContent>
      
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
};