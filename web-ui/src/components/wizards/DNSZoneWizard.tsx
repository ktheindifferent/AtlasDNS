import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Button,
  TextField,
  FormControl,
  FormLabel,
  RadioGroup,
  FormControlLabel,
  Radio,
  Select,
  MenuItem,
  InputLabel,
  Box,
  Typography,
  Alert,
  Chip,
  Paper,
  Grid,
  Switch,
  FormHelperText,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  Help as HelpIcon,
  Add as AddIcon,
  Delete as DeleteIcon,
  ContentCopy as CopyIcon,
} from '@mui/icons-material';
import { useOnboarding } from '../../contexts/OnboardingContext';

interface DNSZoneWizardProps {
  open: boolean;
  onClose: () => void;
  onComplete: (zoneData: any) => void;
}

const DNSZoneWizard: React.FC<DNSZoneWizardProps> = ({ open, onClose, onComplete }) => {
  const { updateProgress } = useOnboarding();
  const [activeStep, setActiveStep] = useState(0);
  const [zoneData, setZoneData] = useState({
    name: '',
    type: 'primary',
    ttl: 3600,
    contactEmail: '',
    primaryNS: '',
    nameservers: [''],
    dnssecEnabled: false,
    geoEnabled: false,
    template: 'custom',
  });
  const [errors, setErrors] = useState<Record<string, string>>({});

  const steps = [
    'Basic Configuration',
    'Nameservers',
    'Advanced Options',
    'Review & Create',
  ];

  const templates = [
    { value: 'custom', label: 'Custom Configuration', description: 'Start from scratch' },
    { value: 'web-hosting', label: 'Web Hosting', description: 'Standard web hosting setup with A, AAAA, CNAME, and MX records' },
    { value: 'email-only', label: 'Email Only', description: 'MX records for email services' },
    { value: 'cdn', label: 'CDN Setup', description: 'Configuration for Content Delivery Networks' },
    { value: 'load-balanced', label: 'Load Balanced', description: 'Multiple A records with health checks' },
    { value: 'geo-routing', label: 'Geographic Routing', description: 'Different responses based on location' },
  ];

  const validateStep = (step: number): boolean => {
    const newErrors: Record<string, string> = {};
    
    switch (step) {
      case 0:
        if (!zoneData.name) {
          newErrors.name = 'Zone name is required';
        } else if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(zoneData.name)) {
          newErrors.name = 'Invalid domain name format';
        }
        if (!zoneData.contactEmail) {
          newErrors.contactEmail = 'Contact email is required';
        } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(zoneData.contactEmail)) {
          newErrors.contactEmail = 'Invalid email format';
        }
        break;
      case 1:
        if (zoneData.type === 'primary' && !zoneData.primaryNS) {
          newErrors.primaryNS = 'Primary nameserver is required';
        }
        if (zoneData.nameservers.filter(ns => ns).length < 2) {
          newErrors.nameservers = 'At least 2 nameservers are required';
        }
        break;
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleNext = () => {
    if (validateStep(activeStep)) {
      setActiveStep((prevStep) => prevStep + 1);
    }
  };

  const handleBack = () => {
    setActiveStep((prevStep) => prevStep - 1);
  };

  const handleComplete = () => {
    if (validateStep(activeStep)) {
      updateProgress('wizard', 'dns-zone-creation');
      onComplete(zoneData);
      onClose();
    }
  };

  const addNameserver = () => {
    setZoneData(prev => ({
      ...prev,
      nameservers: [...prev.nameservers, ''],
    }));
  };

  const removeNameserver = (index: number) => {
    setZoneData(prev => ({
      ...prev,
      nameservers: prev.nameservers.filter((_, i) => i !== index),
    }));
  };

  const updateNameserver = (index: number, value: string) => {
    setZoneData(prev => ({
      ...prev,
      nameservers: prev.nameservers.map((ns, i) => i === index ? value : ns),
    }));
  };

  const renderStepContent = (step: number) => {
    switch (step) {
      case 0:
        return (
          <Box sx={{ mt: 2 }}>
            <Grid container spacing={3}>
              <Grid item xs={12}>
                <FormControl fullWidth sx={{ mb: 2 }}>
                  <FormLabel>Select a Template</FormLabel>
                  <RadioGroup
                    value={zoneData.template}
                    onChange={(e) => setZoneData({ ...zoneData, template: e.target.value })}
                  >
                    {templates.map(template => (
                      <Paper
                        key={template.value}
                        sx={{
                          p: 2,
                          mb: 1,
                          cursor: 'pointer',
                          border: zoneData.template === template.value ? 2 : 1,
                          borderColor: zoneData.template === template.value ? 'primary.main' : 'divider',
                        }}
                        onClick={() => setZoneData({ ...zoneData, template: template.value })}
                      >
                        <FormControlLabel
                          value={template.value}
                          control={<Radio />}
                          label={
                            <Box>
                              <Typography variant="subtitle1">{template.label}</Typography>
                              <Typography variant="caption" color="text.secondary">
                                {template.description}
                              </Typography>
                            </Box>
                          }
                        />
                      </Paper>
                    ))}
                  </RadioGroup>
                </FormControl>
              </Grid>
              
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Zone Name"
                  placeholder="example.com"
                  value={zoneData.name}
                  onChange={(e) => setZoneData({ ...zoneData, name: e.target.value })}
                  error={!!errors.name}
                  helperText={errors.name || 'Enter your domain name without www'}
                  InputProps={{
                    endAdornment: (
                      <Tooltip title="The domain name for your DNS zone">
                        <IconButton size="small">
                          <HelpIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    ),
                  }}
                />
              </Grid>
              
              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel>Zone Type</InputLabel>
                  <Select
                    value={zoneData.type}
                    label="Zone Type"
                    onChange={(e) => setZoneData({ ...zoneData, type: e.target.value })}
                  >
                    <MenuItem value="primary">Primary (Master)</MenuItem>
                    <MenuItem value="secondary">Secondary (Slave)</MenuItem>
                  </Select>
                  <FormHelperText>Primary zones are authoritative</FormHelperText>
                </FormControl>
              </Grid>
              
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  type="number"
                  label="Default TTL (seconds)"
                  value={zoneData.ttl}
                  onChange={(e) => setZoneData({ ...zoneData, ttl: parseInt(e.target.value) })}
                  helperText="Time to live for DNS records"
                />
              </Grid>
              
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Contact Email"
                  placeholder="admin@example.com"
                  value={zoneData.contactEmail}
                  onChange={(e) => setZoneData({ ...zoneData, contactEmail: e.target.value })}
                  error={!!errors.contactEmail}
                  helperText={errors.contactEmail || 'Administrative contact for this zone'}
                />
              </Grid>
            </Grid>
          </Box>
        );
        
      case 1:
        return (
          <Box sx={{ mt: 2 }}>
            <Alert severity="info" sx={{ mb: 2 }}>
              Nameservers are DNS servers that will respond to queries for your domain.
              You need at least 2 nameservers for redundancy.
            </Alert>
            
            {zoneData.type === 'primary' && (
              <TextField
                fullWidth
                label="Primary Nameserver"
                placeholder="ns1.example.com"
                value={zoneData.primaryNS}
                onChange={(e) => setZoneData({ ...zoneData, primaryNS: e.target.value })}
                error={!!errors.primaryNS}
                helperText={errors.primaryNS || 'The main authoritative nameserver'}
                sx={{ mb: 3 }}
              />
            )}
            
            <Typography variant="subtitle1" sx={{ mb: 2 }}>
              Additional Nameservers
            </Typography>
            
            {zoneData.nameservers.map((ns, index) => (
              <Box key={index} sx={{ display: 'flex', gap: 1, mb: 2 }}>
                <TextField
                  fullWidth
                  label={`Nameserver ${index + 1}`}
                  placeholder={`ns${index + 2}.example.com`}
                  value={ns}
                  onChange={(e) => updateNameserver(index, e.target.value)}
                />
                <IconButton
                  onClick={() => removeNameserver(index)}
                  disabled={zoneData.nameservers.length <= 1}
                >
                  <DeleteIcon />
                </IconButton>
              </Box>
            ))}
            
            <Button
              startIcon={<AddIcon />}
              onClick={addNameserver}
              variant="outlined"
              sx={{ mt: 1 }}
            >
              Add Nameserver
            </Button>
            
            {errors.nameservers && (
              <Typography color="error" variant="caption" sx={{ display: 'block', mt: 1 }}>
                {errors.nameservers}
              </Typography>
            )}
          </Box>
        );
        
      case 2:
        return (
          <Box sx={{ mt: 2 }}>
            <Typography variant="h6" sx={{ mb: 2 }}>
              Advanced Options
            </Typography>
            
            <Paper sx={{ p: 2, mb: 2 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
                <Box>
                  <Typography variant="subtitle1">
                    Enable DNSSEC
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Add cryptographic signatures for enhanced security
                  </Typography>
                </Box>
                <Switch
                  checked={zoneData.dnssecEnabled}
                  onChange={(e) => setZoneData({ ...zoneData, dnssecEnabled: e.target.checked })}
                />
              </Box>
              {zoneData.dnssecEnabled && (
                <Alert severity="info" sx={{ mt: 2 }}>
                  DNSSEC will be configured after zone creation. You'll need to add DS records at your registrar.
                </Alert>
              )}
            </Paper>
            
            <Paper sx={{ p: 2, mb: 2 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
                <Box>
                  <Typography variant="subtitle1">
                    Enable GeoDNS
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Serve different responses based on geographic location
                  </Typography>
                </Box>
                <Switch
                  checked={zoneData.geoEnabled}
                  onChange={(e) => setZoneData({ ...zoneData, geoEnabled: e.target.checked })}
                />
              </Box>
              {zoneData.geoEnabled && (
                <Alert severity="info" sx={{ mt: 2 }}>
                  Geographic routing policies can be configured after zone creation.
                </Alert>
              )}
            </Paper>
            
            <Alert severity="success" sx={{ mt: 3 }}>
              <Typography variant="subtitle2" sx={{ mb: 1 }}>
                Quick Tips:
              </Typography>
              <ul style={{ margin: 0, paddingLeft: 20 }}>
                <li>DNSSEC is recommended for zones handling sensitive data</li>
                <li>GeoDNS improves performance by routing users to nearest servers</li>
                <li>You can always enable these features later</li>
              </ul>
            </Alert>
          </Box>
        );
        
      case 3:
        return (
          <Box sx={{ mt: 2 }}>
            <Typography variant="h6" sx={{ mb: 2 }}>
              Review Your Configuration
            </Typography>
            
            <Paper sx={{ p: 2 }}>
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Zone Name
                  </Typography>
                  <Typography variant="body1" sx={{ mb: 2 }}>
                    {zoneData.name}
                  </Typography>
                </Grid>
                
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Zone Type
                  </Typography>
                  <Typography variant="body1" sx={{ mb: 2 }}>
                    {zoneData.type === 'primary' ? 'Primary (Master)' : 'Secondary (Slave)'}
                  </Typography>
                </Grid>
                
                <Grid item xs={6}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Default TTL
                  </Typography>
                  <Typography variant="body1" sx={{ mb: 2 }}>
                    {zoneData.ttl} seconds
                  </Typography>
                </Grid>
                
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Template
                  </Typography>
                  <Typography variant="body1" sx={{ mb: 2 }}>
                    {templates.find(t => t.value === zoneData.template)?.label}
                  </Typography>
                </Grid>
                
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Nameservers
                  </Typography>
                  <Box sx={{ mb: 2 }}>
                    {zoneData.primaryNS && (
                      <Chip label={zoneData.primaryNS} size="small" sx={{ mr: 1, mb: 1 }} />
                    )}
                    {zoneData.nameservers.filter(ns => ns).map((ns, index) => (
                      <Chip key={index} label={ns} size="small" sx={{ mr: 1, mb: 1 }} />
                    ))}
                  </Box>
                </Grid>
                
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Advanced Features
                  </Typography>
                  <Box>
                    {zoneData.dnssecEnabled && (
                      <Chip label="DNSSEC Enabled" color="success" size="small" sx={{ mr: 1 }} />
                    )}
                    {zoneData.geoEnabled && (
                      <Chip label="GeoDNS Enabled" color="success" size="small" sx={{ mr: 1 }} />
                    )}
                    {!zoneData.dnssecEnabled && !zoneData.geoEnabled && (
                      <Typography variant="body2" color="text.secondary">
                        None selected
                      </Typography>
                    )}
                  </Box>
                </Grid>
              </Grid>
            </Paper>
            
            <Alert severity="info" sx={{ mt: 2 }}>
              After creating the zone, you'll be able to add DNS records and configure additional settings.
            </Alert>
          </Box>
        );
        
      default:
        return null;
    }
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="md"
      fullWidth
      PaperProps={{
        sx: { minHeight: '60vh' }
      }}
    >
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          Create DNS Zone
          <Tooltip title="This wizard will guide you through creating a new DNS zone">
            <IconButton size="small">
              <HelpIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
      </DialogTitle>
      
      <DialogContent>
        <Stepper activeStep={activeStep} orientation="vertical">
          {steps.map((label, index) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
              <StepContent>
                {renderStepContent(index)}
                <Box sx={{ mt: 3 }}>
                  <Button
                    variant="contained"
                    onClick={index === steps.length - 1 ? handleComplete : handleNext}
                    sx={{ mr: 1 }}
                  >
                    {index === steps.length - 1 ? 'Create Zone' : 'Continue'}
                  </Button>
                  {index > 0 && (
                    <Button onClick={handleBack}>
                      Back
                    </Button>
                  )}
                </Box>
              </StepContent>
            </Step>
          ))}
        </Stepper>
      </DialogContent>
      
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
      </DialogActions>
    </Dialog>
  );
};

export default DNSZoneWizard;