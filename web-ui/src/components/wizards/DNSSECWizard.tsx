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
  Paper,
  Grid,
  Chip,
  IconButton,
  Tooltip,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  FormHelperText,
} from '@mui/material';
import {
  Help as HelpIcon,
  Security as SecurityIcon,
  VpnKey as KeyIcon,
  Check as CheckIcon,
  ContentCopy as CopyIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
} from '@mui/icons-material';
import { useOnboarding } from '../../contexts/OnboardingContext';

interface DNSSECWizardProps {
  open: boolean;
  onClose: () => void;
  onComplete: (dnssecData: any) => void;
  zoneName: string;
}

const DNSSECWizard: React.FC<DNSSECWizardProps> = ({ 
  open, 
  onClose, 
  onComplete, 
  zoneName 
}) => {
  const { updateProgress } = useOnboarding();
  const [activeStep, setActiveStep] = useState(0);
  const [dnssecData, setDnssecData] = useState({
    algorithm: 'RSASHA256',
    kskKeySize: 2048,
    zskKeySize: 1024,
    kskRotationPeriod: 365,
    zskRotationPeriod: 30,
    nsec3: true,
    nsec3Iterations: 10,
    nsec3Salt: '',
    autoRollover: true,
  });

  const steps = [
    'Understanding DNSSEC',
    'Key Configuration',
    'Security Options',
    'DS Records',
    'Activation',
  ];

  const algorithms = [
    { value: 'RSASHA256', label: 'RSA SHA-256', recommended: true },
    { value: 'RSASHA512', label: 'RSA SHA-512', recommended: false },
    { value: 'ECDSAP256SHA256', label: 'ECDSA P-256 SHA-256', recommended: true },
    { value: 'ECDSAP384SHA384', label: 'ECDSA P-384 SHA-384', recommended: false },
    { value: 'ED25519', label: 'ED25519', recommended: true },
  ];

  const handleNext = () => {
    setActiveStep((prevStep) => prevStep + 1);
  };

  const handleBack = () => {
    setActiveStep((prevStep) => prevStep - 1);
  };

  const handleComplete = () => {
    updateProgress('wizard', 'dnssec-configuration');
    onComplete(dnssecData);
    onClose();
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const generateDSRecord = () => {
    // This would normally be generated based on the actual DNSSEC keys
    return {
      keyTag: '12345',
      algorithm: dnssecData.algorithm,
      digestType: 'SHA-256',
      digest: '1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF',
    };
  };

  const renderStepContent = (step: number) => {
    switch (step) {
      case 0:
        return (
          <Box sx={{ mt: 2 }}>
            <Alert severity="info" sx={{ mb: 3 }}>
              DNSSEC (Domain Name System Security Extensions) adds a layer of security to your DNS 
              by digitally signing your DNS records.
            </Alert>

            <Typography variant="h6" sx={{ mb: 2 }}>
              Why Enable DNSSEC?
            </Typography>

            <List>
              <ListItem>
                <ListItemIcon>
                  <SecurityIcon color="primary" />
                </ListItemIcon>
                <ListItemText
                  primary="Prevents DNS Spoofing"
                  secondary="Protects against cache poisoning and man-in-the-middle attacks"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon>
                  <CheckIcon color="success" />
                </ListItemIcon>
                <ListItemText
                  primary="Data Integrity"
                  secondary="Ensures DNS responses haven't been tampered with"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon>
                  <KeyIcon color="primary" />
                </ListItemIcon>
                <ListItemText
                  primary="Authentication"
                  secondary="Verifies that DNS responses come from authorized servers"
                />
              </ListItem>
            </List>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ mb: 2 }}>
              How DNSSEC Works
            </Typography>

            <Paper sx={{ p: 2, backgroundColor: 'grey.50' }}>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <Chip label="1" size="small" color="primary" sx={{ mr: 1 }} />
                    <Typography variant="subtitle2">Zone Signing Key (ZSK)</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    Signs individual DNS records in your zone
                  </Typography>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <Chip label="2" size="small" color="primary" sx={{ mr: 1 }} />
                    <Typography variant="subtitle2">Key Signing Key (KSK)</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    Signs the ZSK to establish chain of trust
                  </Typography>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <Chip label="3" size="small" color="primary" sx={{ mr: 1 }} />
                    <Typography variant="subtitle2">DS Record</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    Published at parent zone (registrar) to link chain of trust
                  </Typography>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <Chip label="4" size="small" color="primary" sx={{ mr: 1 }} />
                    <Typography variant="subtitle2">Validation</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    Resolvers verify signatures to ensure authenticity
                  </Typography>
                </Grid>
              </Grid>
            </Paper>

            <Alert severity="warning" sx={{ mt: 3 }}>
              <Typography variant="subtitle2" sx={{ mb: 1 }}>
                Important Considerations:
              </Typography>
              <ul style={{ margin: 0, paddingLeft: 20 }}>
                <li>Slightly increases DNS response size</li>
                <li>Requires regular key rotation for security</li>
                <li>Must update DS records at registrar when rotating KSK</li>
              </ul>
            </Alert>
          </Box>
        );

      case 1:
        return (
          <Box sx={{ mt: 2 }}>
            <Typography variant="h6" sx={{ mb: 2 }}>
              Configure DNSSEC Keys
            </Typography>

            <FormControl fullWidth sx={{ mb: 3 }}>
              <InputLabel>Signing Algorithm</InputLabel>
              <Select
                value={dnssecData.algorithm}
                label="Signing Algorithm"
                onChange={(e) => setDnssecData({ ...dnssecData, algorithm: e.target.value })}
              >
                {algorithms.map(algo => (
                  <MenuItem key={algo.value} value={algo.value}>
                    {algo.label}
                    {algo.recommended && (
                      <Chip 
                        label="Recommended" 
                        size="small" 
                        color="success" 
                        sx={{ ml: 1 }} 
                      />
                    )}
                  </MenuItem>
                ))}
              </Select>
              <FormHelperText>
                RSA SHA-256 is widely supported. ECDSA and ED25519 offer smaller keys.
              </FormHelperText>
            </FormControl>

            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle1" sx={{ mb: 2 }}>
                    Key Signing Key (KSK)
                  </Typography>
                  
                  <TextField
                    fullWidth
                    type="number"
                    label="Key Size (bits)"
                    value={dnssecData.kskKeySize}
                    onChange={(e) => setDnssecData({ 
                      ...dnssecData, 
                      kskKeySize: parseInt(e.target.value) 
                    })}
                    helperText="2048 bits recommended for RSA"
                    sx={{ mb: 2 }}
                  />
                  
                  <TextField
                    fullWidth
                    type="number"
                    label="Rotation Period (days)"
                    value={dnssecData.kskRotationPeriod}
                    onChange={(e) => setDnssecData({ 
                      ...dnssecData, 
                      kskRotationPeriod: parseInt(e.target.value) 
                    })}
                    helperText="Typically rotated annually"
                  />
                </Paper>
              </Grid>

              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle1" sx={{ mb: 2 }}>
                    Zone Signing Key (ZSK)
                  </Typography>
                  
                  <TextField
                    fullWidth
                    type="number"
                    label="Key Size (bits)"
                    value={dnssecData.zskKeySize}
                    onChange={(e) => setDnssecData({ 
                      ...dnssecData, 
                      zskKeySize: parseInt(e.target.value) 
                    })}
                    helperText="1024 bits recommended for RSA"
                    sx={{ mb: 2 }}
                  />
                  
                  <TextField
                    fullWidth
                    type="number"
                    label="Rotation Period (days)"
                    value={dnssecData.zskRotationPeriod}
                    onChange={(e) => setDnssecData({ 
                      ...dnssecData, 
                      zskRotationPeriod: parseInt(e.target.value) 
                    })}
                    helperText="Typically rotated monthly"
                  />
                </Paper>
              </Grid>
            </Grid>

            <FormControlLabel
              control={
                <Radio
                  checked={dnssecData.autoRollover}
                  onChange={(e) => setDnssecData({ 
                    ...dnssecData, 
                    autoRollover: e.target.checked 
                  })}
                />
              }
              label="Enable automatic key rollover"
              sx={{ mt: 2 }}
            />

            <Alert severity="info" sx={{ mt: 2 }}>
              Automatic key rollover ensures your keys are rotated regularly without manual intervention.
            </Alert>
          </Box>
        );

      case 2:
        return (
          <Box sx={{ mt: 2 }}>
            <Typography variant="h6" sx={{ mb: 2 }}>
              Security Options
            </Typography>

            <Paper sx={{ p: 2, mb: 3 }}>
              <FormControlLabel
                control={
                  <Radio
                    checked={dnssecData.nsec3}
                    onChange={(e) => setDnssecData({ 
                      ...dnssecData, 
                      nsec3: e.target.checked 
                    })}
                  />
                }
                label={
                  <Box>
                    <Typography variant="subtitle1">Enable NSEC3</Typography>
                    <Typography variant="caption" color="text.secondary">
                      Prevents zone enumeration (recommended for privacy)
                    </Typography>
                  </Box>
                }
              />

              {dnssecData.nsec3 && (
                <Box sx={{ mt: 2, pl: 4 }}>
                  <TextField
                    fullWidth
                    type="number"
                    label="NSEC3 Iterations"
                    value={dnssecData.nsec3Iterations}
                    onChange={(e) => setDnssecData({ 
                      ...dnssecData, 
                      nsec3Iterations: parseInt(e.target.value) 
                    })}
                    helperText="10-20 iterations recommended"
                    sx={{ mb: 2 }}
                  />
                  
                  <TextField
                    fullWidth
                    label="NSEC3 Salt (optional)"
                    placeholder="Leave empty for random salt"
                    value={dnssecData.nsec3Salt}
                    onChange={(e) => setDnssecData({ 
                      ...dnssecData, 
                      nsec3Salt: e.target.value 
                    })}
                    helperText="Random salt will be generated if left empty"
                  />
                </Box>
              )}
            </Paper>

            <Alert severity="info" sx={{ mb: 2 }}>
              <Typography variant="subtitle2" sx={{ mb: 1 }}>
                NSEC vs NSEC3:
              </Typography>
              <ul style={{ margin: 0, paddingLeft: 20 }}>
                <li><strong>NSEC:</strong> Proves non-existence of records but allows zone walking</li>
                <li><strong>NSEC3:</strong> Hashes domain names to prevent enumeration (recommended)</li>
              </ul>
            </Alert>

            <Paper sx={{ p: 2, backgroundColor: 'grey.50' }}>
              <Typography variant="subtitle1" sx={{ mb: 2 }}>
                Best Practices
              </Typography>
              <List dense>
                <ListItem>
                  <ListItemIcon>
                    <CheckIcon color="success" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary="Use NSEC3 to prevent zone enumeration" />
                </ListItem>
                <ListItem>
                  <ListItemIcon>
                    <CheckIcon color="success" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary="Enable automatic key rollover" />
                </ListItem>
                <ListItem>
                  <ListItemIcon>
                    <CheckIcon color="success" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary="Monitor DNSSEC validation status regularly" />
                </ListItem>
                <ListItem>
                  <ListItemIcon>
                    <CheckIcon color="success" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary="Keep DS records updated at registrar" />
                </ListItem>
              </List>
            </Paper>
          </Box>
        );

      case 3:
        return (
          <Box sx={{ mt: 2 }}>
            <Typography variant="h6" sx={{ mb: 2 }}>
              DS Records for {zoneName}
            </Typography>

            <Alert severity="warning" sx={{ mb: 3 }}>
              <Typography variant="subtitle2" sx={{ mb: 1 }}>
                Important: Add these DS records at your domain registrar
              </Typography>
              Without DS records at your registrar, DNSSEC validation will fail.
            </Alert>

            <Paper sx={{ p: 2, mb: 2, backgroundColor: 'grey.50' }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                <Typography variant="subtitle1">
                  DS Record
                </Typography>
                <IconButton 
                  onClick={() => {
                    const ds = generateDSRecord();
                    copyToClipboard(`${zoneName}. IN DS ${ds.keyTag} ${ds.algorithm} ${ds.digestType} ${ds.digest}`);
                  }}
                >
                  <CopyIcon />
                </IconButton>
              </Box>

              <Grid container spacing={2}>
                <Grid item xs={12} sm={6}>
                  <Typography variant="caption" color="text.secondary">
                    Key Tag
                  </Typography>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                    12345
                  </Typography>
                </Grid>
                <Grid item xs={12} sm={6}>
                  <Typography variant="caption" color="text.secondary">
                    Algorithm
                  </Typography>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                    {dnssecData.algorithm}
                  </Typography>
                </Grid>
                <Grid item xs={12} sm={6}>
                  <Typography variant="caption" color="text.secondary">
                    Digest Type
                  </Typography>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                    SHA-256
                  </Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">
                    Digest
                  </Typography>
                  <Typography 
                    variant="body2" 
                    sx={{ 
                      fontFamily: 'monospace',
                      wordBreak: 'break-all',
                      fontSize: '0.85rem'
                    }}
                  >
                    1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
                  </Typography>
                </Grid>
              </Grid>
            </Paper>

            <Typography variant="h6" sx={{ mb: 2, mt: 3 }}>
              Steps to Complete at Your Registrar:
            </Typography>

            <List>
              <ListItem>
                <ListItemIcon>
                  <Chip label="1" size="small" />
                </ListItemIcon>
                <ListItemText
                  primary="Log in to your domain registrar's control panel"
                  secondary="Common registrars: GoDaddy, Namecheap, Cloudflare, etc."
                />
              </ListItem>
              <ListItem>
                <ListItemIcon>
                  <Chip label="2" size="small" />
                </ListItemIcon>
                <ListItemText
                  primary="Navigate to DNS or DNSSEC settings"
                  secondary="Look for 'DNSSEC', 'DS Records', or 'Advanced DNS'"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon>
                  <Chip label="3" size="small" />
                </ListItemIcon>
                <ListItemText
                  primary="Add the DS record values shown above"
                  secondary="Copy each field exactly as shown"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon>
                  <Chip label="4" size="small" />
                </ListItemIcon>
                <ListItemText
                  primary="Save changes and wait for propagation"
                  secondary="May take up to 48 hours to fully propagate"
                />
              </ListItem>
            </List>

            <Alert severity="info" sx={{ mt: 2 }}>
              After adding DS records, you can verify DNSSEC validation using online tools like 
              DNSViz or Verisign's DNSSEC Analyzer.
            </Alert>
          </Box>
        );

      case 4:
        return (
          <Box sx={{ mt: 2 }}>
            <Typography variant="h6" sx={{ mb: 2 }}>
              Ready to Activate DNSSEC
            </Typography>

            <Alert severity="success" sx={{ mb: 3 }}>
              Your DNSSEC configuration is ready! Review the settings below before activation.
            </Alert>

            <Paper sx={{ p: 3 }}>
              <Typography variant="subtitle1" sx={{ mb: 2 }}>
                Configuration Summary
              </Typography>

              <Grid container spacing={2}>
                <Grid item xs={12} sm={6}>
                  <Typography variant="caption" color="text.secondary">
                    Zone
                  </Typography>
                  <Typography variant="body1" sx={{ mb: 2 }}>
                    {zoneName}
                  </Typography>
                </Grid>
                
                <Grid item xs={12} sm={6}>
                  <Typography variant="caption" color="text.secondary">
                    Algorithm
                  </Typography>
                  <Typography variant="body1" sx={{ mb: 2 }}>
                    {algorithms.find(a => a.value === dnssecData.algorithm)?.label}
                  </Typography>
                </Grid>

                <Grid item xs={12} sm={6}>
                  <Typography variant="caption" color="text.secondary">
                    KSK Configuration
                  </Typography>
                  <Typography variant="body2">
                    {dnssecData.kskKeySize} bits, {dnssecData.kskRotationPeriod} day rotation
                  </Typography>
                </Grid>

                <Grid item xs={12} sm={6}>
                  <Typography variant="caption" color="text.secondary">
                    ZSK Configuration
                  </Typography>
                  <Typography variant="body2">
                    {dnssecData.zskKeySize} bits, {dnssecData.zskRotationPeriod} day rotation
                  </Typography>
                </Grid>

                <Grid item xs={12}>
                  <Typography variant="caption" color="text.secondary">
                    Features
                  </Typography>
                  <Box sx={{ mt: 1 }}>
                    {dnssecData.nsec3 && (
                      <Chip label="NSEC3 Enabled" size="small" sx={{ mr: 1 }} />
                    )}
                    {dnssecData.autoRollover && (
                      <Chip label="Auto Rollover" size="small" sx={{ mr: 1 }} />
                    )}
                  </Box>
                </Grid>
              </Grid>
            </Paper>

            <Paper sx={{ p: 2, mt: 3, backgroundColor: 'info.lighter' }}>
              <Typography variant="subtitle1" sx={{ mb: 2 }}>
                What Happens Next?
              </Typography>
              <List dense>
                <ListItem>
                  <ListItemIcon>
                    <InfoIcon color="info" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary="Zone will be signed immediately upon activation" />
                </ListItem>
                <ListItem>
                  <ListItemIcon>
                    <InfoIcon color="info" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary="RRSIG records will be added to all existing records" />
                </ListItem>
                <ListItem>
                  <ListItemIcon>
                    <InfoIcon color="info" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary="DNSKEY records will be published in the zone" />
                </ListItem>
                <ListItem>
                  <ListItemIcon>
                    <InfoIcon color="info" fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary="Automatic key rotation will be scheduled" />
                </ListItem>
              </List>
            </Paper>

            <Alert severity="warning" sx={{ mt: 3 }}>
              Remember: DNSSEC won't be fully functional until you add the DS records at your registrar!
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
        sx: { minHeight: '70vh' }
      }}
    >
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <SecurityIcon color="primary" />
          Configure DNSSEC for {zoneName}
          <Tooltip title="This wizard will help you enable and configure DNSSEC for your zone">
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
                    {index === steps.length - 1 ? 'Activate DNSSEC' : 'Continue'}
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

export default DNSSECWizard;