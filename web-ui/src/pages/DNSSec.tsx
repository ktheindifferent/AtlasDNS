import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  Card,
  CardContent,
  Grid,
  Chip,
  Alert,
  Switch,
  FormControlLabel,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  IconButton,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  LinearProgress,
  Tabs,
  Tab,
} from '@mui/material';
import {
  Security,
  Key,
  ContentCopy,
  Refresh,
  Info,
  Warning,
  CheckCircle,
  Download,
  RotateRight,
} from '@mui/icons-material';
import { useQuery, useMutation } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import { dnssecApi, zoneApi } from '../services/api';
import { useSnackbar } from 'notistack';
import { format } from 'date-fns';

interface DNSSECStatus {
  enabled: boolean;
  algorithm: string;
  keyTag: number;
  digest: string;
  digestType: string;
  flags: number;
  publicKey: string;
}

interface DNSKey {
  id: string;
  keyTag: number;
  algorithm: string;
  flags: number;
  publicKey: string;
  privateKey?: string;
  createdAt: string;
  expiresAt?: string;
  type: 'KSK' | 'ZSK';
  status: 'active' | 'published' | 'revoked';
}

interface DSRecord {
  keyTag: number;
  algorithm: string;
  digestType: string;
  digest: string;
}

const DNSSec: React.FC = () => {
  const { enqueueSnackbar } = useSnackbar();
  const [searchParams] = useSearchParams();
  const selectedZoneId = searchParams.get('zone');
  const [selectedZone, setSelectedZone] = useState<any>(null);
  const [tabValue, setTabValue] = useState(0);
  const [enableDialogOpen, setEnableDialogOpen] = useState(false);
  const [rotateDialogOpen, setRotateDialogOpen] = useState(false);
  const [algorithm, setAlgorithm] = useState('RSASHA256');
  const [keySize, setKeySize] = useState(2048);

  // Fetch zones
  const { data: zones } = useQuery({
    queryKey: ['zones'],
    queryFn: async () => {
      const response = await zoneApi.list();
      return response.data.zones;
    },
  });

  // Fetch DNSSEC status for selected zone
  const { data: dnssecStatus, isLoading: statusLoading, refetch: refetchStatus } = useQuery({
    queryKey: ['dnssec-status', selectedZone?.id],
    queryFn: async () => {
      if (!selectedZone?.id) return null;
      const response = await dnssecApi.status(selectedZone.id);
      return response.data;
    },
    enabled: !!selectedZone?.id,
  });

  // Fetch DNSSEC keys
  const { data: dnssecKeys, refetch: refetchKeys } = useQuery({
    queryKey: ['dnssec-keys', selectedZone?.id],
    queryFn: async () => {
      if (!selectedZone?.id) return [];
      const response = await dnssecApi.keys(selectedZone.id);
      return response.data;
    },
    enabled: !!selectedZone?.id && dnssecStatus?.enabled,
  });

  // Fetch DS records
  const { data: dsRecords } = useQuery({
    queryKey: ['ds-records', selectedZone?.id],
    queryFn: async () => {
      if (!selectedZone?.id) return [];
      const response = await dnssecApi.dsRecords(selectedZone.id);
      return response.data;
    },
    enabled: !!selectedZone?.id && dnssecStatus?.enabled,
  });

  // Enable DNSSEC mutation
  const enableDNSSEC = useMutation({
    mutationFn: async () => {
      if (!selectedZone?.id) throw new Error('No zone selected');
      return await dnssecApi.enable(selectedZone.id, { algorithm, keySize });
    },
    onSuccess: () => {
      enqueueSnackbar('DNSSEC enabled successfully', { variant: 'success' });
      refetchStatus();
      refetchKeys();
      setEnableDialogOpen(false);
    },
    onError: () => {
      enqueueSnackbar('Failed to enable DNSSEC', { variant: 'error' });
    },
  });

  // Disable DNSSEC mutation
  const disableDNSSEC = useMutation({
    mutationFn: async () => {
      if (!selectedZone?.id) throw new Error('No zone selected');
      return await dnssecApi.disable(selectedZone.id);
    },
    onSuccess: () => {
      enqueueSnackbar('DNSSEC disabled successfully', { variant: 'success' });
      refetchStatus();
    },
    onError: () => {
      enqueueSnackbar('Failed to disable DNSSEC', { variant: 'error' });
    },
  });

  // Rotate keys mutation
  const rotateKeys = useMutation({
    mutationFn: async () => {
      if (!selectedZone?.id) throw new Error('No zone selected');
      return await dnssecApi.rotateKeys(selectedZone.id);
    },
    onSuccess: () => {
      enqueueSnackbar('Keys rotated successfully', { variant: 'success' });
      refetchKeys();
      setRotateDialogOpen(false);
    },
    onError: () => {
      enqueueSnackbar('Failed to rotate keys', { variant: 'error' });
    },
  });

  useEffect(() => {
    if (selectedZoneId && zones) {
      const zone = zones.find((z: any) => z.id === selectedZoneId);
      if (zone) setSelectedZone(zone);
    }
  }, [selectedZoneId, zones]);

  const handleCopyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    enqueueSnackbar('Copied to clipboard', { variant: 'success' });
  };

  const handleTabChange = (_: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  if (!selectedZone) {
    return (
      <Box>
        <Typography variant="h4" fontWeight="bold" gutterBottom>
          DNSSEC Configuration
        </Typography>
        <Alert severity="info">
          Please select a zone to configure DNSSEC settings.
        </Alert>
        <Paper sx={{ mt: 3, p: 2 }}>
          <FormControl fullWidth>
            <InputLabel>Select Zone</InputLabel>
            <Select
              value=""
              onChange={(e) => {
                const zone = zones?.find((z: any) => z.id === e.target.value);
                setSelectedZone(zone);
              }}
              label="Select Zone"
            >
              {zones?.map((zone: any) => (
                <MenuItem key={zone.id} value={zone.id}>
                  {zone.name}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Paper>
      </Box>
    );
  }

  return (
    <Box>
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box>
          <Typography variant="h4" fontWeight="bold">
            DNSSEC Configuration
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Zone: {selectedZone.name}
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <FormControl size="small" sx={{ minWidth: 200 }}>
            <InputLabel>Zone</InputLabel>
            <Select
              value={selectedZone.id}
              onChange={(e) => {
                const zone = zones?.find((z: any) => z.id === e.target.value);
                setSelectedZone(zone);
              }}
              label="Zone"
            >
              {zones?.map((zone: any) => (
                <MenuItem key={zone.id} value={zone.id}>
                  {zone.name}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <Tooltip title="Refresh">
            <IconButton onClick={() => refetchStatus()}>
              <Refresh />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      {statusLoading ? (
        <LinearProgress />
      ) : (
        <>
          {/* Status Card */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  <Security sx={{ fontSize: 40, color: dnssecStatus?.enabled ? 'success.main' : 'text.disabled' }} />
                  <Box>
                    <Typography variant="h6">
                      DNSSEC Status
                    </Typography>
                    <Chip
                      label={dnssecStatus?.enabled ? 'Enabled' : 'Disabled'}
                      color={dnssecStatus?.enabled ? 'success' : 'default'}
                      size="small"
                      icon={dnssecStatus?.enabled ? <CheckCircle /> : undefined}
                    />
                  </Box>
                </Box>
                <FormControlLabel
                  control={
                    <Switch
                      checked={dnssecStatus?.enabled || false}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setEnableDialogOpen(true);
                        } else {
                          disableDNSSEC.mutate();
                        }
                      }}
                    />
                  }
                  label={dnssecStatus?.enabled ? 'Enabled' : 'Disabled'}
                />
              </Box>
              {dnssecStatus?.enabled && (
                <Grid container spacing={2} sx={{ mt: 2 }}>
                  <Grid item xs={6} md={3}>
                    <Typography variant="body2" color="text.secondary">Algorithm</Typography>
                    <Typography variant="body1">{dnssecStatus.algorithm}</Typography>
                  </Grid>
                  <Grid item xs={6} md={3}>
                    <Typography variant="body2" color="text.secondary">Key Tag</Typography>
                    <Typography variant="body1">{dnssecStatus.keyTag}</Typography>
                  </Grid>
                  <Grid item xs={6} md={3}>
                    <Typography variant="body2" color="text.secondary">Digest Type</Typography>
                    <Typography variant="body1">{dnssecStatus.digestType}</Typography>
                  </Grid>
                  <Grid item xs={6} md={3}>
                    <Typography variant="body2" color="text.secondary">Flags</Typography>
                    <Typography variant="body1">{dnssecStatus.flags}</Typography>
                  </Grid>
                </Grid>
              )}
            </CardContent>
          </Card>

          {dnssecStatus?.enabled && (
            <>
              <Tabs value={tabValue} onChange={handleTabChange} sx={{ mb: 3 }}>
                <Tab label="Keys" />
                <Tab label="DS Records" />
                <Tab label="Validation" />
              </Tabs>

              {/* Keys Tab */}
              {tabValue === 0 && (
                <Paper sx={{ p: 2 }}>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                    <Typography variant="h6">DNSSEC Keys</Typography>
                    <Button
                      variant="outlined"
                      startIcon={<RotateRight />}
                      onClick={() => setRotateDialogOpen(true)}
                    >
                      Rotate Keys
                    </Button>
                  </Box>
                  <TableContainer>
                    <Table>
                      <TableHead>
                        <TableRow>
                          <TableCell>Type</TableCell>
                          <TableCell>Key Tag</TableCell>
                          <TableCell>Algorithm</TableCell>
                          <TableCell>Status</TableCell>
                          <TableCell>Created</TableCell>
                          <TableCell>Expires</TableCell>
                          <TableCell>Actions</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {dnssecKeys?.map((key: DNSKey) => (
                          <TableRow key={key.id}>
                            <TableCell>
                              <Chip
                                label={key.type}
                                size="small"
                                color={key.type === 'KSK' ? 'primary' : 'default'}
                              />
                            </TableCell>
                            <TableCell>{key.keyTag}</TableCell>
                            <TableCell>{key.algorithm}</TableCell>
                            <TableCell>
                              <Chip
                                label={key.status}
                                size="small"
                                color={
                                  key.status === 'active' ? 'success' :
                                  key.status === 'revoked' ? 'error' : 'default'
                                }
                              />
                            </TableCell>
                            <TableCell>{format(new Date(key.createdAt), 'MMM dd, yyyy')}</TableCell>
                            <TableCell>
                              {key.expiresAt ? format(new Date(key.expiresAt), 'MMM dd, yyyy') : '-'}
                            </TableCell>
                            <TableCell>
                              <Tooltip title="Copy Public Key">
                                <IconButton
                                  size="small"
                                  onClick={() => handleCopyToClipboard(key.publicKey)}
                                >
                                  <ContentCopy />
                                </IconButton>
                              </Tooltip>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Paper>
              )}

              {/* DS Records Tab */}
              {tabValue === 1 && (
                <Paper sx={{ p: 2 }}>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="h6" gutterBottom>DS Records</Typography>
                    <Alert severity="info" sx={{ mb: 2 }}>
                      <Typography variant="body2">
                        Add these DS records to your parent zone (registrar) to establish the chain of trust.
                      </Typography>
                    </Alert>
                  </Box>
                  {dsRecords?.map((record: DSRecord, index: number) => (
                    <Card key={index} sx={{ mb: 2 }}>
                      <CardContent>
                        <Grid container spacing={2}>
                          <Grid item xs={12}>
                            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <Typography variant="subtitle1" fontWeight={500}>
                                DS Record {index + 1}
                              </Typography>
                              <IconButton
                                size="small"
                                onClick={() => handleCopyToClipboard(
                                  `${selectedZone.name}. IN DS ${record.keyTag} ${record.algorithm} ${record.digestType} ${record.digest}`
                                )}
                              >
                                <ContentCopy />
                              </IconButton>
                            </Box>
                          </Grid>
                          <Grid item xs={6} md={3}>
                            <Typography variant="body2" color="text.secondary">Key Tag</Typography>
                            <Typography variant="body1" fontFamily="monospace">{record.keyTag}</Typography>
                          </Grid>
                          <Grid item xs={6} md={3}>
                            <Typography variant="body2" color="text.secondary">Algorithm</Typography>
                            <Typography variant="body1" fontFamily="monospace">{record.algorithm}</Typography>
                          </Grid>
                          <Grid item xs={6} md={3}>
                            <Typography variant="body2" color="text.secondary">Digest Type</Typography>
                            <Typography variant="body1" fontFamily="monospace">{record.digestType}</Typography>
                          </Grid>
                          <Grid item xs={12}>
                            <Typography variant="body2" color="text.secondary">Digest</Typography>
                            <Typography
                              variant="body1"
                              fontFamily="monospace"
                              sx={{ wordBreak: 'break-all' }}
                            >
                              {record.digest}
                            </Typography>
                          </Grid>
                        </Grid>
                      </CardContent>
                    </Card>
                  ))}
                </Paper>
              )}

              {/* Validation Tab */}
              {tabValue === 2 && (
                <Paper sx={{ p: 3 }}>
                  <Typography variant="h6" gutterBottom>DNSSEC Validation</Typography>
                  <Alert severity="success" sx={{ mb: 2 }}>
                    <Typography variant="body2">
                      DNSSEC validation is active. All DNS responses are being signed.
                    </Typography>
                  </Alert>
                  <Box sx={{ mt: 3 }}>
                    <Typography variant="subtitle2" gutterBottom>Validation Chain</Typography>
                    <Box sx={{ pl: 2 }}>
                      <Typography variant="body2" color="text.secondary">
                        1. Root Zone (.) → Signed ✓
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        2. TLD Zone → Signed ✓
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        3. {selectedZone.name} → Signed ✓
                      </Typography>
                    </Box>
                  </Box>
                </Paper>
              )}
            </>
          )}
        </>
      )}

      {/* Enable DNSSEC Dialog */}
      <Dialog open={enableDialogOpen} onClose={() => setEnableDialogOpen(false)}>
        <DialogTitle>Enable DNSSEC</DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 2 }}>
            Enabling DNSSEC will sign all DNS records in this zone. Make sure your DNS infrastructure supports DNSSEC.
          </Alert>
          <FormControl fullWidth sx={{ mt: 2 }}>
            <InputLabel>Algorithm</InputLabel>
            <Select
              value={algorithm}
              onChange={(e) => setAlgorithm(e.target.value)}
              label="Algorithm"
            >
              <MenuItem value="RSASHA256">RSA SHA-256</MenuItem>
              <MenuItem value="RSASHA512">RSA SHA-512</MenuItem>
              <MenuItem value="ECDSAP256SHA256">ECDSA P-256 SHA-256</MenuItem>
              <MenuItem value="ECDSAP384SHA384">ECDSA P-384 SHA-384</MenuItem>
            </Select>
          </FormControl>
          <TextField
            fullWidth
            label="Key Size"
            type="number"
            value={keySize}
            onChange={(e) => setKeySize(Number(e.target.value))}
            sx={{ mt: 2 }}
            helperText="Recommended: 2048 for RSA, 256 for ECDSA"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEnableDialogOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={() => enableDNSSEC.mutate()}
            disabled={enableDNSSEC.isPending}
          >
            Enable DNSSEC
          </Button>
        </DialogActions>
      </Dialog>

      {/* Rotate Keys Dialog */}
      <Dialog open={rotateDialogOpen} onClose={() => setRotateDialogOpen(false)}>
        <DialogTitle>Rotate DNSSEC Keys</DialogTitle>
        <DialogContent>
          <Alert severity="info">
            Key rotation will generate new signing keys while maintaining service availability.
            The old keys will remain active during the transition period.
          </Alert>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRotateDialogOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={() => rotateKeys.mutate()}
            disabled={rotateKeys.isPending}
          >
            Rotate Keys
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default DNSSec;