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
  CircularProgress,
} from '@mui/material';
import { useDispatch } from 'react-redux';
import { AppDispatch } from '../../store';
import { cloneZone } from '../../store/slices/zonesSlice';
import { useSnackbar } from 'notistack';
import { Zone } from '../../store/slices/zonesSlice';
import { ContentCopy } from '@mui/icons-material';
import errorMonitoring from '../../services/errorMonitoring';

interface ZoneCloneDialogProps {
  open: boolean;
  onClose: () => void;
  zone: Zone | null;
}

const ZoneCloneDialog: React.FC<ZoneCloneDialogProps> = ({ open, onClose, zone }) => {
  const dispatch = useDispatch<AppDispatch>();
  const { enqueueSnackbar } = useSnackbar();
  const [newZoneName, setNewZoneName] = useState('');
  const [isCloning, setIsCloning] = useState(false);
  const [validationError, setValidationError] = useState('');

  React.useEffect(() => {
    if (zone && open) {
      setNewZoneName(`${zone.name}.clone`);
      setValidationError('');
    }
  }, [zone, open]);

  const validateZoneName = (name: string): boolean => {
    // Basic DNS zone name validation
    const dnsRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
    
    if (!name) {
      setValidationError('Zone name is required');
      return false;
    }
    
    if (!dnsRegex.test(name)) {
      setValidationError('Invalid DNS zone name format');
      return false;
    }
    
    if (name === zone?.name) {
      setValidationError('New zone name must be different from the original');
      return false;
    }
    
    setValidationError('');
    return true;
  };

  const handleClone = async () => {
    if (!zone || !validateZoneName(newZoneName)) {
      return;
    }

    setIsCloning(true);
    
    try {
      // Add breadcrumb for monitoring
      errorMonitoring.addBreadcrumb({
        message: `Cloning zone: ${zone.name} to ${newZoneName}`,
        category: 'zone-operations',
        level: 'info',
        data: { originalZone: zone.name, newZone: newZoneName },
      });

      await dispatch(cloneZone({ 
        zoneId: zone.id, 
        newName: newZoneName 
      })).unwrap();
      
      enqueueSnackbar(`Zone "${zone.name}" successfully cloned to "${newZoneName}"`, { 
        variant: 'success',
        autoHideDuration: 5000,
      });
      
      onClose();
      setNewZoneName('');
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to clone zone';
      
      // Log error to monitoring
      errorMonitoring.captureException(error instanceof Error ? error : new Error(errorMessage), {
        context: 'zone-clone',
        originalZone: zone.name,
        newZone: newZoneName,
      });
      
      enqueueSnackbar(errorMessage, { 
        variant: 'error',
        autoHideDuration: 5000,
      });
    } finally {
      setIsCloning(false);
    }
  };

  const handleClose = () => {
    if (!isCloning) {
      onClose();
      setNewZoneName('');
      setValidationError('');
    }
  };

  return (
    <Dialog 
      open={open} 
      onClose={handleClose}
      maxWidth="sm"
      fullWidth
    >
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <ContentCopy />
        Clone Zone
      </DialogTitle>
      <DialogContent>
        <Box sx={{ mt: 2 }}>
          {zone && (
            <>
              <Alert severity="info" sx={{ mb: 3 }}>
                This will create a new zone with all records and settings copied from "{zone.name}".
                The new zone will start in an inactive state until DNS propagation completes.
              </Alert>
              
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                Original zone: <strong>{zone.name}</strong>
              </Typography>
              
              <TextField
                autoFocus
                fullWidth
                label="New Zone Name"
                value={newZoneName}
                onChange={(e) => {
                  setNewZoneName(e.target.value);
                  validateZoneName(e.target.value);
                }}
                error={!!validationError}
                helperText={validationError || 'Enter a unique DNS zone name for the clone'}
                disabled={isCloning}
                sx={{ mt: 2 }}
                placeholder="example.com"
                inputProps={{
                  autoComplete: 'off',
                }}
              />

              <Box sx={{ mt: 2 }}>
                <Typography variant="caption" color="text.secondary">
                  The following will be cloned:
                </Typography>
                <ul style={{ margin: '8px 0', paddingLeft: '20px' }}>
                  <li><Typography variant="caption">All DNS records</Typography></li>
                  <li><Typography variant="caption">Zone settings (TTL, refresh, retry, etc.)</Typography></li>
                  <li><Typography variant="caption">DNSSEC configuration (if enabled)</Typography></li>
                </ul>
              </Box>
            </>
          )}
        </Box>
      </DialogContent>
      <DialogActions>
        <Button 
          onClick={handleClose} 
          disabled={isCloning}
        >
          Cancel
        </Button>
        <Button 
          onClick={handleClone}
          variant="contained"
          disabled={!zone || !newZoneName || !!validationError || isCloning}
          startIcon={isCloning ? <CircularProgress size={16} /> : <ContentCopy />}
        >
          {isCloning ? 'Cloning...' : 'Clone Zone'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ZoneCloneDialog;