import React, { useState, useEffect } from 'react';
import {
  Snackbar,
  Alert,
  Button,
  Box,
  Typography
} from '@mui/material';
import { Refresh as RefreshIcon } from '@mui/icons-material';

export const UpdateNotification: React.FC = () => {
  const [showUpdateNotification, setShowUpdateNotification] = useState(false);
  const [registration, setRegistration] = useState<ServiceWorkerRegistration | null>(null);

  useEffect(() => {
    // Listen for service worker update events
    const handleSWUpdate = (event: CustomEvent) => {
      setRegistration(event.detail);
      setShowUpdateNotification(true);
    };

    window.addEventListener('sw-update' as any, handleSWUpdate);

    return () => {
      window.removeEventListener('sw-update' as any, handleSWUpdate);
    };
  }, []);

  const handleUpdate = () => {
    if (registration && registration.waiting) {
      // Tell the service worker to skip waiting
      registration.waiting.postMessage({ type: 'SKIP_WAITING' });
      
      // Listen for the controlling service worker to change
      navigator.serviceWorker.addEventListener('controllerchange', () => {
        window.location.reload();
      });
    }
  };

  const handleDismiss = () => {
    setShowUpdateNotification(false);
  };

  return (
    <Snackbar
      open={showUpdateNotification}
      anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
    >
      <Alert
        severity="info"
        action={
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button 
              size="small" 
              color="inherit" 
              onClick={handleDismiss}
            >
              Later
            </Button>
            <Button 
              size="small" 
              variant="contained" 
              color="primary"
              startIcon={<RefreshIcon />}
              onClick={handleUpdate}
            >
              Update
            </Button>
          </Box>
        }
      >
        <Box>
          <Typography variant="body2" sx={{ fontWeight: 500 }}>
            New version available!
          </Typography>
          <Typography variant="caption" color="text.secondary">
            Click update to get the latest features and improvements
          </Typography>
        </Box>
      </Alert>
    </Snackbar>
  );
};