import React, { useState, useEffect } from 'react';
import {
  Snackbar,
  Alert,
  Box,
  Typography,
  LinearProgress,
  Chip
} from '@mui/material';
import {
  WifiOff as OfflineIcon,
  Wifi as OnlineIcon,
  Sync as SyncIcon,
  CloudOff as CloudOffIcon
} from '@mui/icons-material';
import { useBackgroundSync } from '../services/backgroundSync';

export const OfflineIndicator: React.FC = () => {
  const [isOnline, setIsOnline] = useState(navigator.onLine);
  const [showStatus, setShowStatus] = useState(false);
  const [pendingCount, setPendingCount] = useState(0);
  const [isSyncing, setIsSyncing] = useState(false);
  const { getPendingCount } = useBackgroundSync();

  useEffect(() => {
    const updateOnlineStatus = () => {
      const online = navigator.onLine;
      setIsOnline(online);
      setShowStatus(true);
      
      if (online) {
        setIsSyncing(true);
        // Auto-hide online notification after 3 seconds
        setTimeout(() => {
          setShowStatus(false);
          setIsSyncing(false);
        }, 3000);
      }
    };

    const updatePendingCount = async () => {
      const count = await getPendingCount();
      setPendingCount(count);
    };

    // Event listeners
    window.addEventListener('online', updateOnlineStatus);
    window.addEventListener('offline', updateOnlineStatus);
    
    // Custom sync events
    window.addEventListener('sync-success', updatePendingCount);
    window.addEventListener('sync-error', updatePendingCount);

    // Check initial status
    updatePendingCount();
    
    // Periodic check for pending items
    const interval = setInterval(updatePendingCount, 10000);

    return () => {
      window.removeEventListener('online', updateOnlineStatus);
      window.removeEventListener('offline', updateOnlineStatus);
      window.removeEventListener('sync-success', updatePendingCount);
      window.removeEventListener('sync-error', updatePendingCount);
      clearInterval(interval);
    };
  }, [getPendingCount]);

  // Persistent offline banner
  if (!isOnline) {
    return (
      <Box
        sx={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bgcolor: 'warning.main',
          color: 'warning.contrastText',
          py: 1,
          px: 2,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 1,
          zIndex: 9999,
          boxShadow: 2
        }}
      >
        <CloudOffIcon fontSize="small" />
        <Typography variant="body2" sx={{ fontWeight: 500 }}>
          You're offline - Changes will be synced when connection is restored
        </Typography>
        {pendingCount > 0 && (
          <Chip
            label={`${pendingCount} pending`}
            size="small"
            sx={{
              bgcolor: 'rgba(255, 255, 255, 0.2)',
              color: 'inherit'
            }}
          />
        )}
      </Box>
    );
  }

  // Temporary status notifications
  return (
    <>
      <Snackbar
        open={showStatus && isOnline}
        anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
        sx={{ mt: 6 }}
      >
        <Alert
          severity="success"
          icon={<OnlineIcon />}
          sx={{ alignItems: 'center' }}
        >
          <Box>
            <Typography variant="body2" sx={{ fontWeight: 500 }}>
              Connection restored
            </Typography>
            {isSyncing && pendingCount > 0 && (
              <Box sx={{ mt: 1, display: 'flex', alignItems: 'center', gap: 1 }}>
                <SyncIcon fontSize="small" sx={{ animation: 'spin 1s linear infinite' }} />
                <Typography variant="caption">
                  Syncing {pendingCount} pending changes...
                </Typography>
              </Box>
            )}
          </Box>
          {isSyncing && <LinearProgress sx={{ mt: 1 }} />}
        </Alert>
      </Snackbar>

      <style>
        {`
          @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
          }
        `}
      </style>
    </>
  );
};