import React, { useState, useEffect } from 'react';
import {
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Typography,
  Box,
  IconButton,
  Snackbar,
  Alert
} from '@mui/material';
import {
  GetApp as InstallIcon,
  Close as CloseIcon,
  PhoneIphone as MobileIcon
} from '@mui/icons-material';

interface BeforeInstallPromptEvent extends Event {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: 'accepted' | 'dismissed' }>;
}

export const PWAInstallPrompt: React.FC = () => {
  const [installPrompt, setInstallPrompt] = useState<BeforeInstallPromptEvent | null>(null);
  const [showPrompt, setShowPrompt] = useState(false);
  const [isInstalled, setIsInstalled] = useState(false);
  const [showIOSInstructions, setShowIOSInstructions] = useState(false);
  const [showSuccessMessage, setShowSuccessMessage] = useState(false);

  useEffect(() => {
    // Check if app is already installed
    if (window.matchMedia('(display-mode: standalone)').matches) {
      setIsInstalled(true);
      return;
    }

    // Check if running on iOS
    const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) && !(window as any).MSStream;
    
    if (isIOS && !isInstalled) {
      // Show iOS instructions after a delay
      setTimeout(() => {
        const hasSeenIOSPrompt = localStorage.getItem('atlas-ios-prompt-seen');
        if (!hasSeenIOSPrompt) {
          setShowIOSInstructions(true);
        }
      }, 10000);
    }

    // Listen for beforeinstallprompt event (Chrome/Edge)
    const handleBeforeInstallPrompt = (e: Event) => {
      e.preventDefault();
      setInstallPrompt(e as BeforeInstallPromptEvent);
      
      // Show prompt after a delay or based on user engagement
      setTimeout(() => {
        const hasSeenPrompt = localStorage.getItem('atlas-install-prompt-seen');
        if (!hasSeenPrompt) {
          setShowPrompt(true);
        }
      }, 30000); // Show after 30 seconds
    };

    window.addEventListener('beforeinstallprompt', handleBeforeInstallPrompt);

    // Listen for successful app installation
    window.addEventListener('appinstalled', () => {
      setIsInstalled(true);
      setShowPrompt(false);
      setShowSuccessMessage(true);
      localStorage.setItem('atlas-app-installed', 'true');
    });

    return () => {
      window.removeEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
    };
  }, [isInstalled]);

  const handleInstallClick = async () => {
    if (!installPrompt) return;

    try {
      await installPrompt.prompt();
      const { outcome } = await installPrompt.userChoice;
      
      if (outcome === 'accepted') {
        console.log('User accepted the install prompt');
        setShowPrompt(false);
      } else {
        console.log('User dismissed the install prompt');
        localStorage.setItem('atlas-install-prompt-seen', 'true');
      }
      
      setInstallPrompt(null);
    } catch (error) {
      console.error('Error showing install prompt:', error);
    }
  };

  const handleDismiss = () => {
    setShowPrompt(false);
    localStorage.setItem('atlas-install-prompt-seen', 'true');
  };

  const handleIOSDismiss = () => {
    setShowIOSInstructions(false);
    localStorage.setItem('atlas-ios-prompt-seen', 'true');
  };

  // Android/Chrome Install Dialog
  const InstallDialog = () => (
    <Dialog 
      open={showPrompt} 
      onClose={handleDismiss}
      maxWidth="sm"
      fullWidth
    >
      <DialogTitle>
        <Box display="flex" alignItems="center" justifyContent="space-between">
          <Typography variant="h6">Install Atlas DNS Manager</Typography>
          <IconButton size="small" onClick={handleDismiss}>
            <CloseIcon />
          </IconButton>
        </Box>
      </DialogTitle>
      <DialogContent>
        <Box display="flex" flexDirection="column" alignItems="center" py={2}>
          <MobileIcon sx={{ fontSize: 64, color: 'primary.main', mb: 2 }} />
          <Typography variant="body1" align="center" gutterBottom>
            Install Atlas DNS Manager for quick access and offline functionality
          </Typography>
          <Typography variant="body2" color="text.secondary" align="center">
            • Access DNS management from your home screen
            • Work offline with cached data
            • Receive real-time alerts and notifications
            • Faster loading with app shell architecture
          </Typography>
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleDismiss} color="inherit">
          Not Now
        </Button>
        <Button 
          onClick={handleInstallClick} 
          variant="contained" 
          startIcon={<InstallIcon />}
        >
          Install App
        </Button>
      </DialogActions>
    </Dialog>
  );

  // iOS Instructions Dialog
  const IOSInstructionsDialog = () => (
    <Dialog 
      open={showIOSInstructions} 
      onClose={handleIOSDismiss}
      maxWidth="sm"
      fullWidth
    >
      <DialogTitle>
        <Box display="flex" alignItems="center" justifyContent="space-between">
          <Typography variant="h6">Add to Home Screen</Typography>
          <IconButton size="small" onClick={handleIOSDismiss}>
            <CloseIcon />
          </IconButton>
        </Box>
      </DialogTitle>
      <DialogContent>
        <Box py={2}>
          <Typography variant="body1" gutterBottom>
            To install Atlas DNS Manager on your iOS device:
          </Typography>
          <Box component="ol" sx={{ pl: 2 }}>
            <Typography component="li" variant="body2" gutterBottom>
              Tap the Share button (
              <Box component="span" sx={{ fontFamily: 'monospace' }}>⎙</Box>
              ) in Safari
            </Typography>
            <Typography component="li" variant="body2" gutterBottom>
              Scroll down and tap "Add to Home Screen"
            </Typography>
            <Typography component="li" variant="body2" gutterBottom>
              Enter a name for the app
            </Typography>
            <Typography component="li" variant="body2">
              Tap "Add" to install
            </Typography>
          </Box>
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleIOSDismiss} variant="contained">
          Got It
        </Button>
      </DialogActions>
    </Dialog>
  );

  return (
    <>
      <InstallDialog />
      <IOSInstructionsDialog />
      <Snackbar 
        open={showSuccessMessage} 
        autoHideDuration={6000} 
        onClose={() => setShowSuccessMessage(false)}
      >
        <Alert severity="success" onClose={() => setShowSuccessMessage(false)}>
          Atlas DNS Manager has been installed successfully!
        </Alert>
      </Snackbar>
    </>
  );
};