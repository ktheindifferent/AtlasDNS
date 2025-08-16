import React, { useEffect, useState } from 'react';
import { Box, Snackbar, Typography, Chip } from '@mui/material';
import { useThreeFingerSwipe, useDoubleTap, triggerHaptic } from '../../hooks/useGestures';
import { useNavigate } from 'react-router-dom';
import { useDispatch } from 'react-redux';

interface GestureShortcut {
  gesture: string;
  action: () => void;
  description: string;
}

export const GestureShortcuts: React.FC = () => {
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const [feedback, setFeedback] = useState<string | null>(null);

  // Three-finger swipe shortcuts
  const threeFingerBind = useThreeFingerSwipe(
    () => {
      // Swipe up - Go to dashboard
      triggerHaptic(20);
      navigate('/dashboard');
      showFeedback('Dashboard');
    },
    () => {
      // Swipe down - Open command palette
      triggerHaptic(20);
      // Dispatch action to open command palette
      showFeedback('Command Palette');
    },
    () => {
      // Swipe left - Previous page
      triggerHaptic(20);
      window.history.back();
      showFeedback('Back');
    },
    () => {
      // Swipe right - Next page
      triggerHaptic(20);
      window.history.forward();
      showFeedback('Forward');
    }
  );

  const showFeedback = (message: string) => {
    setFeedback(message);
    setTimeout(() => setFeedback(null), 1500);
  };

  // Global gesture listeners
  useEffect(() => {
    const handleGlobalGestures = (e: TouchEvent) => {
      // Edge swipe from left (back navigation)
      if (e.touches.length === 1) {
        const touch = e.touches[0];
        if (touch.clientX < 20 && e.type === 'touchstart') {
          const handleMove = (moveEvent: TouchEvent) => {
            const moveTouch = moveEvent.touches[0];
            if (moveTouch.clientX > 100) {
              triggerHaptic(10);
              window.history.back();
              document.removeEventListener('touchmove', handleMove);
            }
          };
          document.addEventListener('touchmove', handleMove);
          setTimeout(() => {
            document.removeEventListener('touchmove', handleMove);
          }, 500);
        }
      }
    };

    document.addEventListener('touchstart', handleGlobalGestures);
    return () => {
      document.removeEventListener('touchstart', handleGlobalGestures);
    };
  }, []);

  return (
    <>
      <Box
        {...threeFingerBind()}
        sx={{
          position: 'fixed',
          inset: 0,
          pointerEvents: 'none',
          zIndex: 9999,
        }}
      />
      
      <Snackbar
        open={feedback !== null}
        anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
        sx={{
          top: '50%',
          transform: 'translateY(-50%)',
        }}
      >
        <Chip
          label={feedback}
          color="primary"
          sx={{
            fontSize: '1rem',
            py: 2,
            px: 3,
          }}
        />
      </Snackbar>
    </>
  );
};

// Gesture help overlay component
export const GestureHelp: React.FC<{ open: boolean; onClose: () => void }> = ({
  open,
  onClose,
}) => {
  const gestures: GestureShortcut[] = [
    {
      gesture: 'Swipe Left/Right',
      action: () => {},
      description: 'Navigate between sections',
    },
    {
      gesture: 'Pull Down',
      action: () => {},
      description: 'Refresh data',
    },
    {
      gesture: 'Long Press',
      action: () => {},
      description: 'Open context menu',
    },
    {
      gesture: 'Pinch',
      action: () => {},
      description: 'Zoom in/out on charts',
    },
    {
      gesture: 'Double Tap',
      action: () => {},
      description: 'Reset zoom or quick action',
    },
    {
      gesture: '3-Finger Swipe Up',
      action: () => {},
      description: 'Go to Dashboard',
    },
    {
      gesture: '3-Finger Swipe Down',
      action: () => {},
      description: 'Open Command Palette',
    },
    {
      gesture: '3-Finger Swipe Left',
      action: () => {},
      description: 'Go Back',
    },
    {
      gesture: '3-Finger Swipe Right',
      action: () => {},
      description: 'Go Forward',
    },
    {
      gesture: 'Edge Swipe',
      action: () => {},
      description: 'Navigate back (from left edge)',
    },
  ];

  if (!open) return null;

  return (
    <Box
      onClick={onClose}
      sx={{
        position: 'fixed',
        inset: 0,
        bgcolor: 'rgba(0, 0, 0, 0.8)',
        zIndex: 9999,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        p: 2,
      }}
    >
      <Box
        sx={{
          bgcolor: 'background.paper',
          borderRadius: 2,
          p: 3,
          maxWidth: 400,
          maxHeight: '80vh',
          overflow: 'auto',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <Typography variant="h5" gutterBottom>
          Touch Gestures
        </Typography>
        
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 2 }}>
          {gestures.map((gesture, index) => (
            <Box key={index} sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <Chip
                label={gesture.gesture}
                size="small"
                color="primary"
                sx={{ minWidth: 120 }}
              />
              <Typography variant="body2" color="text.secondary">
                {gesture.description}
              </Typography>
            </Box>
          ))}
        </Box>
        
        <Typography variant="caption" color="text.secondary" sx={{ mt: 3, display: 'block' }}>
          Note: All gestures have keyboard alternatives for accessibility.
        </Typography>
      </Box>
    </Box>
  );
};