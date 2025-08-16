import React, { useRef, useState } from 'react';
import { Box, IconButton, Zoom, Paper } from '@mui/material';
import { ZoomIn, ZoomOut, CenterFocusStrong } from '@mui/icons-material';
import { motion } from 'framer-motion';
import { usePinchZoom, useDoubleTap, useKeyboardAlternative } from '../../hooks/useGestures';

interface PinchZoomContainerProps {
  children: React.ReactNode;
  minScale?: number;
  maxScale?: number;
  showControls?: boolean;
  disabled?: boolean;
}

export const PinchZoomContainer: React.FC<PinchZoomContainerProps> = ({
  children,
  minScale = 0.5,
  maxScale = 3,
  showControls = true,
  disabled = false,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const { bind, scale, position, reset } = usePinchZoom(minScale, maxScale);
  const [manualScale, setManualScale] = useState(1);
  
  const currentScale = disabled ? 1 : scale * manualScale;
  
  // Double tap to reset zoom
  const doubleTapProps = useDoubleTap(() => {
    reset();
    setManualScale(1);
  });
  
  // Keyboard controls
  const keyboardProps = useKeyboardAlternative({
    'ctrl+plus': () => handleZoom(0.2),
    'ctrl+minus': () => handleZoom(-0.2),
    'ctrl+0': () => {
      reset();
      setManualScale(1);
    },
  });
  
  const handleZoom = (delta: number) => {
    const newScale = Math.max(minScale, Math.min(maxScale, manualScale + delta));
    setManualScale(newScale);
  };
  
  const handleReset = () => {
    reset();
    setManualScale(1);
  };

  if (disabled) {
    return <Box>{children}</Box>;
  }

  return (
    <Box
      ref={containerRef}
      sx={{
        position: 'relative',
        overflow: 'hidden',
        touchAction: 'none',
        '&:focus': {
          outline: '2px solid',
          outlineColor: 'primary.main',
          outlineOffset: 2,
        },
      }}
      tabIndex={0}
      role="region"
      aria-label="Zoomable content"
      {...keyboardProps}
    >
      <motion.div
        {...bind()}
        {...doubleTapProps}
        animate={{
          scale: currentScale,
          x: position.x,
          y: position.y,
        }}
        transition={{ type: 'spring', stiffness: 300, damping: 30 }}
        style={{
          transformOrigin: 'center',
          cursor: currentScale > 1 ? 'move' : 'default',
        }}
      >
        {children}
      </motion.div>
      
      {showControls && (
        <Paper
          elevation={2}
          sx={{
            position: 'absolute',
            bottom: 16,
            right: 16,
            display: 'flex',
            flexDirection: 'column',
            gap: 0.5,
            p: 0.5,
            borderRadius: 2,
            opacity: 0.9,
            transition: 'opacity 0.2s',
            '&:hover': {
              opacity: 1,
            },
          }}
        >
          <IconButton
            size="small"
            onClick={() => handleZoom(0.2)}
            disabled={currentScale >= maxScale}
            aria-label="Zoom in"
          >
            <ZoomIn />
          </IconButton>
          
          <IconButton
            size="small"
            onClick={() => handleZoom(-0.2)}
            disabled={currentScale <= minScale}
            aria-label="Zoom out"
          >
            <ZoomOut />
          </IconButton>
          
          <IconButton
            size="small"
            onClick={handleReset}
            disabled={currentScale === 1 && position.x === 0 && position.y === 0}
            aria-label="Reset zoom"
          >
            <CenterFocusStrong />
          </IconButton>
        </Paper>
      )}
      
      {currentScale !== 1 && (
        <Box
          sx={{
            position: 'absolute',
            top: 8,
            left: 8,
            bgcolor: 'background.paper',
            px: 1,
            py: 0.5,
            borderRadius: 1,
            fontSize: '0.75rem',
            opacity: 0.7,
          }}
        >
          {Math.round(currentScale * 100)}%
        </Box>
      )}
    </Box>
  );
};