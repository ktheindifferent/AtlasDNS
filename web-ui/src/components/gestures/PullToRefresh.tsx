import React from 'react';
import { Box, CircularProgress, Typography } from '@mui/material';
import { motion, AnimatePresence } from 'framer-motion';
import { Refresh } from '@mui/icons-material';
import { usePullToRefresh } from '../../hooks/useGestures';

interface PullToRefreshProps {
  onRefresh: () => Promise<void>;
  children: React.ReactNode;
  disabled?: boolean;
}

export const PullToRefresh: React.FC<PullToRefreshProps> = ({
  onRefresh,
  children,
  disabled = false,
}) => {
  const { bind, isRefreshing, pullDistance } = usePullToRefresh(onRefresh);
  
  const pullProgress = Math.min(pullDistance / 80, 1);
  const showIndicator = pullDistance > 10;

  if (disabled) {
    return <>{children}</>;
  }

  return (
    <Box {...bind()} sx={{ position: 'relative', touchAction: 'pan-x' }}>
      <AnimatePresence>
        {(showIndicator || isRefreshing) && (
          <motion.div
            initial={{ opacity: 0, y: -50 }}
            animate={{ 
              opacity: pullProgress,
              y: isRefreshing ? 0 : pullDistance - 50,
            }}
            exit={{ opacity: 0, y: -50 }}
            style={{
              position: 'absolute',
              top: 0,
              left: '50%',
              transform: 'translateX(-50%)',
              zIndex: 10,
            }}
          >
            <Box
              sx={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: 40,
                height: 40,
                borderRadius: '50%',
                bgcolor: 'background.paper',
                boxShadow: 2,
              }}
            >
              {isRefreshing ? (
                <CircularProgress size={24} />
              ) : (
                <motion.div
                  animate={{ rotate: pullProgress * 180 }}
                  transition={{ type: 'spring', stiffness: 200 }}
                >
                  <Refresh 
                    sx={{ 
                      color: pullProgress === 1 ? 'primary.main' : 'text.secondary',
                    }} 
                  />
                </motion.div>
              )}
            </Box>
            {pullProgress === 1 && !isRefreshing && (
              <Typography
                variant="caption"
                sx={{
                  position: 'absolute',
                  top: 45,
                  left: '50%',
                  transform: 'translateX(-50%)',
                  whiteSpace: 'nowrap',
                }}
              >
                Release to refresh
              </Typography>
            )}
          </motion.div>
        )}
      </AnimatePresence>
      
      <Box
        component={motion.div}
        animate={{
          y: isRefreshing ? 50 : Math.min(pullDistance * 0.5, 40),
        }}
        transition={{ type: 'spring', stiffness: 300, damping: 30 }}
      >
        {children}
      </Box>
    </Box>
  );
};