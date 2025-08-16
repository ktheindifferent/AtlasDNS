import React from 'react';
import { Box, Typography, Paper, Alert } from '@mui/material';

const Monitoring: React.FC = () => {
  return (
    <Box>
      <Typography variant="h4" fontWeight="bold" gutterBottom>
        System Monitoring
      </Typography>
      <Paper sx={{ p: 3 }}>
        <Alert severity="info">
          Real-time system monitoring and metrics will be implemented here.
        </Alert>
      </Paper>
    </Box>
  );
};

export default Monitoring;