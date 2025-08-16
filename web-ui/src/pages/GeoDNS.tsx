import React from 'react';
import { Box, Typography, Paper, Alert } from '@mui/material';

const GeoDNS: React.FC = () => {
  return (
    <Box>
      <Typography variant="h4" fontWeight="bold" gutterBottom>
        GeoDNS Configuration
      </Typography>
      <Paper sx={{ p: 3 }}>
        <Alert severity="info">
          Geographic DNS routing configuration will be implemented here.
        </Alert>
      </Paper>
    </Box>
  );
};

export default GeoDNS;