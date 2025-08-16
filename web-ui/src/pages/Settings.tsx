import React from 'react';
import { Box, Typography, Paper, Alert } from '@mui/material';

const Settings: React.FC = () => {
  return (
    <Box>
      <Typography variant="h4" fontWeight="bold" gutterBottom>
        Settings
      </Typography>
      <Paper sx={{ p: 3 }}>
        <Alert severity="info">
          System settings and configuration will be implemented here.
        </Alert>
      </Paper>
    </Box>
  );
};

export default Settings;