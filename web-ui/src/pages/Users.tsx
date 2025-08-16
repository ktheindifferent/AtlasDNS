import React from 'react';
import { Box, Typography, Paper, Alert } from '@mui/material';

const Users: React.FC = () => {
  return (
    <Box>
      <Typography variant="h4" fontWeight="bold" gutterBottom>
        User Management
      </Typography>
      <Paper sx={{ p: 3 }}>
        <Alert severity="info">
          User management functionality will be implemented here.
        </Alert>
      </Paper>
    </Box>
  );
};

export default Users;