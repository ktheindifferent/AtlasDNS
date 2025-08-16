import React from 'react';
import { Box, Typography } from '@mui/material';

const PlaceholderPage: React.FC<{ title: string }> = ({ title }) => (
  <Box>
    <Typography variant="h4">{title}</Typography>
    <Typography variant="body1" sx={{ mt: 2 }}>
      This page is under construction.
    </Typography>
  </Box>
);

export default PlaceholderPage;
