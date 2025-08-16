import React from 'react';
import { Card, CardContent, Typography, Button, Box } from '@mui/material';
import { Add, Refresh, CloudUpload, CloudDownload } from '@mui/icons-material';

const QuickActions: React.FC = () => {
  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom>
          Quick Actions
        </Typography>
        <Box display="flex" flexDirection="column" gap={1} mt={2}>
          <Button variant="outlined" startIcon={<Add />} fullWidth>
            Add DNS Zone
          </Button>
          <Button variant="outlined" startIcon={<Refresh />} fullWidth>
            Flush DNS Cache
          </Button>
          <Button variant="outlined" startIcon={<CloudUpload />} fullWidth>
            Import Zone File
          </Button>
          <Button variant="outlined" startIcon={<CloudDownload />} fullWidth>
            Export All Zones
          </Button>
        </Box>
      </CardContent>
    </Card>
  );
};

export default QuickActions;