import React from 'react';
import {
  Card,
  CardContent,
  Typography,
  Button,
  Grid,
} from '@mui/material';
import {
  Add,
  Upload,
  Download,
  Sync,
  Security,
  Speed,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';

const QuickActions: React.FC = () => {
  const navigate = useNavigate();

  const actions = [
    {
      label: 'Add Zone',
      icon: <Add />,
      color: 'primary',
      onClick: () => navigate('/zones?action=create'),
    },
    {
      label: 'Import Zone',
      icon: <Upload />,
      color: 'secondary',
      onClick: () => navigate('/zones?action=import'),
    },
    {
      label: 'Export Zones',
      icon: <Download />,
      color: 'info',
      onClick: () => navigate('/zones?action=export'),
    },
    {
      label: 'Sync Zones',
      icon: <Sync />,
      color: 'warning',
      onClick: () => console.log('Sync zones'),
    },
    {
      label: 'DNSSEC Setup',
      icon: <Security />,
      color: 'success',
      onClick: () => navigate('/dnssec'),
    },
    {
      label: 'Run Tests',
      icon: <Speed />,
      color: 'error',
      onClick: () => navigate('/monitoring?action=test'),
    },
  ];

  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom>
          Quick Actions
        </Typography>
        <Grid container spacing={2}>
          {actions.map((action) => (
            <Grid item xs={6} key={action.label}>
              <Button
                fullWidth
                variant="outlined"
                color={action.color as any}
                startIcon={action.icon}
                onClick={action.onClick}
                sx={{
                  py: 1.5,
                  justifyContent: 'flex-start',
                  textTransform: 'none',
                }}
              >
                {action.label}
              </Button>
            </Grid>
          ))}
        </Grid>
      </CardContent>
    </Card>
  );
};

export default QuickActions;