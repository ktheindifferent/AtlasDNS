import React from 'react';
import { Grid, Button, Paper, Box } from '@mui/material';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { Add, Dns, HealthAndSafety, Analytics } from '@mui/icons-material';

const QuickActions: React.FC = () => {
  const { t } = useTranslation('dashboard');
  const navigate = useNavigate();

  const actions = [
    {
      label: t('quickActions.addZone'),
      icon: <Add />,
      onClick: () => navigate('/zones?action=add'),
    },
    {
      label: t('quickActions.addRecord'),
      icon: <Dns />,
      onClick: () => navigate('/zones'),
    },
    {
      label: t('quickActions.runHealthCheck'),
      icon: <HealthAndSafety />,
      onClick: () => navigate('/health-checks'),
    },
    {
      label: t('quickActions.viewAnalytics'),
      icon: <Analytics />,
      onClick: () => navigate('/analytics'),
    },
  ];

  return (
    <Paper sx={{ p: 2 }}>
      <Grid container spacing={2}>
        {actions.map((action, index) => (
          <Grid item xs={12} sm={6} key={index}>
            <Button
              fullWidth
              variant="outlined"
              startIcon={action.icon}
              onClick={action.onClick}
            >
              {action.label}
            </Button>
          </Grid>
        ))}
      </Grid>
    </Paper>
  );
};

export default QuickActions;