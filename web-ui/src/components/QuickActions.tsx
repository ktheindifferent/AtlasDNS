import React from 'react';
import { Card, CardContent, Typography, Button, Box, List, ListItem } from '@mui/material';
import { Refresh, Delete, Add, Settings, Security, Speed } from '@mui/icons-material';

const QuickActions: React.FC = () => {
  const actions = [
    {
      icon: <Refresh />,
      label: 'Flush Cache',
      color: 'primary',
      onClick: () => console.log('Flush cache'),
    },
    {
      icon: <Add />,
      label: 'Add Zone',
      color: 'success',
      onClick: () => console.log('Add zone'),
    },
    {
      icon: <Security />,
      label: 'Enable DNSSEC',
      color: 'info',
      onClick: () => console.log('Enable DNSSEC'),
    },
    {
      icon: <Speed />,
      label: 'Run Performance Test',
      color: 'warning',
      onClick: () => console.log('Run performance test'),
    },
    {
      icon: <Settings />,
      label: 'Settings',
      color: 'default',
      onClick: () => console.log('Open settings'),
    },
    {
      icon: <Delete />,
      label: 'Clear Logs',
      color: 'error',
      onClick: () => console.log('Clear logs'),
    },
  ];

  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom>
          Quick Actions
        </Typography>
        <List sx={{ p: 0 }}>
          {actions.map((action, index) => (
            <ListItem key={index} sx={{ px: 0, py: 1 }}>
              <Button
                fullWidth
                variant="outlined"
                color={action.color as any}
                startIcon={action.icon}
                onClick={action.onClick}
                sx={{ justifyContent: 'flex-start' }}
              >
                {action.label}
              </Button>
            </ListItem>
          ))}
        </List>
      </CardContent>
    </Card>
  );
};

export default QuickActions;