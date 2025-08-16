import React from 'react';
import { Card, CardContent, Typography, Box, List, ListItem, ListItemText, Chip, Avatar } from '@mui/material';
import { Info, Warning, Error, CheckCircle } from '@mui/icons-material';

interface ActivityItem {
  id: string;
  type: 'info' | 'warning' | 'error' | 'success';
  message: string;
  timestamp: Date;
  user?: string;
}

const ActivityFeed: React.FC = () => {
  const activities: ActivityItem[] = [
    {
      id: '1',
      type: 'success',
      message: 'DNS cache flushed successfully',
      timestamp: new Date(Date.now() - 5 * 60 * 1000),
      user: 'System',
    },
    {
      id: '2',
      type: 'warning',
      message: 'High query rate detected from 192.168.1.100',
      timestamp: new Date(Date.now() - 15 * 60 * 1000),
    },
    {
      id: '3',
      type: 'info',
      message: 'New zone example.com added',
      timestamp: new Date(Date.now() - 30 * 60 * 1000),
      user: 'Admin',
    },
    {
      id: '4',
      type: 'error',
      message: 'Failed to resolve auth.example.com',
      timestamp: new Date(Date.now() - 45 * 60 * 1000),
    },
    {
      id: '5',
      type: 'success',
      message: 'DNSSEC validation enabled',
      timestamp: new Date(Date.now() - 60 * 60 * 1000),
      user: 'Admin',
    },
  ];

  const getIcon = (type: ActivityItem['type']) => {
    switch (type) {
      case 'info': return <Info fontSize="small" />;
      case 'warning': return <Warning fontSize="small" />;
      case 'error': return <Error fontSize="small" />;
      case 'success': return <CheckCircle fontSize="small" />;
    }
  };

  const getColor = (type: ActivityItem['type']) => {
    switch (type) {
      case 'info': return 'info';
      case 'warning': return 'warning';
      case 'error': return 'error';
      case 'success': return 'success';
    }
  };

  const formatTime = (date: Date) => {
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 60000);
    
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  };

  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom>
          Activity Feed
        </Typography>
        <List sx={{ maxHeight: 400, overflow: 'auto' }}>
          {activities.map(activity => (
            <ListItem key={activity.id} sx={{ px: 0 }}>
              <Box sx={{ display: 'flex', alignItems: 'flex-start', width: '100%', gap: 2 }}>
                <Avatar
                  sx={{
                    width: 32,
                    height: 32,
                    bgcolor: `${getColor(activity.type)}.light`,
                    color: `${getColor(activity.type)}.main`,
                  }}
                >
                  {getIcon(activity.type)}
                </Avatar>
                <Box sx={{ flex: 1 }}>
                  <Typography variant="body2">
                    {activity.message}
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1, mt: 0.5 }}>
                    <Typography variant="caption" color="text.secondary">
                      {formatTime(activity.timestamp)}
                    </Typography>
                    {activity.user && (
                      <Chip label={activity.user} size="small" variant="outlined" />
                    )}
                  </Box>
                </Box>
              </Box>
            </ListItem>
          ))}
        </List>
      </CardContent>
    </Card>
  );
};

export default ActivityFeed;