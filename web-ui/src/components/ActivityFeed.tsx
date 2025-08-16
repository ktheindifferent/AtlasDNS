import React from 'react';
import {
  Card,
  CardContent,
  Typography,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  Avatar,
  Box,
  Chip,
  useTheme,
} from '@mui/material';
import {
  Add,
  Edit,
  Delete,
  Security,
  Warning,
  CheckCircle,
  Error,
  Info,
} from '@mui/icons-material';
import { formatDistanceToNow } from 'date-fns';

interface Activity {
  id: string;
  type: 'create' | 'update' | 'delete' | 'security' | 'warning' | 'success' | 'error' | 'info';
  title: string;
  description: string;
  timestamp: Date;
  user?: string;
}

const ActivityFeed: React.FC = () => {
  const theme = useTheme();

  // Mock data - in production, this would come from an API
  const activities: Activity[] = [
    {
      id: '1',
      type: 'create',
      title: 'Zone Created',
      description: 'example.com zone was created',
      timestamp: new Date(Date.now() - 1000 * 60 * 5),
      user: 'admin@example.com',
    },
    {
      id: '2',
      type: 'update',
      title: 'Records Updated',
      description: '5 A records modified in example.com',
      timestamp: new Date(Date.now() - 1000 * 60 * 15),
      user: 'user@example.com',
    },
    {
      id: '3',
      type: 'security',
      title: 'DNSSEC Enabled',
      description: 'DNSSEC enabled for secure.com',
      timestamp: new Date(Date.now() - 1000 * 60 * 30),
      user: 'admin@example.com',
    },
    {
      id: '4',
      type: 'warning',
      title: 'High Query Rate',
      description: 'Unusual query spike detected for api.example.com',
      timestamp: new Date(Date.now() - 1000 * 60 * 45),
    },
    {
      id: '5',
      type: 'success',
      title: 'Health Check Passed',
      description: 'All configured health checks are passing',
      timestamp: new Date(Date.now() - 1000 * 60 * 60),
    },
  ];

  const getIcon = (type: Activity['type']) => {
    switch (type) {
      case 'create':
        return <Add />;
      case 'update':
        return <Edit />;
      case 'delete':
        return <Delete />;
      case 'security':
        return <Security />;
      case 'warning':
        return <Warning />;
      case 'success':
        return <CheckCircle />;
      case 'error':
        return <Error />;
      case 'info':
        return <Info />;
      default:
        return <Info />;
    }
  };

  const getColor = (type: Activity['type']) => {
    switch (type) {
      case 'create':
        return theme.palette.success.main;
      case 'update':
        return theme.palette.info.main;
      case 'delete':
        return theme.palette.error.main;
      case 'security':
        return theme.palette.primary.main;
      case 'warning':
        return theme.palette.warning.main;
      case 'success':
        return theme.palette.success.main;
      case 'error':
        return theme.palette.error.main;
      case 'info':
        return theme.palette.info.main;
      default:
        return theme.palette.grey[500];
    }
  };

  return (
    <Card>
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Typography variant="h6">Recent Activity</Typography>
          <Chip label="Live" color="success" size="small" variant="outlined" />
        </Box>
        <List sx={{ width: '100%' }}>
          {activities.map((activity) => (
            <ListItem key={activity.id} alignItems="flex-start" sx={{ px: 0 }}>
              <ListItemAvatar>
                <Avatar sx={{ bgcolor: getColor(activity.type), width: 36, height: 36 }}>
                  {getIcon(activity.type)}
                </Avatar>
              </ListItemAvatar>
              <ListItemText
                primary={
                  <Typography variant="body2" fontWeight={500}>
                    {activity.title}
                  </Typography>
                }
                secondary={
                  <Box>
                    <Typography variant="body2" color="text.secondary">
                      {activity.description}
                    </Typography>
                    <Box sx={{ display: 'flex', gap: 1, mt: 0.5 }}>
                      <Typography variant="caption" color="text.secondary">
                        {formatDistanceToNow(activity.timestamp, { addSuffix: true })}
                      </Typography>
                      {activity.user && (
                        <>
                          <Typography variant="caption" color="text.secondary">•</Typography>
                          <Typography variant="caption" color="text.secondary">
                            {activity.user}
                          </Typography>
                        </>
                      )}
                    </Box>
                  </Box>
                }
              />
            </ListItem>
          ))}
        </List>
      </CardContent>
    </Card>
  );
};

export default ActivityFeed;