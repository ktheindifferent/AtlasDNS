import React from 'react';
import { List, ListItem, ListItemText, Typography, Paper } from '@mui/material';
import { useTranslation } from 'react-i18next';

interface ActivityItem {
  id: string;
  message: string;
  timestamp: Date;
  type: 'info' | 'warning' | 'error' | 'success';
}

interface ActivityFeedProps {
  activities?: ActivityItem[];
}

const ActivityFeed: React.FC<ActivityFeedProps> = ({ activities = [] }) => {
  const { t } = useTranslation('dashboard');

  if (activities.length === 0) {
    return (
      <Paper sx={{ p: 2 }}>
        <Typography variant="body2" color="text.secondary" align="center">
          {t('activity.noActivity')}
        </Typography>
      </Paper>
    );
  }

  return (
    <Paper>
      <List>
        {activities.map((activity) => (
          <ListItem key={activity.id}>
            <ListItemText
              primary={activity.message}
              secondary={activity.timestamp.toLocaleString()}
            />
          </ListItem>
        ))}
      </List>
    </Paper>
  );
};

export default ActivityFeed;