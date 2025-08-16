import React from 'react';
import { Card, CardContent, Typography, List, ListItem, ListItemText } from '@mui/material';

const ActivityFeed: React.FC = () => {
  const activities = [
    { id: 1, text: 'Zone example.com updated', time: '2 minutes ago' },
    { id: 2, text: 'Health check passed for api.example.com', time: '5 minutes ago' },
    { id: 3, text: 'New DNS record added to example.org', time: '10 minutes ago' },
  ];

  return (
    <Card>
      <CardContent>
        <Typography variant="h6" gutterBottom>
          Recent Activity
        </Typography>
        <List>
          {activities.map((activity) => (
            <ListItem key={activity.id} disablePadding>
              <ListItemText
                primary={activity.text}
                secondary={activity.time}
              />
            </ListItem>
          ))}
        </List>
      </CardContent>
    </Card>
  );
};

export default ActivityFeed;