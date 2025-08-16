import React, { useState } from 'react';
import {
  Card,
  CardContent,
  Stack,
  Typography,
  IconButton,
  Checkbox,
  Chip,
  Box,
  Collapse,
  Badge,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Folder as FolderIcon,
} from '@mui/icons-material';
import { formatDistanceToNow } from 'date-fns';
import { useDispatch } from 'react-redux';
import { toggleGroupCollapse } from '../../store/slices/notificationSlice';
import NotificationItem from './NotificationItem';
import { NotificationGroup as NotificationGroupType } from '../../types/notification.types';

interface NotificationGroupProps {
  group: NotificationGroupType;
  selected: boolean;
  onToggleSelection: () => void;
}

const NotificationGroup: React.FC<NotificationGroupProps> = ({
  group,
  selected,
  onToggleSelection,
}) => {
  const dispatch = useDispatch();
  const [expanded, setExpanded] = useState(!group.collapsed);

  const handleToggleExpand = () => {
    setExpanded(!expanded);
    dispatch(toggleGroupCollapse(group.id));
  };

  const unreadCount = group.notifications.filter(n => !n.read).length;

  return (
    <Card sx={{ borderLeft: 4, borderColor: 'primary.main' }}>
      <CardContent sx={{ p: 2 }}>
        <Stack direction="row" spacing={1.5} alignItems="center">
          <Checkbox
            checked={selected}
            onChange={onToggleSelection}
            size="small"
          />
          
          <Badge badgeContent={unreadCount} color="error">
            <FolderIcon color="primary" />
          </Badge>
          
          <Box sx={{ flex: 1 }}>
            <Stack direction="row" alignItems="center" spacing={1}>
              <Typography variant="subtitle2" fontWeight="bold">
                {group.title}
              </Typography>
              
              <Chip
                label={`${group.count} notifications`}
                size="small"
                variant="outlined"
              />
              
              {unreadCount > 0 && (
                <Chip
                  label={`${unreadCount} unread`}
                  size="small"
                  color="primary"
                />
              )}
            </Stack>
            
            <Typography variant="caption" color="text.secondary">
              {formatDistanceToNow(group.firstTimestamp, { addSuffix: true })}
              {' - '}
              {formatDistanceToNow(group.lastTimestamp, { addSuffix: true })}
            </Typography>
          </Box>
          
          <IconButton size="small" onClick={handleToggleExpand}>
            {expanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
          </IconButton>
        </Stack>
        
        <Collapse in={expanded} timeout="auto" unmountOnExit>
          <Stack spacing={1} sx={{ mt: 2 }}>
            {group.notifications.map(notification => (
              <NotificationItem
                key={notification.id}
                notification={notification}
                selected={false}
                onToggleSelection={() => {}}
                compact
              />
            ))}
          </Stack>
        </Collapse>
      </CardContent>
    </Card>
  );
};

export default NotificationGroup;