import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  Avatar,
  Chip,
  IconButton,
  Badge,
  Button,
  Divider,
  TextField,
  InputAdornment,
} from '@mui/material';
import { format as timeAgo } from 'timeago.js';
import NotificationsIcon from '@mui/icons-material/Notifications';
import NotificationsActiveIcon from '@mui/icons-material/NotificationsActive';
import FilterListIcon from '@mui/icons-material/FilterList';
import SearchIcon from '@mui/icons-material/Search';
import RefreshIcon from '@mui/icons-material/Refresh';
import AddIcon from '@mui/icons-material/Add';
import EditIcon from '@mui/icons-material/Edit';
import DeleteIcon from '@mui/icons-material/Delete';
import CommentIcon from '@mui/icons-material/Comment';
import PersonAddIcon from '@mui/icons-material/PersonAdd';
import SecurityIcon from '@mui/icons-material/Security';
import DnsIcon from '@mui/icons-material/Dns';
import { useSelector } from 'react-redux';
import { RootState } from '../../store';
import { Activity } from '../../store/slices/collaborationSlice';

interface ActivityFeedProps {
  compact?: boolean;
  autoRefresh?: boolean;
  filterByEntity?: { type: 'zone' | 'record'; id: string };
}

const ActivityFeed: React.FC<ActivityFeedProps> = ({
  compact = false,
  autoRefresh = true,
  filterByEntity,
}) => {
  const { activities: allActivities } = useSelector(
    (state: RootState) => state.collaboration
  );
  const { user: currentUser } = useSelector((state: RootState) => state.auth);
  const [filter, setFilter] = useState<'all' | 'mentions' | 'changes' | 'comments'>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [unreadCount, setUnreadCount] = useState(0);
  const [lastReadTimestamp, setLastReadTimestamp] = useState<string>(
    new Date().toISOString()
  );

  const filteredActivities = allActivities.filter(activity => {
    if (filterByEntity) {
      if (activity.entityType !== filterByEntity.type || 
          activity.entityId !== filterByEntity.id) {
        return false;
      }
    }

    if (searchTerm) {
      const searchLower = searchTerm.toLowerCase();
      return (
        activity.user.name.toLowerCase().includes(searchLower) ||
        activity.action.toLowerCase().includes(searchLower) ||
        activity.details?.toLowerCase().includes(searchLower) ||
        activity.entityName?.toLowerCase().includes(searchLower)
      );
    }

    switch (filter) {
      case 'mentions':
        return activity.details?.includes(`@${currentUser?.name || currentUser?.email}`);
      case 'changes':
        return ['create', 'update', 'delete'].includes(activity.action);
      case 'comments':
        return activity.action === 'commented';
      default:
        return true;
    }
  });

  useEffect(() => {
    const newActivities = allActivities.filter(
      a => new Date(a.timestamp) > new Date(lastReadTimestamp)
    );
    setUnreadCount(newActivities.length);
  }, [allActivities, lastReadTimestamp]);

  const markAsRead = () => {
    setLastReadTimestamp(new Date().toISOString());
    setUnreadCount(0);
  };

  const getActionIcon = (action: string) => {
    switch (action) {
      case 'create':
        return <AddIcon fontSize="small" />;
      case 'update':
        return <EditIcon fontSize="small" />;
      case 'delete':
        return <DeleteIcon fontSize="small" />;
      case 'commented':
        return <CommentIcon fontSize="small" />;
      case 'joined':
        return <PersonAddIcon fontSize="small" />;
      case 'security':
        return <SecurityIcon fontSize="small" />;
      default:
        return <DnsIcon fontSize="small" />;
    }
  };

  const getActionColor = (action: string) => {
    switch (action) {
      case 'create':
        return 'success';
      case 'update':
        return 'warning';
      case 'delete':
        return 'error';
      case 'commented':
        return 'info';
      case 'security':
        return 'error';
      default:
        return 'default';
    }
  };

  const formatActivityText = (activity: Activity) => {
    const userName = activity.user.name || activity.user.email;
    const isCurrentUser = activity.userId === currentUser?.id;
    const userText = isCurrentUser ? 'You' : userName;

    switch (activity.action) {
      case 'create':
        return `${userText} created ${activity.entityType} "${activity.entityName || activity.entityId}"`;
      case 'update':
        return `${userText} updated ${activity.entityType} "${activity.entityName || activity.entityId}"`;
      case 'delete':
        return `${userText} deleted ${activity.entityType} "${activity.entityName || activity.entityId}"`;
      case 'commented':
        return `${userText} commented on ${activity.entityType} "${activity.entityName || activity.entityId}"`;
      case 'joined':
        return `${userText} joined the workspace`;
      default:
        return activity.details || `${userText} performed ${activity.action}`;
    }
  };

  if (compact) {
    return (
      <Box sx={{ position: 'relative' }}>
        <IconButton onClick={markAsRead}>
          <Badge badgeContent={unreadCount} color="error">
            {unreadCount > 0 ? <NotificationsActiveIcon /> : <NotificationsIcon />}
          </Badge>
        </IconButton>
      </Box>
    );
  }

  return (
    <Paper sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Badge badgeContent={unreadCount} color="error">
              <NotificationsIcon />
            </Badge>
            Activity Feed
          </Typography>
          <Box sx={{ display: 'flex', gap: 1 }}>
            {autoRefresh && (
              <IconButton size="small" onClick={() => window.location.reload()}>
                <RefreshIcon />
              </IconButton>
            )}
            {unreadCount > 0 && (
              <Button size="small" onClick={markAsRead}>
                Mark all read
              </Button>
            )}
          </Box>
        </Box>

        <TextField
          fullWidth
          size="small"
          placeholder="Search activities..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon />
              </InputAdornment>
            ),
          }}
          sx={{ mb: 2 }}
        />

        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
          <Chip
            label="All"
            onClick={() => setFilter('all')}
            color={filter === 'all' ? 'primary' : 'default'}
            variant={filter === 'all' ? 'filled' : 'outlined'}
          />
          <Chip
            label="Mentions"
            onClick={() => setFilter('mentions')}
            color={filter === 'mentions' ? 'primary' : 'default'}
            variant={filter === 'mentions' ? 'filled' : 'outlined'}
          />
          <Chip
            label="Changes"
            onClick={() => setFilter('changes')}
            color={filter === 'changes' ? 'primary' : 'default'}
            variant={filter === 'changes' ? 'filled' : 'outlined'}
          />
          <Chip
            label="Comments"
            onClick={() => setFilter('comments')}
            color={filter === 'comments' ? 'primary' : 'default'}
            variant={filter === 'comments' ? 'filled' : 'outlined'}
          />
        </Box>
      </Box>

      <List sx={{ flex: 1, overflow: 'auto', p: 0 }}>
        {filteredActivities.length === 0 ? (
          <Box sx={{ p: 3, textAlign: 'center' }}>
            <NotificationsIcon sx={{ fontSize: 48, color: 'text.disabled', mb: 2 }} />
            <Typography variant="body1" color="text.secondary">
              No activities to show
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Activities will appear here as your team works
            </Typography>
          </Box>
        ) : (
          filteredActivities.map((activity, index) => {
            const isUnread = new Date(activity.timestamp) > new Date(lastReadTimestamp);
            const isCurrentUser = activity.userId === currentUser?.id;

            return (
              <React.Fragment key={activity.id}>
                <ListItem
                  sx={{
                    bgcolor: isUnread ? 'action.hover' : 'transparent',
                    '&:hover': { bgcolor: 'action.hover' },
                  }}
                >
                  <ListItemAvatar>
                    <Avatar
                      src={activity.user.avatar}
                      sx={{
                        width: 36,
                        height: 36,
                        bgcolor: activity.user.color,
                        border: isCurrentUser ? '2px solid #2196F3' : 'none',
                      }}
                    >
                      {!activity.user.avatar && activity.user.name[0].toUpperCase()}
                    </Avatar>
                  </ListItemAvatar>
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                          {getActionIcon(activity.action)}
                          <Typography variant="body2" component="span">
                            {formatActivityText(activity)}
                          </Typography>
                        </Box>
                        {isUnread && (
                          <Chip
                            label="NEW"
                            size="small"
                            color="error"
                            sx={{ height: 16, fontSize: 10 }}
                          />
                        )}
                      </Box>
                    }
                    secondary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.5 }}>
                        <Typography variant="caption" color="text.secondary">
                          {timeAgo(activity.timestamp)}
                        </Typography>
                        {activity.entityType && (
                          <>
                            <Typography variant="caption" color="text.secondary">•</Typography>
                            <Chip
                              label={activity.entityType}
                              size="small"
                              variant="outlined"
                              sx={{ height: 18, fontSize: 11 }}
                            />
                          </>
                        )}
                        {activity.details && activity.details.includes('@') && (
                          <Chip
                            label="Mentioned"
                            size="small"
                            color="primary"
                            variant="outlined"
                            sx={{ height: 18, fontSize: 11 }}
                          />
                        )}
                      </Box>
                    }
                  />
                </ListItem>
                {index < filteredActivities.length - 1 && (
                  <Divider variant="inset" component="li" />
                )}
              </React.Fragment>
            );
          })
        )}
      </List>
    </Paper>
  );
};

export default ActivityFeed;