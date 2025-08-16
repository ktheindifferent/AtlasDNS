import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Drawer,
  Typography,
  IconButton,
  Badge,
  Tabs,
  Tab,
  TextField,
  InputAdornment,
  Chip,
  Button,
  Stack,
  Divider,
  Menu,
  MenuItem,
  Tooltip,
  Paper,
  Checkbox,
  FormControlLabel,
  Alert,
} from '@mui/material';
import {
  Notifications as NotificationsIcon,
  Search as SearchIcon,
  FilterList as FilterIcon,
  Settings as SettingsIcon,
  Clear as ClearIcon,
  DoneAll as DoneAllIcon,
  Delete as DeleteIcon,
  Archive as ArchiveIcon,
  Snooze as SnoozeIcon,
  VolumeOff as VolumeOffIcon,
  Close as CloseIcon,
  MoreVert as MoreVertIcon,
} from '@mui/icons-material';
import { useSelector, useDispatch } from 'react-redux';
import { RootState } from '../../store';
import {
  markAllAsRead,
  clearNotifications,
  setFilter,
  setSearchQuery,
  setDoNotDisturb,
} from '../../store/slices/notificationSlice';
import NotificationItem from './NotificationItem';
import NotificationGroup from './NotificationGroup';
import NotificationFilters from './NotificationFilters';
import NotificationSettings from './NotificationSettings';
import NotificationRules from './NotificationRules';
import NotificationStats from './NotificationStats';
import {
  NotificationCategory,
  NotificationPriority,
  NotificationStatus,
} from '../../types/notification.types';

interface NotificationCenterProps {
  open: boolean;
  onClose: () => void;
  anchor?: 'left' | 'right';
}

const NotificationCenter: React.FC<NotificationCenterProps> = ({
  open,
  onClose,
  anchor = 'right',
}) => {
  const dispatch = useDispatch();
  const {
    notifications,
    groups,
    filter,
    unreadCount,
    searchQuery,
    preferences,
    stats,
  } = useSelector((state: RootState) => state.notifications);

  const [selectedTab, setSelectedTab] = useState(0);
  const [showFilters, setShowFilters] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [showRules, setShowRules] = useState(false);
  const [selectedNotifications, setSelectedNotifications] = useState<Set<string>>(new Set());
  const [bulkActionMenu, setBulkActionMenu] = useState<null | HTMLElement>(null);
  const [snoozeMenuAnchor, setSnoozeMenuAnchor] = useState<null | HTMLElement>(null);

  const filteredNotifications = React.useMemo(() => {
    let filtered = [...notifications];

    // Apply search
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(n =>
        n.title.toLowerCase().includes(query) ||
        n.message.toLowerCase().includes(query)
      );
    }

    // Apply filters
    if (filter.categories?.length) {
      filtered = filtered.filter(n => filter.categories!.includes(n.category));
    }

    if (filter.priorities?.length) {
      filtered = filtered.filter(n => filter.priorities!.includes(n.priority));
    }

    if (filter.statuses?.length) {
      filtered = filtered.filter(n => filter.statuses!.includes(n.status));
    }

    if (filter.read !== undefined) {
      filtered = filtered.filter(n => n.read === filter.read);
    }

    // Apply tab filter
    switch (selectedTab) {
      case 1: // Unread
        filtered = filtered.filter(n => !n.read);
        break;
      case 2: // Urgent
        filtered = filtered.filter(n => 
          n.priority === NotificationPriority.URGENT ||
          n.priority === NotificationPriority.HIGH
        );
        break;
      case 3: // Snoozed
        filtered = filtered.filter(n => n.status === NotificationStatus.SNOOZED);
        break;
      case 4: // Archived
        filtered = filtered.filter(n => n.status === NotificationStatus.ARCHIVED);
        break;
    }

    return filtered;
  }, [notifications, searchQuery, filter, selectedTab]);

  const handleSearch = (event: React.ChangeEvent<HTMLInputElement>) => {
    dispatch(setSearchQuery(event.target.value));
  };

  const handleMarkAllRead = () => {
    dispatch(markAllAsRead());
  };

  const handleClearAll = () => {
    if (window.confirm('Are you sure you want to clear all notifications?')) {
      dispatch(clearNotifications());
      setSelectedNotifications(new Set());
    }
  };

  const handleToggleDoNotDisturb = () => {
    dispatch(setDoNotDisturb({
      ...preferences.doNotDisturb,
      enabled: !preferences.doNotDisturb.enabled,
    }));
  };

  const handleBulkAction = (action: string) => {
    const ids = Array.from(selectedNotifications);
    
    switch (action) {
      case 'markRead':
        // dispatch(markMultipleAsRead(ids));
        break;
      case 'delete':
        // dispatch(deleteMultiple(ids));
        break;
      case 'archive':
        ids.forEach(id => {
          // dispatch(archiveNotification(id));
        });
        break;
    }
    
    setSelectedNotifications(new Set());
    setBulkActionMenu(null);
  };

  const handleSnooze = (duration: number) => {
    const ids = Array.from(selectedNotifications);
    const until = Date.now() + duration;
    
    ids.forEach(id => {
      // dispatch(snoozeNotification({ id, until }));
    });
    
    setSelectedNotifications(new Set());
    setSnoozeMenuAnchor(null);
  };

  const toggleNotificationSelection = (id: string) => {
    const newSelection = new Set(selectedNotifications);
    if (newSelection.has(id)) {
      newSelection.delete(id);
    } else {
      newSelection.add(id);
    }
    setSelectedNotifications(newSelection);
  };

  const getCategoryColor = (category: NotificationCategory): string => {
    const colors: Record<NotificationCategory, string> = {
      [NotificationCategory.SYSTEM]: 'default',
      [NotificationCategory.SECURITY]: 'error',
      [NotificationCategory.ZONE]: 'primary',
      [NotificationCategory.RECORD]: 'info',
      [NotificationCategory.HEALTH]: 'warning',
      [NotificationCategory.PERFORMANCE]: 'secondary',
      [NotificationCategory.USER]: 'success',
      [NotificationCategory.ALERT]: 'error',
      [NotificationCategory.INFO]: 'info',
    };
    return colors[category] || 'default';
  };

  const getPriorityIcon = (priority: NotificationPriority): string => {
    switch (priority) {
      case NotificationPriority.URGENT:
        return '🔴';
      case NotificationPriority.HIGH:
        return '🟠';
      case NotificationPriority.MEDIUM:
        return '🟡';
      case NotificationPriority.LOW:
        return '🟢';
      default:
        return '';
    }
  };

  return (
    <Drawer
      anchor={anchor}
      open={open}
      onClose={onClose}
      PaperProps={{
        sx: {
          width: { xs: '100%', sm: 480, md: 600 },
          maxWidth: '100%',
        },
      }}
    >
      <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
        {/* Header */}
        <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
          <Stack direction="row" alignItems="center" justifyContent="space-between">
            <Stack direction="row" alignItems="center" spacing={2}>
              <Badge badgeContent={unreadCount} color="error">
                <NotificationsIcon />
              </Badge>
              <Typography variant="h6">Notification Center</Typography>
            </Stack>
            
            <Stack direction="row" spacing={1}>
              {preferences.doNotDisturb.enabled && (
                <Chip
                  icon={<VolumeOffIcon />}
                  label="Do Not Disturb"
                  size="small"
                  color="warning"
                  onDelete={handleToggleDoNotDisturb}
                />
              )}
              
              <Tooltip title="Mark all as read">
                <IconButton onClick={handleMarkAllRead} size="small">
                  <DoneAllIcon />
                </IconButton>
              </Tooltip>
              
              <Tooltip title="Filters">
                <IconButton onClick={() => setShowFilters(!showFilters)} size="small">
                  <FilterIcon />
                </IconButton>
              </Tooltip>
              
              <Tooltip title="Settings">
                <IconButton onClick={() => setShowSettings(!showSettings)} size="small">
                  <SettingsIcon />
                </IconButton>
              </Tooltip>
              
              <IconButton onClick={onClose} size="small">
                <CloseIcon />
              </IconButton>
            </Stack>
          </Stack>

          {/* Search Bar */}
          <TextField
            fullWidth
            size="small"
            placeholder="Search notifications..."
            value={searchQuery}
            onChange={handleSearch}
            sx={{ mt: 2 }}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon />
                </InputAdornment>
              ),
              endAdornment: searchQuery && (
                <InputAdornment position="end">
                  <IconButton
                    size="small"
                    onClick={() => dispatch(setSearchQuery(''))}
                  >
                    <ClearIcon />
                  </IconButton>
                </InputAdornment>
              ),
            }}
          />

          {/* Category Filters */}
          {showFilters && (
            <NotificationFilters
              filter={filter}
              onFilterChange={(newFilter) => dispatch(setFilter(newFilter))}
              sx={{ mt: 2 }}
            />
          )}

          {/* Tabs */}
          <Tabs
            value={selectedTab}
            onChange={(_, value) => setSelectedTab(value)}
            variant="scrollable"
            scrollButtons="auto"
            sx={{ mt: 2 }}
          >
            <Tab label={`All (${notifications.length})`} />
            <Tab label={`Unread (${unreadCount})`} />
            <Tab label="Urgent" />
            <Tab label="Snoozed" />
            <Tab label="Archived" />
          </Tabs>
        </Box>

        {/* Bulk Actions Bar */}
        {selectedNotifications.size > 0 && (
          <Paper elevation={2} sx={{ p: 1, m: 1 }}>
            <Stack direction="row" alignItems="center" spacing={1}>
              <Typography variant="body2">
                {selectedNotifications.size} selected
              </Typography>
              
              <Button
                size="small"
                startIcon={<DoneAllIcon />}
                onClick={() => handleBulkAction('markRead')}
              >
                Mark Read
              </Button>
              
              <Button
                size="small"
                startIcon={<SnoozeIcon />}
                onClick={(e) => setSnoozeMenuAnchor(e.currentTarget)}
              >
                Snooze
              </Button>
              
              <Button
                size="small"
                startIcon={<ArchiveIcon />}
                onClick={() => handleBulkAction('archive')}
              >
                Archive
              </Button>
              
              <Button
                size="small"
                startIcon={<DeleteIcon />}
                color="error"
                onClick={() => handleBulkAction('delete')}
              >
                Delete
              </Button>
              
              <Box sx={{ flexGrow: 1 }} />
              
              <IconButton
                size="small"
                onClick={() => setSelectedNotifications(new Set())}
              >
                <ClearIcon />
              </IconButton>
            </Stack>
          </Paper>
        )}

        {/* Snooze Menu */}
        <Menu
          anchorEl={snoozeMenuAnchor}
          open={Boolean(snoozeMenuAnchor)}
          onClose={() => setSnoozeMenuAnchor(null)}
        >
          <MenuItem onClick={() => handleSnooze(15 * 60 * 1000)}>15 minutes</MenuItem>
          <MenuItem onClick={() => handleSnooze(60 * 60 * 1000)}>1 hour</MenuItem>
          <MenuItem onClick={() => handleSnooze(4 * 60 * 60 * 1000)}>4 hours</MenuItem>
          <MenuItem onClick={() => handleSnooze(24 * 60 * 60 * 1000)}>Tomorrow</MenuItem>
          <MenuItem onClick={() => handleSnooze(7 * 24 * 60 * 60 * 1000)}>Next week</MenuItem>
        </Menu>

        {/* Notification List */}
        <Box sx={{ flex: 1, overflow: 'auto', p: 1 }}>
          {filteredNotifications.length === 0 ? (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <NotificationsIcon sx={{ fontSize: 64, color: 'text.disabled' }} />
              <Typography variant="h6" color="text.secondary" sx={{ mt: 2 }}>
                No notifications
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {searchQuery ? 'Try adjusting your search or filters' : 'You\'re all caught up!'}
              </Typography>
            </Box>
          ) : (
            <Stack spacing={1}>
              {preferences.grouping.enabled && groups.length > 0 ? (
                <>
                  {groups.map(group => (
                    <NotificationGroup
                      key={group.id}
                      group={group}
                      selected={group.notifications.every(n => 
                        selectedNotifications.has(n.id)
                      )}
                      onToggleSelection={() => {
                        const allSelected = group.notifications.every(n => 
                          selectedNotifications.has(n.id)
                        );
                        const newSelection = new Set(selectedNotifications);
                        
                        group.notifications.forEach(n => {
                          if (allSelected) {
                            newSelection.delete(n.id);
                          } else {
                            newSelection.add(n.id);
                          }
                        });
                        
                        setSelectedNotifications(newSelection);
                      }}
                    />
                  ))}
                  
                  {filteredNotifications
                    .filter(n => !n.groupId)
                    .map(notification => (
                      <NotificationItem
                        key={notification.id}
                        notification={notification}
                        selected={selectedNotifications.has(notification.id)}
                        onToggleSelection={() => toggleNotificationSelection(notification.id)}
                      />
                    ))}
                </>
              ) : (
                filteredNotifications.map(notification => (
                  <NotificationItem
                    key={notification.id}
                    notification={notification}
                    selected={selectedNotifications.has(notification.id)}
                    onToggleSelection={() => toggleNotificationSelection(notification.id)}
                  />
                ))
              )}
            </Stack>
          )}
        </Box>

        {/* Stats Footer */}
        <Box sx={{ p: 2, borderTop: 1, borderColor: 'divider', bgcolor: 'background.paper' }}>
          <NotificationStats stats={stats} compact />
        </Box>
      </Box>

      {/* Settings Dialog */}
      {showSettings && (
        <NotificationSettings
          open={showSettings}
          onClose={() => setShowSettings(false)}
          preferences={preferences}
        />
      )}

      {/* Rules Dialog */}
      {showRules && (
        <NotificationRules
          open={showRules}
          onClose={() => setShowRules(false)}
        />
      )}
    </Drawer>
  );
};

export default NotificationCenter;