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
  Menu,
  MenuItem,
  Collapse,
  Button,
  Tooltip,
  Avatar,
} from '@mui/material';
import {
  MoreVert as MoreVertIcon,
  Done as DoneIcon,
  Archive as ArchiveIcon,
  Delete as DeleteIcon,
  Snooze as SnoozeIcon,
  OpenInNew as OpenInNewIcon,
  Info as InfoIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as CheckCircleIcon,
} from '@mui/icons-material';
import { formatDistanceToNow } from 'date-fns';
import { useDispatch } from 'react-redux';
import {
  markAsRead,
  deleteNotification,
  archiveNotification,
  snoozeNotification,
} from '../../store/slices/notificationSlice';
import {
  Notification,
  NotificationCategory,
  NotificationPriority,
  NotificationStatus,
} from '../../types/notification.types';

interface NotificationItemProps {
  notification: Notification;
  selected: boolean;
  onToggleSelection: () => void;
  compact?: boolean;
}

const NotificationItem: React.FC<NotificationItemProps> = ({
  notification,
  selected,
  onToggleSelection,
  compact = false,
}) => {
  const dispatch = useDispatch();
  const [menuAnchor, setMenuAnchor] = useState<null | HTMLElement>(null);
  const [expanded, setExpanded] = useState(false);

  const handleMarkAsRead = () => {
    if (!notification.read) {
      dispatch(markAsRead(notification.id));
    }
  };

  const handleDelete = () => {
    dispatch(deleteNotification(notification.id));
    setMenuAnchor(null);
  };

  const handleArchive = () => {
    dispatch(archiveNotification(notification.id));
    setMenuAnchor(null);
  };

  const handleSnooze = (duration: number) => {
    dispatch(snoozeNotification({
      id: notification.id,
      until: Date.now() + duration,
    }));
    setMenuAnchor(null);
  };

  const handleActionClick = (action: any) => {
    if (action.handler) {
      // Execute action handler
      console.log('Executing action:', action);
    }
    handleMarkAsRead();
  };

  const getCategoryIcon = () => {
    switch (notification.category) {
      case NotificationCategory.SECURITY:
        return <SecurityIcon />;
      case NotificationCategory.ALERT:
        return <ErrorIcon />;
      case NotificationCategory.HEALTH:
      case NotificationCategory.PERFORMANCE:
        return <WarningIcon />;
      case NotificationCategory.SYSTEM:
        return <InfoIcon />;
      default:
        return <CheckCircleIcon />;
    }
  };

  const getCategoryColor = (): string => {
    const colors: Record<NotificationCategory, string> = {
      [NotificationCategory.SYSTEM]: '#9E9E9E',
      [NotificationCategory.SECURITY]: '#F44336',
      [NotificationCategory.ZONE]: '#2196F3',
      [NotificationCategory.RECORD]: '#00BCD4',
      [NotificationCategory.HEALTH]: '#FF9800',
      [NotificationCategory.PERFORMANCE]: '#9C27B0',
      [NotificationCategory.USER]: '#4CAF50',
      [NotificationCategory.ALERT]: '#F44336',
      [NotificationCategory.INFO]: '#2196F3',
    };
    return colors[notification.category] || '#9E9E9E';
  };

  const getPriorityColor = (): string => {
    switch (notification.priority) {
      case NotificationPriority.URGENT:
        return 'error';
      case NotificationPriority.HIGH:
        return 'warning';
      case NotificationPriority.MEDIUM:
        return 'info';
      case NotificationPriority.LOW:
        return 'default';
      default:
        return 'default';
    }
  };

  const getStatusChip = () => {
    if (notification.status === NotificationStatus.SNOOZED) {
      return (
        <Chip
          icon={<SnoozeIcon />}
          label="Snoozed"
          size="small"
          variant="outlined"
          color="warning"
        />
      );
    }
    
    if (notification.status === NotificationStatus.ARCHIVED) {
      return (
        <Chip
          icon={<ArchiveIcon />}
          label="Archived"
          size="small"
          variant="outlined"
        />
      );
    }
    
    return null;
  };

  return (
    <Card
      sx={{
        opacity: notification.read ? 0.7 : 1,
        bgcolor: notification.read ? 'background.paper' : 'action.hover',
        borderLeft: 4,
        borderColor: getCategoryColor(),
        position: 'relative',
        '&:hover': {
          boxShadow: 2,
        },
      }}
      onClick={handleMarkAsRead}
    >
      <CardContent sx={{ p: compact ? 1.5 : 2 }}>
        <Stack direction="row" spacing={1.5} alignItems="flex-start">
          <Checkbox
            checked={selected}
            onChange={onToggleSelection}
            onClick={(e) => e.stopPropagation()}
            size="small"
          />
          
          <Avatar
            sx={{
              width: 32,
              height: 32,
              bgcolor: getCategoryColor(),
              fontSize: 16,
            }}
          >
            {getCategoryIcon()}
          </Avatar>
          
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 0.5 }}>
              <Typography
                variant="subtitle2"
                sx={{
                  fontWeight: notification.read ? 'normal' : 'bold',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
              >
                {notification.title}
              </Typography>
              
              {!notification.read && (
                <Box
                  sx={{
                    width: 8,
                    height: 8,
                    borderRadius: '50%',
                    bgcolor: 'primary.main',
                  }}
                />
              )}
              
              <Chip
                label={notification.priority}
                size="small"
                color={getPriorityColor() as any}
                sx={{ height: 20, fontSize: '0.7rem' }}
              />
              
              {getStatusChip()}
            </Stack>
            
            <Typography
              variant="body2"
              color="text.secondary"
              sx={{
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                display: '-webkit-box',
                WebkitLineClamp: expanded ? 'unset' : 2,
                WebkitBoxOrient: 'vertical',
              }}
            >
              {notification.message}
            </Typography>
            
            {notification.message.length > 100 && (
              <Button
                size="small"
                onClick={(e) => {
                  e.stopPropagation();
                  setExpanded(!expanded);
                }}
                sx={{ mt: 0.5, p: 0, minWidth: 0 }}
              >
                {expanded ? 'Show less' : 'Show more'}
              </Button>
            )}
            
            {notification.actions && notification.actions.length > 0 && (
              <Stack direction="row" spacing={1} sx={{ mt: 1 }}>
                {notification.actions.map((action) => (
                  <Button
                    key={action.id}
                    size="small"
                    variant={action.primary ? 'contained' : 'outlined'}
                    onClick={(e) => {
                      e.stopPropagation();
                      handleActionClick(action);
                    }}
                    startIcon={action.icon && <OpenInNewIcon />}
                  >
                    {action.label}
                  </Button>
                ))}
              </Stack>
            )}
            
            <Stack direction="row" alignItems="center" spacing={1} sx={{ mt: 1 }}>
              <Typography variant="caption" color="text.disabled">
                {formatDistanceToNow(notification.timestamp, { addSuffix: true })}
              </Typography>
              
              {notification.metadata?.source && (
                <>
                  <Typography variant="caption" color="text.disabled">•</Typography>
                  <Typography variant="caption" color="text.disabled">
                    {notification.metadata.source}
                  </Typography>
                </>
              )}
              
              {notification.groupId && (
                <Chip
                  label="Grouped"
                  size="small"
                  variant="outlined"
                  sx={{ height: 16, fontSize: '0.65rem' }}
                />
              )}
            </Stack>
          </Box>
          
          <IconButton
            size="small"
            onClick={(e) => {
              e.stopPropagation();
              setMenuAnchor(e.currentTarget);
            }}
          >
            <MoreVertIcon fontSize="small" />
          </IconButton>
        </Stack>
      </CardContent>
      
      <Menu
        anchorEl={menuAnchor}
        open={Boolean(menuAnchor)}
        onClose={() => setMenuAnchor(null)}
        onClick={(e) => e.stopPropagation()}
      >
        {!notification.read && (
          <MenuItem onClick={handleMarkAsRead}>
            <DoneIcon fontSize="small" sx={{ mr: 1 }} />
            Mark as read
          </MenuItem>
        )}
        
        <MenuItem onClick={() => setMenuAnchor(null)}>
          <SnoozeIcon fontSize="small" sx={{ mr: 1 }} />
          Snooze
        </MenuItem>
        
        <MenuItem onClick={handleArchive}>
          <ArchiveIcon fontSize="small" sx={{ mr: 1 }} />
          Archive
        </MenuItem>
        
        <MenuItem onClick={handleDelete} sx={{ color: 'error.main' }}>
          <DeleteIcon fontSize="small" sx={{ mr: 1 }} />
          Delete
        </MenuItem>
      </Menu>
    </Card>
  );
};

export default NotificationItem;