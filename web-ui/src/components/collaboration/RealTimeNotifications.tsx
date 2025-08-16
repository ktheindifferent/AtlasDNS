import React, { useEffect, useState } from 'react';
import { useSnackbar, SnackbarKey } from 'notistack';
import {
  Box,
  Typography,
  Avatar,
  IconButton,
  Button,
  Card,
  CardContent,
  CardActions,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import { useSelector, useDispatch } from 'react-redux';
import { RootState, AppDispatch } from '../../store';
import { useWebSocket } from '../../hooks/useWebSocket';
import { useNavigate } from 'react-router-dom';
import { format } from 'timeago.js';

interface NotificationData {
  id: string;
  type: 'dns-change' | 'mention' | 'comment' | 'collaboration' | 'system';
  title: string;
  message: string;
  user?: {
    id: string;
    name: string;
    avatar?: string;
    color: string;
  };
  entityType?: 'zone' | 'record';
  entityId?: string;
  entityName?: string;
  timestamp: string;
  priority?: 'low' | 'medium' | 'high';
  actionUrl?: string;
}

const RealTimeNotifications: React.FC = () => {
  const { enqueueSnackbar, closeSnackbar } = useSnackbar();
  const navigate = useNavigate();
  const dispatch = useDispatch<AppDispatch>();
  const { user: currentUser } = useSelector((state: RootState) => state.auth);
  const { on, off } = useWebSocket();
  const [notifications, setNotifications] = useState<NotificationData[]>([]);
  const [snackbarKeys, setSnackbarKeys] = useState<Map<string, SnackbarKey>>(new Map());

  useEffect(() => {
    const handleDNSChange = (data: any) => {
      if (data.userId === currentUser?.id) return;

      const notification: NotificationData = {
        id: `dns-${Date.now()}`,
        type: 'dns-change',
        title: 'DNS Change',
        message: `${data.user?.name || 'Someone'} ${data.action} ${data.entityType} "${data.entityName}"`,
        user: data.user,
        entityType: data.entityType,
        entityId: data.entityId,
        entityName: data.entityName,
        timestamp: new Date().toISOString(),
        priority: data.action === 'delete' ? 'high' : 'medium',
        actionUrl: `/${data.entityType}s/${data.entityId}`,
      };

      showNotification(notification);
    };

    const handleMention = (data: any) => {
      if (data.userId === currentUser?.id) return;

      const notification: NotificationData = {
        id: `mention-${Date.now()}`,
        type: 'mention',
        title: 'You were mentioned',
        message: `${data.user?.name || 'Someone'} mentioned you in ${data.context}`,
        user: data.user,
        timestamp: new Date().toISOString(),
        priority: 'high',
        actionUrl: data.url,
      };

      showNotification(notification);
    };

    const handleNewComment = (data: any) => {
      if (data.userId === currentUser?.id) return;
      
      const isMentioned = data.mentions?.includes(currentUser?.id);
      if (!isMentioned && data.entityOwnerId !== currentUser?.id) return;

      const notification: NotificationData = {
        id: `comment-${Date.now()}`,
        type: 'comment',
        title: isMentioned ? 'You were mentioned in a comment' : 'New comment',
        message: `${data.user?.name || 'Someone'} commented on ${data.entityType} "${data.entityName}"`,
        user: data.user,
        entityType: data.entityType,
        entityId: data.entityId,
        entityName: data.entityName,
        timestamp: new Date().toISOString(),
        priority: isMentioned ? 'high' : 'medium',
        actionUrl: `/${data.entityType}s/${data.entityId}`,
      };

      showNotification(notification);
    };

    const handleCollaboration = (data: any) => {
      if (data.userId === currentUser?.id) return;

      const notification: NotificationData = {
        id: `collab-${Date.now()}`,
        type: 'collaboration',
        title: 'Collaboration Update',
        message: data.message,
        user: data.user,
        timestamp: new Date().toISOString(),
        priority: data.priority || 'low',
      };

      showNotification(notification);
    };

    const handleSystemAlert = (data: any) => {
      const notification: NotificationData = {
        id: `system-${Date.now()}`,
        type: 'system',
        title: data.title || 'System Alert',
        message: data.message,
        timestamp: new Date().toISOString(),
        priority: data.priority || 'high',
      };

      showNotification(notification);
    };

    on('dns:change', handleDNSChange);
    on('mention:notification', handleMention);
    on('comment:notification', handleNewComment);
    on('collaboration:update', handleCollaboration);
    on('system:alert', handleSystemAlert);

    return () => {
      off('dns:change');
      off('mention:notification');
      off('comment:notification');
      off('collaboration:update');
      off('system:alert');
    };
  }, [currentUser, on, off]);

  const showNotification = (notification: NotificationData) => {
    setNotifications(prev => [notification, ...prev].slice(0, 10));

    const action = (key: SnackbarKey) => (
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
        {notification.actionUrl && (
          <IconButton
            size="small"
            color="inherit"
            onClick={() => {
              navigate(notification.actionUrl!);
              closeSnackbar(key);
            }}
          >
            <OpenInNewIcon fontSize="small" />
          </IconButton>
        )}
        <IconButton
          size="small"
          color="inherit"
          onClick={() => closeSnackbar(key)}
        >
          <CloseIcon fontSize="small" />
        </IconButton>
      </Box>
    );

    const content = (key: SnackbarKey) => (
      <Card sx={{ minWidth: 300, maxWidth: 400 }}>
        <CardContent sx={{ pb: 1 }}>
          <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1.5 }}>
            {notification.user && (
              <Avatar
                src={notification.user.avatar}
                sx={{
                  width: 32,
                  height: 32,
                  bgcolor: notification.user.color,
                  fontSize: 14,
                }}
              >
                {!notification.user.avatar && notification.user.name[0].toUpperCase()}
              </Avatar>
            )}
            <Box sx={{ flex: 1 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                {notification.title}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {notification.message}
              </Typography>
              <Typography variant="caption" color="text.disabled" sx={{ mt: 0.5 }}>
                {format(notification.timestamp)}
              </Typography>
            </Box>
          </Box>
        </CardContent>
        {notification.actionUrl && (
          <CardActions sx={{ justifyContent: 'flex-end', pt: 0 }}>
            <Button
              size="small"
              onClick={() => {
                navigate(notification.actionUrl!);
                closeSnackbar(key);
              }}
            >
              View
            </Button>
            <Button
              size="small"
              color="inherit"
              onClick={() => closeSnackbar(key)}
            >
              Dismiss
            </Button>
          </CardActions>
        )}
      </Card>
    );

    const key = enqueueSnackbar(notification.message, {
      variant: getVariant(notification.priority),
      autoHideDuration: getAutoHideDuration(notification.priority),
      action,
      content,
      anchorOrigin: {
        vertical: 'top',
        horizontal: 'right',
      },
    });

    setSnackbarKeys(prev => new Map(prev).set(notification.id, key));

    if (notification.priority === 'high' && 'Notification' in window && Notification.permission === 'granted') {
      new Notification(notification.title, {
        body: notification.message,
        icon: notification.user?.avatar || '/logo192.png',
        tag: notification.id,
      });
    }
  };

  const getVariant = (priority?: string) => {
    switch (priority) {
      case 'high':
        return 'error';
      case 'medium':
        return 'warning';
      case 'low':
        return 'info';
      default:
        return 'default';
    }
  };

  const getAutoHideDuration = (priority?: string) => {
    switch (priority) {
      case 'high':
        return 8000;
      case 'medium':
        return 6000;
      case 'low':
        return 4000;
      default:
        return 5000;
    }
  };

  useEffect(() => {
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission();
    }
  }, []);

  return null;
};

export default RealTimeNotifications;