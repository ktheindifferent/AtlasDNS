import React, { useState, useEffect } from 'react';
import {
  IconButton,
  Badge,
  Tooltip,
  Menu,
  MenuItem,
  ListItemText,
  ListItemIcon,
  Typography,
  Box,
  Divider,
} from '@mui/material';
import {
  Notifications as NotificationsIcon,
  NotificationsActive as NotificationsActiveIcon,
  NotificationsOff as NotificationsOffIcon,
  Settings as SettingsIcon,
  Rule as RuleIcon,
  OpenInNew as OpenInNewIcon,
} from '@mui/icons-material';
import { useSelector, useDispatch } from 'react-redux';
import { RootState } from '../../store';
import { markAsRead } from '../../store/slices/notificationSlice';
import NotificationCenter from './NotificationCenter';
import { formatDistanceToNow } from 'date-fns';

interface NotificationBellProps {
  color?: 'inherit' | 'default' | 'primary' | 'secondary';
  size?: 'small' | 'medium' | 'large';
}

const NotificationBell: React.FC<NotificationBellProps> = ({
  color = 'inherit',
  size = 'medium',
}) => {
  const dispatch = useDispatch();
  const { unreadCount, notifications, preferences } = useSelector(
    (state: RootState) => state.notifications
  );
  
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [showCenter, setShowCenter] = useState(false);
  const [animateBell, setAnimateBell] = useState(false);

  const recentNotifications = notifications
    .filter(n => !n.read)
    .slice(0, 5);

  useEffect(() => {
    if (unreadCount > 0 && preferences.sound) {
      // Play notification sound
      const audio = new Audio('/notification.mp3');
      audio.play().catch(() => {});
      
      // Animate bell
      setAnimateBell(true);
      setTimeout(() => setAnimateBell(false), 1000);
    }
  }, [unreadCount, preferences.sound]);

  const handleClick = (event: React.MouseEvent<HTMLElement>) => {
    if (recentNotifications.length > 0) {
      setAnchorEl(event.currentTarget);
    } else {
      setShowCenter(true);
    }
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleNotificationClick = (notificationId: string) => {
    dispatch(markAsRead(notificationId));
    handleClose();
  };

  const handleOpenCenter = () => {
    handleClose();
    setShowCenter(true);
  };

  const getIcon = () => {
    if (preferences.doNotDisturb.enabled) {
      return <NotificationsOffIcon />;
    }
    
    if (unreadCount > 0 && animateBell) {
      return <NotificationsActiveIcon />;
    }
    
    return <NotificationsIcon />;
  };

  return (
    <>
      <Tooltip title={
        preferences.doNotDisturb.enabled 
          ? 'Do Not Disturb is enabled' 
          : `${unreadCount} unread notifications`
      }>
        <IconButton
          color={color}
          size={size}
          onClick={handleClick}
          sx={{
            animation: animateBell ? 'bellRing 0.5s ease-in-out' : undefined,
            '@keyframes bellRing': {
              '0%': { transform: 'rotate(0deg)' },
              '10%': { transform: 'rotate(10deg)' },
              '20%': { transform: 'rotate(-10deg)' },
              '30%': { transform: 'rotate(10deg)' },
              '40%': { transform: 'rotate(-10deg)' },
              '50%': { transform: 'rotate(5deg)' },
              '60%': { transform: 'rotate(-5deg)' },
              '70%': { transform: 'rotate(2deg)' },
              '80%': { transform: 'rotate(-2deg)' },
              '90%': { transform: 'rotate(1deg)' },
              '100%': { transform: 'rotate(0deg)' },
            },
          }}
        >
          <Badge
            badgeContent={unreadCount}
            color="error"
            max={99}
            invisible={preferences.doNotDisturb.enabled}
          >
            {getIcon()}
          </Badge>
        </IconButton>
      </Tooltip>

      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
        PaperProps={{
          sx: {
            width: 360,
            maxHeight: 480,
          },
        }}
      >
        <Box sx={{ px: 2, py: 1 }}>
          <Typography variant="subtitle1" fontWeight="bold">
            Recent Notifications
          </Typography>
        </Box>
        
        <Divider />
        
        {recentNotifications.map((notification) => (
          <MenuItem
            key={notification.id}
            onClick={() => handleNotificationClick(notification.id)}
            sx={{ py: 1.5, px: 2 }}
          >
            <Box sx={{ width: '100%' }}>
              <Typography variant="subtitle2" noWrap>
                {notification.title}
              </Typography>
              <Typography
                variant="body2"
                color="text.secondary"
                sx={{
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  display: '-webkit-box',
                  WebkitLineClamp: 2,
                  WebkitBoxOrient: 'vertical',
                }}
              >
                {notification.message}
              </Typography>
              <Typography variant="caption" color="text.disabled">
                {formatDistanceToNow(notification.timestamp, { addSuffix: true })}
              </Typography>
            </Box>
          </MenuItem>
        ))}
        
        {recentNotifications.length === 0 && (
          <Box sx={{ px: 2, py: 3, textAlign: 'center' }}>
            <NotificationsIcon sx={{ fontSize: 48, color: 'text.disabled' }} />
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              No new notifications
            </Typography>
          </Box>
        )}
        
        <Divider />
        
        <MenuItem onClick={handleOpenCenter}>
          <ListItemIcon>
            <OpenInNewIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText primary="View all notifications" />
        </MenuItem>
      </Menu>

      <NotificationCenter
        open={showCenter}
        onClose={() => setShowCenter(false)}
      />
    </>
  );
};

export default NotificationBell;