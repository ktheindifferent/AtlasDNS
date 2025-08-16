import React from 'react';
import {
  Box,
  Avatar,
  AvatarGroup,
  Tooltip,
  Badge,
  Typography,
  Chip,
  IconButton,
  Popover,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
} from '@mui/material';
import { styled } from '@mui/material/styles';
import { useSelector } from 'react-redux';
import { RootState } from '../../store';
import { User } from '../../store/slices/collaborationSlice';
import PeopleIcon from '@mui/icons-material/People';

const StyledBadge = styled(Badge)<{ status: 'online' | 'idle' | 'away' }>(({ theme, status }) => ({
  '& .MuiBadge-badge': {
    backgroundColor: status === 'online' ? '#44b700' : status === 'idle' ? '#FFA500' : '#757575',
    color: status === 'online' ? '#44b700' : status === 'idle' ? '#FFA500' : '#757575',
    boxShadow: `0 0 0 2px ${theme.palette.background.paper}`,
    '&::after': {
      position: 'absolute',
      top: 0,
      left: 0,
      width: '100%',
      height: '100%',
      borderRadius: '50%',
      animation: status === 'online' ? 'ripple 1.2s infinite ease-in-out' : 'none',
      border: '1px solid currentColor',
      content: '""',
    },
  },
  '@keyframes ripple': {
    '0%': {
      transform: 'scale(.8)',
      opacity: 1,
    },
    '100%': {
      transform: 'scale(2.4)',
      opacity: 0,
    },
  },
}));

interface UserPresenceProps {
  maxDisplay?: number;
  showDetails?: boolean;
}

const UserPresence: React.FC<UserPresenceProps> = ({ maxDisplay = 3, showDetails = true }) => {
  const { activeUsers, presence } = useSelector((state: RootState) => state.collaboration);
  const { user: currentUser } = useSelector((state: RootState) => state.auth);
  const [anchorEl, setAnchorEl] = React.useState<HTMLButtonElement | null>(null);

  const handleClick = (event: React.MouseEvent<HTMLButtonElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const open = Boolean(anchorEl);

  const getUserStatus = (userId: string) => {
    return presence[userId]?.status || 'online';
  };

  const getStatusText = (status: string) => {
    switch (status) {
      case 'online':
        return 'Active';
      case 'idle':
        return 'Idle';
      case 'away':
        return 'Away';
      default:
        return 'Offline';
    }
  };

  const getInitials = (name: string) => {
    return name
      .split(' ')
      .map(part => part[0])
      .join('')
      .toUpperCase()
      .slice(0, 2);
  };

  if (activeUsers.length === 0 && !currentUser) {
    return null;
  }

  const allUsers = currentUser ? [
    { ...currentUser, id: currentUser.id || '', color: '#2196F3', name: currentUser.name || currentUser.email || 'You' } as User,
    ...activeUsers
  ] : activeUsers;

  const displayUsers = allUsers.slice(0, maxDisplay);
  const remainingCount = Math.max(0, allUsers.length - maxDisplay);

  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <PeopleIcon sx={{ fontSize: 20, color: 'text.secondary' }} />
        <Typography variant="body2" color="text.secondary">
          {allUsers.length} {allUsers.length === 1 ? 'user' : 'users'} online
        </Typography>
      </Box>

      <AvatarGroup max={maxDisplay + 1} spacing="medium">
        {displayUsers.map((user) => {
          const status = getUserStatus(user.id);
          const isCurrentUser = user.id === currentUser?.id;

          return (
            <Tooltip
              key={user.id}
              title={
                <Box>
                  <Typography variant="body2">{user.name} {isCurrentUser && '(You)'}</Typography>
                  <Typography variant="caption" sx={{ opacity: 0.8 }}>
                    {getStatusText(status)}
                  </Typography>
                </Box>
              }
            >
              <StyledBadge
                overlap="circular"
                anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
                variant="dot"
                status={status}
              >
                <Avatar
                  src={user.avatar}
                  sx={{
                    width: 32,
                    height: 32,
                    bgcolor: user.color,
                    fontSize: 14,
                    border: isCurrentUser ? '2px solid #2196F3' : 'none',
                  }}
                >
                  {!user.avatar && getInitials(user.name)}
                </Avatar>
              </StyledBadge>
            </Tooltip>
          );
        })}
        {remainingCount > 0 && (
          <IconButton onClick={handleClick} size="small">
            <Avatar sx={{ width: 32, height: 32, bgcolor: 'grey.400', fontSize: 14 }}>
              +{remainingCount}
            </Avatar>
          </IconButton>
        )}
      </AvatarGroup>

      <Popover
        open={open}
        anchorEl={anchorEl}
        onClose={handleClose}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'right',
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
      >
        <Box sx={{ p: 2, minWidth: 280 }}>
          <Typography variant="subtitle2" gutterBottom>
            All Active Users
          </Typography>
          <List dense>
            {allUsers.map((user) => {
              const status = getUserStatus(user.id);
              const isCurrentUser = user.id === currentUser?.id;

              return (
                <ListItem key={user.id}>
                  <ListItemAvatar>
                    <StyledBadge
                      overlap="circular"
                      anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
                      variant="dot"
                      status={status}
                    >
                      <Avatar
                        src={user.avatar}
                        sx={{
                          bgcolor: user.color,
                          border: isCurrentUser ? '2px solid #2196F3' : 'none',
                        }}
                      >
                        {!user.avatar && getInitials(user.name)}
                      </Avatar>
                    </StyledBadge>
                  </ListItemAvatar>
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography variant="body2">
                          {user.name}
                        </Typography>
                        {isCurrentUser && (
                          <Chip label="You" size="small" color="primary" variant="outlined" />
                        )}
                      </Box>
                    }
                    secondary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography variant="caption" color="text.secondary">
                          {user.email}
                        </Typography>
                        <Chip
                          label={getStatusText(status)}
                          size="small"
                          sx={{
                            bgcolor: status === 'online' ? 'success.light' :
                                    status === 'idle' ? 'warning.light' : 'grey.300',
                            color: status === 'online' ? 'success.dark' :
                                   status === 'idle' ? 'warning.dark' : 'grey.700',
                            fontSize: 10,
                            height: 16,
                          }}
                        />
                      </Box>
                    }
                  />
                </ListItem>
              );
            })}
          </List>
        </Box>
      </Popover>
    </Box>
  );
};

export default UserPresence;