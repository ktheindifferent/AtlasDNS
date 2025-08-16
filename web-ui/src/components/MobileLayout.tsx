import React, { useState, useEffect } from 'react';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import {
  Box,
  BottomNavigation,
  BottomNavigationAction,
  Fab,
  SpeedDial,
  SpeedDialIcon,
  SpeedDialAction,
  Paper,
  useTheme,
  useMediaQuery,
  SwipeableDrawer,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  AppBar,
  Toolbar,
  IconButton,
  Typography,
  Avatar,
  Badge,
} from '@mui/material';
import {
  Dashboard,
  Dns,
  Analytics,
  Settings,
  Menu as MenuIcon,
  Add,
  Edit,
  FileCopy,
  Save,
  Share,
  Close,
  Notifications,
  MoreVert,
} from '@mui/icons-material';
import { useGesture } from '@use-gesture/react';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuth } from '../contexts/AuthContext';
import { useSelector } from 'react-redux';
import { RootState } from '../store';

const bottomNavItems = [
  { label: 'Dashboard', icon: <Dashboard />, path: '/dashboard' },
  { label: 'Zones', icon: <Dns />, path: '/zones' },
  { label: 'Analytics', icon: <Analytics />, path: '/analytics' },
  { label: 'Settings', icon: <Settings />, path: '/settings' },
];

const speedDialActions = [
  { icon: <FileCopy />, name: 'Copy', action: 'copy' },
  { icon: <Save />, name: 'Save', action: 'save' },
  { icon: <Share />, name: 'Share', action: 'share' },
  { icon: <Edit />, name: 'Edit', action: 'edit' },
];

interface MobileLayoutProps {
  children?: React.ReactNode;
}

const MobileLayout: React.FC<MobileLayoutProps> = ({ children }) => {
  const theme = useTheme();
  const navigate = useNavigate();
  const location = useLocation();
  const { user } = useAuth();
  const unreadCount = useSelector((state: RootState) => state.notifications.unreadCount);
  
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const isTablet = useMediaQuery(theme.breakpoints.between('sm', 'md'));
  
  const [value, setValue] = useState(0);
  const [speedDialOpen, setSpeedDialOpen] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [swipeDirection, setSwipeDirection] = useState<'left' | 'right' | null>(null);

  // Sync bottom navigation with current route
  useEffect(() => {
    const currentIndex = bottomNavItems.findIndex(item => location.pathname.startsWith(item.path));
    if (currentIndex !== -1) {
      setValue(currentIndex);
    }
  }, [location.pathname]);

  // Handle swipe gestures for navigation
  const bind = useGesture({
    onDrag: ({ direction: [dx], velocity: [vx], distance, cancel }) => {
      if (Math.abs(dx) > 0.5 && Math.abs(vx) > 0.2) {
        if (dx > 0 && value > 0) {
          // Swipe right - go to previous tab
          const newValue = value - 1;
          setValue(newValue);
          navigate(bottomNavItems[newValue].path);
          setSwipeDirection('right');
          cancel();
        } else if (dx < 0 && value < bottomNavItems.length - 1) {
          // Swipe left - go to next tab
          const newValue = value + 1;
          setValue(newValue);
          navigate(bottomNavItems[newValue].path);
          setSwipeDirection('left');
          cancel();
        }
      }
    },
    onDragEnd: () => {
      setTimeout(() => setSwipeDirection(null), 300);
    }
  }, {
    drag: {
      axis: 'x',
      filterTaps: true,
      threshold: 50,
    }
  });

  const handleSpeedDialAction = (action: string) => {
    // Trigger haptic feedback if available
    if ('vibrate' in navigator) {
      navigator.vibrate(10);
    }
    
    // Handle different actions
    switch (action) {
      case 'copy':
        console.log('Copy action');
        break;
      case 'save':
        console.log('Save action');
        break;
      case 'share':
        console.log('Share action');
        break;
      case 'edit':
        navigate('/zones');
        break;
    }
    setSpeedDialOpen(false);
  };

  const handleBottomNavChange = (_event: React.SyntheticEvent, newValue: number) => {
    // Trigger haptic feedback
    if ('vibrate' in navigator) {
      navigator.vibrate(5);
    }
    setValue(newValue);
    navigate(bottomNavItems[newValue].path);
  };

  if (!isMobile && !isTablet) {
    // Return regular layout for desktop
    return <>{children || <Outlet />}</>;
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', height: '100vh' }}>
      {/* Mobile App Bar */}
      <AppBar position="fixed" elevation={0}>
        <Toolbar sx={{ minHeight: { xs: 56, sm: 64 } }}>
          <IconButton
            edge="start"
            color="inherit"
            aria-label="menu"
            onClick={() => setDrawerOpen(true)}
            sx={{ mr: 2 }}
          >
            <MenuIcon />
          </IconButton>
          
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            {bottomNavItems[value]?.label || 'Atlas DNS'}
          </Typography>
          
          <IconButton color="inherit">
            <Badge badgeContent={unreadCount} color="error">
              <Notifications />
            </Badge>
          </IconButton>
          
          <IconButton color="inherit" sx={{ ml: 1 }}>
            <Avatar sx={{ width: 32, height: 32, bgcolor: theme.palette.secondary.main }}>
              {user?.name?.charAt(0) || 'U'}
            </Avatar>
          </IconButton>
        </Toolbar>
      </AppBar>

      {/* Main Content Area with Swipe Gestures */}
      <Box
        sx={{
          flexGrow: 1,
          pt: { xs: 7, sm: 8 },
          pb: 7,
          px: 2,
          overflowY: 'auto',
          touchAction: 'pan-y',
        }}
      >
        <motion.div
          {...bind()}
          animate={{
            x: swipeDirection === 'left' ? -20 : swipeDirection === 'right' ? 20 : 0,
          }}
          transition={{ type: 'spring', stiffness: 300, damping: 30 }}
        >
          <AnimatePresence mode="wait">
            <motion.div
              key={location.pathname}
              initial={{ opacity: 0, x: swipeDirection === 'left' ? 100 : swipeDirection === 'right' ? -100 : 0 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: swipeDirection === 'left' ? -100 : swipeDirection === 'right' ? 100 : 0 }}
              transition={{ duration: 0.2 }}
            >
              {children || <Outlet />}
            </motion.div>
          </AnimatePresence>
        </motion.div>
      </Box>

      {/* Floating Action Button with Speed Dial */}
      <SpeedDial
        ariaLabel="Quick actions"
        sx={{
          position: 'fixed',
          bottom: 80,
          right: 16,
          '& .MuiFab-primary': {
            width: 56,
            height: 56,
          }
        }}
        icon={<SpeedDialIcon openIcon={<Close />} />}
        open={speedDialOpen}
        onClose={() => setSpeedDialOpen(false)}
        onOpen={() => {
          if ('vibrate' in navigator) {
            navigator.vibrate(10);
          }
          setSpeedDialOpen(true);
        }}
      >
        {speedDialActions.map((action) => (
          <SpeedDialAction
            key={action.name}
            icon={action.icon}
            tooltipTitle={action.name}
            onClick={() => handleSpeedDialAction(action.action)}
            tooltipOpen
          />
        ))}
      </SpeedDial>

      {/* Bottom Navigation */}
      <Paper
        sx={{
          position: 'fixed',
          bottom: 0,
          left: 0,
          right: 0,
          zIndex: theme.zIndex.appBar,
        }}
        elevation={3}
      >
        <BottomNavigation
          value={value}
          onChange={handleBottomNavChange}
          showLabels
          sx={{
            height: 56,
            '& .MuiBottomNavigationAction-root': {
              minWidth: 'auto',
              padding: '6px 0',
            },
          }}
        >
          {bottomNavItems.map((item, index) => (
            <BottomNavigationAction
              key={item.path}
              label={item.label}
              icon={item.icon}
              value={index}
            />
          ))}
        </BottomNavigation>
      </Paper>

      {/* Swipeable Drawer for Additional Navigation */}
      <SwipeableDrawer
        anchor="left"
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        onOpen={() => setDrawerOpen(true)}
        disableBackdropTransition={!isMobile}
        disableDiscovery={!isMobile}
      >
        <Box sx={{ width: 250 }}>
          <Toolbar>
            <Typography variant="h6" sx={{ flexGrow: 1 }}>
              Atlas DNS
            </Typography>
            <IconButton onClick={() => setDrawerOpen(false)}>
              <Close />
            </IconButton>
          </Toolbar>
          <List>
            {[
              { text: 'Health Checks', path: '/health-checks' },
              { text: 'Traffic Policies', path: '/traffic-policies' },
              { text: 'GeoDNS', path: '/geodns' },
              { text: 'DNSSEC', path: '/dnssec' },
              { text: 'Monitoring', path: '/monitoring' },
              { text: 'Logs', path: '/logs' },
              { text: 'Users', path: '/users' },
            ].map((item) => (
              <ListItem key={item.text} disablePadding>
                <ListItemButton
                  onClick={() => {
                    navigate(item.path);
                    setDrawerOpen(false);
                  }}
                >
                  <ListItemText primary={item.text} />
                </ListItemButton>
              </ListItem>
            ))}
          </List>
        </Box>
      </SwipeableDrawer>
    </Box>
  );
};

export default MobileLayout;