import React from 'react';
import { Box, IconButton, Typography } from '@mui/material';
import { Delete, Edit, Archive, MoreVert } from '@mui/icons-material';
import { animated } from '@react-spring/web';
import { useSwipeableItem } from '../../hooks/useGestures';

interface SwipeAction {
  icon: React.ReactNode;
  label: string;
  color: string;
  action: () => void;
}

interface SwipeableListItemProps {
  children: React.ReactNode;
  leftActions?: SwipeAction[];
  rightActions?: SwipeAction[];
  disabled?: boolean;
}

export const SwipeableListItem: React.FC<SwipeableListItemProps> = ({
  children,
  leftActions = [],
  rightActions = [],
  disabled = false,
}) => {
  const { bind, x, swiped, reset } = useSwipeableItem(
    rightActions.length > 0 ? () => rightActions[0].action() : undefined,
    leftActions.length > 0 ? () => leftActions[0].action() : undefined,
    80
  );

  if (disabled) {
    return <Box>{children}</Box>;
  }

  return (
    <Box
      sx={{
        position: 'relative',
        overflow: 'hidden',
        touchAction: 'pan-y',
      }}
    >
      {/* Background actions - Left */}
      {leftActions.length > 0 && (
        <Box
          sx={{
            position: 'absolute',
            left: 0,
            top: 0,
            bottom: 0,
            display: 'flex',
            alignItems: 'center',
            px: 2,
            bgcolor: leftActions[0].color,
            color: 'white',
            zIndex: 0,
          }}
        >
          {leftActions[0].icon}
          <Typography variant="body2" sx={{ ml: 1 }}>
            {leftActions[0].label}
          </Typography>
        </Box>
      )}
      
      {/* Background actions - Right */}
      {rightActions.length > 0 && (
        <Box
          sx={{
            position: 'absolute',
            right: 0,
            top: 0,
            bottom: 0,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'flex-end',
            px: 2,
            bgcolor: rightActions[0].color,
            color: 'white',
            zIndex: 0,
          }}
        >
          <Typography variant="body2" sx={{ mr: 1 }}>
            {rightActions[0].label}
          </Typography>
          {rightActions[0].icon}
        </Box>
      )}
      
      {/* Main content */}
      <Box
        component={animated.div}
        {...bind()}
        style={{
          transform: x.to(x => `translateX(${x}px)`),
          position: 'relative',
          backgroundColor: 'background.paper',
          zIndex: 1,
          cursor: 'grab',
          userSelect: 'none',
          WebkitUserSelect: 'none',
        }}
      >
        {children}
      </Box>
    </Box>
  );
};

// Example usage component
export const SwipeableListItemExample: React.FC<{
  title: string;
  subtitle?: string;
  onEdit?: () => void;
  onDelete?: () => void;
  onArchive?: () => void;
}> = ({ title, subtitle, onEdit, onDelete, onArchive }) => {
  const leftActions: SwipeAction[] = [
    {
      icon: <Archive />,
      label: 'Archive',
      color: '#FFA726',
      action: onArchive || (() => console.log('Archive')),
    },
  ];

  const rightActions: SwipeAction[] = [
    {
      icon: <Delete />,
      label: 'Delete',
      color: '#FF5252',
      action: onDelete || (() => console.log('Delete')),
    },
  ];

  return (
    <SwipeableListItem leftActions={leftActions} rightActions={rightActions}>
      <Box
        sx={{
          p: 2,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <Box>
          <Typography variant="body1">{title}</Typography>
          {subtitle && (
            <Typography variant="body2" color="text.secondary">
              {subtitle}
            </Typography>
          )}
        </Box>
        <IconButton size="small" onClick={onEdit}>
          <MoreVert />
        </IconButton>
      </Box>
    </SwipeableListItem>
  );
};