import React, { useState } from 'react';
import {
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Box,
  Typography,
} from '@mui/material';
import { motion } from 'framer-motion';
import { useLongPress, useKeyboardAlternative } from '../../hooks/useGestures';

export interface ContextMenuItem {
  label: string;
  icon?: React.ReactNode;
  action: () => void;
  divider?: boolean;
  disabled?: boolean;
  shortcut?: string;
}

interface LongPressMenuProps {
  items: ContextMenuItem[];
  children: React.ReactNode;
  disabled?: boolean;
}

export const LongPressMenu: React.FC<LongPressMenuProps> = ({
  items,
  children,
  disabled = false,
}) => {
  const [contextMenu, setContextMenu] = useState<{
    mouseX: number;
    mouseY: number;
  } | null>(null);

  const handleLongPress = (event: React.MouseEvent | React.TouchEvent) => {
    event.preventDefault();
    
    let x = 0, y = 0;
    
    if ('touches' in event) {
      const touch = event.touches[0];
      x = touch.clientX;
      y = touch.clientY;
    } else {
      x = event.clientX;
      y = event.clientY;
    }
    
    setContextMenu({ mouseX: x, mouseY: y });
  };

  const handleClose = () => {
    setContextMenu(null);
  };

  const handleMenuItemClick = (action: () => void) => {
    action();
    handleClose();
  };

  const longPressProps = useLongPress(handleLongPress, { delay: 500 });

  // Handle right-click for desktop
  const handleContextMenu = (event: React.MouseEvent) => {
    event.preventDefault();
    if (!disabled) {
      setContextMenu({
        mouseX: event.clientX,
        mouseY: event.clientY,
      });
    }
  };

  // Create keyboard shortcuts map
  const keyboardMap = items.reduce((acc, item) => {
    if (item.shortcut && !item.disabled) {
      acc[item.shortcut] = item.action;
    }
    return acc;
  }, {} as Record<string, () => void>);

  const keyboardProps = useKeyboardAlternative(keyboardMap);

  if (disabled) {
    return <>{children}</>;
  }

  return (
    <>
      <Box
        component={motion.div}
        whileTap={{ scale: 0.98 }}
        {...longPressProps}
        {...keyboardProps}
        onContextMenu={handleContextMenu}
        sx={{
          cursor: 'pointer',
          userSelect: 'none',
          WebkitTouchCallout: 'none',
          WebkitUserSelect: 'none',
          '&:focus': {
            outline: '2px solid',
            outlineColor: 'primary.main',
            outlineOffset: 2,
          },
        }}
        tabIndex={0}
        role="button"
        aria-label="Long press or right-click for options"
      >
        {longPressProps.isPressed && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 0.1, scale: 1 }}
            style={{
              position: 'absolute',
              inset: 0,
              backgroundColor: 'currentColor',
              pointerEvents: 'none',
            }}
          />
        )}
        {children}
      </Box>
      
      <Menu
        open={contextMenu !== null}
        onClose={handleClose}
        anchorReference="anchorPosition"
        anchorPosition={
          contextMenu !== null
            ? { top: contextMenu.mouseY, left: contextMenu.mouseX }
            : undefined
        }
        TransitionProps={{
          style: {
            transformOrigin: contextMenu
              ? `${contextMenu.mouseX}px ${contextMenu.mouseY}px`
              : undefined,
          },
        }}
      >
        {items.map((item, index) => (
          <React.Fragment key={index}>
            {item.divider ? (
              <Divider />
            ) : (
              <MenuItem
                onClick={() => handleMenuItemClick(item.action)}
                disabled={item.disabled}
              >
                {item.icon && <ListItemIcon>{item.icon}</ListItemIcon>}
                <ListItemText primary={item.label} />
                {item.shortcut && (
                  <Typography variant="body2" color="text.secondary" sx={{ ml: 2 }}>
                    {item.shortcut}
                  </Typography>
                )}
              </MenuItem>
            )}
          </React.Fragment>
        ))}
      </Menu>
    </>
  );
};