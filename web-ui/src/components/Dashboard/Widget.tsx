import React from 'react';
import { 
  Box, 
  Typography, 
  IconButton, 
  Tooltip,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText
} from '@mui/material';
import {
  Close as CloseIcon,
  MoreVert as MoreIcon,
  Settings as SettingsIcon,
  Refresh as RefreshIcon,
  Fullscreen as FullscreenIcon
} from '@mui/icons-material';
import { WidgetProps } from './types';
import MetricWidget from './widgets/MetricWidget';
import ChartWidget from './widgets/ChartWidget';
import TableWidget from './widgets/TableWidget';
import GaugeWidget from './widgets/GaugeWidget';
import TextWidget from './widgets/TextWidget';
import AlertWidget from './widgets/AlertWidget';
import RealtimeWidget from './widgets/RealtimeWidget';
import CustomWidget from './widgets/CustomWidget';

const Widget: React.FC<WidgetProps> = ({ 
  config, 
  onRemove, 
  onUpdate,
  isEditMode 
}) => {
  const [anchorEl, setAnchorEl] = React.useState<null | HTMLElement>(null);

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleRefresh = () => {
    onUpdate?.(config.id, { data: null });
    handleMenuClose();
  };

  const renderWidget = () => {
    const commonProps = {
      config,
      onUpdate: onUpdate ? (updates: any) => onUpdate(config.id, updates) : undefined
    };

    switch (config.type) {
      case 'metric':
        return <MetricWidget {...commonProps} />;
      case 'chart':
        return <ChartWidget {...commonProps} />;
      case 'table':
        return <TableWidget {...commonProps} />;
      case 'gauge':
        return <GaugeWidget {...commonProps} />;
      case 'text':
        return <TextWidget {...commonProps} />;
      case 'alert':
        return <AlertWidget {...commonProps} />;
      case 'realtime':
        return <RealtimeWidget {...commonProps} />;
      case 'custom':
        return <CustomWidget {...commonProps} />;
      default:
        return (
          <Box sx={{ p: 2 }}>
            <Typography variant="body2" color="text.secondary">
              Unknown widget type: {config.type}
            </Typography>
          </Box>
        );
    }
  };

  return (
    <Box sx={{ 
      width: '100%', 
      height: '100%', 
      display: 'flex', 
      flexDirection: 'column',
      position: 'relative'
    }}>
      <Box sx={{ 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'space-between',
        px: 2,
        py: 1,
        borderBottom: 1,
        borderColor: 'divider',
        backgroundColor: 'background.paper'
      }}>
        <Typography variant="subtitle1" fontWeight="medium" noWrap>
          {config.title}
        </Typography>
        {isEditMode && (
          <Box sx={{ display: 'flex', gap: 0.5 }}>
            <Tooltip title="Options">
              <IconButton size="small" onClick={handleMenuOpen}>
                <MoreIcon fontSize="small" />
              </IconButton>
            </Tooltip>
            {onRemove && (
              <Tooltip title="Remove Widget">
                <IconButton 
                  size="small" 
                  onClick={() => onRemove(config.id)}
                  color="error"
                >
                  <CloseIcon fontSize="small" />
                </IconButton>
              </Tooltip>
            )}
          </Box>
        )}
      </Box>

      <Box sx={{ 
        flex: 1, 
        overflow: 'auto',
        position: 'relative'
      }}>
        {renderWidget()}
      </Box>

      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleMenuClose}
      >
        <MenuItem onClick={handleRefresh}>
          <ListItemIcon>
            <RefreshIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Refresh Data</ListItemText>
        </MenuItem>
        <MenuItem onClick={handleMenuClose}>
          <ListItemIcon>
            <SettingsIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Widget Settings</ListItemText>
        </MenuItem>
        <MenuItem onClick={handleMenuClose}>
          <ListItemIcon>
            <FullscreenIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Fullscreen</ListItemText>
        </MenuItem>
      </Menu>
    </Box>
  );
};

export default Widget;