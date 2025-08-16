import React, { useState, useCallback, useEffect } from 'react';
import { Responsive, WidthProvider, Layout } from 'react-grid-layout';
import { 
  Box, 
  Paper, 
  IconButton, 
  Tooltip, 
  SpeedDial,
  SpeedDialAction,
  SpeedDialIcon,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Fab
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Save as SaveIcon,
  Upload as UploadIcon,
  Download as DownloadIcon,
  Dashboard as DashboardIcon,
  BarChart as ChartIcon,
  TableChart as TableIcon,
  Speed as GaugeIcon,
  Notifications as AlertIcon,
  TextFields as TextIcon,
  LockOpen as UnlockIcon,
  Lock as LockIcon
} from '@mui/icons-material';
import 'react-grid-layout/css/styles.css';
import 'react-resizable/css/styles.css';
import { DashboardConfig, WidgetConfig, WidgetType, DashboardLayout } from './types';
import Widget from './Widget';
import { generateId } from './utils';
import './Dashboard.css';

const ResponsiveGridLayout = WidthProvider(Responsive);

interface DashboardProps {
  dashboardId?: string;
  initialConfig?: DashboardConfig;
  onSave?: (config: DashboardConfig) => void;
  readOnly?: boolean;
}

const Dashboard: React.FC<DashboardProps> = ({
  dashboardId = 'default',
  initialConfig,
  onSave,
  readOnly = false
}) => {
  const [config, setConfig] = useState<DashboardConfig>(() => {
    const savedConfig = localStorage.getItem(`dashboard_${dashboardId}`);
    if (savedConfig) {
      return JSON.parse(savedConfig);
    }
    return initialConfig || {
      id: dashboardId,
      name: 'My Dashboard',
      widgets: [],
      layouts: { lg: [] },
      createdAt: new Date(),
      updatedAt: new Date()
    };
  });

  const [editMode, setEditMode] = useState(!readOnly);
  const [addWidgetOpen, setAddWidgetOpen] = useState(false);
  const [newWidgetType, setNewWidgetType] = useState<WidgetType>('metric');
  const [newWidgetTitle, setNewWidgetTitle] = useState('');
  const [isDraggable, setIsDraggable] = useState(true);

  useEffect(() => {
    localStorage.setItem(`dashboard_${dashboardId}`, JSON.stringify(config));
  }, [config, dashboardId]);

  const handleLayoutChange = useCallback((layout: Layout[], layouts: any) => {
    setConfig(prev => ({
      ...prev,
      layouts,
      updatedAt: new Date()
    }));
  }, []);

  const addWidget = useCallback(() => {
    if (!newWidgetTitle.trim()) return;

    const newWidget: WidgetConfig = {
      id: generateId(),
      type: newWidgetType,
      title: newWidgetTitle,
      data: null,
      customSettings: {}
    };

    const newLayout: DashboardLayout = {
      i: newWidget.id,
      x: 0,
      y: 0,
      w: getDefaultWidth(newWidgetType),
      h: getDefaultHeight(newWidgetType),
      minW: 2,
      minH: 2
    };

    setConfig(prev => ({
      ...prev,
      widgets: [...prev.widgets, newWidget],
      layouts: {
        ...prev.layouts,
        lg: [...(prev.layouts.lg || []), newLayout]
      },
      updatedAt: new Date()
    }));

    setAddWidgetOpen(false);
    setNewWidgetTitle('');
  }, [newWidgetType, newWidgetTitle]);

  const removeWidget = useCallback((widgetId: string) => {
    setConfig(prev => ({
      ...prev,
      widgets: prev.widgets.filter(w => w.id !== widgetId),
      layouts: {
        ...prev.layouts,
        lg: prev.layouts.lg.filter(l => l.i !== widgetId)
      },
      updatedAt: new Date()
    }));
  }, []);

  const updateWidget = useCallback((widgetId: string, updates: Partial<WidgetConfig>) => {
    setConfig(prev => ({
      ...prev,
      widgets: prev.widgets.map(w => 
        w.id === widgetId ? { ...w, ...updates } : w
      ),
      updatedAt: new Date()
    }));
  }, []);

  const exportConfig = useCallback(() => {
    const dataStr = JSON.stringify(config, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
    const exportFileDefaultName = `dashboard_${config.name}_${Date.now()}.json`;
    
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
  }, [config]);

  const importConfig = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const importedConfig = JSON.parse(e.target?.result as string);
        setConfig({
          ...importedConfig,
          id: dashboardId,
          updatedAt: new Date()
        });
      } catch (error) {
        console.error('Failed to import dashboard configuration:', error);
      }
    };
    reader.readAsText(file);
  }, [dashboardId]);

  const getDefaultWidth = (type: WidgetType): number => {
    switch (type) {
      case 'metric': return 3;
      case 'chart': return 6;
      case 'table': return 8;
      case 'gauge': return 4;
      case 'text': return 4;
      case 'alert': return 4;
      default: return 4;
    }
  };

  const getDefaultHeight = (type: WidgetType): number => {
    switch (type) {
      case 'metric': return 3;
      case 'chart': return 6;
      case 'table': return 8;
      case 'gauge': return 4;
      case 'text': return 3;
      case 'alert': return 2;
      default: return 4;
    }
  };

  const speedDialActions = [
    { icon: <AddIcon />, name: 'Add Widget', action: () => setAddWidgetOpen(true) },
    { icon: <SaveIcon />, name: 'Save Dashboard', action: () => onSave?.(config) },
    { icon: <DownloadIcon />, name: 'Export Config', action: exportConfig },
    { 
      icon: <UploadIcon />, 
      name: 'Import Config', 
      action: () => document.getElementById('import-input')?.click() 
    },
    {
      icon: isDraggable ? <LockIcon /> : <UnlockIcon />,
      name: isDraggable ? 'Lock Layout' : 'Unlock Layout',
      action: () => setIsDraggable(!isDraggable)
    }
  ];

  return (
    <Box sx={{ width: '100%', height: '100%', p: 2 }}>
      <ResponsiveGridLayout
        className="dashboard-grid"
        layouts={config.layouts}
        onLayoutChange={handleLayoutChange}
        rowHeight={60}
        isDraggable={isDraggable && editMode}
        isResizable={isDraggable && editMode}
        breakpoints={{ lg: 1200, md: 996, sm: 768, xs: 480, xxs: 0 }}
        cols={{ lg: 12, md: 10, sm: 6, xs: 4, xxs: 2 }}
        margin={[16, 16]}
        containerPadding={[0, 0]}
      >
        {config.widgets.map(widget => (
          <Paper 
            key={widget.id} 
            elevation={3}
            sx={{ 
              width: '100%', 
              height: '100%',
              overflow: 'hidden',
              display: 'flex',
              flexDirection: 'column'
            }}
          >
            <Widget
              config={widget}
              onRemove={editMode ? removeWidget : undefined}
              onUpdate={editMode ? updateWidget : undefined}
              isEditMode={editMode}
            />
          </Paper>
        ))}
      </ResponsiveGridLayout>

      {editMode && !readOnly && (
        <>
          <SpeedDial
            ariaLabel="Dashboard actions"
            sx={{ position: 'fixed', bottom: 16, right: 16 }}
            icon={<SpeedDialIcon />}
          >
            {speedDialActions.map((action) => (
              <SpeedDialAction
                key={action.name}
                icon={action.icon}
                tooltipTitle={action.name}
                onClick={action.action}
              />
            ))}
          </SpeedDial>

          <input
            type="file"
            id="import-input"
            accept=".json"
            style={{ display: 'none' }}
            onChange={importConfig}
          />
        </>
      )}

      {!readOnly && (
        <Fab
          color={editMode ? "secondary" : "primary"}
          sx={{ position: 'fixed', bottom: 16, left: 16 }}
          onClick={() => setEditMode(!editMode)}
        >
          {editMode ? <LockIcon /> : <EditIcon />}
        </Fab>
      )}

      <Dialog open={addWidgetOpen} onClose={() => setAddWidgetOpen(false)}>
        <DialogTitle>Add New Widget</DialogTitle>
        <DialogContent sx={{ minWidth: 400, pt: 2 }}>
          <FormControl fullWidth sx={{ mb: 2 }}>
            <InputLabel>Widget Type</InputLabel>
            <Select
              value={newWidgetType}
              onChange={(e) => setNewWidgetType(e.target.value as WidgetType)}
              label="Widget Type"
            >
              <MenuItem value="metric">
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <DashboardIcon fontSize="small" />
                  Metric Card
                </Box>
              </MenuItem>
              <MenuItem value="chart">
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <ChartIcon fontSize="small" />
                  Chart
                </Box>
              </MenuItem>
              <MenuItem value="table">
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <TableIcon fontSize="small" />
                  Data Table
                </Box>
              </MenuItem>
              <MenuItem value="gauge">
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <GaugeIcon fontSize="small" />
                  Gauge
                </Box>
              </MenuItem>
              <MenuItem value="text">
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <TextIcon fontSize="small" />
                  Text/Notes
                </Box>
              </MenuItem>
              <MenuItem value="alert">
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <AlertIcon fontSize="small" />
                  Alert
                </Box>
              </MenuItem>
              <MenuItem value="realtime">
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <DashboardIcon fontSize="small" />
                  Real-time Data
                </Box>
              </MenuItem>
              <MenuItem value="custom">
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <DashboardIcon fontSize="small" />
                  Custom Widget
                </Box>
              </MenuItem>
            </Select>
          </FormControl>
          <TextField
            fullWidth
            label="Widget Title"
            value={newWidgetTitle}
            onChange={(e) => setNewWidgetTitle(e.target.value)}
            placeholder="Enter widget title..."
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAddWidgetOpen(false)}>Cancel</Button>
          <Button onClick={addWidget} variant="contained">Add Widget</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Dashboard;