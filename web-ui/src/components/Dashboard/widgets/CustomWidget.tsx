import React, { useState, useEffect } from 'react';
import { 
  Box, 
  TextField, 
  Button, 
  Typography,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Switch,
  FormControlLabel,
  Tabs,
  Tab
} from '@mui/material';
import { Code as CodeIcon, Settings as SettingsIcon } from '@mui/icons-material';
import { WidgetConfig } from '../types';

interface CustomWidgetProps {
  config: WidgetConfig;
  onUpdate?: (updates: Partial<WidgetConfig>) => void;
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index, ...other }) => {
  return (
    <div hidden={value !== index} {...other}>
      {value === index && <Box sx={{ pt: 2 }}>{children}</Box>}
    </div>
  );
};

const CustomWidget: React.FC<CustomWidgetProps> = ({ config, onUpdate }) => {
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [tabValue, setTabValue] = useState(0);
  const [customHtml, setCustomHtml] = useState(config.customSettings?.html || '');
  const [customCss, setCustomCss] = useState(config.customSettings?.css || '');
  const [customJs, setCustomJs] = useState(config.customSettings?.js || '');
  const [apiUrl, setApiUrl] = useState(config.customSettings?.apiUrl || '');
  const [refreshInterval, setRefreshInterval] = useState(config.customSettings?.refreshInterval || 0);
  const [enableApi, setEnableApi] = useState(config.customSettings?.enableApi || false);
  const [renderedContent, setRenderedContent] = useState('');

  useEffect(() => {
    renderCustomContent();
  }, [customHtml, customCss, config.data]);

  useEffect(() => {
    if (enableApi && apiUrl && refreshInterval > 0) {
      const fetchData = async () => {
        try {
          const response = await fetch(apiUrl);
          const data = await response.json();
          onUpdate?.({ data });
        } catch (error) {
          console.error('Failed to fetch data:', error);
        }
      };

      fetchData();
      const interval = setInterval(fetchData, refreshInterval * 1000);
      return () => clearInterval(interval);
    }
  }, [enableApi, apiUrl, refreshInterval]);

  const renderCustomContent = () => {
    try {
      let html = customHtml || '<div>Custom widget content</div>';
      
      if (config.data) {
        html = html.replace(/\{\{(\w+)\}\}/g, (match, key) => {
          return config.data[key] || match;
        });
      }

      const style = customCss ? `<style>${customCss}</style>` : '';
      setRenderedContent(style + html);

      if (customJs) {
        setTimeout(() => {
          try {
            const func = new Function('data', 'widget', customJs);
            func(config.data, { update: onUpdate });
          } catch (error) {
            console.error('Error executing custom JavaScript:', error);
          }
        }, 0);
      }
    } catch (error) {
      console.error('Error rendering custom content:', error);
      setRenderedContent('<div>Error rendering custom content</div>');
    }
  };

  const handleSaveSettings = () => {
    onUpdate?.({
      customSettings: {
        html: customHtml,
        css: customCss,
        js: customJs,
        apiUrl,
        refreshInterval,
        enableApi
      }
    });
    renderCustomContent();
    setSettingsOpen(false);
  };

  const defaultHtmlTemplate = `<div class="custom-widget">
  <h2>{{title}}</h2>
  <p class="value">{{value}}</p>
  <p class="description">{{description}}</p>
</div>`;

  const defaultCssTemplate = `.custom-widget {
  padding: 16px;
  text-align: center;
}

.custom-widget h2 {
  color: #333;
  margin-bottom: 8px;
}

.value {
  font-size: 2em;
  font-weight: bold;
  color: #1976d2;
}

.description {
  color: #666;
  font-size: 0.9em;
}`;

  const defaultJsTemplate = `// Access widget data with 'data' object
// Update widget with widget.update({ data: newData })

console.log('Widget data:', data);

// Example: Update widget every 5 seconds
// setInterval(() => {
//   widget.update({
//     data: { value: Math.random() * 100 }
//   });
// }, 5000);`;

  return (
    <Box sx={{ height: '100%', position: 'relative' }}>
      {onUpdate && (
        <IconButton
          size="small"
          onClick={() => setSettingsOpen(true)}
          sx={{ position: 'absolute', top: 8, right: 8, zIndex: 1 }}
        >
          <SettingsIcon fontSize="small" />
        </IconButton>
      )}

      <Box 
        sx={{ p: 2, height: '100%', overflow: 'auto' }}
        dangerouslySetInnerHTML={{ __html: renderedContent }}
      />

      <Dialog 
        open={settingsOpen} 
        onClose={() => setSettingsOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <CodeIcon />
            Custom Widget Builder
          </Box>
        </DialogTitle>
        <DialogContent>
          <Tabs value={tabValue} onChange={(e, v) => setTabValue(v)}>
            <Tab label="HTML" />
            <Tab label="CSS" />
            <Tab label="JavaScript" />
            <Tab label="Data Source" />
          </Tabs>

          <TabPanel value={tabValue} index={0}>
            <Typography variant="caption" color="text.secondary" gutterBottom>
              Use {"{{variable}}"} to insert data values
            </Typography>
            <TextField
              fullWidth
              multiline
              rows={10}
              value={customHtml}
              onChange={(e) => setCustomHtml(e.target.value)}
              placeholder={defaultHtmlTemplate}
              variant="outlined"
              sx={{ fontFamily: 'monospace' }}
            />
            <Button 
              size="small" 
              onClick={() => setCustomHtml(defaultHtmlTemplate)}
              sx={{ mt: 1 }}
            >
              Load Template
            </Button>
          </TabPanel>

          <TabPanel value={tabValue} index={1}>
            <TextField
              fullWidth
              multiline
              rows={10}
              value={customCss}
              onChange={(e) => setCustomCss(e.target.value)}
              placeholder={defaultCssTemplate}
              variant="outlined"
              sx={{ fontFamily: 'monospace' }}
            />
            <Button 
              size="small" 
              onClick={() => setCustomCss(defaultCssTemplate)}
              sx={{ mt: 1 }}
            >
              Load Template
            </Button>
          </TabPanel>

          <TabPanel value={tabValue} index={2}>
            <Typography variant="caption" color="text.secondary" gutterBottom>
              Access data with 'data' object, update with widget.update()
            </Typography>
            <TextField
              fullWidth
              multiline
              rows={10}
              value={customJs}
              onChange={(e) => setCustomJs(e.target.value)}
              placeholder={defaultJsTemplate}
              variant="outlined"
              sx={{ fontFamily: 'monospace' }}
            />
            <Button 
              size="small" 
              onClick={() => setCustomJs(defaultJsTemplate)}
              sx={{ mt: 1 }}
            >
              Load Template
            </Button>
          </TabPanel>

          <TabPanel value={tabValue} index={3}>
            <FormControlLabel
              control={
                <Switch
                  checked={enableApi}
                  onChange={(e) => setEnableApi(e.target.checked)}
                />
              }
              label="Enable API Data Source"
            />
            
            {enableApi && (
              <>
                <TextField
                  fullWidth
                  label="API URL"
                  value={apiUrl}
                  onChange={(e) => setApiUrl(e.target.value)}
                  placeholder="https://api.example.com/data"
                  sx={{ mt: 2, mb: 2 }}
                />
                
                <TextField
                  fullWidth
                  label="Refresh Interval (seconds)"
                  type="number"
                  value={refreshInterval}
                  onChange={(e) => setRefreshInterval(parseInt(e.target.value) || 0)}
                  helperText="0 = No auto-refresh"
                />
              </>
            )}
          </TabPanel>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSettingsOpen(false)}>Cancel</Button>
          <Button onClick={handleSaveSettings} variant="contained">
            Save & Apply
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default CustomWidget;