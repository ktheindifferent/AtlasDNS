import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Tabs,
  Tab,
  Box,
  Typography,
  Chip,
  Stack,
  FormControlLabel,
  Switch,
  Alert,
  Tooltip,
} from '@mui/material';
import {
  Save,
  Delete,
  Share,
  ContentCopy,
  Download,
  Upload,
  Public,
  Lock,
} from '@mui/icons-material';
import { FilterState, FilterPreset } from '../../types/filtering';
import { useSnackbar } from 'notistack';

interface SavedFiltersProps {
  open: boolean;
  onClose: () => void;
  onSave?: (filter: FilterPreset) => void;
  currentFilter: FilterState;
  savedFilters: FilterPreset[];
  onLoad: (filter: FilterPreset) => void;
  onDelete?: (id: string) => void;
}

const SavedFilters: React.FC<SavedFiltersProps> = ({
  open,
  onClose,
  onSave,
  currentFilter,
  savedFilters,
  onLoad,
  onDelete,
}) => {
  const { enqueueSnackbar } = useSnackbar();
  const [activeTab, setActiveTab] = useState(0);
  const [filterName, setFilterName] = useState('');
  const [filterDescription, setFilterDescription] = useState('');
  const [isPublic, setIsPublic] = useState(false);
  const [tags, setTags] = useState<string[]>([]);
  const [tagInput, setTagInput] = useState('');

  const handleSave = () => {
    if (!filterName.trim()) {
      enqueueSnackbar('Please enter a filter name', { variant: 'error' });
      return;
    }

    const newFilter: FilterPreset = {
      id: Date.now().toString(),
      name: filterName,
      description: filterDescription,
      query: currentFilter,
      isPublic,
      createdBy: 'current-user', // Replace with actual user
      createdAt: new Date(),
      updatedAt: new Date(),
      tags,
    };

    if (onSave) {
      onSave(newFilter);
    }

    enqueueSnackbar('Filter saved successfully', { variant: 'success' });
    handleClose();
  };

  const handleClose = () => {
    setFilterName('');
    setFilterDescription('');
    setIsPublic(false);
    setTags([]);
    setTagInput('');
    onClose();
  };

  const handleAddTag = () => {
    if (tagInput.trim() && !tags.includes(tagInput.trim())) {
      setTags([...tags, tagInput.trim()]);
      setTagInput('');
    }
  };

  const handleRemoveTag = (tag: string) => {
    setTags(tags.filter(t => t !== tag));
  };

  const handleShare = (filter: FilterPreset) => {
    const shareData = {
      id: filter.id,
      name: filter.name,
      query: filter.query,
    };
    const shareUrl = `${window.location.origin}/filters/shared/${btoa(JSON.stringify(shareData))}`;
    navigator.clipboard.writeText(shareUrl);
    enqueueSnackbar('Share link copied to clipboard', { variant: 'success' });
  };

  const handleExport = (filter: FilterPreset) => {
    const dataStr = JSON.stringify(filter, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
    const exportFileDefaultName = `filter-${filter.name.replace(/\s+/g, '-')}.json`;
    
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
  };

  const handleImport = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const filter = JSON.parse(e.target?.result as string);
          onLoad(filter);
          enqueueSnackbar('Filter imported successfully', { variant: 'success' });
        } catch (error) {
          enqueueSnackbar('Invalid filter file', { variant: 'error' });
        }
      };
      reader.readAsText(file);
    }
  };

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="md" fullWidth>
      <DialogTitle>Saved Filters</DialogTitle>
      <DialogContent>
        <Tabs value={activeTab} onChange={(_, value) => setActiveTab(value)}>
          <Tab label="Save Current" />
          <Tab label="My Filters" />
          <Tab label="Shared Filters" />
        </Tabs>

        <Box sx={{ mt: 2, minHeight: 300 }}>
          {activeTab === 0 && (
            <Stack spacing={2}>
              <TextField
                label="Filter Name"
                fullWidth
                value={filterName}
                onChange={(e) => setFilterName(e.target.value)}
                required
              />
              
              <TextField
                label="Description"
                fullWidth
                multiline
                rows={2}
                value={filterDescription}
                onChange={(e) => setFilterDescription(e.target.value)}
              />

              <Box>
                <TextField
                  label="Tags"
                  size="small"
                  value={tagInput}
                  onChange={(e) => setTagInput(e.target.value)}
                  onKeyPress={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      handleAddTag();
                    }
                  }}
                  InputProps={{
                    endAdornment: (
                      <Button size="small" onClick={handleAddTag}>
                        Add
                      </Button>
                    ),
                  }}
                />
                <Stack direction="row" spacing={1} sx={{ mt: 1 }} flexWrap="wrap">
                  {tags.map((tag) => (
                    <Chip
                      key={tag}
                      label={tag}
                      size="small"
                      onDelete={() => handleRemoveTag(tag)}
                    />
                  ))}
                </Stack>
              </Box>

              <FormControlLabel
                control={
                  <Switch
                    checked={isPublic}
                    onChange={(e) => setIsPublic(e.target.checked)}
                  />
                }
                label={
                  <Box display="flex" alignItems="center" gap={1}>
                    {isPublic ? <Public /> : <Lock />}
                    <Typography>
                      {isPublic ? 'Public (visible to all users)' : 'Private (only visible to you)'}
                    </Typography>
                  </Box>
                }
              />

              <Alert severity="info">
                This will save the current filter configuration including query builder rules,
                time range, quick filters, and regex patterns.
              </Alert>
            </Stack>
          )}

          {activeTab === 1 && (
            <Box>
              <Box display="flex" justifyContent="flex-end" mb={2}>
                <Button
                  variant="outlined"
                  startIcon={<Upload />}
                  component="label"
                >
                  Import Filter
                  <input
                    type="file"
                    hidden
                    accept=".json"
                    onChange={handleImport}
                  />
                </Button>
              </Box>
              
              <List>
                {savedFilters
                  .filter(f => !f.isPublic)
                  .map((filter) => (
                    <ListItem key={filter.id}>
                      <ListItemText
                        primary={
                          <Box display="flex" alignItems="center" gap={1}>
                            {filter.name}
                            <Lock fontSize="small" color="action" />
                          </Box>
                        }
                        secondary={
                          <Box>
                            <Typography variant="caption">
                              {filter.description}
                            </Typography>
                            {filter.tags && filter.tags.length > 0 && (
                              <Stack direction="row" spacing={0.5} sx={{ mt: 0.5 }}>
                                {filter.tags.map(tag => (
                                  <Chip key={tag} label={tag} size="small" />
                                ))}
                              </Stack>
                            )}
                          </Box>
                        }
                      />
                      <ListItemSecondaryAction>
                        <Tooltip title="Load filter">
                          <IconButton onClick={() => onLoad(filter)}>
                            <Download />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Share filter">
                          <IconButton onClick={() => handleShare(filter)}>
                            <Share />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Export filter">
                          <IconButton onClick={() => handleExport(filter)}>
                            <ContentCopy />
                          </IconButton>
                        </Tooltip>
                        {onDelete && (
                          <Tooltip title="Delete filter">
                            <IconButton onClick={() => onDelete(filter.id)}>
                              <Delete />
                            </IconButton>
                          </Tooltip>
                        )}
                      </ListItemSecondaryAction>
                    </ListItem>
                  ))}
              </List>
              
              {savedFilters.filter(f => !f.isPublic).length === 0 && (
                <Typography variant="body2" color="textSecondary" align="center">
                  No saved filters yet
                </Typography>
              )}
            </Box>
          )}

          {activeTab === 2 && (
            <List>
              {savedFilters
                .filter(f => f.isPublic)
                .map((filter) => (
                  <ListItem key={filter.id}>
                    <ListItemText
                      primary={
                        <Box display="flex" alignItems="center" gap={1}>
                          {filter.name}
                          <Public fontSize="small" color="primary" />
                        </Box>
                      }
                      secondary={
                        <Box>
                          <Typography variant="caption">
                            {filter.description} • By {filter.createdBy}
                          </Typography>
                          {filter.tags && filter.tags.length > 0 && (
                            <Stack direction="row" spacing={0.5} sx={{ mt: 0.5 }}>
                              {filter.tags.map(tag => (
                                <Chip key={tag} label={tag} size="small" />
                              ))}
                            </Stack>
                          )}
                        </Box>
                      }
                    />
                    <ListItemSecondaryAction>
                      <Tooltip title="Load filter">
                        <IconButton onClick={() => onLoad(filter)}>
                          <Download />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Copy to my filters">
                        <IconButton onClick={() => handleShare(filter)}>
                          <ContentCopy />
                        </IconButton>
                      </Tooltip>
                    </ListItemSecondaryAction>
                  </ListItem>
                ))}
              
              {savedFilters.filter(f => f.isPublic).length === 0 && (
                <Typography variant="body2" color="textSecondary" align="center">
                  No public filters available
                </Typography>
              )}
            </List>
          )}
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleClose}>Cancel</Button>
        {activeTab === 0 && (
          <Button
            variant="contained"
            startIcon={<Save />}
            onClick={handleSave}
            disabled={!filterName.trim()}
          >
            Save Filter
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
};

export default SavedFilters;