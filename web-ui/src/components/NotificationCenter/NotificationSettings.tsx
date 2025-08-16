import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Tabs,
  Tab,
  Box,
  Stack,
  Typography,
  Switch,
  FormControlLabel,
  FormGroup,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Chip,
  Divider,
  Alert,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
} from '@mui/material';
import {
  Delete as DeleteIcon,
  Add as AddIcon,
  Test as TestIcon,
} from '@mui/icons-material';
import { TimePicker } from '@mui/x-date-pickers/TimePicker';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';
import { useDispatch } from 'react-redux';
import { updatePreferences } from '../..

/store/slices/notificationSlice';
import NotificationService from '../../services/notificationService';
import {
  NotificationPreferences,
  NotificationCategory,
  NotificationPriority,
  NotificationChannel,
} from '../../types/notification.types';

interface NotificationSettingsProps {
  open: boolean;
  onClose: () => void;
  preferences: NotificationPreferences;
}

const NotificationSettings: React.FC<NotificationSettingsProps> = ({
  open,
  onClose,
  preferences,
}) => {
  const dispatch = useDispatch();
  const [activeTab, setActiveTab] = useState(0);
  const [localPreferences, setLocalPreferences] = useState(preferences);
  const [testingChannel, setTestingChannel] = useState<NotificationChannel | null>(null);
  const notificationService = NotificationService.getInstance();

  const handleSave = () => {
    dispatch(updatePreferences(localPreferences));
    onClose();
  };

  const handleChannelToggle = (channel: NotificationChannel) => {
    setLocalPreferences({
      ...localPreferences,
      channels: {
        ...localPreferences.channels,
        [channel]: {
          ...localPreferences.channels[channel],
          enabled: !localPreferences.channels[channel]?.enabled,
        },
      },
    });
  };

  const handleDoNotDisturbToggle = () => {
    setLocalPreferences({
      ...localPreferences,
      doNotDisturb: {
        ...localPreferences.doNotDisturb,
        enabled: !localPreferences.doNotDisturb.enabled,
      },
    });
  };

  const handleTestChannel = async (channel: NotificationChannel) => {
    setTestingChannel(channel);
    try {
      await notificationService.sendTestNotification(channel);
    } finally {
      setTestingChannel(null);
    }
  };

  const handleRequestPermission = async () => {
    const permission = await notificationService.requestPermission();
    if (permission === 'granted') {
      setLocalPreferences({
        ...localPreferences,
        desktop: true,
      });
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>Notification Settings</DialogTitle>
      
      <DialogContent>
        <Tabs value={activeTab} onChange={(_, value) => setActiveTab(value)}>
          <Tab label="Channels" />
          <Tab label="Do Not Disturb" />
          <Tab label="Preferences" />
          <Tab label="Advanced" />
        </Tabs>

        <Box sx={{ mt: 3 }}>
          {activeTab === 0 && (
            <Stack spacing={3}>
              <Typography variant="subtitle1">Notification Channels</Typography>
              
              {Object.values(NotificationChannel).map((channel) => (
                <Box key={channel}>
                  <Stack direction="row" alignItems="center" justifyContent="space-between">
                    <FormControlLabel
                      control={
                        <Switch
                          checked={localPreferences.channels[channel]?.enabled || false}
                          onChange={() => handleChannelToggle(channel)}
                        />
                      }
                      label={
                        <Stack>
                          <Typography>{channel.replace('_', ' ').toUpperCase()}</Typography>
                          <Typography variant="caption" color="text.secondary">
                            {getChannelDescription(channel)}
                          </Typography>
                        </Stack>
                      }
                    />
                    
                    <Button
                      size="small"
                      startIcon={<TestIcon />}
                      onClick={() => handleTestChannel(channel)}
                      disabled={!localPreferences.channels[channel]?.enabled || testingChannel === channel}
                    >
                      Test
                    </Button>
                  </Stack>
                  
                  {localPreferences.channels[channel]?.enabled && (
                    <Box sx={{ ml: 4, mt: 1 }}>
                      <FormControl size="small" fullWidth sx={{ mb: 1 }}>
                        <InputLabel>Categories</InputLabel>
                        <Select
                          multiple
                          value={localPreferences.channels[channel]?.categories || []}
                          onChange={(e) => {
                            setLocalPreferences({
                              ...localPreferences,
                              channels: {
                                ...localPreferences.channels,
                                [channel]: {
                                  ...localPreferences.channels[channel]!,
                                  categories: e.target.value as NotificationCategory[],
                                },
                              },
                            });
                          }}
                          renderValue={(selected) => (
                            <Stack direction="row" spacing={0.5}>
                              {selected.map((value) => (
                                <Chip key={value} label={value} size="small" />
                              ))}
                            </Stack>
                          )}
                        >
                          {Object.values(NotificationCategory).map((category) => (
                            <MenuItem key={category} value={category}>
                              {category}
                            </MenuItem>
                          ))}
                        </Select>
                      </FormControl>
                      
                      <FormControl size="small" fullWidth>
                        <InputLabel>Priorities</InputLabel>
                        <Select
                          multiple
                          value={localPreferences.channels[channel]?.priorities || []}
                          onChange={(e) => {
                            setLocalPreferences({
                              ...localPreferences,
                              channels: {
                                ...localPreferences.channels,
                                [channel]: {
                                  ...localPreferences.channels[channel]!,
                                  priorities: e.target.value as NotificationPriority[],
                                },
                              },
                            });
                          }}
                          renderValue={(selected) => (
                            <Stack direction="row" spacing={0.5}>
                              {selected.map((value) => (
                                <Chip key={value} label={value} size="small" />
                              ))}
                            </Stack>
                          )}
                        >
                          {Object.values(NotificationPriority).map((priority) => (
                            <MenuItem key={priority} value={priority}>
                              {priority}
                            </MenuItem>
                          ))}
                        </Select>
                      </FormControl>
                    </Box>
                  )}
                  
                  <Divider sx={{ mt: 2 }} />
                </Box>
              ))}

              {Notification.permission === 'default' && (
                <Alert severity="info" action={
                  <Button size="small" onClick={handleRequestPermission}>
                    Enable
                  </Button>
                }>
                  Browser notifications are not enabled. Enable them to receive desktop notifications.
                </Alert>
              )}
            </Stack>
          )}

          {activeTab === 1 && (
            <Stack spacing={3}>
              <FormControlLabel
                control={
                  <Switch
                    checked={localPreferences.doNotDisturb.enabled}
                    onChange={handleDoNotDisturbToggle}
                  />
                }
                label="Enable Do Not Disturb"
              />

              {localPreferences.doNotDisturb.enabled && (
                <>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={localPreferences.doNotDisturb.allowUrgent}
                        onChange={(e) => {
                          setLocalPreferences({
                            ...localPreferences,
                            doNotDisturb: {
                              ...localPreferences.doNotDisturb,
                              allowUrgent: e.target.checked,
                            },
                          });
                        }}
                      />
                    }
                    label="Allow urgent notifications"
                  />

                  <FormControl fullWidth>
                    <InputLabel>Allowed Categories</InputLabel>
                    <Select
                      multiple
                      value={localPreferences.doNotDisturb.allowedCategories || []}
                      onChange={(e) => {
                        setLocalPreferences({
                          ...localPreferences,
                          doNotDisturb: {
                            ...localPreferences.doNotDisturb,
                            allowedCategories: e.target.value as NotificationCategory[],
                          },
                        });
                      }}
                      renderValue={(selected) => (
                        <Stack direction="row" spacing={0.5}>
                          {selected.map((value) => (
                            <Chip key={value} label={value} size="small" />
                          ))}
                        </Stack>
                      )}
                    >
                      {Object.values(NotificationCategory).map((category) => (
                        <MenuItem key={category} value={category}>
                          {category}
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>

                  <Typography variant="subtitle2">Schedule</Typography>
                  
                  <LocalizationProvider dateAdapter={AdapterDateFns}>
                    <Stack direction="row" spacing={2}>
                      <TimePicker
                        label="Start Time"
                        value={null}
                        onChange={() => {}}
                        renderInput={(params) => <TextField {...params} fullWidth />}
                      />
                      <TimePicker
                        label="End Time"
                        value={null}
                        onChange={() => {}}
                        renderInput={(params) => <TextField {...params} fullWidth />}
                      />
                    </Stack>
                  </LocalizationProvider>

                  <FormGroup>
                    <Typography variant="subtitle2">Days of Week</Typography>
                    <Stack direction="row" spacing={1}>
                      {['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map((day, index) => (
                        <Chip
                          key={day}
                          label={day}
                          clickable
                          color={localPreferences.doNotDisturb.schedule?.daysOfWeek?.includes(index) ? 'primary' : 'default'}
                          onClick={() => {
                            const current = localPreferences.doNotDisturb.schedule?.daysOfWeek || [];
                            const updated = current.includes(index)
                              ? current.filter(d => d !== index)
                              : [...current, index];
                            
                            setLocalPreferences({
                              ...localPreferences,
                              doNotDisturb: {
                                ...localPreferences.doNotDisturb,
                                schedule: {
                                  ...localPreferences.doNotDisturb.schedule,
                                  daysOfWeek: updated,
                                },
                              },
                            });
                          }}
                        />
                      ))}
                    </Stack>
                  </FormGroup>
                </>
              )}
            </Stack>
          )}

          {activeTab === 2 && (
            <Stack spacing={3}>
              <FormGroup>
                <FormControlLabel
                  control={
                    <Switch
                      checked={localPreferences.sound}
                      onChange={(e) => {
                        setLocalPreferences({
                          ...localPreferences,
                          sound: e.target.checked,
                        });
                      }}
                    />
                  }
                  label="Sound notifications"
                />
                
                <FormControlLabel
                  control={
                    <Switch
                      checked={localPreferences.vibration}
                      onChange={(e) => {
                        setLocalPreferences({
                          ...localPreferences,
                          vibration: e.target.checked,
                        });
                      }}
                    />
                  }
                  label="Vibration (mobile)"
                />
                
                <FormControlLabel
                  control={
                    <Switch
                      checked={localPreferences.desktop}
                      onChange={(e) => {
                        setLocalPreferences({
                          ...localPreferences,
                          desktop: e.target.checked,
                        });
                      }}
                    />
                  }
                  label="Desktop notifications"
                />
              </FormGroup>

              <Divider />

              <Typography variant="subtitle1">Grouping</Typography>
              
              <FormControlLabel
                control={
                  <Switch
                    checked={localPreferences.grouping.enabled}
                    onChange={(e) => {
                      setLocalPreferences({
                        ...localPreferences,
                        grouping: {
                          ...localPreferences.grouping,
                          enabled: e.target.checked,
                        },
                      });
                    }}
                  />
                }
                label="Group similar notifications"
              />

              {localPreferences.grouping.enabled && (
                <>
                  <TextField
                    label="Time Window (minutes)"
                    type="number"
                    value={localPreferences.grouping.timeWindow / 60000}
                    onChange={(e) => {
                      setLocalPreferences({
                        ...localPreferences,
                        grouping: {
                          ...localPreferences.grouping,
                          timeWindow: parseInt(e.target.value) * 60000,
                        },
                      });
                    }}
                    fullWidth
                  />
                  
                  <TextField
                    label="Max Group Size"
                    type="number"
                    value={localPreferences.grouping.maxGroupSize}
                    onChange={(e) => {
                      setLocalPreferences({
                        ...localPreferences,
                        grouping: {
                          ...localPreferences.grouping,
                          maxGroupSize: parseInt(e.target.value),
                        },
                      });
                    }}
                    fullWidth
                  />
                </>
              )}
            </Stack>
          )}

          {activeTab === 3 && (
            <Stack spacing={3}>
              <Alert severity="info">
                Advanced settings for notification delivery and processing.
              </Alert>
              
              <Typography variant="subtitle1">Override Keywords</Typography>
              <Typography variant="body2" color="text.secondary">
                Notifications containing these keywords will always be delivered, even during Do Not Disturb.
              </Typography>
              
              <List>
                {localPreferences.doNotDisturb.overrideKeywords?.map((keyword, index) => (
                  <ListItem key={index}>
                    <ListItemText primary={keyword} />
                    <ListItemSecondaryAction>
                      <IconButton
                        edge="end"
                        onClick={() => {
                          const keywords = [...(localPreferences.doNotDisturb.overrideKeywords || [])];
                          keywords.splice(index, 1);
                          setLocalPreferences({
                            ...localPreferences,
                            doNotDisturb: {
                              ...localPreferences.doNotDisturb,
                              overrideKeywords: keywords,
                            },
                          });
                        }}
                      >
                        <DeleteIcon />
                      </IconButton>
                    </ListItemSecondaryAction>
                  </ListItem>
                ))}
              </List>
              
              <Stack direction="row" spacing={1}>
                <TextField
                  label="Add keyword"
                  size="small"
                  fullWidth
                  onKeyPress={(e) => {
                    if (e.key === 'Enter') {
                      const input = e.target as HTMLInputElement;
                      if (input.value) {
                        setLocalPreferences({
                          ...localPreferences,
                          doNotDisturb: {
                            ...localPreferences.doNotDisturb,
                            overrideKeywords: [
                              ...(localPreferences.doNotDisturb.overrideKeywords || []),
                              input.value,
                            ],
                          },
                        });
                        input.value = '';
                      }
                    }
                  }}
                />
                <Button startIcon={<AddIcon />}>Add</Button>
              </Stack>
            </Stack>
          )}
        </Box>
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button onClick={handleSave} variant="contained">Save</Button>
      </DialogActions>
    </Dialog>
  );
};

function getChannelDescription(channel: NotificationChannel): string {
  const descriptions: Record<NotificationChannel, string> = {
    [NotificationChannel.IN_APP]: 'Show notifications within the application',
    [NotificationChannel.EMAIL]: 'Send notifications to your email address',
    [NotificationChannel.SMS]: 'Send notifications via SMS to your phone',
    [NotificationChannel.SLACK]: 'Send notifications to your Slack workspace',
    [NotificationChannel.WEBHOOK]: 'Send notifications to a webhook URL',
    [NotificationChannel.PUSH]: 'Send push notifications to your browser',
  };
  return descriptions[channel] || '';
}

export default NotificationSettings;