import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Switch,
  Fab,
  Box,
  Typography,
  Chip,
  Stack,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Card,
  CardContent,
  Divider,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  ContentCopy as CopyIcon,
} from '@mui/icons-material';
import { useSelector, useDispatch } from 'react-redux';
import { RootState } from '../../store';
import {
  addRule,
  updateRule,
  deleteRule,
} from '../../store/slices/notificationSlice';
import {
  NotificationRule,
  NotificationCondition,
  NotificationRuleAction,
  NotificationCategory,
  NotificationPriority,
} from '../../types/notification.types';

interface NotificationRulesProps {
  open: boolean;
  onClose: () => void;
}

const NotificationRules: React.FC<NotificationRulesProps> = ({ open, onClose }) => {
  const dispatch = useDispatch();
  const rules = useSelector((state: RootState) => state.notifications.rules);
  const [editingRule, setEditingRule] = useState<NotificationRule | null>(null);
  const [showRuleEditor, setShowRuleEditor] = useState(false);

  const handleToggleRule = (rule: NotificationRule) => {
    dispatch(updateRule({
      ...rule,
      enabled: !rule.enabled,
    }));
  };

  const handleDeleteRule = (ruleId: string) => {
    if (window.confirm('Are you sure you want to delete this rule?')) {
      dispatch(deleteRule(ruleId));
    }
  };

  const handleSaveRule = (rule: NotificationRule) => {
    if (editingRule) {
      dispatch(updateRule(rule));
    } else {
      dispatch(addRule(rule));
    }
    setEditingRule(null);
    setShowRuleEditor(false);
  };

  const handleDuplicateRule = (rule: NotificationRule) => {
    const newRule: NotificationRule = {
      ...rule,
      id: `rule-${Date.now()}`,
      name: `${rule.name} (Copy)`,
    };
    dispatch(addRule(newRule));
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>Notification Rules</DialogTitle>
      
      <DialogContent>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Create rules to automatically trigger notifications based on conditions.
        </Typography>

        <List>
          {rules.map((rule) => (
            <Card key={rule.id} sx={{ mb: 2 }}>
              <CardContent>
                <ListItem disableGutters>
                  <ListItemText
                    primary={
                      <Stack direction="row" alignItems="center" spacing={1}>
                        <Typography variant="subtitle1">{rule.name}</Typography>
                        {rule.enabled && (
                          <Chip label="Active" size="small" color="success" />
                        )}
                        {rule.category && (
                          <Chip label={rule.category} size="small" variant="outlined" />
                        )}
                        {rule.priority && (
                          <Chip label={rule.priority} size="small" color="primary" />
                        )}
                      </Stack>
                    }
                    secondary={
                      <Box sx={{ mt: 1 }}>
                        <Typography variant="body2" color="text.secondary">
                          {rule.description}
                        </Typography>
                        
                        {rule.conditions.length > 0 && (
                          <Stack direction="row" spacing={0.5} sx={{ mt: 1 }}>
                            <Typography variant="caption">Conditions:</Typography>
                            {rule.conditions.map((condition, index) => (
                              <Chip
                                key={index}
                                label={`${condition.field} ${condition.operator} ${condition.value}`}
                                size="small"
                                variant="outlined"
                              />
                            ))}
                          </Stack>
                        )}
                        
                        {rule.actions.length > 0 && (
                          <Stack direction="row" spacing={0.5} sx={{ mt: 1 }}>
                            <Typography variant="caption">Actions:</Typography>
                            {rule.actions.map((action, index) => (
                              <Chip
                                key={index}
                                label={action.type}
                                size="small"
                                color="secondary"
                                variant="outlined"
                              />
                            ))}
                          </Stack>
                        )}

                        {(rule.cooldown || rule.maxOccurrences) && (
                          <Stack direction="row" spacing={2} sx={{ mt: 1 }}>
                            {rule.cooldown && (
                              <Typography variant="caption" color="text.secondary">
                                Cooldown: {rule.cooldown / 1000}s
                              </Typography>
                            )}
                            {rule.maxOccurrences && (
                              <Typography variant="caption" color="text.secondary">
                                Max occurrences: {rule.maxOccurrences}
                              </Typography>
                            )}
                          </Stack>
                        )}
                      </Box>
                    }
                  />
                  
                  <ListItemSecondaryAction>
                    <Stack direction="row" spacing={1}>
                      <Switch
                        checked={rule.enabled}
                        onChange={() => handleToggleRule(rule)}
                      />
                      
                      <IconButton
                        size="small"
                        onClick={() => handleDuplicateRule(rule)}
                      >
                        <CopyIcon fontSize="small" />
                      </IconButton>
                      
                      <IconButton
                        size="small"
                        onClick={() => {
                          setEditingRule(rule);
                          setShowRuleEditor(true);
                        }}
                      >
                        <EditIcon fontSize="small" />
                      </IconButton>
                      
                      <IconButton
                        size="small"
                        onClick={() => handleDeleteRule(rule.id)}
                        color="error"
                      >
                        <DeleteIcon fontSize="small" />
                      </IconButton>
                    </Stack>
                  </ListItemSecondaryAction>
                </ListItem>
              </CardContent>
            </Card>
          ))}
        </List>

        {rules.length === 0 && (
          <Box sx={{ textAlign: 'center', py: 4 }}>
            <Typography variant="h6" color="text.secondary">
              No rules configured
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Create rules to automate notifications
            </Typography>
          </Box>
        )}

        <Fab
          color="primary"
          aria-label="add"
          onClick={() => {
            setEditingRule(null);
            setShowRuleEditor(true);
          }}
          sx={{ position: 'fixed', bottom: 80, right: 24 }}
        >
          <AddIcon />
        </Fab>
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>

      {showRuleEditor && (
        <RuleEditor
          rule={editingRule}
          open={showRuleEditor}
          onClose={() => {
            setShowRuleEditor(false);
            setEditingRule(null);
          }}
          onSave={handleSaveRule}
        />
      )}
    </Dialog>
  );
};

interface RuleEditorProps {
  rule: NotificationRule | null;
  open: boolean;
  onClose: () => void;
  onSave: (rule: NotificationRule) => void;
}

const RuleEditor: React.FC<RuleEditorProps> = ({ rule, open, onClose, onSave }) => {
  const [formData, setFormData] = useState<NotificationRule>(
    rule || {
      id: `rule-${Date.now()}`,
      name: '',
      description: '',
      enabled: true,
      conditions: [],
      actions: [],
      category: NotificationCategory.ALERT,
      priority: NotificationPriority.MEDIUM,
    }
  );

  const [newCondition, setNewCondition] = useState<NotificationCondition>({
    field: '',
    operator: 'equals',
    value: '',
  });

  const [newAction, setNewAction] = useState<NotificationRuleAction>({
    type: 'notify',
    config: {},
  });

  const handleAddCondition = () => {
    if (newCondition.field && newCondition.value) {
      setFormData({
        ...formData,
        conditions: [...formData.conditions, newCondition],
      });
      setNewCondition({
        field: '',
        operator: 'equals',
        value: '',
      });
    }
  };

  const handleRemoveCondition = (index: number) => {
    const conditions = [...formData.conditions];
    conditions.splice(index, 1);
    setFormData({ ...formData, conditions });
  };

  const handleAddAction = () => {
    setFormData({
      ...formData,
      actions: [...formData.actions, newAction],
    });
    setNewAction({
      type: 'notify',
      config: {},
    });
  };

  const handleRemoveAction = (index: number) => {
    const actions = [...formData.actions];
    actions.splice(index, 1);
    setFormData({ ...formData, actions });
  };

  const handleSave = () => {
    if (formData.name) {
      onSave(formData);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>{rule ? 'Edit Rule' : 'Create Rule'}</DialogTitle>
      
      <DialogContent>
        <Stack spacing={3} sx={{ mt: 1 }}>
          <TextField
            label="Rule Name"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            fullWidth
            required
          />

          <TextField
            label="Description"
            value={formData.description}
            onChange={(e) => setFormData({ ...formData, description: e.target.value })}
            fullWidth
            multiline
            rows={2}
          />

          <Stack direction="row" spacing={2}>
            <FormControl fullWidth>
              <InputLabel>Category</InputLabel>
              <Select
                value={formData.category}
                onChange={(e) => setFormData({ ...formData, category: e.target.value as NotificationCategory })}
              >
                {Object.values(NotificationCategory).map((category) => (
                  <MenuItem key={category} value={category}>
                    {category}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            <FormControl fullWidth>
              <InputLabel>Priority</InputLabel>
              <Select
                value={formData.priority}
                onChange={(e) => setFormData({ ...formData, priority: e.target.value as NotificationPriority })}
              >
                {Object.values(NotificationPriority).map((priority) => (
                  <MenuItem key={priority} value={priority}>
                    {priority}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Stack>

          <Divider />

          <Box>
            <Typography variant="subtitle1" sx={{ mb: 2 }}>Conditions</Typography>
            
            {formData.conditions.map((condition, index) => (
              <Chip
                key={index}
                label={`${condition.field} ${condition.operator} ${condition.value}`}
                onDelete={() => handleRemoveCondition(index)}
                sx={{ mr: 1, mb: 1 }}
              />
            ))}

            <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
              <TextField
                label="Field"
                value={newCondition.field}
                onChange={(e) => setNewCondition({ ...newCondition, field: e.target.value })}
                size="small"
              />
              
              <FormControl size="small">
                <InputLabel>Operator</InputLabel>
                <Select
                  value={newCondition.operator}
                  onChange={(e) => setNewCondition({ ...newCondition, operator: e.target.value as any })}
                >
                  <MenuItem value="equals">Equals</MenuItem>
                  <MenuItem value="contains">Contains</MenuItem>
                  <MenuItem value="greater_than">Greater Than</MenuItem>
                  <MenuItem value="less_than">Less Than</MenuItem>
                  <MenuItem value="regex">Regex</MenuItem>
                  <MenuItem value="in">In</MenuItem>
                  <MenuItem value="not_in">Not In</MenuItem>
                </Select>
              </FormControl>
              
              <TextField
                label="Value"
                value={newCondition.value}
                onChange={(e) => setNewCondition({ ...newCondition, value: e.target.value })}
                size="small"
              />
              
              <Button onClick={handleAddCondition} startIcon={<AddIcon />}>
                Add
              </Button>
            </Stack>
          </Box>

          <Divider />

          <Box>
            <Typography variant="subtitle1" sx={{ mb: 2 }}>Actions</Typography>
            
            {formData.actions.map((action, index) => (
              <Chip
                key={index}
                label={action.type}
                onDelete={() => handleRemoveAction(index)}
                color="secondary"
                sx={{ mr: 1, mb: 1 }}
              />
            ))}

            <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
              <FormControl size="small" fullWidth>
                <InputLabel>Action Type</InputLabel>
                <Select
                  value={newAction.type}
                  onChange={(e) => setNewAction({ ...newAction, type: e.target.value as any })}
                >
                  <MenuItem value="notify">Notify</MenuItem>
                  <MenuItem value="email">Send Email</MenuItem>
                  <MenuItem value="sms">Send SMS</MenuItem>
                  <MenuItem value="slack">Send to Slack</MenuItem>
                  <MenuItem value="webhook">Call Webhook</MenuItem>
                  <MenuItem value="log">Log</MenuItem>
                </Select>
              </FormControl>
              
              <Button onClick={handleAddAction} startIcon={<AddIcon />}>
                Add
              </Button>
            </Stack>
          </Box>

          <Divider />

          <Stack direction="row" spacing={2}>
            <TextField
              label="Cooldown (seconds)"
              type="number"
              value={formData.cooldown ? formData.cooldown / 1000 : ''}
              onChange={(e) => setFormData({ 
                ...formData, 
                cooldown: e.target.value ? parseInt(e.target.value) * 1000 : undefined 
              })}
              fullWidth
            />

            <TextField
              label="Max Occurrences"
              type="number"
              value={formData.maxOccurrences || ''}
              onChange={(e) => setFormData({ 
                ...formData, 
                maxOccurrences: e.target.value ? parseInt(e.target.value) : undefined 
              })}
              fullWidth
            />
          </Stack>
        </Stack>
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button onClick={handleSave} variant="contained" disabled={!formData.name}>
          Save
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default NotificationRules;