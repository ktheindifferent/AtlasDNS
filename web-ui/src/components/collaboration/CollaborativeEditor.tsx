import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Box,
  Paper,
  TextField,
  Typography,
  Alert,
  AlertTitle,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Chip,
  LinearProgress,
  IconButton,
  Tooltip,
} from '@mui/material';
import LockIcon from '@mui/icons-material/Lock';
import LockOpenIcon from '@mui/icons-material/LockOpen';
import SyncIcon from '@mui/icons-material/Sync';
import WarningIcon from '@mui/icons-material/Warning';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import MergeTypeIcon from '@mui/icons-material/MergeType';
import { useCollaboration } from '../../contexts/CollaborationContext';
import { useSelector } from 'react-redux';
import { RootState } from '../../store';
import * as Y from 'yjs';
import ReactDiffViewer from 'react-diff-viewer-continued';

interface CollaborativeEditorProps {
  entityType: 'zone' | 'record';
  entityId: string;
  initialValue: any;
  onSave: (value: any) => void;
  fields: {
    name: string;
    label: string;
    type: 'text' | 'number' | 'select' | 'multiline';
    options?: string[];
    required?: boolean;
  }[];
}

interface ConflictData {
  field: string;
  localValue: any;
  remoteValue: any;
  baseValue: any;
}

const CollaborativeEditor: React.FC<CollaborativeEditorProps> = ({
  entityType,
  entityId,
  initialValue,
  onSave,
  fields,
}) => {
  const {
    ydoc,
    awareness,
    requestEditLock,
    releaseEditLock,
    trackChange,
    sendTyping,
    getSharedData,
    setSharedData,
  } = useCollaboration();
  
  const { user: currentUser } = useSelector((state: RootState) => state.auth);
  const { editingLocks, typing, activeUsers } = useSelector(
    (state: RootState) => state.collaboration
  );
  
  const [formData, setFormData] = useState(initialValue);
  const [localChanges, setLocalChanges] = useState<{ [key: string]: any }>({});
  const [remoteChanges, setRemoteChanges] = useState<{ [key: string]: any }>({});
  const [conflicts, setConflicts] = useState<ConflictData[]>([]);
  const [hasEditLock, setHasEditLock] = useState(false);
  const [isRequestingLock, setIsRequestingLock] = useState(false);
  const [isSyncing, setIsSyncing] = useState(false);
  const [conflictDialogOpen, setConflictDialogOpen] = useState(false);
  const [selectedResolution, setSelectedResolution] = useState<{ [field: string]: 'local' | 'remote' | 'custom' }>({});
  const [customValues, setCustomValues] = useState<{ [field: string]: any }>({});
  const yMapRef = useRef<Y.Map<any> | null>(null);
  const typingTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    if (!ydoc) return;

    const yMap = ydoc.getMap(`${entityType}:${entityId}`);
    yMapRef.current = yMap;

    if (yMap.size === 0) {
      Object.entries(initialValue).forEach(([key, value]) => {
        yMap.set(key, value);
      });
    } else {
      const sharedData: any = {};
      yMap.forEach((value, key) => {
        sharedData[key] = value;
      });
      setFormData(sharedData);
    }

    const handleYMapChange = () => {
      const newData: any = {};
      const changes: any = {};
      
      yMap.forEach((value, key) => {
        newData[key] = value;
        if (value !== formData[key] && !localChanges[key]) {
          changes[key] = value;
        }
      });

      setRemoteChanges(changes);
      
      const detectedConflicts: ConflictData[] = [];
      Object.keys(localChanges).forEach(field => {
        if (changes[field] !== undefined && changes[field] !== localChanges[field]) {
          detectedConflicts.push({
            field,
            localValue: localChanges[field],
            remoteValue: changes[field],
            baseValue: initialValue[field],
          });
        }
      });

      if (detectedConflicts.length > 0) {
        setConflicts(detectedConflicts);
        setConflictDialogOpen(true);
      } else if (Object.keys(changes).length > 0) {
        setFormData(prevData => ({ ...prevData, ...changes }));
      }
    };

    yMap.observe(handleYMapChange);

    return () => {
      yMap.unobserve(handleYMapChange);
    };
  }, [ydoc, entityType, entityId, initialValue, formData, localChanges]);

  useEffect(() => {
    if (!awareness) return;

    const handleAwarenessChange = () => {
      const states = Array.from(awareness.getStates().values());
      const editingUsers = states
        .filter((state: any) => 
          state.editing?.entityType === entityType && 
          state.editing?.entityId === entityId
        )
        .map((state: any) => state.user);

      setIsSyncing(editingUsers.length > 1);
    };

    awareness.on('change', handleAwarenessChange);

    return () => {
      awareness.off('change', handleAwarenessChange);
    };
  }, [awareness, entityType, entityId]);

  const requestLock = async () => {
    setIsRequestingLock(true);
    const granted = await requestEditLock(`${entityType}:${entityId}`);
    setHasEditLock(granted);
    setIsRequestingLock(false);

    if (granted && awareness) {
      awareness.setLocalStateField('editing', {
        entityType,
        entityId,
        timestamp: Date.now(),
      });
    }
  };

  const releaseLock = () => {
    releaseEditLock(`${entityType}:${entityId}`);
    setHasEditLock(false);

    if (awareness) {
      awareness.setLocalStateField('editing', null);
    }
  };

  const handleFieldChange = (field: string, value: any) => {
    if (!hasEditLock) {
      requestLock();
      return;
    }

    const newData = { ...formData, [field]: value };
    setFormData(newData);
    setLocalChanges(prev => ({ ...prev, [field]: value }));

    if (yMapRef.current) {
      yMapRef.current.set(field, value);
    }

    sendTyping(`${entityType}:${entityId}:${field}`, true);

    if (typingTimeoutRef.current) {
      clearTimeout(typingTimeoutRef.current);
    }
    typingTimeoutRef.current = setTimeout(() => {
      sendTyping(`${entityType}:${entityId}:${field}`, false);
    }, 1000);
  };

  const resolveConflicts = () => {
    const resolvedData = { ...formData };

    conflicts.forEach(conflict => {
      const resolution = selectedResolution[conflict.field];
      if (resolution === 'local') {
        resolvedData[conflict.field] = conflict.localValue;
      } else if (resolution === 'remote') {
        resolvedData[conflict.field] = conflict.remoteValue;
      } else if (resolution === 'custom') {
        resolvedData[conflict.field] = customValues[conflict.field];
      }
    });

    setFormData(resolvedData);
    setLocalChanges({});
    setRemoteChanges({});
    setConflicts([]);
    setConflictDialogOpen(false);

    if (yMapRef.current) {
      Object.entries(resolvedData).forEach(([key, value]) => {
        yMapRef.current!.set(key, value);
      });
    }
  };

  const handleSave = () => {
    const changes = Object.keys(localChanges).map(field => ({
      field,
      oldValue: initialValue[field],
      newValue: formData[field],
    }));

    if (changes.length > 0) {
      trackChange({
        userId: currentUser?.id || '',
        user: {
          id: currentUser?.id || '',
          name: currentUser?.name || currentUser?.email || '',
          email: currentUser?.email || '',
          color: '#2196F3',
        },
        action: 'update',
        entityType,
        entityId,
        changes,
        description: `Updated ${entityType} ${entityId}`,
      });
    }

    onSave(formData);
    setLocalChanges({});
    releaseLock();
  };

  const getCurrentEditor = () => {
    const lockHolder = editingLocks[`${entityType}:${entityId}`];
    if (lockHolder && lockHolder !== currentUser?.id) {
      const editor = activeUsers.find(u => u.id === lockHolder);
      return editor;
    }
    return null;
  };

  const getFieldTypingUsers = (field: string) => {
    const location = `${entityType}:${entityId}:${field}`;
    return Object.values(typing)
      .filter(t => t.location === location && t.userId !== currentUser?.id)
      .map(t => activeUsers.find(u => u.id === t.userId))
      .filter(Boolean);
  };

  const currentEditor = getCurrentEditor();

  return (
    <>
      <Paper sx={{ p: 3 }}>
        {isSyncing && (
          <LinearProgress sx={{ mb: 2 }} />
        )}

        {currentEditor && !hasEditLock && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            <AlertTitle>Currently being edited</AlertTitle>
            {currentEditor.name} is currently editing this {entityType}.
            You can request edit access or wait for them to finish.
          </Alert>
        )}

        {conflicts.length > 0 && (
          <Alert 
            severity="error" 
            sx={{ mb: 2 }}
            action={
              <Button color="inherit" size="small" onClick={() => setConflictDialogOpen(true)}>
                Resolve
              </Button>
            }
          >
            <AlertTitle>Conflicts detected</AlertTitle>
            There are {conflicts.length} conflicting changes that need to be resolved.
          </Alert>
        )}

        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
          <Typography variant="h6">
            Edit {entityType.charAt(0).toUpperCase() + entityType.slice(1)}
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
            {hasEditLock ? (
              <Chip
                label="Edit lock acquired"
                color="success"
                icon={<LockIcon />}
                onDelete={releaseLock}
              />
            ) : (
              <Tooltip title="Request edit lock to prevent conflicts">
                <Button
                  variant="outlined"
                  startIcon={<LockOpenIcon />}
                  onClick={requestLock}
                  disabled={isRequestingLock || !!currentEditor}
                >
                  {isRequestingLock ? 'Requesting...' : 'Request Edit Lock'}
                </Button>
              </Tooltip>
            )}
            {isSyncing && (
              <Chip
                label="Syncing"
                color="info"
                icon={<SyncIcon />}
                size="small"
              />
            )}
          </Box>
        </Box>

        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          {fields.map(field => {
            const typingUsers = getFieldTypingUsers(field.name);
            const hasRemoteChange = remoteChanges[field.name] !== undefined;

            return (
              <Box key={field.name}>
                <TextField
                  fullWidth
                  label={field.label}
                  name={field.name}
                  value={formData[field.name] || ''}
                  onChange={(e) => handleFieldChange(field.name, e.target.value)}
                  required={field.required}
                  multiline={field.type === 'multiline'}
                  rows={field.type === 'multiline' ? 4 : 1}
                  type={field.type === 'number' ? 'number' : 'text'}
                  select={field.type === 'select'}
                  disabled={!hasEditLock && !!currentEditor}
                  InputProps={{
                    endAdornment: hasRemoteChange && (
                      <Tooltip title="This field was changed by another user">
                        <WarningIcon color="warning" fontSize="small" />
                      </Tooltip>
                    ),
                  }}
                >
                  {field.type === 'select' && field.options?.map(option => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </TextField>
                {typingUsers.length > 0 && (
                  <Typography variant="caption" color="text.secondary">
                    {typingUsers.map(u => u?.name).join(', ')} {typingUsers.length === 1 ? 'is' : 'are'} typing...
                  </Typography>
                )}
              </Box>
            );
          })}
        </Box>

        <Box sx={{ display: 'flex', gap: 2, mt: 3 }}>
          <Button
            variant="contained"
            onClick={handleSave}
            disabled={!hasEditLock || Object.keys(localChanges).length === 0}
          >
            Save Changes
          </Button>
          <Button
            variant="outlined"
            onClick={() => {
              setFormData(initialValue);
              setLocalChanges({});
              releaseLock();
            }}
          >
            Cancel
          </Button>
        </Box>
      </Paper>

      <Dialog
        open={conflictDialogOpen}
        onClose={() => {}}
        maxWidth="lg"
        fullWidth
        disableEscapeKeyDown
      >
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <MergeTypeIcon />
            Resolve Conflicts
          </Box>
        </DialogTitle>
        <DialogContent>
          <Alert severity="info" sx={{ mb: 2 }}>
            Another user made changes while you were editing. Please resolve the conflicts below.
          </Alert>
          {conflicts.map(conflict => (
            <Box key={conflict.field} sx={{ mb: 3 }}>
              <Typography variant="subtitle1" gutterBottom>
                {fields.find(f => f.name === conflict.field)?.label || conflict.field}
              </Typography>
              <ReactDiffViewer
                oldValue={String(conflict.localValue)}
                newValue={String(conflict.remoteValue)}
                splitView={true}
                leftTitle="Your Changes"
                rightTitle="Their Changes"
                styles={{
                  variables: {
                    light: {
                      diffViewerBackground: '#fafafa',
                    },
                  },
                }}
              />
              <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
                <Button
                  variant={selectedResolution[conflict.field] === 'local' ? 'contained' : 'outlined'}
                  onClick={() => setSelectedResolution(prev => ({ ...prev, [conflict.field]: 'local' }))}
                >
                  Keep Mine
                </Button>
                <Button
                  variant={selectedResolution[conflict.field] === 'remote' ? 'contained' : 'outlined'}
                  onClick={() => setSelectedResolution(prev => ({ ...prev, [conflict.field]: 'remote' }))}
                >
                  Keep Theirs
                </Button>
                <Button
                  variant={selectedResolution[conflict.field] === 'custom' ? 'contained' : 'outlined'}
                  onClick={() => setSelectedResolution(prev => ({ ...prev, [conflict.field]: 'custom' }))}
                >
                  Custom
                </Button>
              </Box>
              {selectedResolution[conflict.field] === 'custom' && (
                <TextField
                  fullWidth
                  multiline
                  rows={2}
                  value={customValues[conflict.field] || ''}
                  onChange={(e) => setCustomValues(prev => ({ ...prev, [conflict.field]: e.target.value }))}
                  placeholder="Enter custom value..."
                  sx={{ mt: 1 }}
                />
              )}
            </Box>
          ))}
        </DialogContent>
        <DialogActions>
          <Button
            onClick={resolveConflicts}
            variant="contained"
            disabled={conflicts.some(c => !selectedResolution[c.field])}
          >
            Resolve & Continue
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default CollaborativeEditor;