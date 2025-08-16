import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Alert,
  AlertTitle,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Radio,
  RadioGroup,
  FormControlLabel,
  Chip,
  IconButton,
  Collapse,
  Divider,
  useTheme,
  alpha,
} from '@mui/material';
import {
  Warning,
  Error as ErrorIcon,
  CheckCircle,
  Info,
  ExpandMore,
  ExpandLess,
  Merge,
  Delete,
  Edit,
  AutoAwesome,
} from '@mui/icons-material';

interface DNSConflict {
  id: string;
  type: 'error' | 'warning';
  message: string;
  records: Array<{
    id: string;
    type: string;
    name: string;
    value: string;
    ttl: number;
  }>;
  resolution: {
    automatic?: boolean;
    suggestions: Array<{
      id: string;
      action: 'keep' | 'replace' | 'merge' | 'delete';
      description: string;
      result?: any;
    }>;
  };
}

interface ConflictResolverProps {
  conflicts: DNSConflict[];
  onResolve: (resolvedRecords: any[]) => void;
}

export const ConflictResolver: React.FC<ConflictResolverProps> = ({
  conflicts,
  onResolve,
}) => {
  const theme = useTheme();
  const [expandedConflicts, setExpandedConflicts] = useState<Set<string>>(new Set());
  const [selectedResolutions, setSelectedResolutions] = useState<Map<string, string>>(new Map());
  const [aiResolving, setAiResolving] = useState(false);

  const toggleConflict = (conflictId: string) => {
    const newExpanded = new Set(expandedConflicts);
    if (newExpanded.has(conflictId)) {
      newExpanded.delete(conflictId);
    } else {
      newExpanded.add(conflictId);
    }
    setExpandedConflicts(newExpanded);
  };

  const selectResolution = (conflictId: string, resolutionId: string) => {
    const newSelections = new Map(selectedResolutions);
    newSelections.set(conflictId, resolutionId);
    setSelectedResolutions(newSelections);
  };

  const autoResolveConflicts = async () => {
    setAiResolving(true);
    
    // Simulate AI resolution
    setTimeout(() => {
      const autoResolutions = new Map<string, string>();
      conflicts.forEach(conflict => {
        if (conflict.resolution.automatic) {
          // Select the first suggestion as the automatic resolution
          autoResolutions.set(conflict.id, conflict.resolution.suggestions[0].id);
        }
      });
      setSelectedResolutions(autoResolutions);
      setAiResolving(false);
    }, 1500);
  };

  const applyResolutions = () => {
    // Apply the selected resolutions
    const resolvedRecords: any[] = [];
    
    conflicts.forEach(conflict => {
      const selectedResolution = selectedResolutions.get(conflict.id);
      if (selectedResolution) {
        const resolution = conflict.resolution.suggestions.find(s => s.id === selectedResolution);
        if (resolution?.result) {
          resolvedRecords.push(...resolution.result);
        }
      }
    });
    
    onResolve(resolvedRecords);
  };

  const getSeverityIcon = (type: string) => {
    switch (type) {
      case 'error':
        return <ErrorIcon color="error" />;
      case 'warning':
        return <Warning color="warning" />;
      default:
        return <Info color="info" />;
    }
  };

  const getActionIcon = (action: string) => {
    switch (action) {
      case 'keep':
        return <CheckCircle color="success" />;
      case 'replace':
        return <Edit color="primary" />;
      case 'merge':
        return <Merge color="info" />;
      case 'delete':
        return <Delete color="error" />;
      default:
        return <Info />;
    }
  };

  const unresolvedCount = conflicts.filter(c => !selectedResolutions.has(c.id)).length;

  return (
    <Card>
      <CardContent>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
          <Typography variant="h6" display="flex" alignItems="center" gap={1}>
            <Warning color="warning" />
            Conflict Resolution
          </Typography>
          <Box display="flex" gap={1}>
            <Chip
              label={`${conflicts.length} conflicts`}
              color="warning"
              variant="outlined"
            />
            {unresolvedCount > 0 && (
              <Chip
                label={`${unresolvedCount} unresolved`}
                color="error"
              />
            )}
          </Box>
        </Box>

        <Alert severity="warning" sx={{ mb: 2 }}>
          <AlertTitle>DNS Record Conflicts Detected</AlertTitle>
          We've detected potential conflicts in your DNS configuration. 
          Review and resolve them before saving.
        </Alert>

        <Box display="flex" justifyContent="flex-end" mb={2}>
          <Button
            variant="outlined"
            startIcon={<AutoAwesome />}
            onClick={autoResolveConflicts}
            disabled={aiResolving}
          >
            {aiResolving ? 'Resolving...' : 'Auto-Resolve with AI'}
          </Button>
        </Box>

        <List>
          {conflicts.map((conflict, index) => {
            const isExpanded = expandedConflicts.has(conflict.id);
            const hasResolution = selectedResolutions.has(conflict.id);
            
            return (
              <React.Fragment key={conflict.id}>
                {index > 0 && <Divider />}
                <ListItem
                  sx={{
                    flexDirection: 'column',
                    alignItems: 'stretch',
                    backgroundColor: hasResolution ? 
                      alpha(theme.palette.success.main, 0.05) : 
                      'transparent',
                  }}
                >
                  <Box display="flex" justifyContent="space-between" alignItems="center">
                    <Box display="flex" alignItems="center" gap={1}>
                      <ListItemIcon sx={{ minWidth: 'auto' }}>
                        {getSeverityIcon(conflict.type)}
                      </ListItemIcon>
                      <ListItemText
                        primary={conflict.message}
                        secondary={`Affects ${conflict.records.length} record(s)`}
                      />
                    </Box>
                    <IconButton onClick={() => toggleConflict(conflict.id)}>
                      {isExpanded ? <ExpandLess /> : <ExpandMore />}
                    </IconButton>
                  </Box>

                  <Collapse in={isExpanded}>
                    <Box mt={2}>
                      {/* Affected Records */}
                      <Typography variant="subtitle2" gutterBottom>
                        Affected Records:
                      </Typography>
                      <Box ml={2} mb={2}>
                        {conflict.records.map(record => (
                          <Chip
                            key={record.id}
                            label={`${record.type} ${record.name} → ${record.value}`}
                            size="small"
                            sx={{ mr: 1, mb: 1 }}
                          />
                        ))}
                      </Box>

                      {/* Resolution Options */}
                      <Typography variant="subtitle2" gutterBottom>
                        Resolution Options:
                      </Typography>
                      <RadioGroup
                        value={selectedResolutions.get(conflict.id) || ''}
                        onChange={(e) => selectResolution(conflict.id, e.target.value)}
                      >
                        {conflict.resolution.suggestions.map(suggestion => (
                          <FormControlLabel
                            key={suggestion.id}
                            value={suggestion.id}
                            control={<Radio />}
                            label={
                              <Box display="flex" alignItems="center" gap={1}>
                                {getActionIcon(suggestion.action)}
                                <Typography variant="body2">
                                  {suggestion.description}
                                </Typography>
                                {conflict.resolution.automatic && 
                                 suggestion.id === conflict.resolution.suggestions[0].id && (
                                  <Chip
                                    label="Recommended"
                                    size="small"
                                    color="primary"
                                    variant="outlined"
                                  />
                                )}
                              </Box>
                            }
                            sx={{
                              ml: 2,
                              mb: 1,
                              '& .MuiFormControlLabel-label': {
                                width: '100%',
                              },
                            }}
                          />
                        ))}
                      </RadioGroup>
                    </Box>
                  </Collapse>
                </ListItem>
              </React.Fragment>
            );
          })}
        </List>

        {conflicts.length > 0 && (
          <Box display="flex" justifyContent="flex-end" mt={3}>
            <Button
              variant="contained"
              startIcon={<CheckCircle />}
              onClick={applyResolutions}
              disabled={unresolvedCount > 0}
            >
              Apply Resolutions
            </Button>
          </Box>
        )}
      </CardContent>
    </Card>
  );
};