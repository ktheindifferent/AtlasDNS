import React, { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  Timeline,
  TimelineItem,
  TimelineSeparator,
  TimelineConnector,
  TimelineContent,
  TimelineDot,
  TimelineOppositeContent,
  Avatar,
  Chip,
  IconButton,
  Collapse,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from '@mui/material';
import ReactDiffViewer from 'react-diff-viewer-continued';
import { format } from 'date-fns';
import AddIcon from '@mui/icons-material/Add';
import EditIcon from '@mui/icons-material/Edit';
import DeleteIcon from '@mui/icons-material/Delete';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import CompareArrowsIcon from '@mui/icons-material/CompareArrows';
import HistoryIcon from '@mui/icons-material/History';
import RestoreIcon from '@mui/icons-material/Restore';
import { useSelector } from 'react-redux';
import { RootState } from '../../store';
import { ChangeHistoryItem } from '../../store/slices/collaborationSlice';

interface ChangeHistoryProps {
  entityType?: 'zone' | 'record';
  entityId?: string;
  limit?: number;
  compact?: boolean;
}

const ChangeHistory: React.FC<ChangeHistoryProps> = ({
  entityType,
  entityId,
  limit = 10,
  compact = false,
}) => {
  const { changeHistory: allHistory } = useSelector(
    (state: RootState) => state.collaboration
  );
  const [expandedItems, setExpandedItems] = useState<Set<string>>(new Set());
  const [diffDialogOpen, setDiffDialogOpen] = useState(false);
  const [selectedChange, setSelectedChange] = useState<ChangeHistoryItem | null>(null);
  const [showAll, setShowAll] = useState(false);

  const filteredHistory = allHistory.filter(item => {
    if (entityType && item.entityType !== entityType) return false;
    if (entityId && item.entityId !== entityId) return false;
    return true;
  });

  const displayHistory = showAll ? filteredHistory : filteredHistory.slice(0, limit);

  const toggleExpanded = (itemId: string) => {
    const newExpanded = new Set(expandedItems);
    if (newExpanded.has(itemId)) {
      newExpanded.delete(itemId);
    } else {
      newExpanded.add(itemId);
    }
    setExpandedItems(newExpanded);
  };

  const getActionIcon = (action: string) => {
    switch (action) {
      case 'create':
        return <AddIcon />;
      case 'update':
        return <EditIcon />;
      case 'delete':
        return <DeleteIcon />;
      default:
        return <HistoryIcon />;
    }
  };

  const getActionColor = (action: string): 'success' | 'warning' | 'error' | 'info' => {
    switch (action) {
      case 'create':
        return 'success';
      case 'update':
        return 'warning';
      case 'delete':
        return 'error';
      default:
        return 'info';
    }
  };

  const formatValue = (value: any): string => {
    if (value === null || value === undefined) return 'null';
    if (typeof value === 'object') return JSON.stringify(value, null, 2);
    return String(value);
  };

  const openDiffDialog = (change: ChangeHistoryItem) => {
    setSelectedChange(change);
    setDiffDialogOpen(true);
  };

  if (filteredHistory.length === 0) {
    return (
      <Paper sx={{ p: 3, textAlign: 'center' }}>
        <HistoryIcon sx={{ fontSize: 48, color: 'text.disabled', mb: 2 }} />
        <Typography variant="body1" color="text.secondary">
          No change history available
        </Typography>
      </Paper>
    );
  }

  return (
    <>
      <Paper sx={{ p: compact ? 2 : 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <HistoryIcon />
            Change History
          </Typography>
          {filteredHistory.length > limit && !showAll && (
            <Button
              size="small"
              onClick={() => setShowAll(true)}
              endIcon={<ExpandMoreIcon />}
            >
              Show All ({filteredHistory.length})
            </Button>
          )}
          {showAll && (
            <Button
              size="small"
              onClick={() => setShowAll(false)}
              endIcon={<ExpandLessIcon />}
            >
              Show Less
            </Button>
          )}
        </Box>

        <Timeline position={compact ? 'right' : 'alternate'}>
          {displayHistory.map((item) => {
            const isExpanded = expandedItems.has(item.id);
            
            return (
              <TimelineItem key={item.id}>
                {!compact && (
                  <TimelineOppositeContent
                    sx={{ m: 'auto 0' }}
                    align="right"
                    variant="body2"
                    color="text.secondary"
                  >
                    {format(new Date(item.timestamp), 'MMM d, yyyy')}
                    <br />
                    {format(new Date(item.timestamp), 'h:mm a')}
                  </TimelineOppositeContent>
                )}
                <TimelineSeparator>
                  <TimelineConnector sx={{ bgcolor: 'grey.300' }} />
                  <TimelineDot color={getActionColor(item.action)}>
                    {getActionIcon(item.action)}
                  </TimelineDot>
                  <TimelineConnector sx={{ bgcolor: 'grey.300' }} />
                </TimelineSeparator>
                <TimelineContent sx={{ py: '12px', px: 2 }}>
                  <Paper elevation={2} sx={{ p: 2 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                      <Avatar
                        src={item.user.avatar}
                        sx={{ width: 24, height: 24, bgcolor: item.user.color }}
                      >
                        {!item.user.avatar && item.user.name[0].toUpperCase()}
                      </Avatar>
                      <Typography variant="subtitle2">{item.user.name}</Typography>
                      <Chip
                        label={item.action}
                        size="small"
                        color={getActionColor(item.action)}
                        variant="outlined"
                      />
                      {compact && (
                        <Typography variant="caption" color="text.secondary">
                          {format(new Date(item.timestamp), 'MMM d, h:mm a')}
                        </Typography>
                      )}
                    </Box>
                    
                    <Typography variant="body2" color="text.secondary">
                      {item.description || `${item.action} ${item.entityType} ${item.entityId}`}
                    </Typography>

                    {item.changes.length > 0 && (
                      <Box sx={{ mt: 1 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography variant="caption" color="text.secondary">
                            {item.changes.length} field{item.changes.length > 1 ? 's' : ''} changed
                          </Typography>
                          <IconButton
                            size="small"
                            onClick={() => toggleExpanded(item.id)}
                          >
                            {isExpanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                          </IconButton>
                          <IconButton
                            size="small"
                            onClick={() => openDiffDialog(item)}
                          >
                            <CompareArrowsIcon />
                          </IconButton>
                        </Box>
                        
                        <Collapse in={isExpanded}>
                          <Box sx={{ mt: 1, pl: 2 }}>
                            {item.changes.map((change, idx) => (
                              <Box key={idx} sx={{ mb: 1 }}>
                                <Typography variant="caption" sx={{ fontWeight: 500 }}>
                                  {change.field}:
                                </Typography>
                                <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', ml: 2 }}>
                                  <Chip
                                    label={formatValue(change.oldValue).substring(0, 30)}
                                    size="small"
                                    variant="outlined"
                                    sx={{ textDecoration: 'line-through', opacity: 0.7 }}
                                  />
                                  <Typography variant="caption">→</Typography>
                                  <Chip
                                    label={formatValue(change.newValue).substring(0, 30)}
                                    size="small"
                                    color="primary"
                                    variant="outlined"
                                  />
                                </Box>
                              </Box>
                            ))}
                          </Box>
                        </Collapse>
                      </Box>
                    )}

                    <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: 1 }}>
                      <Button
                        size="small"
                        startIcon={<RestoreIcon />}
                        variant="text"
                        disabled
                      >
                        Revert
                      </Button>
                    </Box>
                  </Paper>
                </TimelineContent>
              </TimelineItem>
            );
          })}
        </Timeline>
      </Paper>

      <Dialog
        open={diffDialogOpen}
        onClose={() => setDiffDialogOpen(false)}
        maxWidth="lg"
        fullWidth
      >
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <CompareArrowsIcon />
            Change Diff Viewer
          </Box>
        </DialogTitle>
        <DialogContent>
          {selectedChange && selectedChange.changes.map((change, idx) => (
            <Box key={idx} sx={{ mb: 3 }}>
              <Typography variant="subtitle1" gutterBottom>
                {change.field}
              </Typography>
              <ReactDiffViewer
                oldValue={formatValue(change.oldValue)}
                newValue={formatValue(change.newValue)}
                splitView={true}
                showDiffOnly={false}
                styles={{
                  variables: {
                    light: {
                      diffViewerBackground: '#fafafa',
                      addedBackground: '#e8f5e9',
                      removedBackground: '#ffebee',
                      wordAddedBackground: '#c8e6c9',
                      wordRemovedBackground: '#ffcdd2',
                    },
                  },
                }}
              />
            </Box>
          ))}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDiffDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default ChangeHistory;