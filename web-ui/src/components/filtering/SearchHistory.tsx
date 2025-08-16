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
  ListItemIcon,
  ListItemSecondaryAction,
  IconButton,
  Typography,
  Box,
  TextField,
  InputAdornment,
  Chip,
  Stack,
  Tooltip,
} from '@mui/material';
import {
  History,
  Search,
  Delete,
  Clear,
  AccessTime,
  TrendingUp,
  ContentCopy,
} from '@mui/icons-material';
import { formatDistanceToNow } from 'date-fns';
import { SearchHistory as SearchHistoryType } from '../../types/filtering';

interface SearchHistoryProps {
  open: boolean;
  onClose: () => void;
  history: SearchHistoryType[];
  onSelect: (item: SearchHistoryType) => void;
  onClear?: () => void;
  onDelete?: (id: string) => void;
}

const SearchHistory: React.FC<SearchHistoryProps> = ({
  open,
  onClose,
  history,
  onSelect,
  onClear,
  onDelete,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<'all' | 'recent' | 'popular'>('all');

  const filteredHistory = history.filter(item =>
    item.query.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const categorizedHistory = () => {
    switch (selectedCategory) {
      case 'recent':
        return [...filteredHistory].sort((a, b) => 
          new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
        ).slice(0, 10);
      case 'popular':
        // Group by query and count occurrences
        const queryCount = filteredHistory.reduce((acc, item) => {
          acc[item.query] = (acc[item.query] || 0) + 1;
          return acc;
        }, {} as Record<string, number>);
        
        // Sort by count and return unique queries
        const uniqueQueries = Object.keys(queryCount)
          .sort((a, b) => queryCount[b] - queryCount[a])
          .slice(0, 10)
          .map(query => filteredHistory.find(h => h.query === query)!);
        
        return uniqueQueries;
      default:
        return filteredHistory;
    }
  };

  const handleCopy = (query: string) => {
    navigator.clipboard.writeText(query);
  };

  const getQueryStats = (query: string) => {
    const count = history.filter(h => h.query === query).length;
    const avgResults = history
      .filter(h => h.query === query)
      .reduce((sum, h) => sum + h.resultCount, 0) / count;
    
    return { count, avgResults: Math.round(avgResults) };
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>
        <Box display="flex" justifyContent="space-between" alignItems="center">
          <Box display="flex" alignItems="center" gap={1}>
            <History />
            <Typography variant="h6">Search History</Typography>
          </Box>
          {onClear && history.length > 0 && (
            <Tooltip title="Clear all history">
              <IconButton size="small" onClick={onClear}>
                <Clear />
              </IconButton>
            </Tooltip>
          )}
        </Box>
      </DialogTitle>
      
      <DialogContent>
        <Stack spacing={2}>
          <TextField
            fullWidth
            size="small"
            placeholder="Search history..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <Search />
                </InputAdornment>
              ),
            }}
          />

          <Stack direction="row" spacing={1}>
            <Chip
              label="All"
              onClick={() => setSelectedCategory('all')}
              color={selectedCategory === 'all' ? 'primary' : 'default'}
              variant={selectedCategory === 'all' ? 'filled' : 'outlined'}
            />
            <Chip
              label="Recent"
              icon={<AccessTime />}
              onClick={() => setSelectedCategory('recent')}
              color={selectedCategory === 'recent' ? 'primary' : 'default'}
              variant={selectedCategory === 'recent' ? 'filled' : 'outlined'}
            />
            <Chip
              label="Popular"
              icon={<TrendingUp />}
              onClick={() => setSelectedCategory('popular')}
              color={selectedCategory === 'popular' ? 'primary' : 'default'}
              variant={selectedCategory === 'popular' ? 'filled' : 'outlined'}
            />
          </Stack>

          <List sx={{ maxHeight: 400, overflow: 'auto' }}>
            {categorizedHistory().map((item) => {
              const stats = getQueryStats(item.query);
              
              return (
                <ListItem
                  key={item.id}
                  button
                  onClick={() => {
                    onSelect(item);
                    onClose();
                  }}
                >
                  <ListItemIcon>
                    <Search />
                  </ListItemIcon>
                  <ListItemText
                    primary={item.query}
                    secondary={
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Typography variant="caption">
                          {formatDistanceToNow(new Date(item.timestamp), { addSuffix: true })}
                        </Typography>
                        <Typography variant="caption">
                          • {item.resultCount} results
                        </Typography>
                        {stats.count > 1 && (
                          <Chip
                            label={`Used ${stats.count}x`}
                            size="small"
                            color="primary"
                            variant="outlined"
                          />
                        )}
                      </Stack>
                    }
                  />
                  <ListItemSecondaryAction>
                    <Tooltip title="Copy query">
                      <IconButton
                        size="small"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleCopy(item.query);
                        }}
                      >
                        <ContentCopy />
                      </IconButton>
                    </Tooltip>
                    {onDelete && (
                      <Tooltip title="Delete">
                        <IconButton
                          size="small"
                          onClick={(e) => {
                            e.stopPropagation();
                            onDelete(item.id);
                          }}
                        >
                          <Delete />
                        </IconButton>
                      </Tooltip>
                    )}
                  </ListItemSecondaryAction>
                </ListItem>
              );
            })}
          </List>

          {categorizedHistory().length === 0 && (
            <Box textAlign="center" py={3}>
              <Typography variant="body2" color="textSecondary">
                {searchTerm ? 'No matching searches found' : 'No search history yet'}
              </Typography>
            </Box>
          )}

          {selectedCategory === 'popular' && categorizedHistory().length > 0 && (
            <Alert severity="info">
              <Typography variant="caption">
                Showing your most frequently used searches
              </Typography>
            </Alert>
          )}
        </Stack>
      </DialogContent>
      
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
};

export default SearchHistory;