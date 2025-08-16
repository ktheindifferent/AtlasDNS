import React from 'react';
import {
  Box,
  Chip,
  Stack,
  Typography,
  IconButton,
  Tooltip,
  Paper,
} from '@mui/material';
import { Clear, Add } from '@mui/icons-material';

interface QuickFilterChipsProps {
  selected: string[];
  onChange: (selected: string[]) => void;
  options: string[];
}

const QuickFilterChips: React.FC<QuickFilterChipsProps> = ({
  selected,
  onChange,
  options,
}) => {
  const handleToggle = (option: string) => {
    if (selected.includes(option)) {
      onChange(selected.filter(s => s !== option));
    } else {
      onChange([...selected, option]);
    }
  };

  const handleClearAll = () => {
    onChange([]);
  };

  const unselectedOptions = options.filter(opt => !selected.includes(opt));

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
        <Typography variant="subtitle2">Quick Filters</Typography>
        {selected.length > 0 && (
          <Tooltip title="Clear all quick filters">
            <IconButton size="small" onClick={handleClearAll}>
              <Clear />
            </IconButton>
          </Tooltip>
        )}
      </Box>

      <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
        {selected.map((filter) => (
          <Chip
            key={filter}
            label={filter}
            onDelete={() => handleToggle(filter)}
            color="primary"
            size="small"
            sx={{ mb: 1 }}
          />
        ))}
        
        {unselectedOptions.map((option) => (
          <Chip
            key={option}
            label={option}
            onClick={() => handleToggle(option)}
            variant="outlined"
            size="small"
            sx={{ 
              mb: 1,
              '&:hover': {
                backgroundColor: 'primary.main',
                color: 'white',
                borderColor: 'primary.main',
              }
            }}
          />
        ))}
      </Stack>

      {selected.length > 0 && (
        <Paper elevation={0} sx={{ p: 1, mt: 1, bgcolor: 'grey.50' }}>
          <Typography variant="caption" color="textSecondary">
            {selected.length} filter{selected.length !== 1 ? 's' : ''} active
          </Typography>
        </Paper>
      )}
    </Box>
  );
};

export default QuickFilterChips;