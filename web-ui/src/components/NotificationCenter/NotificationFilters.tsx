import React from 'react';
import {
  Box,
  Stack,
  Chip,
  Typography,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Checkbox,
  ListItemText,
  Button,
  SxProps,
} from '@mui/material';
import { Clear as ClearIcon } from '@mui/icons-material';
import {
  NotificationFilter,
  NotificationCategory,
  NotificationPriority,
  NotificationStatus,
  NotificationChannel,
} from '../../types/notification.types';

interface NotificationFiltersProps {
  filter: NotificationFilter;
  onFilterChange: (filter: NotificationFilter) => void;
  sx?: SxProps;
}

const NotificationFilters: React.FC<NotificationFiltersProps> = ({
  filter,
  onFilterChange,
  sx,
}) => {
  const handleCategoryChange = (categories: NotificationCategory[]) => {
    onFilterChange({
      ...filter,
      categories: categories.length > 0 ? categories : undefined,
    });
  };

  const handlePriorityChange = (priorities: NotificationPriority[]) => {
    onFilterChange({
      ...filter,
      priorities: priorities.length > 0 ? priorities : undefined,
    });
  };

  const handleStatusChange = (statuses: NotificationStatus[]) => {
    onFilterChange({
      ...filter,
      statuses: statuses.length > 0 ? statuses : undefined,
    });
  };

  const handleChannelChange = (channels: NotificationChannel[]) => {
    onFilterChange({
      ...filter,
      channels: channels.length > 0 ? channels : undefined,
    });
  };

  const handleClearFilters = () => {
    onFilterChange({});
  };

  const hasActiveFilters = 
    filter.categories?.length ||
    filter.priorities?.length ||
    filter.statuses?.length ||
    filter.channels?.length;

  return (
    <Box sx={sx}>
      <Stack spacing={2}>
        <Stack direction="row" alignItems="center" justifyContent="space-between">
          <Typography variant="subtitle2">Filters</Typography>
          {hasActiveFilters && (
            <Button
              size="small"
              startIcon={<ClearIcon />}
              onClick={handleClearFilters}
            >
              Clear all
            </Button>
          )}
        </Stack>

        <Stack direction="row" spacing={1} flexWrap="wrap">
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel>Category</InputLabel>
            <Select
              multiple
              value={filter.categories || []}
              onChange={(e) => handleCategoryChange(e.target.value as NotificationCategory[])}
              renderValue={(selected) => `${selected.length} selected`}
            >
              {Object.values(NotificationCategory).map((category) => (
                <MenuItem key={category} value={category}>
                  <Checkbox checked={filter.categories?.includes(category) || false} />
                  <ListItemText primary={category} />
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel>Priority</InputLabel>
            <Select
              multiple
              value={filter.priorities || []}
              onChange={(e) => handlePriorityChange(e.target.value as NotificationPriority[])}
              renderValue={(selected) => `${selected.length} selected`}
            >
              {Object.values(NotificationPriority).map((priority) => (
                <MenuItem key={priority} value={priority}>
                  <Checkbox checked={filter.priorities?.includes(priority) || false} />
                  <ListItemText primary={priority} />
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel>Status</InputLabel>
            <Select
              multiple
              value={filter.statuses || []}
              onChange={(e) => handleStatusChange(e.target.value as NotificationStatus[])}
              renderValue={(selected) => `${selected.length} selected`}
            >
              {Object.values(NotificationStatus).map((status) => (
                <MenuItem key={status} value={status}>
                  <Checkbox checked={filter.statuses?.includes(status) || false} />
                  <ListItemText primary={status} />
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel>Channel</InputLabel>
            <Select
              multiple
              value={filter.channels || []}
              onChange={(e) => handleChannelChange(e.target.value as NotificationChannel[])}
              renderValue={(selected) => `${selected.length} selected`}
            >
              {Object.values(NotificationChannel).map((channel) => (
                <MenuItem key={channel} value={channel}>
                  <Checkbox checked={filter.channels?.includes(channel) || false} />
                  <ListItemText primary={channel} />
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Stack>

        {hasActiveFilters && (
          <Stack direction="row" spacing={1} flexWrap="wrap">
            {filter.categories?.map((category) => (
              <Chip
                key={category}
                label={category}
                size="small"
                onDelete={() => {
                  const newCategories = filter.categories!.filter(c => c !== category);
                  handleCategoryChange(newCategories);
                }}
              />
            ))}
            
            {filter.priorities?.map((priority) => (
              <Chip
                key={priority}
                label={priority}
                size="small"
                color="primary"
                onDelete={() => {
                  const newPriorities = filter.priorities!.filter(p => p !== priority);
                  handlePriorityChange(newPriorities);
                }}
              />
            ))}
            
            {filter.statuses?.map((status) => (
              <Chip
                key={status}
                label={status}
                size="small"
                color="secondary"
                onDelete={() => {
                  const newStatuses = filter.statuses!.filter(s => s !== status);
                  handleStatusChange(newStatuses);
                }}
              />
            ))}
            
            {filter.channels?.map((channel) => (
              <Chip
                key={channel}
                label={channel}
                size="small"
                variant="outlined"
                onDelete={() => {
                  const newChannels = filter.channels!.filter(c => c !== channel);
                  handleChannelChange(newChannels);
                }}
              />
            ))}
          </Stack>
        )}
      </Stack>
    </Box>
  );
};

export default NotificationFilters;