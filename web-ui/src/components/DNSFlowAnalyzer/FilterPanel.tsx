import React, { useState } from 'react';
import {
  Box,
  Drawer,
  Typography,
  IconButton,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  Slider,
  FormGroup,
  FormControlLabel,
  Checkbox,
  TextField,
  Divider,
  SelectChangeEvent,
  OutlinedInput,
} from '@mui/material';
import { FilterList, Close, RestartAlt } from '@mui/icons-material';
import { FilterOptions, DNSQueryType, DNSResponseCode } from './types';

interface FilterPanelProps {
  filters: FilterOptions;
  onChange: (filters: FilterOptions) => void;
}

const QUERY_TYPES: DNSQueryType[] = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV', 'DNSKEY', 'CAA'];
const RESPONSE_CODES: DNSResponseCode[] = ['NOERROR', 'NXDOMAIN', 'SERVFAIL', 'REFUSED', 'FORMERR', 'NOTIMP', 'TIMEOUT'];

const FilterPanel: React.FC<FilterPanelProps> = ({ filters, onChange }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [localFilters, setLocalFilters] = useState<FilterOptions>(filters);

  const handleDrawerToggle = () => {
    setIsOpen(!isOpen);
    if (!isOpen) {
      setLocalFilters(filters);
    }
  };

  const handleApplyFilters = () => {
    onChange(localFilters);
    setIsOpen(false);
  };

  const handleResetFilters = () => {
    const resetFilters: FilterOptions = {
      queryTypes: [],
      sources: [],
      responseCodes: [],
      minLatency: 0,
      maxLatency: 1000,
      showAnomalies: true,
    };
    setLocalFilters(resetFilters);
    onChange(resetFilters);
  };

  const handleQueryTypeChange = (event: SelectChangeEvent<DNSQueryType[]>) => {
    setLocalFilters({
      ...localFilters,
      queryTypes: event.target.value as DNSQueryType[],
    });
  };

  const handleResponseCodeChange = (event: SelectChangeEvent<DNSResponseCode[]>) => {
    setLocalFilters({
      ...localFilters,
      responseCodes: event.target.value as DNSResponseCode[],
    });
  };

  const handleLatencyChange = (event: Event, newValue: number | number[]) => {
    const [min, max] = newValue as number[];
    setLocalFilters({
      ...localFilters,
      minLatency: min,
      maxLatency: max,
    });
  };

  const activeFilterCount = 
    filters.queryTypes.length + 
    filters.sources.length + 
    filters.responseCodes.length +
    (filters.minLatency > 0 ? 1 : 0) +
    (filters.maxLatency < 1000 ? 1 : 0);

  return (
    <>
      <IconButton
        onClick={handleDrawerToggle}
        color="primary"
        sx={{ position: 'relative' }}
      >
        <FilterList />
        {activeFilterCount > 0 && (
          <Box
            sx={{
              position: 'absolute',
              top: 8,
              right: 8,
              backgroundColor: 'error.main',
              borderRadius: '50%',
              width: 16,
              height: 16,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Typography variant="caption" sx={{ color: 'white', fontSize: 10 }}>
              {activeFilterCount}
            </Typography>
          </Box>
        )}
      </IconButton>

      <Drawer
        anchor="right"
        open={isOpen}
        onClose={handleDrawerToggle}
        PaperProps={{ sx: { width: 350 } }}
      >
        <Box sx={{ p: 2 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h6">Filters</Typography>
            <IconButton onClick={handleDrawerToggle}>
              <Close />
            </IconButton>
          </Box>

          <Divider sx={{ mb: 2 }} />

          {/* Query Types */}
          <FormControl fullWidth sx={{ mb: 3 }}>
            <InputLabel>Query Types</InputLabel>
            <Select
              multiple
              value={localFilters.queryTypes}
              onChange={handleQueryTypeChange}
              input={<OutlinedInput label="Query Types" />}
              renderValue={(selected) => (
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                  {selected.map((value) => (
                    <Chip key={value} label={value} size="small" />
                  ))}
                </Box>
              )}
            >
              {QUERY_TYPES.map((type) => (
                <MenuItem key={type} value={type}>
                  <Checkbox checked={localFilters.queryTypes.indexOf(type) > -1} />
                  {type}
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          {/* Response Codes */}
          <FormControl fullWidth sx={{ mb: 3 }}>
            <InputLabel>Response Codes</InputLabel>
            <Select
              multiple
              value={localFilters.responseCodes}
              onChange={handleResponseCodeChange}
              input={<OutlinedInput label="Response Codes" />}
              renderValue={(selected) => (
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                  {selected.map((value) => (
                    <Chip 
                      key={value} 
                      label={value} 
                      size="small"
                      color={value === 'NOERROR' ? 'success' : 'error'}
                    />
                  ))}
                </Box>
              )}
            >
              {RESPONSE_CODES.map((code) => (
                <MenuItem key={code} value={code}>
                  <Checkbox checked={localFilters.responseCodes.indexOf(code) > -1} />
                  <Chip 
                    label={code} 
                    size="small" 
                    color={code === 'NOERROR' ? 'success' : 'error'}
                    variant="outlined"
                  />
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          {/* Latency Range */}
          <Box sx={{ mb: 3 }}>
            <Typography gutterBottom>
              Latency Range: {localFilters.minLatency}ms - {localFilters.maxLatency}ms
            </Typography>
            <Slider
              value={[localFilters.minLatency, localFilters.maxLatency]}
              onChange={handleLatencyChange}
              valueLabelDisplay="auto"
              min={0}
              max={1000}
              step={10}
              marks={[
                { value: 0, label: '0ms' },
                { value: 250, label: '250ms' },
                { value: 500, label: '500ms' },
                { value: 750, label: '750ms' },
                { value: 1000, label: '1s' },
              ]}
            />
          </Box>

          {/* Sources */}
          <FormControl fullWidth sx={{ mb: 3 }}>
            <TextField
              label="Source IPs (comma-separated)"
              variant="outlined"
              value={localFilters.sources?.join(', ') || ''}
              onChange={(e) => {
                const sources = e.target.value
                  .split(',')
                  .map(s => s.trim())
                  .filter(s => s.length > 0);
                setLocalFilters({
                  ...localFilters,
                  sources,
                });
              }}
              helperText="e.g., 192.168.1.1, 10.0.0.1"
            />
          </FormControl>

          {/* Domains */}
          <FormControl fullWidth sx={{ mb: 3 }}>
            <TextField
              label="Domain Filter (comma-separated)"
              variant="outlined"
              value={localFilters.domains?.join(', ') || ''}
              onChange={(e) => {
                const domains = e.target.value
                  .split(',')
                  .map(s => s.trim())
                  .filter(s => s.length > 0);
                setLocalFilters({
                  ...localFilters,
                  domains,
                });
              }}
              helperText="e.g., example.com, *.google.com"
            />
          </FormControl>

          {/* Show Anomalies */}
          <FormGroup sx={{ mb: 3 }}>
            <FormControlLabel
              control={
                <Checkbox
                  checked={localFilters.showAnomalies}
                  onChange={(e) => setLocalFilters({
                    ...localFilters,
                    showAnomalies: e.target.checked,
                  })}
                />
              }
              label="Show Anomalies"
            />
          </FormGroup>

          <Divider sx={{ mb: 2 }} />

          {/* Action Buttons */}
          <Box sx={{ display: 'flex', gap: 2 }}>
            <Button
              fullWidth
              variant="outlined"
              startIcon={<RestartAlt />}
              onClick={handleResetFilters}
            >
              Reset
            </Button>
            <Button
              fullWidth
              variant="contained"
              onClick={handleApplyFilters}
            >
              Apply Filters
            </Button>
          </Box>

          {/* Active Filters Summary */}
          {activeFilterCount > 0 && (
            <Box sx={{ mt: 3 }}>
              <Typography variant="subtitle2" gutterBottom>
                Active Filters ({activeFilterCount})
              </Typography>
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                {filters.queryTypes.map(type => (
                  <Chip key={type} label={`Type: ${type}`} size="small" onDelete={() => {
                    const newTypes = filters.queryTypes.filter(t => t !== type);
                    onChange({ ...filters, queryTypes: newTypes });
                  }} />
                ))}
                {filters.responseCodes.map(code => (
                  <Chip key={code} label={`Code: ${code}`} size="small" onDelete={() => {
                    const newCodes = filters.responseCodes.filter(c => c !== code);
                    onChange({ ...filters, responseCodes: newCodes });
                  }} />
                ))}
                {filters.minLatency > 0 && (
                  <Chip label={`Min: ${filters.minLatency}ms`} size="small" onDelete={() => {
                    onChange({ ...filters, minLatency: 0 });
                  }} />
                )}
                {filters.maxLatency < 1000 && (
                  <Chip label={`Max: ${filters.maxLatency}ms`} size="small" onDelete={() => {
                    onChange({ ...filters, maxLatency: 1000 });
                  }} />
                )}
              </Box>
            </Box>
          )}
        </Box>
      </Drawer>
    </>
  );
};

export default FilterPanel;