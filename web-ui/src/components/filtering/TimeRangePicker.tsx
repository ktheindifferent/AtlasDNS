import React, { useState } from 'react';
import {
  Box,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
  Stack,
  Paper,
  TextField,
  Button,
} from '@mui/material';
import { DateTimePicker } from '@mui/x-date-pickers/DateTimePicker';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDayjs } from '@mui/x-date-pickers/AdapterDayjs';
import dayjs, { Dayjs } from 'dayjs';
import { TimeRange } from '../../types/filtering';
import {
  AccessTime,
  Today,
  DateRange,
  Schedule,
  CalendarMonth,
} from '@mui/icons-material';

interface TimeRangePickerProps {
  value: TimeRange;
  onChange: (range: TimeRange) => void;
}

const TimeRangePicker: React.FC<TimeRangePickerProps> = ({ value, onChange }) => {
  const [customStart, setCustomStart] = useState<Dayjs | null>(
    value.start ? dayjs(value.start) : null
  );
  const [customEnd, setCustomEnd] = useState<Dayjs | null>(
    value.end ? dayjs(value.end) : null
  );

  const presets = [
    { value: 'last-hour', label: 'Last Hour', icon: <AccessTime /> },
    { value: 'last-24h', label: 'Last 24 Hours', icon: <Today /> },
    { value: 'last-7d', label: 'Last 7 Days', icon: <DateRange /> },
    { value: 'last-30d', label: 'Last 30 Days', icon: <Schedule /> },
    { value: 'last-90d', label: 'Last 90 Days', icon: <CalendarMonth /> },
    { value: 'custom', label: 'Custom Range', icon: <DateRange /> },
  ];

  const handlePresetChange = (preset: string) => {
    const now = new Date();
    let start: Date | null = null;
    let end: Date | null = new Date();

    switch (preset) {
      case 'last-hour':
        start = new Date(now.getTime() - 60 * 60 * 1000);
        break;
      case 'last-24h':
        start = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        break;
      case 'last-7d':
        start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      case 'last-30d':
        start = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        break;
      case 'last-90d':
        start = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
        break;
      case 'custom':
        start = customStart?.toDate() || null;
        end = customEnd?.toDate() || null;
        break;
    }

    onChange({
      start,
      end,
      preset: preset as any,
    });
  };

  const handleCustomRangeApply = () => {
    onChange({
      start: customStart?.toDate() || null,
      end: customEnd?.toDate() || null,
      preset: 'custom',
    });
  };

  const getQuickRanges = () => {
    const now = dayjs();
    return [
      { label: 'Today', start: now.startOf('day'), end: now.endOf('day') },
      { label: 'Yesterday', start: now.subtract(1, 'day').startOf('day'), end: now.subtract(1, 'day').endOf('day') },
      { label: 'This Week', start: now.startOf('week'), end: now.endOf('week') },
      { label: 'Last Week', start: now.subtract(1, 'week').startOf('week'), end: now.subtract(1, 'week').endOf('week') },
      { label: 'This Month', start: now.startOf('month'), end: now.endOf('month') },
      { label: 'Last Month', start: now.subtract(1, 'month').startOf('month'), end: now.subtract(1, 'month').endOf('month') },
      { label: 'This Year', start: now.startOf('year'), end: now.endOf('year') },
      { label: 'Last Year', start: now.subtract(1, 'year').startOf('year'), end: now.subtract(1, 'year').endOf('year') },
    ];
  };

  return (
    <LocalizationProvider dateAdapter={AdapterDayjs}>
      <Box>
        <Typography variant="h6" gutterBottom>
          Time Range Selection
        </Typography>

        <Stack spacing={3}>
          <Box>
            <Typography variant="subtitle2" gutterBottom>
              Presets
            </Typography>
            <ToggleButtonGroup
              value={value.preset || 'custom'}
              exclusive
              onChange={(_, newValue) => {
                if (newValue) {
                  handlePresetChange(newValue);
                }
              }}
              sx={{ flexWrap: 'wrap' }}
            >
              {presets.map((preset) => (
                <ToggleButton key={preset.value} value={preset.value}>
                  <Stack direction="row" spacing={1} alignItems="center">
                    {preset.icon}
                    <Typography variant="body2">{preset.label}</Typography>
                  </Stack>
                </ToggleButton>
              ))}
            </ToggleButtonGroup>
          </Box>

          {value.preset === 'custom' && (
            <Paper elevation={1} sx={{ p: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                Custom Date Range
              </Typography>
              <Stack direction="row" spacing={2} alignItems="center">
                <DateTimePicker
                  label="Start Date & Time"
                  value={customStart}
                  onChange={setCustomStart}
                  slotProps={{
                    textField: {
                      size: 'small',
                      fullWidth: true,
                    },
                  }}
                />
                <Typography>to</Typography>
                <DateTimePicker
                  label="End Date & Time"
                  value={customEnd}
                  onChange={setCustomEnd}
                  slotProps={{
                    textField: {
                      size: 'small',
                      fullWidth: true,
                    },
                  }}
                />
                <Button
                  variant="contained"
                  onClick={handleCustomRangeApply}
                  disabled={!customStart || !customEnd}
                >
                  Apply
                </Button>
              </Stack>

              <Box mt={2}>
                <Typography variant="subtitle2" gutterBottom>
                  Quick Ranges
                </Typography>
                <Stack direction="row" spacing={1} flexWrap="wrap">
                  {getQuickRanges().map((range) => (
                    <Button
                      key={range.label}
                      size="small"
                      variant="outlined"
                      onClick={() => {
                        setCustomStart(range.start);
                        setCustomEnd(range.end);
                        onChange({
                          start: range.start.toDate(),
                          end: range.end.toDate(),
                          preset: 'custom',
                        });
                      }}
                    >
                      {range.label}
                    </Button>
                  ))}
                </Stack>
              </Box>
            </Paper>
          )}

          {value.start && value.end && (
            <Paper elevation={1} sx={{ p: 2, bgcolor: 'grey.50' }}>
              <Typography variant="subtitle2" gutterBottom>
                Selected Range
              </Typography>
              <Typography variant="body2">
                From: <strong>{dayjs(value.start).format('YYYY-MM-DD HH:mm:ss')}</strong>
              </Typography>
              <Typography variant="body2">
                To: <strong>{dayjs(value.end).format('YYYY-MM-DD HH:mm:ss')}</strong>
              </Typography>
              <Typography variant="caption" color="textSecondary">
                Duration: {dayjs(value.end).diff(value.start, 'day')} days
              </Typography>
            </Paper>
          )}
        </Stack>
      </Box>
    </LocalizationProvider>
  );
};

export default TimeRangePicker;