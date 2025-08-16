import React from 'react';
import {
  Box,
  Grid,
  Typography,
  Card,
  CardContent,
  Stack,
  LinearProgress,
  Chip,
} from '@mui/material';
import {
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  AccessTime as AccessTimeIcon,
  Category as CategoryIcon,
  Priority as PriorityIcon,
} from '@mui/icons-material';
import { NotificationStats as NotificationStatsType } from '../../types/notification.types';

interface NotificationStatsProps {
  stats: NotificationStatsType;
  compact?: boolean;
}

const NotificationStats: React.FC<NotificationStatsProps> = ({ stats, compact = false }) => {
  const getPercentage = (value: number, total: number): number => {
    return total > 0 ? Math.round((value / total) * 100) : 0;
  };

  if (compact) {
    return (
      <Stack direction="row" spacing={2} alignItems="center">
        <Chip
          icon={<AccessTimeIcon />}
          label={`Today: ${stats.todayCount}`}
          size="small"
          variant="outlined"
        />
        <Chip
          label={`Week: ${stats.weekCount}`}
          size="small"
          variant="outlined"
        />
        <Chip
          label={`Unread: ${stats.unread}`}
          size="small"
          color={stats.unread > 0 ? 'primary' : 'default'}
        />
        <Typography variant="caption" color="text.secondary">
          Total: {stats.total}
        </Typography>
      </Stack>
    );
  }

  return (
    <Box>
      <Grid container spacing={2}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Overview
              </Typography>
              
              <Stack spacing={2}>
                <Box>
                  <Stack direction="row" justifyContent="space-between" alignItems="center">
                    <Typography variant="body2">Total Notifications</Typography>
                    <Typography variant="h5">{stats.total}</Typography>
                  </Stack>
                </Box>

                <Box>
                  <Stack direction="row" justifyContent="space-between" alignItems="center">
                    <Typography variant="body2">Unread</Typography>
                    <Typography variant="h6" color="primary">
                      {stats.unread}
                    </Typography>
                  </Stack>
                  <LinearProgress
                    variant="determinate"
                    value={getPercentage(stats.unread, stats.total)}
                    sx={{ mt: 1 }}
                  />
                </Box>

                <Box>
                  <Stack direction="row" justifyContent="space-between" alignItems="center">
                    <Typography variant="body2">Today</Typography>
                    <Stack direction="row" alignItems="center" spacing={0.5}>
                      <Typography variant="h6">{stats.todayCount}</Typography>
                      {stats.todayCount > stats.weekCount / 7 ? (
                        <TrendingUpIcon color="success" fontSize="small" />
                      ) : (
                        <TrendingDownIcon color="error" fontSize="small" />
                      )}
                    </Stack>
                  </Stack>
                </Box>

                <Box>
                  <Stack direction="row" justifyContent="space-between" alignItems="center">
                    <Typography variant="body2">This Week</Typography>
                    <Typography variant="h6">{stats.weekCount}</Typography>
                  </Stack>
                </Box>
              </Stack>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                By Category
              </Typography>
              
              <Stack spacing={1}>
                {Object.entries(stats.byCategory).map(([category, count]) => (
                  <Box key={category}>
                    <Stack direction="row" justifyContent="space-between" alignItems="center">
                      <Typography variant="body2">{category}</Typography>
                      <Typography variant="body2">{count}</Typography>
                    </Stack>
                    <LinearProgress
                      variant="determinate"
                      value={getPercentage(count, stats.total)}
                      sx={{ height: 4 }}
                    />
                  </Box>
                ))}
              </Stack>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                By Priority
              </Typography>
              
              <Stack spacing={1}>
                {Object.entries(stats.byPriority).map(([priority, count]) => {
                  const colors: Record<string, string> = {
                    urgent: 'error',
                    high: 'warning',
                    medium: 'info',
                    low: 'success',
                  };
                  
                  return (
                    <Box key={priority}>
                      <Stack direction="row" justifyContent="space-between" alignItems="center">
                        <Stack direction="row" alignItems="center" spacing={1}>
                          <Box
                            sx={{
                              width: 12,
                              height: 12,
                              borderRadius: '50%',
                              bgcolor: `${colors[priority] || 'grey'}.main`,
                            }}
                          />
                          <Typography variant="body2">{priority}</Typography>
                        </Stack>
                        <Typography variant="body2">{count}</Typography>
                      </Stack>
                      <LinearProgress
                        variant="determinate"
                        value={getPercentage(count, stats.total)}
                        color={colors[priority] as any}
                        sx={{ height: 4 }}
                      />
                    </Box>
                  );
                })}
              </Stack>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                By Channel
              </Typography>
              
              <Stack spacing={1}>
                {Object.entries(stats.byChannel).map(([channel, count]) => (
                  <Box key={channel}>
                    <Stack direction="row" justifyContent="space-between" alignItems="center">
                      <Typography variant="body2">
                        {channel.replace('_', ' ').toUpperCase()}
                      </Typography>
                      <Typography variant="body2">{count}</Typography>
                    </Stack>
                    <LinearProgress
                      variant="determinate"
                      value={getPercentage(count, stats.total)}
                      sx={{ height: 4 }}
                    />
                  </Box>
                ))}
              </Stack>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default NotificationStats;