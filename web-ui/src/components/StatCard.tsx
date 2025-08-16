import React from 'react';
import { Card, CardContent, Typography, Box } from '@mui/material';
import { TrendingUp, TrendingDown } from '@mui/icons-material';

interface StatCardProps {
  title: string;
  value: string | number;
  change?: number;
  icon?: React.ReactNode;
  color?: string;
}

const StatCard: React.FC<StatCardProps> = ({ title, value, change = 0, icon, color }) => {
  return (
    <Card>
      <CardContent>
        <Box display="flex" justifyContent="space-between" alignItems="center">
          <Box>
            <Typography color="textSecondary" gutterBottom variant="body2">
              {title}
            </Typography>
            <Typography variant="h5" component="h2">
              {value}
            </Typography>
            {change !== 0 && (
              <Box display="flex" alignItems="center" mt={1}>
                {change > 0 ? (
                  <TrendingUp fontSize="small" style={{ color: '#10b981' }} />
                ) : (
                  <TrendingDown fontSize="small" style={{ color: '#ef4444' }} />
                )}
                <Typography variant="body2" style={{ marginLeft: 4 }}>
                  {Math.abs(change)}%
                </Typography>
              </Box>
            )}
          </Box>
          {icon && (
            <Box style={{ color: color || '#3b82f6' }}>
              {icon}
            </Box>
          )}
        </Box>
      </CardContent>
    </Card>
  );
};

export default StatCard;