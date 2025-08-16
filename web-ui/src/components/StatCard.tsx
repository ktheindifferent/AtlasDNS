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

const StatCard: React.FC<StatCardProps> = ({ title, value, change, icon, color }) => {
  return (
    <Card>
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <Box>
            <Typography color="textSecondary" gutterBottom variant="body2">
              {title}
            </Typography>
            <Typography variant="h4" component="div">
              {value}
            </Typography>
            {change !== undefined && (
              <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                {change > 0 ? (
                  <TrendingUp color="success" sx={{ mr: 0.5 }} />
                ) : (
                  <TrendingDown color="error" sx={{ mr: 0.5 }} />
                )}
                <Typography
                  variant="body2"
                  color={change > 0 ? 'success.main' : 'error.main'}
                >
                  {Math.abs(change)}%
                </Typography>
              </Box>
            )}
          </Box>
          {icon && (
            <Box sx={{ color: color || 'primary.main' }}>
              {icon}
            </Box>
          )}
        </Box>
      </CardContent>
    </Card>
  );
};

export default StatCard;