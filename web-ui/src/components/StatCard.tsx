import React from 'react';
import { Card, CardContent, Typography, Box, useTheme } from '@mui/material';
import { TrendingUp, TrendingDown } from '@mui/icons-material';

interface StatCardProps {
  title: string;
  value: string | number;
  change?: number;
  icon: React.ReactNode;
  color: string;
  onClick?: () => void;
}

const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  change,
  icon,
  color,
  onClick,
}) => {
  const theme = useTheme();

  const getChangeIcon = () => {
    if (change === undefined || change === 0) return null;
    if (change > 0) return <TrendingUp fontSize="small" />;
    return <TrendingDown fontSize="small" />;
  };

  const getChangeColor = () => {
    if (change === undefined || change === 0) return 'text.secondary';
    return change > 0 ? 'success.main' : 'error.main';
  };

  return (
    <Card
      sx={{
        cursor: onClick ? 'pointer' : 'default',
        transition: 'transform 0.2s, box-shadow 0.2s',
        '&:hover': onClick ? {
          transform: 'translateY(-4px)',
          boxShadow: theme.shadows[4],
        } : {},
      }}
      onClick={onClick}
    >
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
          <Box
            sx={{
              width: 48,
              height: 48,
              borderRadius: 2,
              bgcolor: `${color}20`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: color,
            }}
          >
            {icon}
          </Box>
          {change !== undefined && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Typography variant="body2" color={getChangeColor()}>
                {change > 0 ? '+' : ''}{change}%
              </Typography>
              <Box sx={{ color: getChangeColor() }}>
                {getChangeIcon()}
              </Box>
            </Box>
          )}
        </Box>
        <Typography variant="h4" fontWeight="bold" gutterBottom>
          {value}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {title}
        </Typography>
      </CardContent>
    </Card>
  );
};

export default StatCard;