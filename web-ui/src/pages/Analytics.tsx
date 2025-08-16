import React from 'react';
import { Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';

const Analytics: React.FC = () => {
  const { t } = useTranslation();
  
  return (
    <Typography variant="h4">
      {t('navigation.analytics')}
    </Typography>
  );
};

export default Analytics;
