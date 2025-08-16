import React from 'react';
import { Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';

const Monitoring: React.FC = () => {
  const { t } = useTranslation();
  
  return (
    <Typography variant="h4">
      {t('navigation.monitoring')}
    </Typography>
  );
};

export default Monitoring;
