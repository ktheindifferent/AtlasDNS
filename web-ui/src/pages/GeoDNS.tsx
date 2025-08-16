import React from 'react';
import { Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';

const GeoDNS: React.FC = () => {
  const { t } = useTranslation();
  
  return (
    <Typography variant="h4">
      {t('navigation.geoDNS')}
    </Typography>
  );
};

export default GeoDNS;
