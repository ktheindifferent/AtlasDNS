import React from 'react';
import { Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';

const DNSSec: React.FC = () => {
  const { t } = useTranslation();
  
  return (
    <Typography variant="h4">
      {t('navigation.dNSSec')}
    </Typography>
  );
};

export default DNSSec;
