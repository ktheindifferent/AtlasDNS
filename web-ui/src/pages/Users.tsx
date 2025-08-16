import React from 'react';
import { Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';

const Users: React.FC = () => {
  const { t } = useTranslation();
  
  return (
    <Typography variant="h4">
      {t('navigation.users')}
    </Typography>
  );
};

export default Users;
