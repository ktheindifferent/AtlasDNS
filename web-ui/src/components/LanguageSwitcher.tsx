import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  IconButton,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Tooltip,
  Typography,
  Divider,
  Box,
} from '@mui/material';
import { Language as LanguageIcon } from '@mui/icons-material';
import { SUPPORTED_LANGUAGES, type SupportedLanguage } from '../i18n/config';

const LanguageSwitcher: React.FC = () => {
  const { i18n, t } = useTranslation();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);

  const handleClick = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleLanguageChange = (language: SupportedLanguage) => {
    i18n.changeLanguage(language);
    
    // Update document direction for RTL languages
    const dir = SUPPORTED_LANGUAGES[language].dir;
    document.documentElement.dir = dir;
    document.documentElement.lang = language;
    
    // Store preference
    localStorage.setItem('i18nextLng', language);
    
    handleClose();
  };

  const currentLanguage = i18n.language.split('-')[0] as SupportedLanguage;
  const currentLangConfig = SUPPORTED_LANGUAGES[currentLanguage] || SUPPORTED_LANGUAGES.en;

  return (
    <>
      <Tooltip title={t('language.select')}>
        <IconButton
          onClick={handleClick}
          color="inherit"
          aria-label="change language"
          aria-controls="language-menu"
          aria-haspopup="true"
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <LanguageIcon />
            <Typography variant="body2" sx={{ display: { xs: 'none', sm: 'block' } }}>
              {currentLangConfig.flag}
            </Typography>
          </Box>
        </IconButton>
      </Tooltip>
      
      <Menu
        id="language-menu"
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'right',
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
        PaperProps={{
          sx: {
            minWidth: 200,
            mt: 1,
          },
        }}
      >
        <MenuItem disabled>
          <Typography variant="caption" color="text.secondary">
            {t('language.current')}
          </Typography>
        </MenuItem>
        <Divider />
        
        {Object.entries(SUPPORTED_LANGUAGES).map(([code, config]) => (
          <MenuItem
            key={code}
            onClick={() => handleLanguageChange(code as SupportedLanguage)}
            selected={currentLanguage === code}
            sx={{
              direction: config.dir,
            }}
          >
            <ListItemIcon>
              <Typography>{config.flag}</Typography>
            </ListItemIcon>
            <ListItemText>
              {config.name}
            </ListItemText>
          </MenuItem>
        ))}
      </Menu>
    </>
  );
};

export default LanguageSwitcher;