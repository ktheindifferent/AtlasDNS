import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  Box,
  Button,
  Card,
  CardContent,
  TextField,
  Typography,
  FormControlLabel,
  Checkbox,
  Link,
  Alert,
} from '@mui/material';
import { useAuth } from '../contexts/AuthContext';
import LanguageSwitcher from '../components/LanguageSwitcher';

const Login: React.FC = () => {
  const { t } = useTranslation('auth');
  const navigate = useNavigate();
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await login(username, password);
      navigate('/dashboard');
    } catch (err) {
      setError(t('errors.invalidCredentials'));
    }
  };

  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '100vh',
        bgcolor: 'background.default',
      }}
    >
      <Box sx={{ position: 'absolute', top: 16, right: 16 }}>
        <LanguageSwitcher />
      </Box>
      
      <Card sx={{ maxWidth: 400, width: '100%', m: 2 }}>
        <CardContent sx={{ p: 4 }}>
          <Typography variant="h4" align="center" gutterBottom>
            {t('login.title')}
          </Typography>
          <Typography variant="body2" align="center" color="text.secondary" gutterBottom>
            {t('login.subtitle')}
          </Typography>
          
          {error && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {error}
            </Alert>
          )}
          
          <Box component="form" onSubmit={handleSubmit} sx={{ mt: 3 }}>
            <TextField
              fullWidth
              label={t('login.username')}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              margin="normal"
              required
              autoFocus
            />
            <TextField
              fullWidth
              label={t('login.password')}
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              margin="normal"
              required
            />
            <FormControlLabel
              control={
                <Checkbox
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  color="primary"
                />
              }
              label={t('login.rememberMe')}
              sx={{ mt: 1 }}
            />
            <Button
              type="submit"
              fullWidth
              variant="contained"
              sx={{ mt: 3, mb: 2 }}
            >
              {t('login.signIn')}
            </Button>
            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
              <Link href="#" variant="body2">
                {t('login.forgotPassword')}
              </Link>
              <Link href="#" variant="body2">
                {t('login.noAccount')}
              </Link>
            </Box>
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
};

export default Login;