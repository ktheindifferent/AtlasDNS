import React, { Suspense, lazy } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
import { Provider } from 'react-redux';
import { ThemeProvider, CssBaseline } from '@mui/material';
import { SnackbarProvider } from 'notistack';
import { LocalizationProvider } from '@mui/x-date-pickers';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';

import { store } from './store';
import { theme } from './theme';
import { AuthProvider } from './contexts/AuthContext';
import { WebSocketProvider } from './contexts/WebSocketContext';
import PrivateRoute from './components/PrivateRoute';
import Layout from './components/Layout';
import LoadingScreen from './components/LoadingScreen';

// Lazy load pages for code splitting
const Dashboard = lazy(() => import('./pages/Dashboard'));
const Zones = lazy(() => import('./pages/Zones'));
const Records = lazy(() => import('./pages/Records'));
const HealthChecks = lazy(() => import('./pages/HealthChecks'));
const TrafficPolicies = lazy(() => import('./pages/TrafficPolicies'));
const Analytics = lazy(() => import('./pages/Analytics'));
const Settings = lazy(() => import('./pages/Settings'));
const Login = lazy(() => import('./pages/Login'));
const Users = lazy(() => import('./pages/Users'));
const Logs = lazy(() => import('./pages/Logs'));
const GeoDNS = lazy(() => import('./pages/GeoDNS'));
const DNSSec = lazy(() => import('./pages/DNSSec'));
const Monitoring = lazy(() => import('./pages/Monitoring'));

// Create a client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 3,
      staleTime: 5 * 60 * 1000, // 5 minutes
      cacheTime: 10 * 60 * 1000, // 10 minutes
    },
  },
});

function App() {
  return (
    <Provider store={store}>
      <QueryClientProvider client={queryClient}>
        <ThemeProvider theme={theme}>
          <LocalizationProvider dateAdapter={AdapterDateFns}>
            <SnackbarProvider 
              maxSnack={3}
              anchorOrigin={{
                vertical: 'bottom',
                horizontal: 'right',
              }}
            >
              <CssBaseline />
              <Router>
                <AuthProvider>
                  <WebSocketProvider>
                    <Suspense fallback={<LoadingScreen />}>
                      <Routes>
                        <Route path="/login" element={<Login />} />
                        <Route
                          path="/"
                          element={
                            <PrivateRoute>
                              <Layout />
                            </PrivateRoute>
                          }
                        >
                          <Route index element={<Navigate to="/dashboard" replace />} />
                          <Route path="dashboard" element={<Dashboard />} />
                          <Route path="zones" element={<Zones />} />
                          <Route path="zones/:zoneId/records" element={<Records />} />
                          <Route path="health-checks" element={<HealthChecks />} />
                          <Route path="traffic-policies" element={<TrafficPolicies />} />
                          <Route path="analytics" element={<Analytics />} />
                          <Route path="geodns" element={<GeoDNS />} />
                          <Route path="dnssec" element={<DNSSec />} />
                          <Route path="monitoring" element={<Monitoring />} />
                          <Route path="logs" element={<Logs />} />
                          <Route path="users" element={<Users />} />
                          <Route path="settings" element={<Settings />} />
                        </Route>
                      </Routes>
                    </Suspense>
                  </WebSocketProvider>
                </AuthProvider>
              </Router>
              <ReactQueryDevtools initialIsOpen={false} />
            </SnackbarProvider>
          </LocalizationProvider>
        </ThemeProvider>
      </QueryClientProvider>
    </Provider>
  );
}

export default App;