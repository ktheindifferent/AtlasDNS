import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import { store } from '../store';

// API base URL - can be configured via environment variable
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5380/api/v2';

// Create axios instance
const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
apiClient.interceptors.request.use(
  (config) => {
    const state = store.getState();
    const token = state.auth?.token;
    
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for error handling
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Handle unauthorized access
      store.dispatch({ type: 'auth/logout' });
      window.location.href = '/login';
    }
    
    return Promise.reject(error);
  }
);

// Generic API methods
export const api = {
  get: <T = any>(url: string, config?: AxiosRequestConfig): Promise<AxiosResponse<T>> => 
    apiClient.get<T>(url, config),
  
  post: <T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<AxiosResponse<T>> => 
    apiClient.post<T>(url, data, config),
  
  put: <T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<AxiosResponse<T>> => 
    apiClient.put<T>(url, data, config),
  
  patch: <T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<AxiosResponse<T>> => 
    apiClient.patch<T>(url, data, config),
  
  delete: <T = any>(url: string, config?: AxiosRequestConfig): Promise<AxiosResponse<T>> => 
    apiClient.delete<T>(url, config),
};

// Zone API
export const zoneApi = {
  list: (params?: any) => api.get('/zones', { params }),
  get: (zoneId: string) => api.get(`/zones/${zoneId}`),
  create: (data: any) => api.post('/zones', data),
  update: (zoneId: string, data: any) => api.put(`/zones/${zoneId}`, data),
  delete: (zoneId: string) => api.delete(`/zones/${zoneId}`),
  validate: (zoneId: string) => api.get(`/zones/${zoneId}/validate`),
  export: (zoneId: string) => api.get(`/zones/${zoneId}/export`),
  import: (data: any) => api.post('/zones/import', data),
  transfer: (zoneId: string, data: any) => api.post(`/zones/${zoneId}/transfer`, data),
};

// Record API
export const recordApi = {
  list: (zoneId: string, params?: any) => api.get(`/zones/${zoneId}/records`, { params }),
  get: (zoneId: string, recordId: string) => api.get(`/zones/${zoneId}/records/${recordId}`),
  create: (zoneId: string, data: any) => api.post(`/zones/${zoneId}/records`, data),
  update: (zoneId: string, recordId: string, data: any) => 
    api.put(`/zones/${zoneId}/records/${recordId}`, data),
  delete: (zoneId: string, recordId: string) => api.delete(`/zones/${zoneId}/records/${recordId}`),
  bulkCreate: (zoneId: string, data: any) => api.post(`/zones/${zoneId}/records/bulk`, data),
  bulkUpdate: (zoneId: string, data: any) => api.put(`/zones/${zoneId}/records/bulk`, data),
  bulkDelete: (zoneId: string, data: any) => api.delete(`/zones/${zoneId}/records/bulk`, { data }),
};

// Health Check API
export const healthCheckApi = {
  list: (params?: any) => api.get('/health-checks', { params }),
  get: (checkId: string) => api.get(`/health-checks/${checkId}`),
  create: (data: any) => api.post('/health-checks', data),
  update: (checkId: string, data: any) => api.put(`/health-checks/${checkId}`, data),
  delete: (checkId: string) => api.delete(`/health-checks/${checkId}`),
  test: (checkId: string) => api.post(`/health-checks/${checkId}/test`),
  history: (checkId: string, params?: any) => 
    api.get(`/health-checks/${checkId}/history`, { params }),
};

// Traffic Policy API
export const trafficPolicyApi = {
  list: (params?: any) => api.get('/traffic-policies', { params }),
  get: (policyId: string) => api.get(`/traffic-policies/${policyId}`),
  create: (data: any) => api.post('/traffic-policies', data),
  update: (policyId: string, data: any) => api.put(`/traffic-policies/${policyId}`, data),
  delete: (policyId: string) => api.delete(`/traffic-policies/${policyId}`),
  simulate: (policyId: string, data: any) => api.post(`/traffic-policies/${policyId}/simulate`, data),
  apply: (policyId: string) => api.post(`/traffic-policies/${policyId}/apply`),
};

// Analytics API
export const analyticsApi = {
  overview: (params?: any) => api.get('/analytics/overview', { params }),
  queries: (params?: any) => api.get('/analytics/queries', { params }),
  performance: (params?: any) => api.get('/analytics/performance', { params }),
  geography: (params?: any) => api.get('/analytics/geography', { params }),
  topDomains: (params?: any) => api.get('/analytics/top-domains', { params }),
  responseCodes: (params?: any) => api.get('/analytics/response-codes', { params }),
  threats: (params?: any) => api.get('/analytics/threats', { params }),
  export: (params?: any) => api.get('/analytics/export', { params }),
};

// GeoDNS API
export const geoDnsApi = {
  list: (params?: any) => api.get('/geodns', { params }),
  get: (geoId: string) => api.get(`/geodns/${geoId}`),
  create: (data: any) => api.post('/geodns', data),
  update: (geoId: string, data: any) => api.put(`/geodns/${geoId}`, data),
  delete: (geoId: string) => api.delete(`/geodns/${geoId}`),
  regions: () => api.get('/geodns/regions'),
  test: (data: any) => api.post('/geodns/test', data),
};

// DNSSEC API
export const dnssecApi = {
  status: (zoneId: string) => api.get(`/zones/${zoneId}/dnssec`),
  enable: (zoneId: string, data: any) => api.post(`/zones/${zoneId}/dnssec/enable`, data),
  disable: (zoneId: string) => api.post(`/zones/${zoneId}/dnssec/disable`),
  keys: (zoneId: string) => api.get(`/zones/${zoneId}/dnssec/keys`),
  rotateKeys: (zoneId: string) => api.post(`/zones/${zoneId}/dnssec/rotate-keys`),
  dsRecords: (zoneId: string) => api.get(`/zones/${zoneId}/dnssec/ds-records`),
};

// Monitoring API
export const monitoringApi = {
  status: () => api.get('/monitoring/status'),
  metrics: (params?: any) => api.get('/monitoring/metrics', { params }),
  alerts: (params?: any) => api.get('/monitoring/alerts', { params }),
  createAlert: (data: any) => api.post('/monitoring/alerts', data),
  updateAlert: (alertId: string, data: any) => api.put(`/monitoring/alerts/${alertId}`, data),
  deleteAlert: (alertId: string) => api.delete(`/monitoring/alerts/${alertId}`),
  acknowledgeAlert: (alertId: string) => api.post(`/monitoring/alerts/${alertId}/acknowledge`),
};

// User API
export const userApi = {
  list: (params?: any) => api.get('/users', { params }),
  get: (userId: string) => api.get(`/users/${userId}`),
  create: (data: any) => api.post('/users', data),
  update: (userId: string, data: any) => api.put(`/users/${userId}`, data),
  delete: (userId: string) => api.delete(`/users/${userId}`),
  changePassword: (userId: string, data: any) => api.post(`/users/${userId}/change-password`, data),
  resetPassword: (userId: string) => api.post(`/users/${userId}/reset-password`),
  profile: () => api.get('/users/profile'),
  updateProfile: (data: any) => api.put('/users/profile', data),
};

// Auth API
export const authApi = {
  login: (data: any) => api.post('/auth/login', data),
  logout: () => api.post('/auth/logout'),
  refresh: () => api.post('/auth/refresh'),
  verify: () => api.get('/auth/verify'),
  forgotPassword: (data: any) => api.post('/auth/forgot-password', data),
  resetPassword: (data: any) => api.post('/auth/reset-password', data),
};

// Settings API
export const settingsApi = {
  get: () => api.get('/settings'),
  update: (data: any) => api.put('/settings', data),
  getCategory: (category: string) => api.get(`/settings/${category}`),
  updateCategory: (category: string, data: any) => api.put(`/settings/${category}`, data),
};

// Logs API
export const logsApi = {
  list: (params?: any) => api.get('/logs', { params }),
  get: (logId: string) => api.get(`/logs/${logId}`),
  search: (params?: any) => api.get('/logs/search', { params }),
  export: (params?: any) => api.get('/logs/export', { params }),
};

// Webhook API
export const webhookApi = {
  list: (params?: any) => api.get('/webhooks', { params }),
  get: (webhookId: string) => api.get(`/webhooks/${webhookId}`),
  create: (data: any) => api.post('/webhooks', data),
  update: (webhookId: string, data: any) => api.put(`/webhooks/${webhookId}`, data),
  delete: (webhookId: string) => api.delete(`/webhooks/${webhookId}`),
  test: (webhookId: string) => api.post(`/webhooks/${webhookId}/test`),
  history: (webhookId: string, params?: any) => 
    api.get(`/webhooks/${webhookId}/history`, { params }),
};

// Bulk Operations API
export const bulkApi = {
  execute: (data: any) => api.post('/bulk', data),
  validate: (data: any) => api.post('/bulk/validate', data),
  history: (params?: any) => api.get('/bulk/history', { params }),
  get: (operationId: string) => api.get(`/bulk/${operationId}`),
  cancel: (operationId: string) => api.post(`/bulk/${operationId}/cancel`),
};

export default api;