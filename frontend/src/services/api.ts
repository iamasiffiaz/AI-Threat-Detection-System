/**
 * Axios API client with JWT interceptors and error handling.
 * All API calls go through this module.
 */
import axios, { type AxiosInstance, type AxiosError } from 'axios'
import toast from 'react-hot-toast'

const BASE_URL = import.meta.env.VITE_API_URL || '/api/v1'

const api: AxiosInstance = axios.create({
  baseURL: BASE_URL,
  headers: { 'Content-Type': 'application/json' },
  timeout: 30000,
})

// ─── Request Interceptor: Attach JWT ─────────────────────────────────────────

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// ─── Response Interceptor: Handle Auth Errors ────────────────────────────────

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    if (error.response?.status === 401) {
      // Try to refresh the token
      const refreshToken = localStorage.getItem('refresh_token')
      if (refreshToken && !error.config?.url?.includes('/auth/refresh')) {
        try {
          const { data } = await axios.post(`${BASE_URL}/auth/refresh`, null, {
            params: { refresh_token: refreshToken },
          })
          localStorage.setItem('access_token', data.access_token)
          localStorage.setItem('refresh_token', data.refresh_token)
          // Retry original request
          if (error.config) {
            error.config.headers.Authorization = `Bearer ${data.access_token}`
            return api(error.config)
          }
        } catch {
          localStorage.removeItem('access_token')
          localStorage.removeItem('refresh_token')
          window.location.href = '/login'
        }
      } else {
        localStorage.removeItem('access_token')
        localStorage.removeItem('refresh_token')
        window.location.href = '/login'
      }
    }

    const message = (error.response?.data as { detail?: string })?.detail || error.message
    if (error.response?.status !== 401) {
      toast.error(message || 'An error occurred')
    }

    return Promise.reject(error)
  }
)

export default api

// ─── Auth API ─────────────────────────────────────────────────────────────────

export const authApi = {
  login: (username: string, password: string) =>
    api.post('/auth/login', { username, password }),
  me: () => api.get('/auth/me'),
  users: () => api.get('/auth/users'),
}

// ─── Logs API ────────────────────────────────────────────────────────────────

export const logsApi = {
  getAll: (params?: Record<string, unknown>) => api.get('/logs', { params }),
  getStatistics: () => api.get('/logs/statistics'),
  streamLog: (logData: unknown) => api.post('/logs/stream', logData),
  bulkIngest: (logs: unknown[]) => api.post('/logs/bulk', { logs }),
  upload: (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    return api.post('/logs/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
  },
  generateSample: (count = 100) => api.post('/logs/generate-sample', null, { params: { count } }),
  trainModel: (force = false) => api.post('/logs/train-model', null, { params: { force } }),
}

// ─── Alerts API ───────────────────────────────────────────────────────────────

export const alertsApi = {
  getAll: (params?: Record<string, unknown>) => api.get('/alerts', { params }),
  getSummary: () => api.get('/alerts/summary'),
  getById: (id: number) => api.get(`/alerts/${id}`),
  update: (id: number, data: unknown) => api.patch(`/alerts/${id}`, data),
  analyze: (id: number) => api.post(`/alerts/${id}/analyze`),
}

// ─── Anomalies API ───────────────────────────────────────────────────────────

export const anomaliesApi = {
  getAll: (params?: Record<string, unknown>) => api.get('/anomalies', { params }),
  getTrends: (hours = 24) => api.get('/anomalies/trends', { params: { hours } }),
  getTopIPs: (limit = 10) => api.get('/anomalies/top-ips', { params: { limit } }),
  getModelInfo: () => api.get('/anomalies/model-info'),
}

// ─── Dashboard API ────────────────────────────────────────────────────────────

export const dashboardApi = {
  getOverview: () => api.get('/dashboard/overview'),
}
