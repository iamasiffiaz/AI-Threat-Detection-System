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
  timeout: 60000,
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
      const refreshToken = localStorage.getItem('refresh_token')
      if (refreshToken && !error.config?.url?.includes('/auth/refresh')) {
        try {
          const { data } = await axios.post(`${BASE_URL}/auth/refresh`, null, {
            params: { refresh_token: refreshToken },
          })
          localStorage.setItem('access_token', data.access_token)
          localStorage.setItem('refresh_token', data.refresh_token)
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
  reanalyzeAll: () => api.post('/alerts/reanalyze-all'),
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

// ─── Incidents API ────────────────────────────────────────────────────────────

export const incidentsApi = {
  getAll: (params?: Record<string, unknown>) => api.get('/incidents', { params }),
  getSummary: () => api.get('/incidents/summary'),
  getById: (id: number) => api.get(`/incidents/${id}`),
  getTimeline: (id: number) => api.get(`/incidents/${id}/timeline`),
  create: (data: unknown) => api.post('/incidents', data),
  update: (id: number, data: unknown) => api.patch(`/incidents/${id}`, data),
  assign: (id: number, assigned_to: string) => api.post(`/incidents/${id}/assign`, { assigned_to }),
  setStatus: (id: number, status: string) => api.post(`/incidents/${id}/status`, { status }),
  escalate: (id: number) => api.post(`/incidents/${id}/escalate`),
  delete: (id: number) => api.delete(`/incidents/${id}`),
}

// ─── Intelligence API ─────────────────────────────────────────────────────────

export const intelligenceApi = {
  lookupIP: (ip: string) => api.get(`/intelligence/ip/${ip}`),
  geoIP: (ip: string) => api.get(`/intelligence/ip/${ip}/geo`),
  bulkLookup: (ips: string[]) => api.post('/intelligence/bulk', { ips }),
  topThreats: (limit = 20, minRep = 50) =>
    api.get('/intelligence/top-threats', { params: { limit, min_reputation: minRep } }),
}

// ─── Investigation API ────────────────────────────────────────────────────────

export const investigationApi = {
  forensicReport: (ip: string, hours = 24) =>
    api.get(`/investigation/ip/${ip}`, { params: { hours } }),
  ipLogs: (ip: string, hours = 24, limit = 100) =>
    api.get(`/investigation/ip/${ip}/logs`, { params: { hours, limit } }),
  ipAlerts: (ip: string, hours = 72) =>
    api.get(`/investigation/ip/${ip}/alerts`, { params: { hours } }),
  ipBehavior: (ip: string) => api.get(`/investigation/ip/${ip}/behavior`),
  alertDeepDive: (alertId: number) => api.get(`/investigation/alert/${alertId}`),
}

// ─── SOAR API ─────────────────────────────────────────────────────────────────

export const soarApi = {
  getBlacklist: (activeOnly = true) =>
    api.get('/soar/blacklist', { params: { active_only: activeOnly } }),
  checkBlacklist: (ip: string) => api.get(`/soar/blacklist/${ip}`),
  blockIP: (data: { ip_address: string; reason: string; attack_types?: string[]; expires_in_hours?: number }) =>
    api.post('/soar/blacklist', data),
  unblockIP: (ip: string) => api.delete(`/soar/blacklist/${ip}`),
  getPlaybooks: () => api.get('/soar/playbooks'),
  getPlaybook: (attackType: string) => api.get(`/soar/playbooks/${attackType}`),
  triggerResponse: (alertId: number) => api.post(`/soar/respond/${alertId}`),
  getStats: () => api.get('/soar/stats'),
}

// ─── SOC Assistant API ────────────────────────────────────────────────────────

export const socAssistantApi = {
  ask: (question: string, context?: string, alertIds?: number[]) =>
    api.post('/soc-assistant/ask', { question, context, alert_ids: alertIds }),
  explainAlert: (alertId: number) => api.post(`/soc-assistant/explain/${alertId}`),
  adviseAlert: (alertId: number) => api.post(`/soc-assistant/advise/${alertId}`),
  incidentSummary: (incidentId: number) => api.post(`/soc-assistant/incident/${incidentId}`),
}

// ─── Event Viewer API ─────────────────────────────────────────────────────────

export const eventViewerApi = {
  getStatus:        () => api.get('/event-viewer/status'),
  start:            (channels?: string[], intervalSeconds = 5) =>
    api.post('/event-viewer/start', { channels, interval_seconds: intervalSeconds }),
  stop:             () => api.post('/event-viewer/stop'),
  getRecent:        (limit = 50) => api.get('/event-viewer/recent', { params: { limit } }),
  pullNow:          (channel = 'Security', count = 50) =>
    api.post('/event-viewer/pull-now', { channel, count }),
  resetWatermarks:  () => api.post('/event-viewer/reset-watermarks'),
  purgeSampleData:  () => api.post('/event-viewer/purge-sample-data'),
  getChannels:      () => api.get('/event-viewer/channels'),
  getEventIds:      () => api.get('/event-viewer/event-ids'),
}

// ─── System Status ────────────────────────────────────────────────────────────

export const systemApi = {
  status: () => api.get('/status'),
  health: () => axios.get('/health'),
}

// ─── Threat Feeds API ─────────────────────────────────────────────────────────

export const threatFeedsApi = {
  getAll: (params?: Record<string, unknown>) => api.get('/threat-feeds', { params }),
  getById: (id: number) => api.get(`/threat-feeds/${id}`),
  createManual: (data: unknown) => api.post('/threat-feeds/manual', data),
  importMock: () => api.post('/threat-feeds/import', null, { params: { mock: true } }),
  importFile: (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    return api.post('/threat-feeds/import', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
  },
  delete: (id: number) => api.delete(`/threat-feeds/${id}`),
}

// ─── IOC Extraction API ───────────────────────────────────────────────────────

export const iocsApi = {
  extract: (data: {
    text: string
    alert_id?: number
    incident_id?: number
    persist?: boolean
    source_context?: string
  }) => api.post('/iocs/extract', data),
}

// ─── MITRE API ────────────────────────────────────────────────────────────────

export const mitreApi = {
  getMappings: (params?: Record<string, unknown>) => api.get('/mitre/mappings', { params }),
  mapAlert: (alertId: number) => api.post(`/mitre/map-alert/${alertId}`),
  mapIncident: (incidentId: number) => api.post(`/mitre/map-incident/${incidentId}`),
  getIncident: (incidentId: number) => api.get(`/mitre/incident/${incidentId}`),
}

// ─── Analyst Notes API ────────────────────────────────────────────────────────

export const notesApi = {
  getAll: (params?: Record<string, unknown>) => api.get('/analyst-notes', { params }),
  create: (data: unknown) => api.post('/analyst-notes', data),
  update: (id: number, data: unknown) => api.put(`/analyst-notes/${id}`, data),
  delete: (id: number) => api.delete(`/analyst-notes/${id}`),
}

// ─── Reports API ──────────────────────────────────────────────────────────────

export const reportsApi = {
  getAll: () => api.get('/reports'),
  getById: (id: number) => api.get(`/reports/${id}`),
  generate: (incidentId: number) => api.post(`/reports/generate/${incidentId}`),
  downloadUrl: (id: number) => `${BASE_URL}/reports/${id}/download`,
}

// ─── SOC Platform 2.0 API ─────────────────────────────────────────────────────

export const socApi = {
  scoreAlert: (alertId: number) => api.post(`/soc/severity/score-alert/${alertId}`),
  explainAlert: (alertId: number) => api.post(`/soc/explain/alert/${alertId}`),
  explainIncident: (incidentId: number) => api.post(`/soc/explain/incident/${incidentId}`),
  getTimeline: (incidentId: number) => api.get(`/soc/timeline/${incidentId}`),
  reconstructTimeline: (incidentId: number) => api.post(`/soc/timeline/${incidentId}/reconstruct`),
  getSettings: () => api.get('/soc/settings'),
  updateSettings: (data: unknown) => api.put('/soc/settings', data),
  dashboardStats: (role?: string) => api.get('/soc/dashboard-stats', { params: { role } }),
}

