// AI Threat Intelligence SOC Platform 2.0
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Toaster } from 'react-hot-toast'
import { AppLayout } from './components/Layout/AppLayout'
import { LoginPage } from './pages/LoginPage'
import { DashboardPage } from './pages/DashboardPage'
import { LogsPage } from './pages/LogsPage'
import { AlertsPage } from './pages/AlertsPage'
import { AnomaliesPage } from './pages/AnomaliesPage'
import { IncidentsPage } from './pages/IncidentsPage'
import { IntelligencePage } from './pages/IntelligencePage'
import { InvestigationPage } from './pages/InvestigationPage'
import { SOARPage } from './pages/SOARPage'
import { SOCAssistantPage } from './pages/SOCAssistantPage'
import EventViewerPage from './pages/EventViewerPage'
import { ThreatFeedsPage } from './pages/ThreatFeedsPage'
import { MitrePage } from './pages/MitrePage'
import { ReportsPage } from './pages/ReportsPage'
import { SettingsPage } from './pages/SettingsPage'
import { useAuthStore } from './store/authStore'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 10_000,
    },
  },
})

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuthStore()
  if (!isAuthenticated) return <Navigate to="/login" replace />
  return <>{children}</>
}

function PublicRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuthStore()
  if (isAuthenticated) return <Navigate to="/" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<PublicRoute><LoginPage /></PublicRoute>} />

          <Route element={<ProtectedRoute><AppLayout /></ProtectedRoute>}>
            <Route path="/"               element={<DashboardPage />} />
            <Route path="/logs"           element={<LogsPage />} />
            <Route path="/alerts"         element={<AlertsPage />} />
            <Route path="/anomalies"      element={<AnomaliesPage />} />
            <Route path="/incidents"      element={<IncidentsPage />} />
            <Route path="/intelligence"   element={<IntelligencePage />} />
            <Route path="/threat-feeds"   element={<ThreatFeedsPage />} />
            <Route path="/mitre"          element={<MitrePage />} />
            <Route path="/investigation"  element={<InvestigationPage />} />
            <Route path="/reports"        element={<ReportsPage />} />
            <Route path="/soar"           element={<SOARPage />} />
            <Route path="/soc-assistant"  element={<SOCAssistantPage />} />
            <Route path="/event-viewer"   element={<EventViewerPage />} />
            <Route path="/settings"       element={<SettingsPage />} />
          </Route>

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>

      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: '#182234',
            color: '#F1F5F9',
            border: '1px solid #2A3548',
            borderRadius: '10px',
            fontSize: '14px',
            boxShadow: '0 8px 24px rgba(0,0,0,0.35)',
          },
          success: { iconTheme: { primary: '#22C55E', secondary: '#182234' } },
          error:   { iconTheme: { primary: '#EF4444', secondary: '#182234' } },
        }}
      />
    </QueryClientProvider>
  )
}
