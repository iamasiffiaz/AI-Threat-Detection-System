// Enterprise SOC Platform v2.0
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
            <Route path="/investigation"  element={<InvestigationPage />} />
            <Route path="/soar"           element={<SOARPage />} />
            <Route path="/soc-assistant"  element={<SOCAssistantPage />} />
            <Route path="/event-viewer"   element={<EventViewerPage />} />
          </Route>

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>

      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: '#1f2937',
            color: '#f3f4f6',
            border: '1px solid #374151',
            borderRadius: '12px',
            fontSize: '14px',
          },
          success: { iconTheme: { primary: '#10b981', secondary: '#1f2937' } },
          error:   { iconTheme: { primary: '#ef4444', secondary: '#1f2937' } },
        }}
      />
    </QueryClientProvider>
  )
}
