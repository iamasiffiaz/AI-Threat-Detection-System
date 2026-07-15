import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export type DashboardRole =
  | 'soc_analyst'
  | 'soc_manager'
  | 'threat_intel_analyst'
  | 'executive_viewer'
  | 'admin'

interface RoleState {
  dashboardRole: DashboardRole
  setDashboardRole: (role: DashboardRole) => void
}

export const useRoleStore = create<RoleState>()(
  persist(
    (set) => ({
      dashboardRole: 'soc_analyst',
      setDashboardRole: (dashboardRole) => set({ dashboardRole }),
    }),
    { name: 'soc-dashboard-role' }
  )
)

export const ROLE_LABELS: Record<DashboardRole, string> = {
  soc_analyst: 'SOC Analyst',
  soc_manager: 'SOC Manager',
  threat_intel_analyst: 'Threat Intel Analyst',
  executive_viewer: 'Executive Viewer',
  admin: 'Admin',
}
