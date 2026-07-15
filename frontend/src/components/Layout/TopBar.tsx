import { ROLE_LABELS, useRoleStore, type DashboardRole } from '../../store/roleStore'
import { Shield } from 'lucide-react'

export function TopBar() {
  const { dashboardRole, setDashboardRole } = useRoleStore()

  return (
    <header className="sticky top-0 z-40 h-14 border-b border-soc-border bg-soc-panel/85 backdrop-blur-md flex items-center justify-between px-6">
      <div className="flex items-center gap-3 min-w-0">
        <Shield className="w-4 h-4 text-cyber-400 shrink-0" />
        <span className="font-display text-sm font-semibold tracking-tight text-soc-text truncate">
          Security Operations
        </span>
        <span className="text-soc-faint text-xs hidden sm:inline">· Command center</span>
      </div>
      <div className="flex items-center gap-3">
        <span className="text-xs text-soc-muted">Role view</span>
        <select
          value={dashboardRole}
          onChange={(e) => setDashboardRole(e.target.value as DashboardRole)}
          className="soc-input w-auto py-1.5 text-xs min-w-[180px]"
          aria-label="Dashboard role view"
        >
          {(Object.keys(ROLE_LABELS) as DashboardRole[]).map((role) => (
            <option key={role} value={role}>
              {ROLE_LABELS[role]}
            </option>
          ))}
        </select>
        <span className="px-2.5 py-1 rounded-md border border-cyber-500/30 bg-cyber-500/10 text-cyber-300 text-[11px] font-semibold">
          {ROLE_LABELS[dashboardRole]}
        </span>
      </div>
    </header>
  )
}
