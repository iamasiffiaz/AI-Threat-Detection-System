import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, FileText, Bell, TrendingUp,
  LogOut, Shield, Activity, ChevronRight,
  Globe, Search, Lock, Bot, Siren, Monitor,
  Radar, Crosshair, FileBarChart2, Settings,
} from 'lucide-react'
import clsx from 'clsx'
import { useAuthStore } from '../../store/authStore'
import { ROLE_LABELS, useRoleStore } from '../../store/roleStore'

const navSections = [
  {
    label: 'MONITOR',
    items: [
      { to: '/',              icon: LayoutDashboard, label: 'Dashboard'      },
      { to: '/logs',          icon: FileText,        label: 'Logs'           },
      { to: '/anomalies',     icon: TrendingUp,      label: 'Anomalies'      },
      { to: '/event-viewer',  icon: Monitor,         label: 'Event Viewer'   },
    ],
  },
  {
    label: 'DETECT & RESPOND',
    items: [
      { to: '/alerts',    icon: Bell,            label: 'Alerts'       },
      { to: '/incidents', icon: Siren,           label: 'Incidents'    },
      { to: '/soar',      icon: Lock,            label: 'SOAR'         },
    ],
  },
  {
    label: 'INTELLIGENCE',
    items: [
      { to: '/threat-feeds',  icon: Radar,   label: 'Threat Feeds' },
      { to: '/mitre',         icon: Crosshair, label: 'MITRE ATT&CK' },
      { to: '/intelligence',  icon: Globe,   label: 'Threat Intel'   },
      { to: '/investigation', icon: Search,  label: 'Investigation'  },
      { to: '/reports',       icon: FileBarChart2, label: 'Reports' },
    ],
  },
  {
    label: 'AI & ADMIN',
    items: [
      { to: '/soc-assistant', icon: Bot, label: 'SOC Assistant'  },
      { to: '/settings',      icon: Settings, label: 'Settings' },
    ],
  },
]

export function Sidebar() {
  const { user, logout } = useAuthStore()
  const { dashboardRole } = useRoleStore()

  return (
    <aside className="fixed inset-y-0 left-0 w-64 bg-soc-panel/95 backdrop-blur-md border-r border-soc-border flex flex-col z-50">
      <div className="flex items-center gap-3 px-5 py-5 border-b border-soc-border">
        <div className="flex items-center justify-center w-9 h-9 rounded-xl bg-cyber-600/20 border border-cyber-500/30">
          <Shield className="w-5 h-5 text-cyber-400" />
        </div>
        <div>
          <p className="text-sm font-display font-semibold text-soc-text leading-tight tracking-tight">
            SOC Platform 2.0
          </p>
          <p className="text-[10px] text-soc-muted leading-tight uppercase tracking-[0.14em]">
            Security Ops
          </p>
        </div>
      </div>

      <nav className="flex-1 px-3 py-4 space-y-4 overflow-y-auto">
        {navSections.map((section) => (
          <div key={section.label}>
            <p className="px-3 mb-1 text-[10px] font-semibold text-soc-faint tracking-widest uppercase">
              {section.label}
            </p>
            <div className="space-y-0.5">
              {section.items.map(({ to, icon: Icon, label }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={to === '/'}
                  className={({ isActive }) =>
                    clsx(
                      'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors group',
                      isActive
                        ? 'bg-cyber-500/12 text-cyber-300 border border-cyber-500/25'
                        : 'text-soc-muted hover:text-soc-text hover:bg-soc-elevated/70 border border-transparent'
                    )
                  }
                >
                  {({ isActive }) => (
                    <>
                      <Icon
                        className={clsx(
                          'w-4 h-4 shrink-0',
                          isActive ? 'text-cyber-400' : 'text-soc-faint group-hover:text-soc-muted'
                        )}
                      />
                      {label}
                      {isActive && <ChevronRight className="w-3 h-3 ml-auto text-cyber-500" />}
                    </>
                  )}
                </NavLink>
              ))}
            </div>
          </div>
        ))}
      </nav>

      <div className="px-4 py-3 border-t border-soc-border">
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-soc-card/80 border border-soc-border">
          <Activity className="w-3.5 h-3.5 text-threat-low" />
          <span className="text-xs text-soc-muted">SOC Status</span>
          <span className="ml-auto flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-threat-low animate-pulse" />
            <span className="text-xs text-threat-low">Active</span>
          </span>
        </div>
      </div>

      <div className="px-4 py-4 border-t border-soc-border">
        <div className="flex items-center gap-3 mb-3">
          <div className="w-8 h-8 rounded-full bg-cyber-500/20 border border-cyber-500/30 flex items-center justify-center">
            <span className="text-xs font-semibold text-cyber-300">
              {user?.username?.[0]?.toUpperCase() ?? 'U'}
            </span>
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-soc-text truncate">{user?.username ?? 'User'}</p>
            <p className="text-xs text-soc-faint">{ROLE_LABELS[dashboardRole]}</p>
          </div>
        </div>
        <button
          onClick={logout}
          className="flex items-center gap-2 w-full px-3 py-2 rounded-lg text-sm text-soc-muted hover:text-threat-critical hover:bg-threat-critical/5 transition-colors"
        >
          <LogOut className="w-4 h-4" />
          Sign Out
        </button>
      </div>
    </aside>
  )
}
