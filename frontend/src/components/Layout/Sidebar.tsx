import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, FileText, Bell, TrendingUp,
  Settings, LogOut, Shield, Activity, ChevronRight
} from 'lucide-react'
import clsx from 'clsx'
import { useAuthStore } from '../../store/authStore'

const navItems = [
  { to: '/',           icon: LayoutDashboard, label: 'Dashboard'  },
  { to: '/logs',       icon: FileText,        label: 'Logs'        },
  { to: '/alerts',     icon: Bell,            label: 'Alerts'      },
  { to: '/anomalies',  icon: TrendingUp,      label: 'Anomalies'   },
]

export function Sidebar() {
  const { user, logout } = useAuthStore()

  return (
    <aside className="fixed inset-y-0 left-0 w-64 bg-gray-900 border-r border-gray-800 flex flex-col z-50">
      {/* Logo */}
      <div className="flex items-center gap-3 px-6 py-5 border-b border-gray-800">
        <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-cyber-500/20 border border-cyber-500/30">
          <Shield className="w-5 h-5 text-cyber-400" />
        </div>
        <div>
          <p className="text-sm font-semibold text-white leading-tight">AI Threat</p>
          <p className="text-xs text-gray-400 leading-tight">Detection System</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all group',
                isActive
                  ? 'bg-cyber-500/15 text-cyber-300 border border-cyber-500/20'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800'
              )
            }
          >
            {({ isActive }) => (
              <>
                <Icon className={clsx('w-4 h-4', isActive ? 'text-cyber-400' : 'text-gray-500 group-hover:text-gray-400')} />
                {label}
                {isActive && <ChevronRight className="w-3 h-3 ml-auto text-cyber-500" />}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Live Status Indicator */}
      <div className="px-4 py-3 border-t border-gray-800">
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-gray-800/60">
          <Activity className="w-3.5 h-3.5 text-green-400" />
          <span className="text-xs text-gray-400">System</span>
          <span className="ml-auto flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
            <span className="text-xs text-green-400">Online</span>
          </span>
        </div>
      </div>

      {/* User Info + Logout */}
      <div className="px-4 py-4 border-t border-gray-800">
        <div className="flex items-center gap-3 mb-3">
          <div className="w-8 h-8 rounded-full bg-cyber-500/20 border border-cyber-500/30 flex items-center justify-center">
            <span className="text-xs font-semibold text-cyber-300">
              {user?.username?.[0]?.toUpperCase() ?? 'U'}
            </span>
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-gray-200 truncate">{user?.username ?? 'User'}</p>
            <p className="text-xs text-gray-500 capitalize">{user?.role ?? 'analyst'}</p>
          </div>
        </div>
        <button
          onClick={logout}
          className="flex items-center gap-2 w-full px-3 py-2 rounded-lg text-sm text-gray-400 hover:text-red-400 hover:bg-red-400/5 transition-colors"
        >
          <LogOut className="w-4 h-4" />
          Sign Out
        </button>
      </div>
    </aside>
  )
}
