import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Eye, EyeOff, AlertCircle } from 'lucide-react'
import toast from 'react-hot-toast'
import { authApi } from '../services/api'
import { useAuthStore } from '../store/authStore'

export function LoginPage() {
  const navigate = useNavigate()
  const { setUser, setTokens } = useAuthStore()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      const { data } = await authApi.login(username, password)
      setTokens(data.access_token, data.refresh_token)

      const { data: user } = await authApi.me()
      setUser(user)

      toast.success(`Welcome back, ${user.username}!`)
      navigate('/')
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(detail || 'Invalid credentials. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4 relative overflow-hidden">
      <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(ellipse_at_top,_rgba(59,130,246,0.16),_transparent_55%)]" />
      <div
        className="absolute inset-0 opacity-[0.04] pointer-events-none"
        style={{
          backgroundImage:
            'linear-gradient(#2A3548 1px, transparent 1px), linear-gradient(90deg, #2A3548 1px, transparent 1px)',
          backgroundSize: '40px 40px',
        }}
      />

      <div className="relative w-full max-w-md animate-fade-in">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-cyber-500/15 border border-cyber-500/30 mb-4 shadow-card">
            <Shield className="w-7 h-7 text-cyber-400" />
          </div>
          <p className="text-[11px] uppercase tracking-[0.18em] text-cyber-400 font-semibold">
            Enterprise Security
          </p>
          <h1 className="font-display text-[1.65rem] font-semibold text-soc-text mt-2 tracking-tight">
            SOC Platform 2.0
          </h1>
          <p className="text-soc-muted mt-1.5 text-sm leading-relaxed">
            AI Threat Intelligence for modern security teams
          </p>
        </div>

        <div className="soc-card p-8">
          <h2 className="text-lg font-semibold text-soc-text mb-1">Sign in</h2>
          <p className="text-sm text-soc-muted mb-6">Use your analyst credentials to continue</p>

          {error && (
            <div className="flex items-center gap-2 p-3 mb-5 rounded-lg bg-threat-critical/10 border border-threat-critical/30 text-threat-critical text-sm">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-soc-muted mb-1.5">
                Username
              </label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter your username"
                required
                autoFocus
                className="soc-input"
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-soc-muted mb-1.5">
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  required
                  className="soc-input pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-soc-faint hover:text-soc-muted"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-cyber-600 hover:bg-cyber-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold py-2.5 rounded-lg text-sm transition-colors mt-2 shadow-sm"
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Signing in…
                </span>
              ) : 'Sign in'}
            </button>
          </form>

          <div className="mt-6 p-3 rounded-lg bg-soc-panel/80 border border-soc-border">
            <p className="text-xs text-soc-faint font-medium mb-1">Demo account</p>
            <p className="text-xs text-soc-muted font-mono">admin / Admin1234!</p>
          </div>
        </div>

        <p className="text-center text-xs text-soc-faint mt-6">
          AI Threat Intelligence SOC Platform 2.0 — Defensive use only
        </p>
      </div>
    </div>
  )
}
