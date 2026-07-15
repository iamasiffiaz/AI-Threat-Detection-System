import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { socApi } from '../services/api'
import { Settings } from 'lucide-react'
import toast from 'react-hot-toast'
import { LoadingSpinner } from '../components/common/LoadingSpinner'

export function SettingsPage() {
  const qc = useQueryClient()
  const { data, isLoading } = useQuery({
    queryKey: ['soc-settings'],
    queryFn: () => socApi.getSettings().then((r) => r.data),
  })
  const [form, setForm] = useState<Record<string, unknown>>({})

  useEffect(() => {
    if (data) setForm(data)
  }, [data])

  const saveMut = useMutation({
    mutationFn: () => socApi.updateSettings(form),
    onSuccess: () => {
      toast.success('Settings saved')
      qc.invalidateQueries({ queryKey: ['soc-settings'] })
    },
  })

  if (isLoading) return <LoadingSpinner />

  const set = (key: string, value: unknown) => setForm((f) => ({ ...f, [key]: value }))

  return (
    <div className="p-6 space-y-6 animate-fade-in max-w-3xl">
      <div>
        <h1 className="page-title flex items-center gap-2"><Settings className="w-6 h-6 text-cyber-400" /> Settings</h1>
        <p className="text-sm text-soc-muted mt-1">Platform configuration for SOC Platform 2.0.</p>
      </div>

      <div className="soc-card p-5 space-y-4">
        <label className="block text-sm">
          <span className="text-soc-muted">Organization name</span>
          <input className="soc-input mt-1" value={String(form.organization_name || '')} onChange={(e) => set('organization_name', e.target.value)} />
        </label>
        <label className="block text-sm">
          <span className="text-soc-muted">Default role</span>
          <select className="soc-input mt-1" value={String(form.default_role || 'soc_analyst')} onChange={(e) => set('default_role', e.target.value)}>
            <option value="soc_analyst">SOC Analyst</option>
            <option value="soc_manager">SOC Manager</option>
            <option value="threat_intel_analyst">Threat Intel Analyst</option>
            <option value="executive_viewer">Executive Viewer</option>
            <option value="admin">Admin</option>
          </select>
        </label>
        <label className="block text-sm">
          <span className="text-soc-muted">AI provider (placeholder)</span>
          <input className="soc-input mt-1" value={String(form.ai_provider || '')} onChange={(e) => set('ai_provider', e.target.value)} />
        </label>
        <label className="block text-sm">
          <span className="text-soc-muted">API key (placeholder — not used for attacks)</span>
          <input className="soc-input mt-1" type="password" value={String(form.api_key_placeholder || '')} onChange={(e) => set('api_key_placeholder', e.target.value)} />
        </label>
        <label className="block text-sm">
          <span className="text-soc-muted">Threat feed refresh interval (minutes)</span>
          <input className="soc-input mt-1" type="number" value={Number(form.threat_feed_refresh_interval || 60)} onChange={(e) => set('threat_feed_refresh_interval', Number(e.target.value))} />
        </label>
        <label className="block text-sm">
          <span className="text-soc-muted">Severity threshold</span>
          <input className="soc-input mt-1" type="number" value={Number(form.severity_threshold || 40)} onChange={(e) => set('severity_threshold', Number(e.target.value))} />
        </label>
        <div className="flex flex-col gap-2 text-sm">
          {[
            ['mitre_mapping_enabled', 'MITRE mapping enabled'],
            ['pdf_reports_enabled', 'PDF reports enabled'],
            ['audit_logging_enabled', 'Audit logging enabled'],
          ].map(([key, label]) => (
            <label key={key} className="flex items-center gap-2 text-soc-muted">
              <input type="checkbox" checked={Boolean(form[key])} onChange={(e) => set(key, e.target.checked)} />
              {label}
            </label>
          ))}
        </div>
        <button className="soc-btn-primary" onClick={() => saveMut.mutate()} disabled={saveMut.isPending}>
          Save Settings
        </button>
      </div>
    </div>
  )
}
