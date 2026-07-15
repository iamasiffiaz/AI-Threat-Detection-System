import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { notesApi } from '../../services/api'
import { useAuthStore } from '../../store/authStore'
import { Trash2, Plus } from 'lucide-react'
import toast from 'react-hot-toast'

const NOTE_TYPES = ['Observation', 'Action Taken', 'Escalation', 'False Positive', 'Recommendation']

interface Props {
  alertId?: number
  incidentId?: number
}

export function AnalystNotesPanel({ alertId, incidentId }: Props) {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const [noteText, setNoteText] = useState('')
  const [noteType, setNoteType] = useState('Observation')
  const [filter, setFilter] = useState('')

  const { data: notes = [], isLoading } = useQuery({
    queryKey: ['analyst-notes', alertId, incidentId],
    queryFn: () =>
      notesApi.getAll({ alert_id: alertId, incident_id: incidentId }).then((r) => r.data),
  })

  const createMut = useMutation({
    mutationFn: () =>
      notesApi.create({
        alert_id: alertId,
        incident_id: incidentId,
        analyst_name: user?.username || 'analyst',
        note_text: noteText,
        note_type: noteType,
      }),
    onSuccess: () => {
      setNoteText('')
      qc.invalidateQueries({ queryKey: ['analyst-notes'] })
      toast.success('Note added')
    },
  })

  const deleteMut = useMutation({
    mutationFn: (id: number) => notesApi.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['analyst-notes'] })
      toast.success('Note deleted')
    },
  })

  const filtered = (notes as Array<Record<string, unknown>>).filter(
    (n) => !filter || n.note_type === filter
  )

  return (
    <div className="soc-card p-4 space-y-3">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <h3 className="text-sm font-semibold text-cyber-300 tracking-wide uppercase">Analyst Notes</h3>
        <select className="soc-input w-auto py-1 text-xs" value={filter} onChange={(e) => setFilter(e.target.value)}>
          <option value="">All types</option>
          {NOTE_TYPES.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
      </div>

      <div className="flex flex-col gap-2 sm:flex-row">
        <select className="soc-input sm:w-44" value={noteType} onChange={(e) => setNoteType(e.target.value)}>
          {NOTE_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <input
          className="soc-input flex-1"
          placeholder="Add investigation note…"
          value={noteText}
          onChange={(e) => setNoteText(e.target.value)}
        />
        <button
          className="soc-btn-primary"
          disabled={!noteText.trim() || createMut.isPending}
          onClick={() => createMut.mutate()}
        >
          <Plus className="w-4 h-4" /> Add
        </button>
      </div>

      {isLoading ? (
        <p className="text-sm text-soc-faint">Loading notes…</p>
      ) : filtered.length === 0 ? (
        <p className="text-sm text-soc-faint">No notes yet.</p>
      ) : (
        <ul className="space-y-2 max-h-72 overflow-y-auto">
          {filtered.map((n) => (
            <li key={String(n.id)} className="border border-soc-border rounded-md p-3 bg-soc-panel/50">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <p className="text-xs text-cyber-400 font-semibold">{String(n.note_type)}</p>
                  <p className="text-sm text-soc-text mt-1">{String(n.note_text)}</p>
                  <p className="text-[11px] text-soc-faint mt-2">
                    {String(n.analyst_name)} · {n.created_at ? new Date(String(n.created_at)).toLocaleString() : ''}
                  </p>
                </div>
                <button
                  className="text-soc-faint hover:text-threat-critical"
                  onClick={() => deleteMut.mutate(Number(n.id))}
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
