import { useState } from 'react'
import { ClipboardList, Plus } from 'lucide-react'
import { ErrorState, LoadingState, SeverityBadge } from '../components/Common'
import { useApi } from '../hooks/useApi'
import { api } from '../services/api'

export default function Investigations() {
  const investigations = useApi(api.investigations)
  const [selectedId, setSelectedId] = useState(null)
  const [note, setNote] = useState('')
  const selected = useApi(() => selectedId ? api.investigation(selectedId) : Promise.resolve(null), [selectedId])

  async function addNote() {
    if (!selectedId || !note.trim()) return
    await api.addNote(selectedId, { note: note.trim() })
    setNote('')
    selected.setData(await api.investigation(selectedId))
  }

  if (investigations.loading) return <LoadingState />
  if (investigations.error) return <ErrorState error={investigations.error} />
  const items = investigations.data?.items || []
  return (
    <div className="space-y-5">
      <div className="flex items-end justify-between"><div><h1 className="text-xl font-semibold">Investigation Workspace</h1><p className="mt-1 text-sm text-slate-500">Evidence, findings and analyst audit trail</p></div></div>
      <div className="grid gap-4 xl:grid-cols-[300px_1fr]">
        <div className="panel overflow-hidden">
          {items.length ? items.map((item) => (
            <button key={item.id} onClick={() => setSelectedId(item.id)} className={`w-full border-b border-slate-800 px-4 py-4 text-left hover:bg-slate-800/40 ${selectedId === item.id ? 'bg-cyan-400/[0.04]' : ''}`}>
              <div className="font-medium">{item.title || item.id}</div><div className="mt-1 text-xs text-slate-500">{item.status} • {item.updated_at || '—'}</div>
            </button>
          )) : <div className="py-16 text-center text-sm text-slate-500">No investigations found</div>}
        </div>
        <div className="panel p-5">
          {!selectedId ? <div className="grid h-64 place-items-center text-sm text-slate-500">Open an investigation to review evidence</div> : selected.loading ? <LoadingState /> : selected.error ? <ErrorState error={selected.error} /> : (
            <div>
              <div className="flex items-start justify-between"><div><h2 className="text-lg font-semibold">{selected.data?.title || selectedId}</h2><div className="mt-1 text-xs text-slate-500">{selected.data?.id}</div></div><SeverityBadge severity={selected.data?.status} /></div>
              <div className="mt-5">
                <h3 className="text-sm font-semibold">Findings</h3>
                <p className="mt-2 rounded-lg bg-soc-950 p-3 text-sm leading-6 text-slate-300">{selected.data?.findings || 'No findings recorded.'}</p>
              </div>
              <div className="mt-5">
                <h3 className="text-sm font-semibold">Analyst notes</h3>
                <div className="mt-2 space-y-2">
                  {(selected.data?.notes || []).map((entry, index) => <div key={entry.id || index} className="border-l-2 border-cyan-400/40 pl-3 text-sm text-slate-300"><div>{entry.note}</div><div className="mt-1 text-xs text-slate-500">{entry.created_at || ''}</div></div>)}
                </div>
              </div>
              <div className="mt-5 flex gap-2"><input className="field flex-1" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add an investigation note..." /><button className="primary-button" onClick={addNote}>Add note</button></div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
