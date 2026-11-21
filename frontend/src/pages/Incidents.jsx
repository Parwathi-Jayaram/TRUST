import { useState } from 'react'
import { AlertTriangle, ChevronRight } from 'lucide-react'
import { ErrorState, LoadingState, SeverityBadge } from '../components/Common'
import { useApi } from '../hooks/useApi'
import { api } from '../services/api'

export default function Incidents() {
  const incidents = useApi(api.incidents)
  const [selectedId, setSelectedId] = useState(null)
  const selected = useApi(() => selectedId ? api.incident(selectedId) : Promise.resolve(null), [selectedId])
  const [status, setStatus] = useState('')

  async function updateStatus() {
    if (!selectedId || !status) return
    await api.updateIncidentStatus(selectedId, status)
    incidents.setData(await api.incidents())
  }

  if (incidents.loading) return <LoadingState />
  if (incidents.error) return <ErrorState error={incidents.error} />
  const items = incidents.data?.items || []

  return (
    <div className="space-y-5">
      <div><h1 className="text-xl font-semibold">Incident Management</h1><p className="mt-1 text-sm text-slate-500">Track, triage and update security incidents</p></div>
      <div className="grid gap-4 xl:grid-cols-[1fr_360px]">
        <div className="panel overflow-hidden">
          {items.length ? items.map((incident) => (
            <button key={incident.id} onClick={() => { setSelectedId(incident.id); setStatus(incident.status || '') }} className={`flex w-full items-center gap-4 border-b border-slate-800 px-4 py-4 text-left hover:bg-slate-800/40 ${selectedId === incident.id ? 'bg-cyan-400/[0.04]' : ''}`}>
              <AlertTriangle size={18} className="shrink-0 text-orange-400" />
              <div className="min-w-0 flex-1"><div className="flex items-center gap-2"><span className="font-medium">{incident.title || incident.id}</span><SeverityBadge severity={incident.severity} /></div><div className="mt-1 text-xs text-slate-500">{incident.id} • {incident.status} • {incident.updated_at || incident.detection_time || '—'}</div></div>
              <ChevronRight size={16} className="text-slate-600" />
            </button>
          )) : <div className="py-16 text-center text-sm text-slate-500">No incidents returned</div>}
        </div>
        <div className="panel p-5">
          {!selectedId ? <div className="grid h-64 place-items-center text-sm text-slate-500">Select an incident</div> : selected.loading ? <LoadingState /> : selected.error ? <ErrorState error={selected.error} /> : (
            <div>
              <h2 className="text-lg font-semibold">{selected.data?.title || selectedId}</h2>
              <div className="mt-4 space-y-3 text-sm">
                <div className="flex justify-between border-b border-slate-800 pb-3"><span className="text-slate-500">Status</span><span>{selected.data?.status || '—'}</span></div>
                <div className="flex justify-between border-b border-slate-800 pb-3"><span className="text-slate-500">Source entity</span><span>{selected.data?.source_entity_id || '—'}</span></div>
                <div className="flex justify-between border-b border-slate-800 pb-3"><span className="text-slate-500">Assigned analyst</span><span>{selected.data?.assigned_analyst || 'Unassigned'}</span></div>
              </div>
              <label className="mt-5 block text-xs font-semibold uppercase tracking-wider text-slate-500">Update status</label>
              <select className="field mt-2 w-full" value={status} onChange={(e) => setStatus(e.target.value)}>
                {['NEW','INVESTIGATING','CONFIRMED','CONTAINMENT_RECOMMENDED','CONTAINED','RESOLVED','CLOSED'].map((item) => <option key={item}>{item}</option>)}
              </select>
              <button className="primary-button mt-3 w-full" onClick={updateStatus}>Apply update</button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
