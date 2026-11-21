import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertTriangle, ArrowUpRight, ChevronRight, Clock3, FileSearch, LockKeyhole } from 'lucide-react'
import { ErrorState, LoadingState, SeverityBadge } from '../components/Common'
import { usePersona } from '../context/PersonaContext'
import { useApi } from '../hooks/useApi'
import { api } from '../services/api'

function incidentExplanation(incident, threat, persona) {
  const entity = incident?.source_entity_id || 'an unspecified entity'
  if (persona === 'executive') {
    const priority = String(incident?.severity || '').toLowerCase()
    return `This ${priority || 'unrated'}-severity incident is associated with ${entity}. The linked event is ${threat?.category || 'not available'}. This is a demonstration record and should be validated before operational decisions.`
  }
  if (persona === 'operator') {
    return `Review ${entity} and the adjacent assets in its graph neighborhood. The incident is currently ${String(incident?.status || 'unassigned').toLowerCase()}. No isolation or configuration change is performed by this view.`
  }
  return threat
    ? `${threat.explanation || threat.category || 'A security event'} is linked to this incident. Event ${threat.id} is rated ${String(threat.severity || incident?.severity || 'unknown').toLowerCase()}. Check the evidence description and event time below; the graph association alone does not establish compromise.`
    : `This incident references ${entity}, but no related event details were returned. Review the source entity and incident status; do not infer a cause from the association alone.`
}

export default function Incidents() {
  const navigate = useNavigate()
  const { persona } = usePersona()
  const incidents = useApi(api.incidents)
  const [selectedId, setSelectedId] = useState(null)
  const selected = useApi(
    () => selectedId ? api.incident(selectedId) : Promise.resolve(null),
    [selectedId],
  )
  const alertId = selected.data?.associated_alerts?.[0]
  const relatedThreat = useApi(
    () => alertId ? api.threat(alertId) : Promise.resolve(null),
    [alertId],
  )

  if (incidents.loading) return <LoadingState />
  if (incidents.error) return <ErrorState error={incidents.error} onRetry={incidents.reload} />
  const items = incidents.data?.items || []

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold">Incident Management</h1>
        <p className="mt-1 text-sm text-slate-500">Understand the detection context, supporting evidence, and affected assets.</p>
      </div>
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_420px]">
        <section className="panel overflow-hidden">
          <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3">
            <h2 className="text-sm font-semibold">Incident queue</h2><span className="text-xs text-slate-500">{items.length} records</span>
          </div>
          {items.length ? items.map((incident) => (
            <button key={incident.id} onClick={() => setSelectedId(incident.id)} className={`flex w-full items-center gap-4 border-b border-slate-800 px-4 py-4 text-left transition hover:bg-slate-800/40 ${selectedId === incident.id ? 'bg-cyan-400/[0.05]' : ''}`}>
              <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-orange-400/10 text-orange-300"><AlertTriangle size={17} /></span>
              <span className="min-w-0 flex-1">
                <span className="flex flex-wrap items-center gap-2"><span className="truncate text-sm font-medium">{incident.title || incident.id}</span><SeverityBadge severity={incident.severity} /></span>
                <span className="mt-1 block text-xs text-slate-500">{incident.id} · {incident.status} · {incident.updated_at || incident.detection_time || 'Time unavailable'}</span>
              </span>
              <ChevronRight size={16} className="shrink-0 text-slate-600" />
            </button>
          )) : <div className="py-16 text-center text-sm text-slate-500">No incidents returned</div>}
        </section>

        <section className="panel min-h-72 p-5">
          {!selectedId ? <div className="grid h-64 place-items-center text-center"><div><FileSearch className="mx-auto mb-3 text-slate-600" /><div className="text-sm text-slate-400">Select an incident to inspect its explanation and evidence.</div></div></div> : selected.loading ? <LoadingState /> : selected.error ? <ErrorState error={selected.error} /> : (
            <div>
              <div className="flex items-start justify-between gap-3">
                <div><h2 className="text-lg font-semibold">{selected.data?.title || selectedId}</h2><div className="mt-1 text-xs text-slate-500">{selected.data?.id}</div></div>
                <SeverityBadge severity={selected.data?.severity} />
              </div>

              <div className="explanation-card mt-4">
                <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-wider text-cyan-300"><FileSearch size={13} /> Why this incident is shown</div>
                {relatedThreat.loading ? <p className="mt-2 text-xs text-slate-400">Loading related event context...</p> : (
                  <p className="mt-2 text-xs leading-5 text-slate-300">{incidentExplanation(selected.data, relatedThreat.data, persona)}</p>
                )}
              </div>
              {relatedThreat.error && <p className="mt-2 text-xs text-red-300">Related event context unavailable: {relatedThreat.error.message}</p>}

              <div className="mt-4 space-y-3 text-sm">
                <div className="flex justify-between gap-3 border-b border-slate-800 pb-3"><span className="text-slate-500">Status</span><span className="text-right">{selected.data?.status || '—'}</span></div>
                <div className="flex justify-between gap-3 border-b border-slate-800 pb-3"><span className="text-slate-500">Source entity</span><span className="text-right">{selected.data?.source_entity_id || '—'}</span></div>
                <div className="flex justify-between gap-3 border-b border-slate-800 pb-3"><span className="text-slate-500">Assigned analyst</span><span className="text-right">{selected.data?.assigned_analyst || 'Unassigned'}</span></div>
                <div className="flex justify-between gap-3 border-b border-slate-800 pb-3"><span className="text-slate-500">Related event</span><span className="text-right">{relatedThreat.data?.id || alertId || 'No linked event'}</span></div>
                <div className="flex justify-between gap-3 border-b border-slate-800 pb-3"><span className="text-slate-500">Evidence status</span><span className="text-right">{relatedThreat.data?.evidence?.evidence_status || 'Not supplied'}</span></div>
              </div>

              {relatedThreat.data?.evidence?.description && (
                <div className="mt-4 rounded-lg border border-slate-800 bg-soc-950 p-3">
                  <div className="flex items-center gap-2 text-xs font-semibold"><Clock3 size={13} className="text-cyan-400" /> Supporting evidence</div>
                  <p className="mt-2 text-xs leading-5 text-slate-400">{relatedThreat.data.evidence.description}</p>
                  <p className="mt-2 text-[10px] text-slate-500">Observed {relatedThreat.data.evidence.observed_at || 'time unavailable'} · source {relatedThreat.data.evidence.source_system || 'not supplied'}</p>
                </div>
              )}

              {selected.data?.source_entity_id && (
                <button className="secondary-button mt-4 w-full justify-center gap-2" onClick={() => navigate(`/attack-graph?entityId=${encodeURIComponent(selected.data.source_entity_id)}`)}>
                  Explore source entity in graph <ArrowUpRight size={14} />
                </button>
              )}

              <div className="mt-5 flex gap-2 rounded-lg border border-amber-500/20 bg-amber-500/[0.05] p-3 text-xs leading-5 text-amber-200/80">
                <LockKeyhole size={15} className="mt-0.5 shrink-0" />
                <p>Incident status is read-only until authenticated, role-based updates are configured.</p>
              </div>
            </div>
          )}
        </section>
      </div>
    </div>
  )
}
