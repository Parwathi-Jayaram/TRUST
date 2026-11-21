import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, SlidersHorizontal } from 'lucide-react'
import { ErrorState, LoadingState, ProvenanceBadge, SeverityBadge } from '../components/Common'
import { useApi } from '../hooks/useApi'
import { api } from '../services/api'

export default function ThreatHunting() {
  const navigate = useNavigate()
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const { data, loading, error } = useApi(() => api.threats(severity ? { severity } : {}), [severity])

  const threats = useMemo(() => {
    const items = data?.items || []
    const term = search.trim().toLowerCase()
    return term ? items.filter((item) => JSON.stringify(item).toLowerCase().includes(term)) : items
  }, [data, search])

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div><h1 className="text-xl font-semibold">Threat Hunting</h1><p className="mt-1 text-sm text-slate-500">Search detections, entities and supporting evidence</p></div>
        <div className="flex gap-2">
          <div className="relative">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input className="field w-64 pl-9" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search users, IPs, devices..." />
          </div>
          <select className="field w-36" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">All severity</option><option>critical</option><option>high</option><option>medium</option><option>low</option>
          </select>
        </div>
      </div>
      {loading ? <LoadingState /> : error ? <ErrorState error={error} /> : (
        <div className="panel overflow-hidden">
          <div className="grid grid-cols-[1.2fr_.7fr_.7fr_.7fr_1.2fr_.9fr] border-b border-slate-800 px-4 py-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
            <span>Detection</span><span>Severity</span><span>Risk</span><span>Entity</span><span>Timestamp</span><span>Provenance</span>
          </div>
          {threats.length ? threats.map((threat) => (
            <button key={threat.id || threat.threat_id} onClick={() => navigate('/attack-graph')} className="grid w-full grid-cols-[1.2fr_.7fr_.7fr_.7fr_1.2fr_.9fr] items-center border-b border-slate-800/70 px-4 py-4 text-left text-sm hover:bg-slate-800/40">
              <div className="pr-3"><div className="font-medium">{threat.category || threat.description || threat.name}</div><div className="mt-1 text-xs text-slate-500">{threat.id || threat.threat_id}</div></div>
              <div><SeverityBadge severity={threat.severity} /></div>
              <div className="font-semibold text-slate-200">{threat.risk_score ?? '—'}</div>
              <div className="text-slate-300">{threat.entity_id || threat.associated_entities?.[0]?.id || '—'}</div>
              <div className="text-xs text-slate-400">{threat.detection_timestamp || threat.event_time || '—'}</div>
              <div><ProvenanceBadge isSynthetic={threat.is_synthetic} /></div>
            </button>
          )) : <div className="py-16 text-center text-sm text-slate-500">No threats match the current filters</div>}
        </div>
      )}
    </div>
  )
}
