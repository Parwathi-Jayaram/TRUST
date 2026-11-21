import { Activity, AlertTriangle, Boxes, ShieldAlert, Siren } from 'lucide-react'
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { StatCard, LoadingState, ErrorState, SeverityBadge } from '../components/Common'
import { useApi } from '../hooks/useApi'
import { api } from '../services/api'

export default function Dashboard() {
  const overview = useApi(api.dashboard)
  const distribution = useApi(api.threatDistribution)
  const activity = useApi(api.recentActivity)

  if (overview.loading || distribution.loading || activity.loading) return <LoadingState label="Loading SOC overview..." />
  if (overview.error) return <ErrorState error={overview.error} />

  const o = overview.data || {}
  const severityData = Object.entries(distribution.data?.by_severity || {}).map(([name, value]) => ({ name, value }))
  const events = activity.data?.items || []

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold">SOC Command Center</h1>
        <p className="mt-1 text-sm text-slate-500">Live operational posture across monitored infrastructure</p>
      </div>
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <StatCard label="Monitored assets" value={o.total_monitored_entities} icon={Boxes} />
        <StatCard label="Active threats" value={o.detected_threats} icon={ShieldAlert} tone="amber" />
        <StatCard label="Critical incidents" value={o.critical_alerts} icon={Siren} tone="red" />
        <StatCard label="High-risk entities" value={o.high_risk_entities} icon={AlertTriangle} tone="violet" />
        <StatCard label="Investigations" value={o.current_investigation_count} icon={Activity} tone="cyan" />
      </section>

      <section className="grid gap-4 xl:grid-cols-[1.35fr_1fr]">
        <div className="panel p-5">
          <div className="section-heading"><div><h2>Threat severity distribution</h2><p>Current detected event severity</p></div></div>
          <div className="mt-4 h-64">
            {severityData.length ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityData} margin={{ left: -20 }}>
                  <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="name" stroke="#64748b" tick={{ fontSize: 11 }} />
                  <YAxis stroke="#64748b" tick={{ fontSize: 11 }} allowDecimals={false} />
                  <Tooltip cursor={{ fill: '#111d2d' }} contentStyle={{ background: '#0d1623', border: '1px solid #334155', borderRadius: 8 }} />
                  <Bar dataKey="value" radius={[5, 5, 0, 0]}>
                    {severityData.map((entry) => <Cell key={entry.name} fill={{ critical: '#f87171', high: '#fb923c', medium: '#fbbf24', low: '#38bdf8', info: '#94a3b8' }[entry.name] || '#94a3b8'} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : <div className="grid h-full place-items-center text-sm text-slate-500">No severity data</div>}
          </div>
        </div>

        <div className="panel p-5">
          <div className="section-heading"><div><h2>Recent security activity</h2><p>Latest graph and investigation events</p></div></div>
          <div className="mt-3 divide-y divide-slate-800">
            {events.length ? events.slice(0, 7).map((item, index) => (
              <div key={item.id || index} className="flex gap-3 py-3">
                <div className={`mt-1 h-2 w-2 shrink-0 rounded-full ${item.severity === 'high' || item.severity === 'critical' ? 'bg-orange-400' : 'bg-cyan-400'}`} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-start justify-between gap-3">
                    <span className="truncate text-sm">{item.description || item.title}</span>
                    <SeverityBadge severity={item.severity} />
                  </div>
                  <div className="mt-1 text-xs text-slate-500">{item.timestamp || item.event_time || 'Timestamp unavailable'}</div>
                </div>
              </div>
            )) : <div className="py-10 text-center text-sm text-slate-500">No recent activity</div>}
          </div>
        </div>
      </section>
    </div>
  )
}
