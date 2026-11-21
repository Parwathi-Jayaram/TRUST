import { Activity, AlertTriangle, Boxes, ShieldAlert, Siren } from 'lucide-react'
import { Background, Controls, ReactFlow } from '@xyflow/react'
import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { StatCard, LoadingState, ErrorState, SeverityBadge } from '../components/Common'
import EntityNode from '../components/EntityNode'
import { useApi } from '../hooks/useApi'
import { api } from '../services/api'
import { createGraphLayout } from '../utils/graphLayout'

const nodeTypes = { entity: EntityNode }

function ConnectivityPreview() {
  const navigate = useNavigate()
  const graph = useApi(() => api.graphSubgraph('HOST-001', 2))
  const layout = useMemo(() => createGraphLayout(graph.data?.nodes, graph.data?.edges, 'HOST-001'), [graph.data])

  return (
    <section className="panel overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 px-5 py-4">
        <div><h2 className="text-sm font-semibold">Asset connectivity</h2><p className="mt-1 text-xs text-slate-500">A two-hop sample neighborhood around WS-FIN-01</p></div>
        <button className="secondary-button h-8" onClick={() => navigate('/attack-graph?entityId=HOST-001')}>Explore full graph</button>
      </div>
      {graph.loading ? <div className="grid h-[330px] place-items-center text-sm text-slate-500">Loading graph preview...</div> : graph.error ? (
        <div className="grid h-[330px] place-items-center p-5 text-center text-sm text-red-300">Connectivity preview unavailable: {graph.error.message}</div>
      ) : layout.nodes.length ? (
        <>
          <div className="h-[330px]">
            <ReactFlow
              nodes={layout.nodes}
              edges={layout.edges}
              nodeTypes={nodeTypes}
              fitView
              fitViewOptions={{ padding: 0.2 }}
              nodesDraggable={false}
              nodesConnectable={false}
              panOnDrag={false}
              zoomOnScroll={false}
              onNodeClick={(_, node) => navigate(`/attack-graph?entityId=${encodeURIComponent(node.id)}`)}
            >
              <Background color="#1e293b" gap={20} />
              <Controls showInteractive={false} />
            </ReactFlow>
          </div>
          <div className="flex items-center justify-between border-t border-slate-800 px-5 py-2 text-[10px] text-slate-500">
            <span>{layout.nodes.length} entities · {layout.edges.length} relationships</span>
            <span>Sample data · click an entity to explore</span>
          </div>
        </>
      ) : <div className="grid h-[330px] place-items-center text-sm text-slate-500">No connectivity data available</div>}
    </section>
  )
}

export default function Dashboard() {
  const overview = useApi(api.dashboard)
  const distribution = useApi(api.threatDistribution)
  const activity = useApi(api.recentActivity)

  if (overview.loading) return <LoadingState label="Loading SOC overview..." />
  if (overview.error) return <ErrorState error={overview.error} onRetry={overview.reload} />

  const o = overview.data || {}
  const severityData = Object.entries(distribution.data?.by_severity || {}).map(([name, value]) => ({ name, value }))
  const events = activity.data?.items || []

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold">SOC Command Center</h1>
        <p className="mt-1 text-sm text-slate-500">Current security posture overview</p>
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
            {distribution.loading ? <div className="grid h-full place-items-center text-sm text-slate-500">Loading severity data...</div> : distribution.error ? (
              <div role="alert" className="grid h-full place-items-center text-center text-sm text-red-300">
                <div><p>Could not load threat severity data.</p><button className="secondary-button mt-3" onClick={distribution.reload}>Retry</button></div>
              </div>
            ) : severityData.length ? (
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
            {activity.loading ? <div className="py-10 text-center text-sm text-slate-500">Loading activity...</div> : activity.error ? (
              <div role="alert" className="py-8 text-center text-sm text-red-300">
                <p>Could not load recent activity.</p><button className="secondary-button mt-3" onClick={activity.reload}>Retry</button>
              </div>
            ) : events.length ? events.slice(0, 7).map((item, index) => (
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
      <ConnectivityPreview />
    </div>
  )
}
