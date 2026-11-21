import { useCallback, useMemo, useState } from 'react'
import { Background, Controls, MiniMap, ReactFlow, useEdgesState, useNodesState } from '@xyflow/react'
import { RotateCcw, Search, SlidersHorizontal } from 'lucide-react'
import { ErrorState, LoadingState, SeverityBadge } from '../components/Common'
import { useApi } from '../hooks/useApi'
import { api } from '../services/api'

const typeColors = {
  User: '#60a5fa', Host: '#22d3ee', Server: '#a78bfa', IPAddress: '#f59e0b',
  Application: '#34d399', Vulnerability: '#fb7185', Incident: '#f87171', Process: '#94a3b8',
  SecurityEvent: '#c084fc', Evidence: '#64748b',
}

export default function AttackGraph() {
  const [entityId, setEntityId] = useState('HOST-001')
  const [depth, setDepth] = useState(2)
  const [filter, setFilter] = useState('')
  const [selected, setSelected] = useState(null)
  const graph = useApi(() => api.graphSubgraph(entityId, depth), [entityId, depth])
  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])

  useMemo(() => {
    const payload = graph.data
    if (!payload) return
    const allNodes = payload.nodes || []
    const allEdges = payload.edges || payload.relationships || []
    const visibleNodes = filter ? allNodes.filter((n) => n.labels?.some((l) => l.toLowerCase().includes(filter.toLowerCase())) || n.type?.toLowerCase().includes(filter.toLowerCase())) : allNodes
    const visibleIds = new Set(visibleNodes.map((n) => n.id))
    setNodes(visibleNodes.map((node, index) => ({
      id: node.id,
      position: { x: 180 + (index % 4) * 210, y: 60 + Math.floor(index / 4) * 150 },
      data: { label: node.name || node.id, properties: node.properties || node },
      style: {
        border: node.id === entityId ? '2px solid #38bdf8' : '1px solid #334155',
        borderRadius: 8, color: '#e2e8f0', background: '#111d2d',
        fontSize: 12, width: 150, boxShadow: node.id === entityId ? '0 0 22px rgba(56,189,248,.18)' : undefined,
      },
    })))
    setEdges(allEdges.filter((edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target)).map((edge, index) => ({
      id: edge.id || `edge-${index}`, source: edge.source, target: edge.target,
      label: edge.type, animated: edge.type !== 'OBSERVED_ON',
      style: { stroke: '#64748b' }, labelStyle: { fill: '#94a3b8', fontSize: 9 },
      markerEnd: { type: 'arrowclosed', color: '#64748b' },
    })))
  }, [graph.data, filter, entityId])

  const onNodeClick = useCallback((_, node) => setSelected({ id: node.id, ...node.data.properties }), [])

  if (graph.loading) return <LoadingState label="Loading Neo4j graph neighborhood..." />
  if (graph.error) return <ErrorState error={graph.error} />

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div><h1 className="text-xl font-semibold">Interactive Attack Graph</h1><p className="mt-1 text-sm text-slate-500">Entity relationships and multi-hop infrastructure exposure</p></div>
        <div className="flex gap-2">
          <div className="relative"><Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" /><input className="field w-44 pl-9" value={entityId} onChange={(e) => setEntityId(e.target.value)} placeholder="Entity ID" /></div>
          <select className="field w-28" value={depth} onChange={(e) => setDepth(Number(e.target.value))}><option value={1}>1 hop</option><option value={2}>2 hops</option><option value={3}>3 hops</option></select>
          <input className="field w-32" value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter type" />
        </div>
      </div>
      <div className="grid h-[590px] gap-4 xl:grid-cols-[1fr_280px]">
        <div className="panel overflow-hidden">
          <ReactFlow nodes={nodes} edges={edges} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} onNodeClick={onNodeClick} fitView>
            <Background color="#1e293b" gap={18} />
            <Controls />
            <MiniMap nodeColor={(node) => typeColors[node.data?.properties?.type] || '#475569'} maskColor="rgba(7,11,18,.75)" />
          </ReactFlow>
        </div>
        <div className="panel p-4">
          <div className="flex items-center justify-between"><h2 className="font-semibold">Entity inspector</h2><button className="icon-button" onClick={() => setSelected(null)} title="Clear selection"><RotateCcw size={15} /></button></div>
          {selected ? (
            <div className="mt-4 space-y-3 text-sm">
              <div><div className="text-xs text-slate-500">Entity ID</div><div className="mt-1 break-all font-medium">{selected.id}</div></div>
              {Object.entries(selected).filter(([k]) => k !== 'id').slice(0, 12).map(([key, value]) => (
                <div key={key} className="border-t border-slate-800 pt-3"><div className="text-xs capitalize text-slate-500">{key.replaceAll('_', ' ')}</div><div className="mt-1 break-words text-slate-300">{typeof value === 'object' ? JSON.stringify(value) : String(value ?? '—')}</div></div>
              ))}
            </div>
          ) : <div className="mt-16 text-center text-sm text-slate-500">Select a node to inspect properties</div>}
        </div>
      </div>
    </div>
  )
}
