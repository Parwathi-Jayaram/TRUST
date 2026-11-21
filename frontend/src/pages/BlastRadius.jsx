import { useEffect, useState } from 'react'
import { Background, Controls, ReactFlow, useEdgesState, useNodesState } from '@xyflow/react'
import { Crosshair } from 'lucide-react'
import { ErrorState, LoadingState, SeverityBadge } from '../components/Common'
import { useApi } from '../hooks/useApi'
import { api } from '../services/api'

export default function BlastRadius() {
  const [entityId, setEntityId] = useState('HOST-001')
  const [depth, setDepth] = useState(3)
  const result = useApi(() => api.blastRadius(entityId, depth), [entityId, depth])
  const [nodes, setNodes] = useNodesState([])
  const [edges, setEdges] = useEdgesState([])

  useEffect(() => {
    const data = result.data || {}
    const graphNodes = data.nodes || data.affected_entities || []
    setNodes(graphNodes.map((node, index) => ({
      id: node.id,
      position: { x: 80 + (index % 3) * 240, y: 50 + Math.floor(index / 3) * 150 },
      data: { label: node.name || node.id },
      style: { border: '1px solid #334155', borderRadius: 8, background: '#111d2d', color: '#e2e8f0', fontSize: 12, width: 150 },
    })))
    const relationships = data.edges || (data.paths || []).flatMap((path) => path.relationships || [])
    setEdges(relationships.map((edge, index) => ({
      id: edge.id || `e-${index}`,
      source: edge.source,
      target: edge.target,
      label: edge.type,
      animated: true,
      style: { stroke: '#fb923c' },
      markerEnd: { type: 'arrowclosed', color: '#fb923c' },
    })))
  }, [result.data, setNodes, setEdges])

  if (result.loading) return <LoadingState label="Calculating graph blast radius..." />
  if (result.error) return <ErrorState error={result.error} />

  const data = result.data || {}
  const affected = data.affected_entities || data.entities || []
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div><h1 className="text-xl font-semibold">Blast Radius Analysis</h1><p className="mt-1 text-sm text-slate-500">Potential exposure from a source entity</p></div>
        <div className="flex gap-2">
          <div className="relative"><Crosshair size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" /><input className="field w-44 pl-9" value={entityId} onChange={(e) => setEntityId(e.target.value)} /></div>
          <select className="field w-28" value={depth} onChange={(e) => setDepth(Number(e.target.value))}><option value={1}>1 hop</option><option value={2}>2 hops</option><option value={3}>3 hops</option></select>
        </div>
      </div>
      <section className="grid gap-3 md:grid-cols-4">
        {[['Potential exposure', data.reachable_entities_count ?? affected.length], ['Direct assets', data.directly_connected_count ?? '—'], ['Critical assets', data.critical_assets_count ?? '—'], ['Exposure depth', data.depth ?? depth]].map(([label, value]) => (
          <div className="panel p-4" key={label}><div className="text-xs uppercase tracking-wider text-slate-500">{label}</div><div className="mt-2 text-2xl font-semibold">{value}</div></div>
        ))}
      </section>
      <div className="grid gap-4 xl:grid-cols-[1fr_380px]">
        <div className="panel h-[470px] overflow-hidden"><ReactFlow nodes={nodes} edges={edges} fitView><Background color="#1e293b" gap={18} /><Controls /></ReactFlow></div>
        <div className="panel overflow-hidden">
          <div className="border-b border-slate-800 px-4 py-3 text-sm font-semibold">Affected assets</div>
          <div className="max-h-[418px] overflow-auto divide-y divide-slate-800">
            {affected.length ? affected.map((asset, index) => (
              <div key={asset.id || index} className="flex items-center justify-between px-4 py-3">
                <div><div className="text-sm font-medium">{asset.name || asset.id}</div><div className="mt-1 text-xs text-slate-500">{asset.type || asset.labels?.join(', ') || 'Entity'} • {asset.id}</div></div>
                <SeverityBadge severity={asset.risk_level || asset.criticality || 'potential'} />
              </div>
            )) : <div className="py-16 text-center text-sm text-slate-500">No affected entities returned</div>}
          </div>
        </div>
      </div>
    </div>
  )
}
