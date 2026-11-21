import { useCallback, useEffect, useMemo, useState } from 'react'
import { Background, Controls, MiniMap, ReactFlow, useEdgesState, useNodesState } from '@xyflow/react'
import { useSearchParams } from 'react-router-dom'
import { AlertCircle, ArrowDownRight, Info, RotateCcw, Search } from 'lucide-react'
import EntityNode from '../components/EntityNode'
import { ErrorState, LoadingState, SeverityBadge } from '../components/Common'
import { usePersona } from '../context/PersonaContext'
import { useApi } from '../hooks/useApi'
import { api } from '../services/api'
import { createGraphLayout } from '../utils/graphLayout'

const nodeTypes = { entity: EntityNode }

function getEntityExplanation(entity, relatedEdges, graphNodes, persona) {
  const properties = entity.data?.properties || {}
  const entityId = entity.id
  const entityName = entity.data?.name || entityId
  const entityType = entity.data?.type || 'graph entity'
  const links = relatedEdges.length
  const relatedNames = [...new Set(relatedEdges.map((edge) => {
    const neighborId = edge.source === entityId ? edge.target : edge.source
    const neighbor = graphNodes.find((node) => node.id === neighborId)
    return neighbor?.data?.name || neighborId
  }))]
  const criticality = String(properties.criticality || 'unknown').toLowerCase()

  if (persona === 'executive') {
    const impact = criticality === 'critical' || criticality === 'high'
      ? 'This asset is marked as a high business-priority asset in the fixture.'
      : 'The fixture does not mark this asset as high business priority.'
    return `${entityName} is a ${entityType}. ${impact} It has ${links} modeled connection${links === 1 ? '' : 's'} in the displayed neighborhood. A graph connection indicates a relationship, not proof of compromise.`
  }
  if (persona === 'operator') {
    return `${entityName} (${entityId}) is recorded as a ${entityType}. The displayed neighborhood includes ${relatedNames.length ? relatedNames.join(', ') : 'no other visible assets'}. Use the linked systems as investigation context; no operational changes are made from this graph.`
  }
  return `${entityName} is a ${entityType} with ${links} visible relationship${links === 1 ? '' : 's'}. Its recorded criticality is ${criticality}. Review the related events and evidence below before treating a modeled connection as an incident finding.`
}

function getRelationshipExplanation(edge, source, target, persona) {
  const from = source?.data?.name || source?.data?.id || edge.source
  const to = target?.data?.name || target?.data?.id || edge.target
  const relation = edge.data?.type || edge.data?.relationship_type || edge.label || 'RELATED_TO'
  if (persona === 'executive') {
    return `${from} is modeled as ${relation.toLowerCase().replaceAll('_', ' ')} ${to}. This describes infrastructure connectivity and does not by itself indicate malicious activity.`
  }
  if (persona === 'operator') {
    return `Connection: ${from} → ${to}. Relationship type: ${relation}. Use this link to identify adjacent assets that may need review.`
  }
  return `The graph records a ${relation} relationship from ${from} to ${to}. Evidence status: ${edge.data?.evidence_status || 'not supplied'}. Validate the associated event and source evidence before drawing a conclusion.`
}

export default function AttackGraph() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [entityId, setEntityId] = useState(() => searchParams.get('entityId') || 'HOST-001')
  const [depth, setDepth] = useState(2)
  const [typeFilter, setTypeFilter] = useState('all')
  const [selectedElement, setSelectedElement] = useState(null)
  const [selectedEventId, setSelectedEventId] = useState(null)
  const { persona } = usePersona()
  const entityList = useApi(api.graphEntities)
  const graph = useApi(() => api.graphSubgraph(entityId, depth), [entityId, depth])
  const threats = useApi(api.threats)
  const eventDetail = useApi(
    () => selectedEventId ? api.threat(selectedEventId) : Promise.resolve(null),
    [selectedEventId],
  )
  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  const [flowInstance, setFlowInstance] = useState(null)

  useEffect(() => {
    const queryEntity = searchParams.get('entityId')
    if (queryEntity && queryEntity !== entityId) setEntityId(queryEntity)
  }, [searchParams, entityId])

  useEffect(() => {
    if (!graph.data) return
    const layout = createGraphLayout(
      graph.data.nodes || [],
      graph.data.edges || graph.data.relationships || [],
      entityId,
      typeFilter,
    )
    setNodes(layout.nodes)
    setEdges(layout.edges)
    setSelectedElement(null)
    setSelectedEventId(null)
  }, [graph.data, entityId, typeFilter, setNodes, setEdges])

  useEffect(() => {
    if (!flowInstance || !nodes.length) return undefined
    const frame = window.requestAnimationFrame(() => flowInstance.fitView({ padding: 0.25, duration: 180 }))
    return () => window.cancelAnimationFrame(frame)
  }, [flowInstance, nodes.length, entityId, depth, typeFilter])

  const relatedEvents = useMemo(() => {
    if (selectedElement?.kind !== 'node') return []
    const id = selectedElement.item.id
    return (threats.data?.items || []).filter((event) =>
      event.entity_id === id || event.associated_entities?.includes(id),
    )
  }, [selectedElement, threats.data])

  const onNodeClick = useCallback((_, node) => {
    setSelectedElement({ kind: 'node', item: node })
    setSelectedEventId(null)
  }, [])

  const onEdgeClick = useCallback((_, edge) => {
    setSelectedElement({ kind: 'edge', item: edge })
    setSelectedEventId(null)
  }, [])

  function chooseEntity(event) {
    const nextId = event.target.value
    setEntityId(nextId)
    setSearchParams({ entityId: nextId })
  }

  if (graph.loading || entityList.loading) return <LoadingState label="Loading graph neighborhood..." />
  if (entityList.error) return <ErrorState error={entityList.error} onRetry={entityList.reload} />
  if (graph.error) return <ErrorState error={graph.error} onRetry={graph.reload} />

  const entityOptions = entityList.data?.items || []
  const selectedNode = selectedElement?.kind === 'node' ? selectedElement.item : null
  const selectedEdge = selectedElement?.kind === 'edge' ? selectedElement.item : null
  const selectedNodeEdges = selectedNode
    ? edges.filter((edge) => edge.source === selectedNode.id || edge.target === selectedNode.id)
    : []
  const edgeSource = selectedEdge && nodes.find((node) => node.id === selectedEdge.source)
  const edgeTarget = selectedEdge && nodes.find((node) => node.id === selectedEdge.target)
  const availableTypes = [...new Set(entityOptions.map((item) => item.type).filter(Boolean))].sort()

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Interactive Attack Graph</h1>
          <p className="mt-1 text-sm text-slate-500">Explore modeled asset connections and inspect why each link matters.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <label className="sr-only" htmlFor="graph-root">Starting entity</label>
          <div className="relative">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <select id="graph-root" className="field w-56 pl-9" value={entityId} onChange={chooseEntity}>
              {entityOptions.map((entity) => <option key={entity.id} value={entity.id}>{entity.name || entity.id} · {entity.id}</option>)}
            </select>
          </div>
          <label className="sr-only" htmlFor="graph-depth">Graph depth</label>
          <select id="graph-depth" className="field w-28" value={depth} onChange={(event) => setDepth(Number(event.target.value))}>
            <option value={1}>1 hop</option><option value={2}>2 hops</option><option value={3}>3 hops</option>
          </select>
          <label className="sr-only" htmlFor="graph-type">Filter entity type</label>
          <select id="graph-type" className="field w-36" value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)}>
            <option value="all">All entity types</option>
            {availableTypes.map((type) => <option key={type} value={type}>{type}</option>)}
          </select>
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800 bg-soc-900/70 px-3 py-2 text-xs">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-slate-400">
          <span className="inline-flex items-center gap-1.5"><Info size={13} className="text-cyan-400" />Click a node or link for an explanation</span>
          <span>{nodes.length} entities</span><span>{edges.length} relationships</span>
          <span className="text-amber-300/80">Synthetic prototype data</span>
        </div>
        <button className="secondary-button h-8 gap-2" onClick={() => { setSelectedElement(null); setSelectedEventId(null) }}>
          <RotateCcw size={13} /> Clear selection
        </button>
      </div>

      <div className="grid min-h-[620px] gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
        <section className="panel overflow-hidden">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-slate-800 px-4 py-3 text-[10px] text-slate-400">
            {[
              ['User', '#60a5fa'], ['Host', '#22d3ee'], ['Server', '#a78bfa'],
              ['Application', '#34d399'], ['IP address', '#f59e0b'], ['Incident', '#f87171'],
            ].map(([label, color]) => <span key={label} className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} />{label}</span>)}
          </div>
          {nodes.length ? (
            <div className="h-[560px]">
              <ReactFlow
                nodes={nodes}
                edges={edges}
                nodeTypes={nodeTypes}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                onNodeClick={onNodeClick}
                onEdgeClick={onEdgeClick}
                onInit={setFlowInstance}
                fitView
                fitViewOptions={{ padding: 0.25 }}
                minZoom={0.25}
                maxZoom={1.8}
              >
                <Background color="#1e293b" gap={20} />
                <Controls />
                <MiniMap bgColor="#0d1623" nodeStrokeColor="#0a1019" nodeBorderRadius={3} nodeColor={(node) => ({
                  User: '#60a5fa', Host: '#22d3ee', Server: '#a78bfa',
                  Application: '#34d399', IPAddress: '#f59e0b', Incident: '#f87171',
                }[node.data?.type] || '#64748b')} maskColor="rgba(7,11,18,.75)" />
              </ReactFlow>
            </div>
          ) : (
            <div className="grid h-[560px] place-items-center px-6 text-center">
              <div><AlertCircle className="mx-auto mb-2 text-slate-500" /><div className="text-sm font-medium">No entities match this filter</div><div className="mt-1 text-xs text-slate-500">Choose another entity type or increase the graph depth.</div></div>
            </div>
          )}
        </section>

        <aside className="panel max-h-[620px] overflow-auto p-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div><h2 className="font-semibold">Explainability</h2><p className="mt-1 text-[11px] text-slate-500">{personasLabel(persona)}</p></div>
            {selectedElement && <span className="badge bg-cyan-400/10 text-cyan-200 ring-cyan-400/20">{selectedElement.kind}</span>}
          </div>
          {selectedNode ? (
            <div className="space-y-4 pt-4">
              <div>
                <div className="text-xs uppercase tracking-wider text-slate-500">Selected entity</div>
                <div className="mt-1 break-words font-semibold">{selectedNode.data.name || selectedNode.id}</div>
                <div className="mt-1 break-all text-xs text-slate-500">{selectedNode.data.type} · {selectedNode.id}</div>
              </div>
              <div className="explanation-card">
                <div className="text-[10px] font-bold uppercase tracking-wider text-cyan-300">What this means</div>
                <p className="mt-2 text-xs leading-5 text-slate-300">{getEntityExplanation(selectedNode, selectedNodeEdges, nodes, persona)}</p>
              </div>
              <div>
                <div className="mb-2 flex items-center justify-between">
                  <h3 className="text-xs font-semibold">Related detections</h3>
                  <span className="text-[10px] text-slate-500">{relatedEvents.length}</span>
                </div>
                {threats.error ? <p className="text-xs text-red-300">Detections unavailable: {threats.error.message}</p> : relatedEvents.length ? (
                  <div className="space-y-2">
                    {relatedEvents.slice(0, 5).map((event) => (
                      <button key={event.id} onClick={() => setSelectedEventId(event.id)} className={`w-full rounded-lg border p-2.5 text-left ${selectedEventId === event.id ? 'border-cyan-400/40 bg-cyan-400/[0.06]' : 'border-slate-800 hover:bg-slate-800/50'}`}>
                        <span className="flex items-center justify-between gap-2"><span className="truncate text-xs font-medium">{event.description || event.category}</span><SeverityBadge severity={event.severity} /></span>
                        <span className="mt-1 block text-[10px] text-slate-500">{event.id} · {event.detection_timestamp || 'time unavailable'}</span>
                      </button>
                    ))}
                  </div>
                ) : <p className="text-xs leading-5 text-slate-500">No detections linked to this entity in the loaded prototype events.</p>}
              </div>
              {selectedEventId && (
                <div className="rounded-lg border border-slate-800 bg-soc-950 p-3">
                  <div className="text-xs font-semibold">Evidence context · {selectedEventId}</div>
                  {eventDetail.loading ? <p className="mt-2 text-xs text-slate-500">Loading evidence...</p> : eventDetail.error ? (
                    <p className="mt-2 text-xs text-red-300">{eventDetail.error.message}</p>
                  ) : (
                    <p className="mt-2 text-xs leading-5 text-slate-400">{eventDetail.data?.evidence?.description || eventDetail.data?.explanation || 'No evidence description is available.'}</p>
                  )}
                </div>
              )}
              <div>
                <h3 className="mb-2 text-xs font-semibold">Visible relationships</h3>
                <div className="space-y-2">
                  {selectedNodeEdges.slice(0, 6).map((edge) => (
                    <button key={edge.id} onClick={() => setSelectedElement({ kind: 'edge', item: edge })} className="flex w-full items-center gap-2 rounded-md p-2 text-left text-[10px] text-slate-400 hover:bg-slate-800/60">
                      <ArrowDownRight size={13} className="shrink-0 text-cyan-400" /><span className="truncate">{edge.data?.type || edge.data?.relationship_type || edge.label}</span><span className="ml-auto shrink-0">{edge.source === selectedNode.id ? 'outgoing' : 'incoming'}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          ) : selectedEdge ? (
            <div className="space-y-4 pt-4">
              <div><div className="text-xs uppercase tracking-wider text-slate-500">Relationship</div><div className="mt-1 font-semibold">{selectedEdge.data?.type || selectedEdge.data?.relationship_type || selectedEdge.label}</div></div>
              <div className="explanation-card"><div className="text-[10px] font-bold uppercase tracking-wider text-cyan-300">Why this link is shown</div><p className="mt-2 text-xs leading-5 text-slate-300">{getRelationshipExplanation(selectedEdge, edgeSource, edgeTarget, persona)}</p></div>
              <div className="space-y-2 text-xs"><div><span className="text-slate-500">From </span>{edgeSource?.data.name || selectedEdge.source}</div><div><span className="text-slate-500">To </span>{edgeTarget?.data.name || selectedEdge.target}</div><div><span className="text-slate-500">Relationship ID </span><span className="break-all">{selectedEdge.id}</span></div></div>
            </div>
          ) : (
            <div className="pt-8 text-center">
              <Info className="mx-auto mb-3 text-slate-600" size={20} />
              <p className="text-sm font-medium text-slate-300">Select a graph item</p>
              <p className="mx-auto mt-2 max-w-[230px] text-xs leading-5 text-slate-500">Click a node to see its context and linked detections, or click a relationship to inspect its direction and type.</p>
              <div className="mt-5 rounded-lg border border-slate-800 bg-soc-950 p-3 text-left text-[10px] leading-5 text-slate-500">
                <div className="font-semibold text-slate-400">Reading the graph</div>
                <div>• Arrows show recorded source → target direction.</div>
                <div>• Hop depth controls the neighborhood size.</div>
                <div>• Connections are not proof of compromise.</div>
              </div>
            </div>
          )}
        </aside>
      </div>
    </div>
  )
}

function personasLabel(persona) {
  return {
    analyst: 'Analyst view · evidence and relationships',
    executive: 'Executive view · impact summary',
    operator: 'Operator view · affected assets',
  }[persona] || 'Analyst view'
}
