export function createGraphLayout(records = [], relationships = [], rootId, typeFilter = 'all') {
  const visibleRecords = records.filter((record) => {
    const type = record.type || record.properties?.type || record.labels?.[0] || 'Entity'
    return String(record.id) === String(rootId) || typeFilter === 'all' || type.toLowerCase() === typeFilter.toLowerCase()
  })
  const visibleIds = new Set(visibleRecords.map((record) => String(record.id)))
  const visibleRelationships = relationships.filter((edge) =>
    visibleIds.has(String(edge.source)) && visibleIds.has(String(edge.target)),
  )
  const adjacency = new Map(visibleRecords.map((record) => [String(record.id), new Set()]))

  for (const edge of visibleRelationships) {
    adjacency.get(String(edge.source))?.add(String(edge.target))
    adjacency.get(String(edge.target))?.add(String(edge.source))
  }

  const levels = new Map()
  const queue = []
  if (visibleIds.has(String(rootId))) {
    levels.set(String(rootId), 0)
    queue.push(String(rootId))
  }
  while (queue.length) {
    const current = queue.shift()
    for (const neighbor of adjacency.get(current) || []) {
      if (levels.has(neighbor)) continue
      levels.set(neighbor, levels.get(current) + 1)
      queue.push(neighbor)
    }
  }
  let nextLevel = Math.max(0, ...levels.values()) + 1
  for (const record of visibleRecords) {
    if (!levels.has(String(record.id))) levels.set(String(record.id), nextLevel++)
  }

  const recordsByLevel = new Map()
  for (const record of visibleRecords) {
    const level = levels.get(String(record.id))
    if (!recordsByLevel.has(level)) recordsByLevel.set(level, [])
    recordsByLevel.get(level).push(record)
  }

  const nodes = visibleRecords.map((record) => {
    const properties = record.properties || record
    const type = record.type || properties.type || record.labels?.[0] || 'Entity'
    const level = levels.get(String(record.id))
    const peers = recordsByLevel.get(level)
    const index = peers.indexOf(record)
    return {
      id: String(record.id),
      type: 'entity',
      position: {
        x: 70 + level * 255,
        y: 80 + index * 125 - ((peers.length - 1) * 125) / 2,
      },
      data: {
        id: record.id,
        name: record.name || properties.name,
        type,
        criticality: properties.criticality,
        properties,
        level,
      },
    }
  })

  const edges = visibleRelationships.map((edge, index) => ({
    id: String(edge.id || `relationship-${index}`),
    source: String(edge.source),
    target: String(edge.target),
    type: 'smoothstep',
    animated: false,
    data: edge,
    style: { stroke: '#64748b', strokeWidth: 1.5 },
    labelStyle: { fill: '#94a3b8', fontSize: 9, fontWeight: 600 },
    labelBgStyle: { fill: '#0a1019', fillOpacity: 0.9 },
    markerEnd: { type: 'arrowclosed', color: '#64748b', width: 14, height: 14 },
  }))

  return { nodes, edges }
}
