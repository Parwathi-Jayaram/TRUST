export function normalizeEntity(entity) {
  const properties = entity.properties || entity
  return {
    ...entity,
    ...properties,
    id: entity.id || properties.id,
    name: entity.name || properties.name,
    type: entity.type || properties.type || entity.labels?.[0],
    properties,
  }
}

export function normalizeRelationship(relationship) {
  const properties = relationship.properties || {}
  return {
    ...relationship,
    id: relationship.id || properties.relationship_id,
    source: relationship.source || relationship.source_id,
    target: relationship.target || relationship.target_id,
    type: relationship.type || properties.relationship_type,
  }
}

export function selectGraphEntity(entities, selectedId) {
  if (!Array.isArray(entities)) return null
  const available = entities.filter((entity) => entity?.id !== undefined && entity?.id !== null)
  return available.find((entity) => String(entity.id) === String(selectedId))
    || available[0]
    || null
}

function activityTime(item) {
  const timestamp = item.timestamp || item.event_time || item.updated_at
  const parsed = Date.parse(timestamp || '')
  return Number.isNaN(parsed) ? Number.NEGATIVE_INFINITY : parsed
}

function normalizeActivityItem(item) {
  return {
    ...item,
    id: item.id || item.event_id || item.investigation_id,
    description: item.description || item.event_type || item.title,
    timestamp: item.timestamp || item.event_time || item.updated_at,
  }
}

export function normalizeRecentActivity(data) {
  const events = (data.events || []).map((event) => ({
    ...normalizeActivityItem(event),
    activity_type: 'event',
  }))
  const investigations = (data.investigations || []).map((investigation) => ({
    ...normalizeActivityItem(investigation),
    activity_type: 'investigation',
  }))
  const items = Array.isArray(data.items)
    ? data.items.map(normalizeActivityItem)
    : [...events, ...investigations]

  return {
    ...data,
    items: items.sort((left, right) => activityTime(right) - activityTime(left)),
  }
}

export function normalizeAttackPaths(data) {
  return {
    ...data,
    paths: (data.paths || []).map((path) => ({
      ...path,
      nodes: (path.nodes || []).map(normalizeEntity),
      relationships: (path.relationships || []).map(normalizeRelationship),
    })),
  }
}

export function provenanceLabel(isSynthetic) {
  if (isSynthetic === true) return 'Synthetic'
  if (isSynthetic === false) return 'Not marked synthetic'
  return 'Provenance unavailable'
}
