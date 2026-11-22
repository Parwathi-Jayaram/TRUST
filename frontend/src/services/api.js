import {
  normalizeAttackPaths,
  normalizeEntity,
  normalizeRecentActivity,
  normalizeRelationship,
} from '../utils/integrationData'

const BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api'
let apiMode = 'unknown'
const TOKEN_STORAGE_KEY = 'trustrail_api_token'

export function getApiToken() {
  return sessionStorage.getItem(TOKEN_STORAGE_KEY) || ''
}

export function setApiToken(token) {
  sessionStorage.setItem(TOKEN_STORAGE_KEY, token)
}

export function clearApiToken() {
  sessionStorage.removeItem(TOKEN_STORAGE_KEY)
}

async function requestResponse(path, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers,
  }
  const token = getApiToken()
  if (token) headers.Authorization = `Bearer ${token}`

  let response
  try {
    response = await fetch(`${BASE_URL}${path}`, {
      ...options,
      headers,
    })
  } catch (error) {
    throw new Error(
      `Cannot reach the TRUSTRAIL backend at ${BASE_URL}. Start the FastAPI server on port 8000.`,
    )
  }
  if (response.status === 401) {
    clearApiToken()
    window.dispatchEvent(new Event('trustrail-api-unauthorized'))
  }
  if (!response.ok) {
    let detail = `Request failed (${response.status})`
    try {
      const body = await response.json()
      const errorDetail = body.detail || body.message
      detail = Array.isArray(errorDetail)
        ? errorDetail.map((item) => item.msg || JSON.stringify(item)).join('; ')
        : typeof errorDetail === 'string' ? errorDetail : detail
    } catch {}
    throw new Error(detail)
  }
  return response
}

async function request(path, options = {}) {
  const response = await requestResponse(path, options)
  const body = await response.json()
  const isEnvelope = body?.success === true && 'data' in body
  apiMode = isEnvelope ? 'neo4j' : 'fixture'
  return isEnvelope ? body.data : body
}

function normalizeIncident(incident) {
  return {
    ...incident,
    severity: incident.severity || incident.priority,
    associated_alerts: incident.associated_alerts || (incident.related_event_id ? [incident.related_event_id] : []),
  }
}

function normalizeInvestigation(investigation) {
  return {
    ...investigation,
    notes: (investigation.notes || []).map((entry) => ({
      ...entry,
      note: entry.note || entry.content,
    })),
  }
}

function normalizeThreat(threat) {
  const id = threat.id || threat.threat_id || threat.event_id
  return {
    ...threat,
    id,
    threat_id: id,
    category: threat.category || threat.event_type || threat.attack_category,
    entity_id: threat.entity_id || threat.source_entity_id,
    associated_entities: threat.associated_entities || (threat.entity_id ? [threat.entity_id] : []),
    detection_timestamp: threat.detection_timestamp || threat.event_time,
  }
}

function normalizeSubgraph(graph) {
  const nodes = (graph.nodes || []).map(normalizeEntity)
  const root = graph.root ? normalizeEntity(graph.root) : null
  if (root && !nodes.some((node) => String(node.id) === String(root.id))) nodes.unshift(root)
  return {
    ...graph,
    nodes,
    edges: (graph.edges || graph.relationships || []).map(normalizeRelationship),
  }
}

export const api = {
  health: async () => request('/health'),
  dashboard: async () => {
    const data = await request('/dashboard/overview')
    return data.counts
      ? { ...data.counts, unavailable_metrics: data.unavailable_metrics || {} }
      : data
  },
  threatDistribution: async () => {
    const data = await request('/dashboard/threat-distribution')
    if (data.by_severity) return data
    const by_severity = {}
    for (const item of data.distribution || []) {
      by_severity[item.severity] = (by_severity[item.severity] || 0) + item.count
    }
    return { ...data, by_severity }
  },
  recentActivity: async () => {
    const data = await request('/dashboard/recent-activity')
    return normalizeRecentActivity(data)
  },
  graphEntities: async (params = {}) => {
    const query = new URLSearchParams(params).toString()
    const data = await request('/graph/entities' + (query ? '?' + query : ''))
    return { ...data, items: (data.items || data.entities || []).map(normalizeEntity) }
  },
  graphSubgraph: async (id, depth = 2) => {
    const data = await request('/graph/subgraph/' + encodeURIComponent(id) + '?depth=' + depth)
    return normalizeSubgraph(data)
  },
  attackPaths: async (sourceId, targetId, depth = 3, limit = 20) => {
    const query = new URLSearchParams({ depth: String(depth), limit: String(limit) })
    const data = await request(
      '/graph/attack-paths/' + encodeURIComponent(sourceId)
        + '/' + encodeURIComponent(targetId) + '?' + query,
    )
    return normalizeAttackPaths(data)
  },
  graphEntity: async (id) => normalizeEntity(await request('/graph/entity/' + encodeURIComponent(id))),
  threats: async (params = {}) => {
    const query = new URLSearchParams({ limit: '20' }).toString()
    const data = await request('/threats' + (query ? '?' + query : ''))
    const items = (data.items || data.threats || []).map(normalizeThreat)
    return { ...data, items: params.severity ? items.filter((item) => item.severity?.toLowerCase() === params.severity.toLowerCase()) : items }
  },
  threat: async (id) => {
    const threat = normalizeThreat(await request('/threats/' + encodeURIComponent(id)))
    const evidence = await api.threatEvidence(id)
    return { ...threat, evidence: evidence.items[0] || null }
  },
  threatEvidence: async (id) => {
    const data = await request('/threats/evidence/' + encodeURIComponent(id))
    return { ...data, items: data.items || data.evidence || [] }
  },
  blastRadius: async (id, depth = 3) => {
    const data = await request('/blast-radius/' + encodeURIComponent(id) + '?depth=' + depth)
    const relationships = (data.edges || data.relationships || []).map(normalizeRelationship)
    const entities = (data.affected_entities || data.entities || []).map(normalizeEntity)
    const nodes = data.nodes
      ? data.nodes.map(normalizeEntity)
      : entities
    const source = data.source_entity ? normalizeEntity(data.source_entity) : null
    return {
      ...data,
      nodes: source && !nodes.some((node) => String(node.id) === String(source.id)) ? [source, ...nodes] : nodes,
      edges: relationships,
      affected_entities: entities,
      reachable_entities_count: data.reachable_entities_count ?? data.reachable_entity_count,
      critical_assets_count: data.critical_assets_count ?? data.critical_infrastructure_exposure,
    }
  },
  incidents: async () => {
    const data = await request('/incidents')
    return { ...data, items: (data.items || data.incidents || []).map(normalizeIncident) }
  },
  incident: async (id) => normalizeIncident(await request('/incidents/' + encodeURIComponent(id))),
  containment: async (payload) => {
    if (apiMode === 'fixture') {
      return request('/containment/simulate', {
        method: 'POST',
        body: JSON.stringify(payload),
      })
    }

    const graph = await api.graphSubgraph(payload.entity_id, payload.depth)
    const actionTypes = {
      isolate_host: { action: 'isolate_entity', type: 'host', label: 'host' },
      disable_account: { action: 'disable_account', type: 'user', label: 'user account' },
      block_ip: { action: 'block_ip', type: 'ipaddress', label: 'IP address' },
      restrict_server: { action: 'restrict_server', type: 'server', label: 'server' },
    }
    const actions = payload.actions.map((id) => {
      const config = actionTypes[id]
      if (!config) throw new Error(`Unsupported containment action: ${id}`)
      const target = graph.nodes.find((node) => String(node.type || '').toLowerCase() === config.type)
      if (!target) throw new Error(`No related ${config.label} is available for this simulation.`)
      return { action: config.action, target_entity_id: target.id }
    })
    const data = await request('/containment/simulate', {
      method: 'POST',
      body: JSON.stringify({ source_entity_id: payload.entity_id, depth: payload.depth, actions }),
    })
    return {
      ...data,
      before: {
        reachable_entities_count: data.before.potentially_affected_entities,
        critical_assets_remaining: data.before.critical_assets_reachable,
        potentially_affected_users: data.before.users_potentially_affected,
        residual_risk: 'Baseline potential exposure',
      },
      after: {
        reachable_entities_count: data.after.remaining_exposed_entities,
        critical_assets_remaining: data.after.critical_assets_still_reachable,
        potentially_affected_users: data.after.users_still_potentially_affected,
        residual_risk: `${data.residual_exposure_percent}% of modeled exposure remains`,
      },
    }
  },
  investigations: async () => {
    const data = await request('/investigations')
    return { ...data, items: (data.items || data.investigations || []).map(normalizeInvestigation) }
  },
  createInvestigation: async (payload) => {
    const data = await request('/investigations', {
      method: 'POST',
      body: JSON.stringify({
        title: payload.title,
        alert_id: payload.alert_id || payload.event_id || null,
        entity_ids: payload.entity_ids || [],
      }),
    })
    return normalizeInvestigation(data)
  },
  investigation: async (id) => normalizeInvestigation(await request('/investigations/' + encodeURIComponent(id))),
  investigationEvidence: async (id) => {
    const data = await request('/investigations/' + encodeURIComponent(id) + '/evidence')
    return data.evidence || []
  },
  investigationTimeline: async (id) => {
    const data = await request('/investigations/' + encodeURIComponent(id) + '/timeline')
    return data.timeline || []
  },
  investigationAttackPaths: async (id, sourceId, targetId) => {
    const query = new URLSearchParams({
      source_id: sourceId,
      target_id: targetId,
    }).toString()
    return request(
      '/investigations/' + encodeURIComponent(id) + '/attack-paths?' + query,
    )
  },
  investigationReport: async (id) => {
    const response = await requestResponse(
      '/investigations/' + encodeURIComponent(id) + '/report',
      { method: 'POST' },
    )
    return {
      blob: await response.blob(),
      status: response.headers.get('X-Report-Status') || 'unknown',
    }
  },
  addNote: async (id, payload) => normalizeInvestigation(await request('/investigations/' + encodeURIComponent(id) + '/notes', {
    method: 'POST',
    body: JSON.stringify({ content: payload.content || payload.note }),
  })),
}
