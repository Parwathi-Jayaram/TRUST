const BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api'

async function request(path, options = {}) {
  const response = await fetch(`${BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  })
  if (!response.ok) {
    let detail = `Request failed (${response.status})`
    try {
      const body = await response.json()
      detail = body.detail || body.message || detail
    } catch {}
    throw new Error(detail)
  }
  return response.json()
}

export const api = {
  dashboard: () => request('/dashboard/overview'),
  threatDistribution: () => request('/dashboard/threat-distribution'),
  recentActivity: () => request('/dashboard/recent-activity'),
  graphEntities: (params = {}) => {
    const query = new URLSearchParams(params).toString()
    return request('/graph/entities' + (query ? '?' + query : ''))
  },
  graphSubgraph: (id, depth = 2) => request('/graph/subgraph/' + encodeURIComponent(id) + '?depth=' + depth),
  graphEntity: (id) => request('/graph/entity/' + encodeURIComponent(id)),
  threats: (params = {}) => {
    const query = new URLSearchParams(params).toString()
    return request('/threats' + (query ? '?' + query : ''))
  },
  threat: (id) => request('/threats/' + encodeURIComponent(id)),
  threatEvidence: (id) => request('/threats/evidence/' + encodeURIComponent(id)),
  blastRadius: (id, depth = 3) => request('/blast-radius/' + encodeURIComponent(id) + '?depth=' + depth),
  incidents: () => request('/incidents'),
  incident: (id) => request('/incidents/' + encodeURIComponent(id)),
  containment: (payload) => request('/containment/simulate', {
    method: 'POST',
    body: JSON.stringify(payload),
  }),
  investigations: () => request('/investigations'),
  createInvestigation: (payload) => request('/investigations', {
    method: 'POST',
    body: JSON.stringify(payload),
  }),
  investigation: (id) => request('/investigations/' + encodeURIComponent(id)),
  addNote: (id, payload) => request('/investigations/' + encodeURIComponent(id) + '/notes', {
    method: 'POST',
    body: JSON.stringify(payload),
  }),
}
