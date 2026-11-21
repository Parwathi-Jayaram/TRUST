import assert from 'node:assert/strict'
import test from 'node:test'

import {
  normalizeAttackPaths,
  normalizeRecentActivity,
  provenanceLabel,
  selectGraphEntity,
} from '../src/utils/integrationData.js'

test('recent activity merges events and investigations by timestamp', () => {
  const result = normalizeRecentActivity({
    events: [{
      event_id: 'EVT-1',
      event_time: '2026-11-20T10:00:00Z',
      is_synthetic: true,
    }],
    investigations: [{
      investigation_id: 'INV-1',
      title: 'Review event',
      status: 'OPEN',
      updated_at: '2026-11-20T11:00:00Z',
      is_synthetic: true,
    }],
  })

  assert.deepEqual(result.items.map((item) => item.id), ['INV-1', 'EVT-1'])
  assert.equal(result.items[0].activity_type, 'investigation')
  assert.equal(result.items[0].is_synthetic, true)
  assert.equal(result.items[1].is_synthetic, true)
})

test('recent activity preserves supplied fixture items and unknown provenance', () => {
  const result = normalizeRecentActivity({
    items: [{ event_id: 'EVT-2', description: 'Existing fixture item' }],
  })

  assert.equal(result.items[0].id, 'EVT-2')
  assert.equal(result.items[0].description, 'Existing fixture item')
  assert.equal(result.items[0].is_synthetic, undefined)
})

test('graph entity selection uses an existing requested entity or first available', () => {
  const entities = [{ id: 'HOST-1' }, { id: 'HOST-2' }]

  assert.equal(selectGraphEntity(entities, 'HOST-2').id, 'HOST-2')
  assert.equal(selectGraphEntity(entities, 'missing').id, 'HOST-1')
  assert.equal(selectGraphEntity([], ''), null)
})

test('attack path adapter normalizes its entities and directed relationships', () => {
  const result = normalizeAttackPaths({
    total_paths: 1,
    paths: [{
      nodes: [
        { labels: ['Entity'], properties: { id: 'A', name: 'Source' } },
        { labels: ['Entity'], properties: { id: 'B', name: 'Target' } },
      ],
      relationships: [{
        type: 'CONNECTS_TO',
        source_id: 'A',
        target_id: 'B',
      }],
    }],
  })

  assert.equal(result.total_paths, 1)
  assert.deepEqual(result.paths[0].nodes.map((node) => node.id), ['A', 'B'])
  assert.deepEqual(
    [result.paths[0].relationships[0].source, result.paths[0].relationships[0].target],
    ['A', 'B'],
  )
})

test('provenance labels distinguish synthetic, explicitly unmarked, and unknown', () => {
  assert.equal(provenanceLabel(true), 'Synthetic')
  assert.equal(provenanceLabel(false), 'Not marked synthetic')
  assert.equal(provenanceLabel(undefined), 'Provenance unavailable')
})
