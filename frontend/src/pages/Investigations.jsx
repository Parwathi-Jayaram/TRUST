import { useRef, useState } from 'react'
import { FileText, LoaderCircle } from 'lucide-react'
import { ErrorState, LoadingState, ProvenanceBadge, SeverityBadge } from '../components/Common'
import { useApi } from '../hooks/useApi'
import { api } from '../services/api'

export default function Investigations() {
  const investigations = useApi(api.investigations)
  const [selectedId, setSelectedId] = useState(null)
  const [note, setNote] = useState('')
  const [pathSourceId, setPathSourceId] = useState('')
  const [pathTargetId, setPathTargetId] = useState('')
  const [attackPaths, setAttackPaths] = useState(null)
  const [attackPathError, setAttackPathError] = useState(null)
  const [attackPathLoading, setAttackPathLoading] = useState(false)
  const attackPathRequestId = useRef(0)
  const [reportSnapshot, setReportSnapshot] = useState(null)
  const [reportSnapshotError, setReportSnapshotError] = useState(null)
  const [reportSnapshotLoading, setReportSnapshotLoading] = useState(false)
  const reportSnapshotRequestId = useRef(0)
  const selected = useApi(() => selectedId ? api.investigation(selectedId) : Promise.resolve(null), [selectedId])

  function selectInvestigation(id) {
    attackPathRequestId.current += 1
    reportSnapshotRequestId.current += 1
    setSelectedId(id)
    setPathSourceId('')
    setPathTargetId('')
    setAttackPaths(null)
    setAttackPathError(null)
    setAttackPathLoading(false)
    setReportSnapshot(null)
    setReportSnapshotError(null)
    setReportSnapshotLoading(false)
  }

  async function addNote() {
    if (!selectedId || !note.trim()) return
    await api.addNote(selectedId, { note: note.trim() })
    setNote('')
    selected.setData(await api.investigation(selectedId))
  }

  async function findAttackPaths() {
    if (!selectedId || !pathSourceId || !pathTargetId || pathSourceId === pathTargetId) return
    const requestId = ++attackPathRequestId.current
    setAttackPathLoading(true)
    setAttackPathError(null)
    setAttackPaths(null)
    try {
      const result = await api.investigationAttackPaths(
        selectedId,
        pathSourceId,
        pathTargetId,
      )
      if (attackPathRequestId.current === requestId) setAttackPaths(result)
    } catch (error) {
      if (attackPathRequestId.current === requestId) setAttackPathError(error)
    } finally {
      if (attackPathRequestId.current === requestId) setAttackPathLoading(false)
    }
  }

  async function captureReportSnapshot() {
    if (!selectedId) return
    const requestId = ++reportSnapshotRequestId.current
    setReportSnapshotLoading(true)
    setReportSnapshotError(null)
    setReportSnapshot(null)
    try {
      const result = await api.createInvestigationReportSnapshot(selectedId)
      if (reportSnapshotRequestId.current === requestId) {
        setReportSnapshot(result)
      }
    } catch (error) {
      if (reportSnapshotRequestId.current === requestId) {
        setReportSnapshotError(error)
      }
    } finally {
      if (reportSnapshotRequestId.current === requestId) {
        setReportSnapshotLoading(false)
      }
    }
  }

  async function reloadReportSnapshot() {
    if (!selectedId || !reportSnapshot?.report_id) return
    const requestId = ++reportSnapshotRequestId.current
    setReportSnapshotLoading(true)
    setReportSnapshotError(null)
    try {
      const result = await api.investigationReportSnapshot(
        selectedId,
        reportSnapshot.report_id,
      )
      if (reportSnapshotRequestId.current === requestId) {
        setReportSnapshot(result)
      }
    } catch (error) {
      if (reportSnapshotRequestId.current === requestId) {
        setReportSnapshotError(error)
      }
    } finally {
      if (reportSnapshotRequestId.current === requestId) {
        setReportSnapshotLoading(false)
      }
    }
  }

  if (investigations.loading) return <LoadingState />
  if (investigations.error) return <ErrorState error={investigations.error} />
  const items = investigations.data?.items || []
  const investigationEntityIds = Array.isArray(selected.data?.entity_ids)
    ? selected.data.entity_ids
    : []
  return (
    <div className="space-y-5">
      <div className="flex items-end justify-between"><div><h1 className="text-xl font-semibold">Investigation Workspace</h1><p className="mt-1 text-sm text-slate-500">Evidence, findings and analyst audit trail</p></div></div>
      <div className="grid gap-4 xl:grid-cols-[300px_1fr]">
        <div className="panel overflow-hidden">
          {items.length ? items.map((item) => (
            <button key={item.id} onClick={() => selectInvestigation(item.id)} className={`w-full border-b border-slate-800 px-4 py-4 text-left hover:bg-slate-800/40 ${selectedId === item.id ? 'bg-cyan-400/[0.04]' : ''}`}>
              <div className="font-medium">{item.title || item.id}</div>
              <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-500">
                <span>{item.status} • {item.updated_at || '—'}</span>
                <ProvenanceBadge isSynthetic={item.is_synthetic} />
              </div>
            </button>
          )) : <div className="py-16 text-center text-sm text-slate-500">No investigations found</div>}
        </div>
        <div className="panel p-5">
          {!selectedId ? <div className="grid h-64 place-items-center text-sm text-slate-500">Open an investigation to review evidence</div> : selected.loading ? <LoadingState /> : selected.error ? <ErrorState error={selected.error} /> : (
            <div>
              <div className="flex items-start justify-between"><div><h2 className="text-lg font-semibold">{selected.data?.title || selectedId}</h2><div className="mt-1 text-xs text-slate-500">{selected.data?.id}</div><div className="mt-2"><ProvenanceBadge isSynthetic={selected.data?.is_synthetic} /></div></div><SeverityBadge severity={selected.data?.status} /></div>
              <div className="mt-5">
                <h3 className="text-sm font-semibold">Findings</h3>
                <p className="mt-2 rounded-lg bg-soc-950 p-3 text-sm leading-6 text-slate-300">{selected.data?.findings || 'No findings recorded.'}</p>
              </div>
              <details className="mt-5 rounded-lg border border-slate-800 bg-soc-950 p-4">
                <summary className="cursor-pointer text-sm font-semibold">Attack path analysis</summary>
                <p className="mt-2 text-xs leading-5 text-slate-400">
                  Explore directed graph links between entities in this investigation.
                  A possible path is not proof that an attacker traversed it.
                </p>
                {investigationEntityIds.length < 2 ? (
                  <p className="mt-3 text-sm text-slate-500">
                    Link at least two entities to this investigation to explore paths.
                  </p>
                ) : (
                  <>
                    <div className="mt-3 grid gap-3 md:grid-cols-2">
                      <label className="space-y-1 text-xs text-slate-400">
                        Source entity
                        <select
                          className="field w-full"
                          onChange={(event) => {
                            attackPathRequestId.current += 1
                            setPathSourceId(event.target.value)
                            setAttackPaths(null)
                            setAttackPathError(null)
                            setAttackPathLoading(false)
                          }}
                          value={pathSourceId}
                        >
                          <option value="">Select a source</option>
                          {investigationEntityIds.map((entityId) => (
                            <option key={entityId} value={entityId}>{entityId}</option>
                          ))}
                        </select>
                      </label>
                      <label className="space-y-1 text-xs text-slate-400">
                        Target entity
                        <select
                          className="field w-full"
                          onChange={(event) => {
                            attackPathRequestId.current += 1
                            setPathTargetId(event.target.value)
                            setAttackPaths(null)
                            setAttackPathError(null)
                            setAttackPathLoading(false)
                          }}
                          value={pathTargetId}
                        >
                          <option value="">Select a target</option>
                          {investigationEntityIds.map((entityId) => (
                            <option key={entityId} value={entityId}>{entityId}</option>
                          ))}
                        </select>
                      </label>
                    </div>
                    <button
                      className="primary-button mt-3"
                      disabled={
                        attackPathLoading
                        || !pathSourceId
                        || !pathTargetId
                        || pathSourceId === pathTargetId
                      }
                      onClick={findAttackPaths}
                      type="button"
                    >
                      {attackPathLoading ? 'Searching graph...' : 'Find paths'}
                    </button>
                    {attackPathError && (
                      <p className="mt-3 text-sm text-red-300" role="alert">
                        {attackPathError.message}
                      </p>
                    )}
                    {attackPaths && (
                      <div className="mt-4 space-y-3">
                        <p className="text-sm text-slate-300">
                          {attackPaths.total_paths
                            ? `${attackPaths.total_paths} path${attackPaths.total_paths === 1 ? '' : 's'} found`
                            : 'No directed paths found for these entities.'}
                        </p>
                        {attackPaths.paths.map((path, index) => (
                          <div key={`${path.depth}-${index}`} className="rounded-lg border border-slate-800 p-3">
                            <p className="mb-2 text-xs font-semibold text-slate-400">
                              Path {index + 1} · {path.depth} hop{path.depth === 1 ? '' : 's'}
                            </p>
                            <div className="flex flex-wrap items-center gap-2 text-xs">
                              {path.nodes.map((node, nodeIndex) => (
                                <span key={`${node.id}-${nodeIndex}`} className="contents">
                                  <span className="rounded bg-slate-800 px-2 py-1 text-slate-200">
                                    {node.properties?.name || node.properties?.type || node.id}
                                  </span>
                                  {path.relationships[nodeIndex] && (
                                    <span className="text-cyan-300">
                                      —{path.relationships[nodeIndex].type}→
                                    </span>
                                  )}
                                </span>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                )}
              </details>
              <details className="mt-5 rounded-lg border border-slate-800 bg-soc-950 p-4">
                <summary className="cursor-pointer text-sm font-semibold">Report data snapshot</summary>
                <p className="mt-2 text-xs leading-5 text-slate-400">
                  Capture and review a backend snapshot of this investigation.
                  It preserves the captured data and does not generate an AI explanation.
                </p>
                <div className="mt-3 flex flex-wrap gap-2">
                  <button
                    className="primary-button inline-flex items-center gap-2"
                    disabled={reportSnapshotLoading}
                    onClick={captureReportSnapshot}
                    type="button"
                  >
                    {reportSnapshotLoading
                      ? <LoaderCircle className="animate-spin" size={16} />
                      : <FileText size={16} />}
                    {reportSnapshotLoading ? 'Capturing snapshot...' : 'Capture report snapshot'}
                  </button>
                  {reportSnapshot?.report_id && (
                    <button
                      className="secondary-button"
                      disabled={reportSnapshotLoading}
                      onClick={reloadReportSnapshot}
                      type="button"
                    >
                      Reload stored snapshot
                    </button>
                  )}
                </div>
                {reportSnapshotError && (
                  <p className="mt-3 text-sm text-red-300" role="alert">
                    {reportSnapshotError.message}
                  </p>
                )}
                {reportSnapshot && (
                  <div className="mt-4 space-y-4" aria-live="polite">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <div className="text-sm font-semibold text-slate-200">
                          Snapshot {reportSnapshot.report_id}
                        </div>
                        <div className="mt-1 text-xs text-slate-500">
                          Captured {reportSnapshot.snapshot_captured_at}
                        </div>
                      </div>
                      <ProvenanceBadge isSynthetic={reportSnapshot.provenance?.is_synthetic} />
                    </div>
                    {reportSnapshot.partial && (
                      <p className="rounded-lg border border-amber-500/20 bg-amber-500/[0.05] p-3 text-sm text-amber-200">
                        Partial report: one or more data sources are unavailable or not implemented.
                      </p>
                    )}
                    <p className="rounded-lg bg-slate-900 p-3 text-sm leading-6 text-slate-300">
                      {reportSnapshot.executive_summary?.text || 'No summary is available.'}
                    </p>
                    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                      <div className="rounded-lg border border-slate-800 p-3">
                        <div className="text-xs text-slate-500">Risk assessment</div>
                        <div className="mt-1 text-sm text-slate-200">
                          {reportSnapshot.risk_assessment?.score == null
                            ? reportSnapshot.risk_assessment?.status || 'Unavailable'
                            : `${reportSnapshot.risk_assessment.score} (${reportSnapshot.risk_assessment.level})`}
                        </div>
                        <div className="mt-1 text-xs text-slate-500">
                          Member 4 investigation-priority score
                        </div>
                      </div>
                      <div className="rounded-lg border border-slate-800 p-3">
                        <div className="text-xs text-slate-500">Graph sections</div>
                        <div className="mt-1 text-sm text-slate-200">
                          {reportSnapshot.graph?.subgraphs?.length || 0}
                        </div>
                        <div className="mt-1 text-xs text-slate-500">
                          {reportSnapshot.graph?.status || 'Unavailable'}
                        </div>
                      </div>
                      <div className="rounded-lg border border-slate-800 p-3">
                        <div className="text-xs text-slate-500">Evidence records</div>
                        <div className="mt-1 text-sm text-slate-200">
                          {reportSnapshot.evidence?.length || 0}
                        </div>
                        <div className="mt-1 text-xs text-slate-500">
                          {reportSnapshot.findings?.length || 0} event assessments
                        </div>
                      </div>
                      <div className="rounded-lg border border-slate-800 p-3">
                        <div className="text-xs text-slate-500">Unavailable features</div>
                        <div className="mt-1 text-sm text-slate-200">
                          Threat intelligence: {reportSnapshot.threat_intelligence?.status || 'unknown'}
                        </div>
                        <div className="mt-1 text-xs text-slate-500">
                          AI explanation: {reportSnapshot.ai_explanation?.status || 'unknown'}
                        </div>
                      </div>
                    </div>
                    {(reportSnapshot.findings || []).map((finding) => (
                      <div key={finding.finding_id} className="rounded-lg border border-slate-800 p-3">
                        <div className="text-sm font-semibold text-slate-200">
                          Event {finding.event_id} · {finding.event_type || 'unknown type'}
                        </div>
                        <div className="mt-2 grid gap-2 text-xs text-slate-400 sm:grid-cols-3">
                          <span>Source evidence: {finding.source_evidence_status || 'unknown'}</span>
                          <span>Model signal: {finding.model_generated_signal || 'unavailable'}</span>
                          <span>Prediction: {finding.prediction || 'unavailable'}</span>
                        </div>
                        {!!finding.evidence_ids?.length && (
                          <div className="mt-2 text-xs text-slate-500">
                            Evidence: {finding.evidence_ids.join(', ')}
                          </div>
                        )}
                      </div>
                    ))}
                    {!!reportSnapshot.limitations?.length && (
                      <div>
                        <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                          Limitations
                        </h4>
                        <ul className="mt-2 list-disc space-y-1 pl-5 text-xs text-slate-400">
                          {reportSnapshot.limitations.map((limitation, index) => (
                            <li key={`${index}-${limitation}`}>{limitation}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </details>
              <div className="mt-5">
                <h3 className="text-sm font-semibold">Analyst notes</h3>
                <div className="mt-2 space-y-2">
                  {(selected.data?.notes || []).map((entry, index) => <div key={entry.id || index} className="border-l-2 border-cyan-400/40 pl-3 text-sm text-slate-300"><div>{entry.note}</div><div className="mt-1 text-xs text-slate-500">{entry.created_at || ''}</div></div>)}
                </div>
              </div>
              <div className="mt-5 flex gap-2"><input className="field flex-1" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add an investigation note..." /><button className="primary-button" onClick={addNote}>Add note</button></div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
