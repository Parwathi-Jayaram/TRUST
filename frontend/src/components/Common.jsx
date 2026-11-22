import { AlertCircle, LoaderCircle } from 'lucide-react'
import { provenanceLabel } from '../utils/integrationData'

export function LoadingState({ label = 'Loading operational data...' }) {
  return (
    <div className="grid min-h-52 place-items-center rounded-xl border border-slate-800 bg-soc-900">
      <div className="flex items-center gap-3 text-sm text-slate-400">
        <LoaderCircle className="animate-spin text-cyan-400" size={18} />{label}
      </div>
    </div>
  )
}

export function ErrorState({ error, onRetry }) {
  return (
    <div className="flex min-h-52 flex-col items-center justify-center rounded-xl border border-red-500/20 bg-red-500/[0.04] p-6 text-center">
      <AlertCircle className="mb-3 text-red-400" />
      <div className="font-semibold text-red-200">Unable to load data</div>
      <div className="mt-1 max-w-lg text-sm text-slate-400">{error?.message || String(error)}</div>
      {onRetry && <button className="secondary-button mt-4" onClick={onRetry}>Retry request</button>}
    </div>
  )
}

export function SeverityBadge({ severity }) {
  const value = String(severity || 'unknown').toLowerCase()
  const styles = {
    critical: 'bg-red-500/15 text-red-300 ring-red-500/30',
    high: 'bg-orange-500/15 text-orange-300 ring-orange-500/30',
    medium: 'bg-amber-500/15 text-amber-300 ring-amber-500/30',
    low: 'bg-sky-500/15 text-sky-300 ring-sky-500/30',
    info: 'bg-slate-500/15 text-slate-300 ring-slate-500/30',
  }
  return <span className={`badge ${styles[value] || styles.info}`}>{value}</span>
}

export function ProvenanceBadge({ isSynthetic }) {
  const label = provenanceLabel(isSynthetic)
  const style = isSynthetic === true
    ? 'bg-amber-500/15 text-amber-200 ring-amber-500/30'
    : isSynthetic === false
      ? 'bg-slate-500/15 text-slate-300 ring-slate-500/30'
      : 'bg-slate-700/50 text-slate-400 ring-slate-600/40'

  return <span className={`badge ${style}`} title="Based on source metadata">{label}</span>
}

export function StatCard({ label, value, icon: Icon, tone = 'cyan', detail }) {
  const toneStyles = {
    cyan: 'text-cyan-400 bg-cyan-400/10 ring-cyan-400/20',
    red: 'text-red-400 bg-red-400/10 ring-red-400/20',
    amber: 'text-amber-400 bg-amber-400/10 ring-amber-400/20',
    violet: 'text-violet-400 bg-violet-400/10 ring-violet-400/20',
  }
  return (
    <div className="panel p-4">
      <div className="flex items-start justify-between">
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">{label}</div>
          <div className="mt-2 text-3xl font-semibold tracking-tight">{value ?? '—'}</div>
          {detail && <div className="mt-1 text-xs text-slate-500">{detail}</div>}
        </div>
        {Icon && <div className={`grid h-10 w-10 place-items-center rounded-lg ring-1 ${toneStyles[tone]}`}><Icon size={19} /></div>}
      </div>
    </div>
  )
}
