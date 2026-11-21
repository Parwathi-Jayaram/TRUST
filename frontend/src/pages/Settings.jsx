export default function Settings() {
  return (
    <div className="space-y-5">
      <div><h1 className="text-xl font-semibold">System Settings</h1><p className="mt-1 text-sm text-slate-500">API and analyst workspace configuration</p></div>
      <div className="panel max-w-2xl p-5">
        <h2 className="font-semibold">Backend connection</h2>
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <label className="text-xs text-slate-500">API base URL<input className="field mt-2 w-full" readOnly value={import.meta.env.VITE_API_BASE_URL || '/api'} /></label>
          <label className="text-xs text-slate-500">Graph traversal limit<input className="field mt-2 w-full" readOnly value="3 hops" /></label>
        </div>
        <div className="mt-5 rounded-lg border border-amber-500/20 bg-amber-500/[0.05] p-3 text-xs leading-5 text-amber-200/80">
          Containment controls are simulation-only. The frontend never performs network isolation or account changes directly.
        </div>
      </div>
    </div>
  )
}
