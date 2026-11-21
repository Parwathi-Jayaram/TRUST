import { Bell, ChevronDown, CircleHelp, Radio } from 'lucide-react'

export default function Navbar() {
  return (
    <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-slate-800/80 bg-soc-950/95 px-4 backdrop-blur md:px-6">
      <div className="flex items-center gap-2 text-xs text-slate-400">
        <span className="relative flex h-2 w-2">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-30" />
          <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
        </span>
        <span>Systems operational</span>
        <span className="ml-1 hidden text-slate-600 md:inline">•</span>
        <span className="hidden md:inline">Neo4j graph connected</span>
      </div>
      <div className="flex items-center gap-2">
        <button className="icon-button" title="Help"><CircleHelp size={17} /></button>
        <button className="icon-button relative" title="Alerts">
          <Bell size={17} /><span className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-red-400" />
        </button>
        <button className="ml-1 flex items-center gap-2 rounded-lg border border-slate-800 bg-soc-900 px-2 py-1.5">
          <div className="grid h-7 w-7 place-items-center rounded-md bg-slate-700 text-xs font-bold">AR</div>
          <div className="hidden text-left sm:block">
            <div className="text-xs font-semibold">Alex Rivera</div>
            <div className="text-[10px] text-slate-500">Tier 2 Analyst</div>
          </div>
          <ChevronDown size={14} className="text-slate-500" />
        </button>
      </div>
    </header>
  )
}
