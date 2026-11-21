import { NavLink } from 'react-router-dom'
import {
  Activity, AlertTriangle, Boxes, Crosshair, FlaskConical,
  LayoutDashboard, Search, Settings, ShieldCheck,
} from 'lucide-react'

const links = [
  { to: '/dashboard', label: 'Command Center', icon: LayoutDashboard },
  { to: '/threat-hunting', label: 'Threat Hunting', icon: Search },
  { to: '/attack-graph', label: 'Attack Graph', icon: Boxes },
  { to: '/blast-radius', label: 'Blast Radius', icon: Crosshair },
  { to: '/containment', label: 'Containment', icon: FlaskConical },
  { to: '/incidents', label: 'Incidents', icon: AlertTriangle },
  { to: '/investigations', label: 'Investigations', icon: Activity },
]

export default function Sidebar() {
  return (
    <aside className="fixed inset-y-0 left-0 z-40 hidden w-[248px] border-r border-slate-800/80 bg-soc-900 lg:flex lg:flex-col">
      <div className="flex h-16 items-center gap-3 border-b border-slate-800/80 px-5">
        <div className="grid h-9 w-9 place-items-center rounded-lg bg-cyan-400/10 text-cyan-400 ring-1 ring-cyan-400/30">
          <ShieldCheck size={20} />
        </div>
        <div>
          <div className="font-semibold tracking-wide">TRUSTRAIL <span className="text-cyan-400">AI</span></div>
          <div className="mt-0.5 text-[10px] font-semibold uppercase tracking-[0.24em] text-slate-500">SOC Operations</div>
        </div>
      </div>
      <nav className="flex-1 space-y-1 px-3 py-5">
        {links.map(({ to, label, icon: Icon }) => (
          <NavLink key={to} to={to} className={({ isActive }) =>
            `group flex h-11 items-center gap-3 rounded-lg px-3 text-sm transition ${
              isActive ? 'bg-cyan-400/10 text-cyan-300 ring-1 ring-inset ring-cyan-400/20' : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-100'
            }`
          }>
            <Icon size={18} />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>
      <NavLink to="/settings" className="mx-3 mb-4 flex h-11 items-center gap-3 rounded-lg px-3 text-sm text-slate-400 hover:bg-slate-800/60">
        <Settings size={18} /> System Settings
      </NavLink>
    </aside>
  )
}
