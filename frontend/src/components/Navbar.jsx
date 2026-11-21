import { useEffect, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { Bell, ChevronDown, CircleHelp, ShieldCheck, UserRound } from 'lucide-react'
import { useApi } from '../hooks/useApi'
import { personas, usePersona } from '../context/PersonaContext'
import { api } from '../services/api'

function readNotifications() {
  try {
    const stored = JSON.parse(window.localStorage.getItem('trustrial-read-notifications') || '[]')
    return new Set(Array.isArray(stored) ? stored : [])
  } catch {
    return new Set()
  }
}

function HelpDialog({ onClose }) {
  useEffect(() => {
    function onKeyDown(event) {
      if (event.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [onClose])

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/70 p-4" onMouseDown={(event) => {
      if (event.target === event.currentTarget) onClose()
    }}>
      <section role="dialog" aria-modal="true" aria-labelledby="help-title" className="panel w-full max-w-xl p-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 id="help-title" className="text-lg font-semibold">SOC workspace guide</h2>
            <p className="mt-1 text-sm text-slate-400">Quick instructions for this interactive prototype.</p>
          </div>
          <button className="secondary-button" onClick={onClose}>Close</button>
        </div>
        <div className="mt-5 space-y-4 text-sm">
          <div><h3 className="font-semibold text-cyan-300">Explore the attack graph</h3><p className="mt-1 leading-6 text-slate-400">Choose an entity and hop depth. Drag to arrange nodes, zoom to inspect, and click a node or relationship to read its explanation and evidence context.</p></div>
          <div><h3 className="font-semibold text-cyan-300">Choose a reading level</h3><p className="mt-1 leading-6 text-slate-400">Use the profile menu to switch between SOC Analyst, Executive, and IT Operator summaries. These are presentation preferences, not access permissions.</p></div>
          <div><h3 className="font-semibold text-cyan-300">Review an incident</h3><p className="mt-1 leading-6 text-slate-400">Select an incident to see its status, related detections, evidence, and a plain-language explanation. Use the linked entity to open its graph neighborhood.</p></div>
          <div className="rounded-lg border border-amber-500/20 bg-amber-500/[0.05] p-3 text-xs leading-5 text-amber-200/80">
            Prototype data is synthetic. Containment actions are simulations only; this interface does not isolate devices or change accounts.
          </div>
        </div>
      </section>
    </div>
  )
}

export default function Navbar() {
  const navigate = useNavigate()
  const location = useLocation()
  const { persona, choosePersona } = usePersona()
  const activity = useApi(api.recentActivity)
  const [openMenu, setOpenMenu] = useState(null)
  const [showHelp, setShowHelp] = useState(false)
  const [readIds, setReadIds] = useState(readNotifications)
  const menuRef = useRef(null)
  const items = activity.data?.items || []
  const unreadCount = items.filter((item) => !readIds.has(item.event_id || item.id)).length

  useEffect(() => {
    function onPointerDown(event) {
      if (menuRef.current && !menuRef.current.contains(event.target)) setOpenMenu(null)
    }
    function onKeyDown(event) {
      if (event.key === 'Escape') setOpenMenu(null)
    }
    document.addEventListener('pointerdown', onPointerDown)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('pointerdown', onPointerDown)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [])

  function markRead(id) {
    const next = new Set(readIds)
    next.add(id)
    setReadIds(next)
    try {
      window.localStorage.setItem('trustrial-read-notifications', JSON.stringify([...next]))
    } catch {
      // Notifications remain usable for the current page session.
    }
  }

  function markAllRead() {
    const next = new Set(readIds)
    for (const item of items) {
      const id = item.event_id || item.id
      if (id) next.add(id)
    }
    setReadIds(next)
    try {
      window.localStorage.setItem('trustrial-read-notifications', JSON.stringify([...next]))
    } catch {
      // Notifications remain usable for the current page session.
    }
  }

  function openActivity(item) {
    const id = item.event_id || item.id
    if (id) markRead(id)
    setOpenMenu(null)
    navigate('/threat-hunting')
  }

  return (
    <>
      <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-slate-800/80 bg-soc-950/95 px-4 backdrop-blur md:px-6">
        <div className="flex items-center gap-2 text-xs text-slate-400">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-amber-400 opacity-30" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-amber-400" />
          </span>
          <span>Prototype • synthetic data</span>
          <span className="ml-1 hidden text-slate-600 md:inline">•</span>
          <span className="hidden md:inline">{location.pathname === '/attack-graph' ? 'Graph explorer' : 'SOC workspace'}</span>
        </div>
        <div className="flex items-center gap-2" ref={menuRef}>
          <button className="icon-button" title="Help and instructions" aria-label="Help and instructions" onClick={() => { setOpenMenu(null); setShowHelp(true) }}>
            <CircleHelp size={17} />
          </button>
          <div className="relative">
            <button className="icon-button relative" title="Notifications" aria-label={`Notifications, ${unreadCount} unread`} aria-expanded={openMenu === 'notifications'} onClick={() => setOpenMenu(openMenu === 'notifications' ? null : 'notifications')}>
              <Bell size={17} />
              {unreadCount > 0 && <span className="absolute -right-1 -top-1 grid h-[17px] min-w-[17px] place-items-center rounded-full bg-red-500 px-1 text-[9px] font-bold text-white">{unreadCount}</span>}
            </button>
            {openMenu === 'notifications' && (
              <div className="popover right-0 w-[min(360px,calc(100vw-2rem))]">
                <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3">
                  <div className="font-semibold">Recent activity</div>
                  {unreadCount > 0 ? <button className="text-xs text-cyan-300 hover:text-cyan-200" onClick={markAllRead}>Mark all read</button> : <span className="text-xs text-slate-500">All caught up</span>}
                </div>
                {activity.loading ? <div className="p-5 text-sm text-slate-400">Loading activity...</div> : activity.error ? (
                  <div className="p-4 text-sm text-red-300">Could not load notifications: {activity.error.message}</div>
                ) : items.length ? (
                  <div className="max-h-80 overflow-auto">
                    {items.slice(0, 8).map((item) => {
                      const id = item.event_id || item.id
                      const read = readIds.has(id)
                      return (
                        <button key={id} onClick={() => openActivity(item)} className="flex w-full gap-3 border-b border-slate-800/70 px-4 py-3 text-left hover:bg-slate-800/50">
                          <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${read ? 'bg-slate-700' : 'bg-cyan-400'}`} />
                          <span className="min-w-0 flex-1">
                            <span className="flex items-center justify-between gap-2"><span className="truncate text-sm">{item.description || item.title || item.event_type || id}</span><span className="text-[10px] uppercase text-slate-500">{item.severity || 'event'}</span></span>
                            <span className="mt-1 block text-xs text-slate-500">{item.event_time || item.timestamp || 'Time unavailable'}</span>
                          </span>
                        </button>
                      )
                    })}
                  </div>
                ) : <div className="p-5 text-sm text-slate-500">No recent notifications</div>}
                <button className="w-full px-4 py-3 text-left text-xs font-semibold text-cyan-300 hover:bg-slate-800/40" onClick={() => { setOpenMenu(null); navigate('/threat-hunting') }}>View threat activity</button>
              </div>
            )}
          </div>
          <div className="relative">
            <button className="ml-1 flex items-center gap-2 rounded-lg border border-slate-800 bg-soc-900 px-2 py-1.5 hover:border-slate-700" aria-label="Open profile and view preferences" aria-expanded={openMenu === 'profile'} onClick={() => setOpenMenu(openMenu === 'profile' ? null : 'profile')}>
              <div className="grid h-7 w-7 place-items-center rounded-md bg-cyan-400/10 text-cyan-300"><UserRound size={15} /></div>
              <div className="hidden text-left sm:block">
                <div className="text-xs font-semibold">Alex Rivera</div>
                <div className="text-[10px] text-slate-500">{personas[persona].label} view</div>
              </div>
              <ChevronDown size={14} className="text-slate-500" />
            </button>
            {openMenu === 'profile' && (
              <div className="popover right-0 w-64 p-3">
                <div className="flex items-center gap-3 border-b border-slate-800 px-1 pb-3">
                  <div className="grid h-9 w-9 place-items-center rounded-lg bg-cyan-400/10 text-cyan-300"><ShieldCheck size={18} /></div>
                  <div><div className="text-sm font-semibold">Alex Rivera</div><div className="text-xs text-slate-500">Prototype analyst profile</div></div>
                </div>
                <div className="px-1 pt-3">
                  <div className="mb-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">Explanation view</div>
                  {Object.entries(personas).map(([key, value]) => (
                    <button key={key} onClick={() => { choosePersona(key); setOpenMenu(null) }} className={`mb-1 w-full rounded-lg px-2.5 py-2 text-left ${persona === key ? 'bg-cyan-400/10 text-cyan-200' : 'text-slate-300 hover:bg-slate-800'}`}>
                      <span className="block text-xs font-semibold">{value.label}</span><span className="mt-0.5 block text-[10px] text-slate-500">{value.description}</span>
                    </button>
                  ))}
                </div>
                <div className="mt-2 border-t border-slate-800 px-1 pt-2 text-[10px] leading-4 text-amber-200/70">View preference only; this prototype does not enforce account permissions.</div>
              </div>
            )}
          </div>
        </div>
      </header>
      {showHelp && <HelpDialog onClose={() => setShowHelp(false)} />}
    </>
  )
}
