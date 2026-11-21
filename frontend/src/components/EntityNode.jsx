import { Handle, Position } from '@xyflow/react'

const colors = {
  User: '#60a5fa',
  Host: '#22d3ee',
  Server: '#a78bfa',
  IPAddress: '#f59e0b',
  Application: '#34d399',
  Vulnerability: '#fb7185',
  Incident: '#f87171',
  Process: '#94a3b8',
}

export default function EntityNode({ data, selected }) {
  const color = colors[data.type] || '#94a3b8'
  return (
    <div className={`entity-node ${selected ? 'entity-node-selected' : ''}`} style={{ '--node-accent': color }}>
      <Handle type="target" position={Position.Left} className="!h-2 !w-2 !border-slate-950 !bg-slate-400" />
      <div className="flex items-start gap-2">
        <span className="mt-1 h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: color }} />
        <div className="min-w-0">
          <div className="truncate text-xs font-semibold text-slate-100">{data.name || data.id}</div>
          <div className="mt-1 truncate text-[10px] text-slate-400">{data.type || 'Entity'} · {data.id}</div>
          {data.criticality && <div className="mt-1 text-[9px] uppercase tracking-wider text-slate-500">{data.criticality} criticality</div>}
        </div>
      </div>
      <Handle type="source" position={Position.Right} className="!h-2 !w-2 !border-slate-950 !bg-slate-400" />
    </div>
  )
}
