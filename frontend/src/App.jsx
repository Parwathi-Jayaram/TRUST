import { Navigate, Route, Routes } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import Navbar from './components/Navbar'
import Dashboard from './pages/Dashboard'
import ThreatHunting from './pages/ThreatHunting'
import AttackGraph from './pages/AttackGraph'
import BlastRadius from './pages/BlastRadius'
import Containment from './pages/Containment'
import Incidents from './pages/Incidents'
import Investigations from './pages/Investigations'
import Settings from './pages/Settings'
import { PersonaProvider } from './context/PersonaContext'

export default function App() {
  return (
    <PersonaProvider>
      <div className="min-h-screen bg-soc-950 text-slate-100">
        <Sidebar />
        <div className="lg:pl-[248px]">
          <Navbar />
          <main className="min-h-[calc(100vh-64px)] px-4 pb-8 pt-5 md:px-6">
            <Routes>
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/threat-hunting" element={<ThreatHunting />} />
              <Route path="/attack-graph" element={<AttackGraph />} />
              <Route path="/blast-radius" element={<BlastRadius />} />
              <Route path="/containment" element={<Containment />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="/investigations" element={<Investigations />} />
              <Route path="/settings" element={<Settings />} />
            </Routes>
          </main>
        </div>
      </div>
    </PersonaProvider>
  )
}
