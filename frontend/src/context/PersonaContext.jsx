import { createContext, useContext, useMemo, useState } from 'react'

const PersonaContext = createContext(null)

export const personas = {
  analyst: { label: 'SOC Analyst', description: 'Evidence, detections and relationship details' },
  executive: { label: 'Executive', description: 'Business impact and concise risk summaries' },
  operator: { label: 'IT Operator', description: 'Affected assets and operational context' },
}

export function PersonaProvider({ children }) {
  const [persona, setPersona] = useState(() => {
    try {
      const saved = window.localStorage.getItem('trustrial-persona')
      return typeof saved === 'string' && Object.hasOwn(personas, saved) ? saved : 'analyst'
    } catch {
      return 'analyst'
    }
  })

  function choosePersona(value) {
    if (!(value in personas)) return
    setPersona(value)
    try {
      window.localStorage.setItem('trustrial-persona', value)
    } catch {
      // The selected view still works when browser storage is unavailable.
    }
  }

  const value = useMemo(() => ({ persona, choosePersona }), [persona])
  return <PersonaContext.Provider value={value}>{children}</PersonaContext.Provider>
}

export function usePersona() {
  const context = useContext(PersonaContext)
  if (!context) throw new Error('usePersona must be used within PersonaProvider')
  return context
}
