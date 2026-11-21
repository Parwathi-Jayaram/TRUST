import { useEffect, useState } from 'react'

export function useApi(loader, dependencies = []) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let active = true
    setLoading(true)
    setError(null)
    Promise.resolve()
      .then(loader)
      .then((value) => active && setData(value))
      .catch((reason) => active && setError(reason))
      .finally(() => active && setLoading(false))
    return () => { active = false }
  }, dependencies)

  return { data, loading, error, setData }
}
