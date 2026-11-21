import { useState } from 'react'

export default function ApiAccessGate({ onSubmit }) {
  const [token, setToken] = useState('')

  function submit(event) {
    event.preventDefault()
    const value = token.trim()
    if (value) onSubmit(value)
  }

  return (
    <main className="grid min-h-screen place-items-center bg-soc-950 px-4 text-slate-100">
      <form className="panel w-full max-w-md space-y-5 p-6" onSubmit={submit}>
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-300">
            TRUSTRAIL AI
          </p>
          <h1 className="mt-2 text-xl font-semibold">API access required</h1>
          <p className="mt-2 text-sm text-slate-400">
            Enter the access token provided by the project administrator.
          </p>
        </div>
        <label className="block space-y-2 text-sm text-slate-300">
          Access token
          <input
            autoComplete="current-password"
            className="field w-full"
            onChange={(event) => setToken(event.target.value)}
            required
            type="password"
            value={token}
          />
        </label>
        <button className="primary-button w-full" type="submit">
          Continue
        </button>
      </form>
    </main>
  )
}
