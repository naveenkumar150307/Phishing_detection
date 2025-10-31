import { useState } from 'react'
import axios from 'axios'
import { getBackendUrl } from '../utils/api'

export default function UrlChecker() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const [blocked, setBlocked] = useState(false)
  const [blockedReason, setBlockedReason] = useState('')

  const submit = async (e) => {
    e?.preventDefault()
    setError('')
    setResult(null)
    setBlocked(false)
    setBlockedReason('')
    const trimmed = url.trim()
    if (!trimmed) {
      setError('Please enter a URL')
      return
    }
    setLoading(true)
    const base = getBackendUrl()
    try {
      let res
      try {
        res = await axios.post(`${base}/verify`, { url: trimmed }, { timeout: 10000 })
      } catch (_) {
        res = await axios.post(`${base}/check_url`, { url: trimmed }, { timeout: 10000 })
      }
      const data = res.data || {}
      setResult(data)

      // Derive status and reason
      const statusRaw = data?.status ?? (data?.is_phishing === true ? 'phishing' : (data?.is_phishing === false ? 'legitimate' : 'unknown'))
      const status = String(statusRaw).toLowerCase()
      const reason = data?.reason || data?.meta?.reason || ''

      // Act based on status
      if (status.includes('phish') || status.includes('malicious')) {
        // Show in-app red block screen and do not navigate
        setBlocked(true)
        setBlockedReason(reason || 'Blocked — phishing detected')
      } else if (status.includes('suspicious')) {
        // Redirect to warning page in same tab; do not open the destination site
        const warnUrl = `http://127.0.0.1:5173/warning?url=${encodeURIComponent(trimmed)}&reason=${encodeURIComponent(reason || 'Suspicious link')}`
        window.location.href = warnUrl
      } else if (status.includes('legit') || status.includes('safe')) {
        // Open the original site in the same tab
        window.location.href = trimmed
      }
    } catch (err) {
      setError(err?.response?.data?.detail || err?.message || 'Request failed')
    } finally {
      setLoading(false)
    }
  }

  // Auto-fill from ?url= and auto-submit once on first render
  if (typeof window !== 'undefined') {
    if (!url) {
      const qp = new URLSearchParams(window.location.search)
      const qurl = qp.get('url')
      if (qurl) {
        setUrl(qurl)
        // Fire async submit without blocking render
        setTimeout(() => submit(), 0)
      }
    }
  }

  return (
    <div style={{ marginBottom: 24 }}>
      {blocked && (
        <div style={{
          position: 'fixed', inset: 0, background: '#7f1d1d', color: 'white',
          display: 'grid', placeItems: 'center', zIndex: 50
        }}>
          <div style={{
            background: '#991b1b', padding: 24, borderRadius: 16, boxShadow: '0 10px 30px rgba(0,0,0,0.35)',
            width: 'min(720px, 92vw)'
          }}>
            <h2 style={{marginTop:0}}>Blocked — phishing detected</h2>
            <div style={{wordBreak:'break-word', marginBottom: 8}}>{url}</div>
            <div style={{opacity:0.9}}>{blockedReason}</div>
          </div>
        </div>
      )}
      <form onSubmit={submit} style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 12 }}>
        <input
          type="url"
          placeholder="Paste URL to check (https://...)"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          style={{ flex: 1, padding: '10px 12px', borderRadius: 8, border: '1px solid #d1d5db' }}
          required
        />
        <button
          type="submit"
          onClick={submit}
          disabled={loading}
          style={{ padding: '10px 14px', borderRadius: 8, background: '#111827', color: 'white', border: 'none', cursor: 'pointer' }}
        >
          {loading ? 'Checking...' : 'Check URL'}
        </button>
      </form>
      {error && (
        <div style={{ color: '#b91c1c', fontSize: 14, marginBottom: 8 }}>{error}</div>
      )}
      {result && (
        <div style={{ padding: 12, border: '1px solid #e5e7eb', borderRadius: 12 }}>
          {(() => {
            const derived = result?.status
              ? String(result.status)
              : (result?.is_phishing === true
                  ? 'phishing'
                  : (result?.is_phishing === false ? 'legitimate' : 'unknown'))
            return (
              <div style={{ marginBottom: 6 }}>
                <strong>Status: </strong>
                <span style={{ textTransform: 'capitalize' }}>{derived}</span>
              </div>
            )
          })()}
          {'confidence' in result && (
            <div style={{ marginBottom: 6 }}>
              <strong>Confidence: </strong>
              <span>{Number(result.confidence).toFixed(2)}</span>
            </div>
          )}
          {'label' in result && (
            <div style={{ marginBottom: 6 }}>
              <strong>Label: </strong>
              <span>{String(result.label)}</span>
            </div>
          )}
          {'reason' in result && result.reason && (
            <div style={{ marginBottom: 6 }}>
              <strong>Reason: </strong>
              <span>{String(result.reason)}</span>
            </div>
          )}
          {'latency_ms' in result && (
            <div>
              <strong>Latency: </strong>
              <span>{result.latency_ms} ms</span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
