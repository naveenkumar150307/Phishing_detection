export function getBackendUrl() {
  // Prefer env var set by Vite if provided
  const fromEnv = import.meta?.env?.VITE_BACKEND_URL
  if (fromEnv) return fromEnv.replace(/\/$/, '')

  // Default to local FastAPI
  return 'http://127.0.0.1:8000'
}
