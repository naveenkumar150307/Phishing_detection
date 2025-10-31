import React from 'react'
import ApiMonitor from './componenets/ApiMonitor'
import UrlChecker from './componenets/UrlChecker'

export default function App() {
  return (
    <div style={{fontFamily: 'system-ui, Arial, sans-serif', padding: 24}}>
      <h1 style={{fontSize: 24, marginBottom: 12}}>PhishGuard</h1>
      <UrlChecker />
      <ApiMonitor />
    </div>
  )
}
