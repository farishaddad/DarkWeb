import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'
import { MockProvider } from './data/mockProvider'
import { LiveProvider } from './data/liveProvider'
import { useAppStore } from './store/appStore'
import { APP_CONFIG } from './config'

const provider = APP_CONFIG.dataMode === 'live'
  ? new LiveProvider(APP_CONFIG.apiBaseUrl, APP_CONFIG.apiKey)
  : new MockProvider()

useAppStore.getState().setProvider(provider)

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
