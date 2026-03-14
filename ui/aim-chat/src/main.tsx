// Buffer polyfill — cbor-x (used by @corpollc/qntm) calls Buffer.isBuffer()
import { Buffer } from 'buffer'
;(globalThis as unknown as Record<string, unknown>).Buffer = Buffer

import React from 'react'
import ReactDOM from 'react-dom/client'
import { HashRouter } from 'react-router-dom'
import App from './App'
import './styles.css'

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <HashRouter>
      <App />
    </HashRouter>
  </React.StrictMode>,
)
