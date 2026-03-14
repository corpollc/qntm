import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  // Base path for GitHub Pages — set via env or default to '/'
  base: process.env.VITE_BASE_PATH || '/',
  server: {
    port: 5173,
  },
  define: {
    // cbor-x uses Buffer.isBuffer() — provide global Buffer for browser
    'globalThis.Buffer': 'globalThis.Buffer',
  },
})
