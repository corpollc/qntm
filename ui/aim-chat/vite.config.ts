/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  // Cloudflare Pages serves this static app from the domain root.
  base: '/',
  server: {
    port: 5173,
  },
  define: {
    // cbor-x uses Buffer.isBuffer() — provide global Buffer for browser
    'globalThis.Buffer': 'globalThis.Buffer',
  },
  test: {
    environment: 'happy-dom',
    exclude: ['tests/e2e/**', 'node_modules/**'],
  },
})
