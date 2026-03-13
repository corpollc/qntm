import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
  },
  define: {
    // cbor-x uses Buffer.isBuffer() — provide global Buffer for browser
    'globalThis.Buffer': 'globalThis.Buffer',
  },
})
