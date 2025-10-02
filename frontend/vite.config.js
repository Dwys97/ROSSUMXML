// In frontend/vite.config.js

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    // We'll let Vite use its default port (5173)
    proxy: {
      // All requests to /api will be sent to our Python proxy server
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''), // If your backend routes don't start with /api
      },
    },
  },
})