// frontend/vite.config.js
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  root: '.',          // assume you run 'npm run dev' inside frontend
  base: '/',          // serve assets relative to /
  server: {
    host: true,       // 0.0.0.0
    port: 5173,
    strictPort: true, // fail if port busy
    hmr: true,       // enable HMR for Codespaces
    proxy: {
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      },
    },
  },
});
