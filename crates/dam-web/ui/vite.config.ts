import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'node:path'

const designRoot = path.resolve(__dirname, 'src/design-system')

export default defineConfig(({ command }) => ({
  base: command === 'serve' ? '/' : '/assets/',
  plugins: [react()],
  resolve: {
    alias: [
      { find: '@rpblc/design/tokens.css', replacement: path.join(designRoot, 'tokens/tokens.css') },
      { find: '@rpblc/design/components.css', replacement: path.join(designRoot, 'styles/components.css') },
      { find: '@rpblc/design/reset.css', replacement: path.join(designRoot, 'styles/reset.css') },
      { find: '@rpblc/design/fonts.css', replacement: path.join(designRoot, 'tokens/fonts.css') },
      { find: '@rpblc/design', replacement: path.join(designRoot, 'index.ts') },
      { find: '@', replacement: path.resolve(__dirname, 'src') },
    ],
  },
  build: {
    outDir: path.resolve(__dirname, '../assets'),
    emptyOutDir: false,
    target: 'es2020',
    rollupOptions: {
      input: path.resolve(__dirname, 'index.html'),
      output: {
        entryFileNames: 'bundle.js',
        chunkFileNames: 'bundle-[name].js',
        assetFileNames: (info) => {
          if (info.name && info.name.endsWith('.css')) return 'bundle.css'
          return 'bundle-[name][extname]'
        },
      },
    },
    cssCodeSplit: false,
  },
  server: {
    port: 5181,
    proxy: {
      '/api': 'http://127.0.0.1:2896',
    },
  },
}))
