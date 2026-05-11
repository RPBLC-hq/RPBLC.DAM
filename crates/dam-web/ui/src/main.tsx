import '@rpblc/design/reset.css'
import '@rpblc/design/fonts.css'
import '@rpblc/design/tokens.css'
import '@rpblc/design/components.css'
import '@/styles/app.css'

import React from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider } from '@tanstack/react-router'
import { ThemeProvider } from '@rpblc/design'

import { router } from '@/app/router'
import { resolveSurface } from '@/lib/surface'
import { LocaleProvider } from '@/lib/i18n'
import { ThemePreferenceProvider, useThemePreference } from '@/lib/theme'

const surface = resolveSurface()
document.documentElement.dataset.surface = surface

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5_000,
      refetchOnWindowFocus: true,
    },
  },
})

function ThemedRouter() {
  const { theme } = useThemePreference()
  return (
    <ThemeProvider theme={theme} persist={false}>
      <RouterProvider router={router} />
    </ThemeProvider>
  )
}

const root = document.getElementById('dam-root')

if (root) {
  createRoot(root).render(
    <React.StrictMode>
      <QueryClientProvider client={queryClient}>
        <LocaleProvider>
          <ThemePreferenceProvider>
            <ThemedRouter />
          </ThemePreferenceProvider>
        </LocaleProvider>
      </QueryClientProvider>
    </React.StrictMode>,
  )
}
