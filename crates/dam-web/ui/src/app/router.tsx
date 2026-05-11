import {
  Outlet,
  RootRoute,
  Route,
  Router,
  createBrowserHistory,
  createMemoryHistory,
  redirect,
} from '@tanstack/react-router'

import { AppShell } from '@/layouts/AppShell'
import { ActivityPage } from '@/features/activity/ActivityPage'
import { AllowedPage } from '@/features/allowed/AllowedPage'
import { ConnectPage } from '@/features/connect/ConnectPage'
import { HealthPage } from '@/features/health/HealthPage'
import { InsightsPage } from '@/features/insights/InsightsPage'
import { SettingsPage } from '@/features/settings/SettingsPage'
import { SystemPage } from '@/features/system/SystemPage'
import { WalletListPage } from '@/features/wallet/WalletListPage'
import { resolveSurface } from '@/lib/surface'
import { BlankRoute } from '@/pages/BlankRoute'

const surface = resolveSurface()

const rootRoute = new RootRoute({
  component: () => <Outlet />,
})

const shellRoute = new Route({
  getParentRoute: () => rootRoute,
  id: 'shell',
  component: AppShell,
})

// Smart landing: web → Insights when protected, Connect otherwise.
// Tray always lands on Connect (its surface-resolution path is handled
// in `initialTrayPath` below). The redirect uses the bootstrap-derived
// `surface` constant to pick at SPA-load time without an API call,
// letting the cached connect query fill in afterwards.
const defaultRoute = new Route({
  getParentRoute: () => shellRoute,
  path: '/',
  beforeLoad: async () => {
    if (surface === 'tray') return
    let state: string | undefined
    // Fetch lives outside the redirect path: if it fails (daemon down,
    // CORS, etc.), `state` stays undefined and we land at `/connect`.
    // The redirect() calls below must run *outside* the try/catch —
    // tanstack-router signals redirects by throwing a non-Error object
    // and a try/catch around them swallows the signal.
    try {
      const response = await fetch('/api/v1/connect', {
        headers: { accept: 'application/json' },
        credentials: 'same-origin',
      })
      const payload = (await response.json()) as
        | { ok?: boolean; data?: { state?: string } }
        | null
      if (payload && payload.ok) state = payload.data?.state
    } catch {
      // Fall through; state stays undefined → `/connect`.
    }
    if (state === 'protected') throw redirect({ to: '/insights' })
    throw redirect({ to: '/connect' })
  },
  component: ConnectPage,
})

const connectRoute = new Route({
  getParentRoute: () => shellRoute,
  path: '/connect',
  component: ConnectPage,
})

const insightsRoute = new Route({
  getParentRoute: () => shellRoute,
  path: '/insights',
  component: InsightsPage,
})

const walletRoute = new Route({
  getParentRoute: () => shellRoute,
  path: '/wallet',
  component: WalletListPage,
})

const allowedRoute = new Route({
  getParentRoute: () => shellRoute,
  path: '/allowed',
  component: AllowedPage,
})

const settingsRoute = new Route({
  getParentRoute: () => shellRoute,
  path: '/settings',
  component: SettingsPage,
})

const activityRoute = new Route({
  getParentRoute: () => shellRoute,
  path: '/activity',
  component: ActivityPage,
})

const systemRoute = new Route({
  getParentRoute: () => shellRoute,
  path: '/system',
  component: SystemPage,
})

const healthRoute = new Route({
  getParentRoute: () => shellRoute,
  path: '/health',
  component: HealthPage,
})

const frameFallbackRoute = new Route({
  getParentRoute: () => shellRoute,
  path: '$',
  component: BlankRoute,
})

const routeTree = rootRoute.addChildren([
  shellRoute.addChildren([
    defaultRoute,
    connectRoute,
    insightsRoute,
    walletRoute,
    allowedRoute,
    activityRoute,
    settingsRoute,
    systemRoute,
    healthRoute,
    frameFallbackRoute,
  ]),
])

function initialTrayPath(): string {
  const currentPath = window.location.pathname
  return currentPath === '/' ? '/connect' : currentPath
}

export const router = new Router({
  routeTree,
  history: surface === 'tray'
    ? createMemoryHistory({ initialEntries: [initialTrayPath()] })
    : createBrowserHistory(),
})

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}
