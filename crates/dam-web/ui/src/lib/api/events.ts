import { useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'

/**
 * Topics emitted by the backend's EventBus. Stable wire identifiers —
 * mirror in `crates/dam-web/src/events_bus.rs`. Each topic maps to one
 * or more TanStack Query keys to invalidate; the React shell re-fetches
 * the canonical state from the matching JSON endpoint.
 */
export type EventTopic =
  | 'request.pending'
  | 'request.resolved'
  | 'connect.update'
  | 'wallet.invalidate'
  | 'heartbeat'

/**
 * Subscribe to /api/v1/events for the lifetime of the calling component.
 *
 * Mounted once at the app root. The browser's EventSource auto-reconnects
 * on transient network failure, so no exponential-backoff layer is
 * necessary in v1.
 */
export function useEventStream(): void {
  const queryClient = useQueryClient()

  useEffect(() => {
    const source = new EventSource('/api/v1/events', { withCredentials: true })

    const onPending = () => {
      void queryClient.invalidateQueries({ queryKey: ['pending-requests'] })
    }
    const onResolved = () => {
      void queryClient.invalidateQueries({ queryKey: ['pending-requests'] })
    }
    const onConnect = () => {
      void queryClient.invalidateQueries({ queryKey: ['connect'] })
    }
    const onWallet = () => {
      void queryClient.invalidateQueries({ queryKey: ['wallet'] })
    }
    // EventSource auto-reconnects on transient drops (server restart,
    // network blip). On every (re)open we re-invalidate the live keys
    // — any frames the client missed while disconnected would otherwise
    // leave the cache stale. The first `open` after mount also covers
    // initial subscription.
    const onOpen = () => {
      void queryClient.invalidateQueries({ queryKey: ['connect'] })
      void queryClient.invalidateQueries({ queryKey: ['pending-requests'] })
      void queryClient.invalidateQueries({ queryKey: ['wallet'] })
    }

    source.addEventListener('request.pending', onPending)
    source.addEventListener('request.resolved', onResolved)
    source.addEventListener('connect.update', onConnect)
    source.addEventListener('wallet.invalidate', onWallet)
    source.addEventListener('open', onOpen)

    return () => {
      source.removeEventListener('request.pending', onPending)
      source.removeEventListener('request.resolved', onResolved)
      source.removeEventListener('connect.update', onConnect)
      source.removeEventListener('wallet.invalidate', onWallet)
      source.removeEventListener('open', onOpen)
      source.close()
    }
  }, [queryClient])
}
