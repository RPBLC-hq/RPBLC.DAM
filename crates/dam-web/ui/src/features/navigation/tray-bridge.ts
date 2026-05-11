import { useEffect } from 'react'

import type { Surface } from '@/lib/surface'

const TRAY_MESSAGES = {
  rpblc: 'dam-tray:open-rpblc',
  damWebTab: 'dam-tray:open-dam-web',
  quit: 'dam-tray:quit',
  connect: 'dam-tray:connect',
  restart: 'dam-tray:restart-macos',
  registerLogin: 'dam-tray:register-launch-at-login',
  skipLogin: 'dam-tray:skip-launch-at-login',
} as const

type TrayExternalTarget = 'rpblc' | 'dam-web-tab'

type TrayIpcWindow = Window & {
  ipc?: {
    postMessage?: (message: string) => void
  }
}

export function useTrayBridge(surface: Surface) {
  useEffect(() => {
    if (surface !== 'tray') return

    function onClick(event: MouseEvent) {
      const target = event.target
      if (!(target instanceof Element)) return

      const trayElement = target.closest<HTMLElement>(
        '[data-tray-external], [data-tray-quit], [data-tray-connect], [data-tray-restart], [data-tray-register-login], [data-tray-skip-login]',
      )
      if (!trayElement) return

      const external = trayElement.dataset.trayExternal as TrayExternalTarget | undefined
      const message = external === 'rpblc'
        ? TRAY_MESSAGES.rpblc
        : external === 'dam-web-tab'
          ? TRAY_MESSAGES.damWebTab
          : trayElement.hasAttribute('data-tray-register-login')
            ? TRAY_MESSAGES.registerLogin
            : trayElement.hasAttribute('data-tray-skip-login')
              ? TRAY_MESSAGES.skipLogin
              : trayElement.hasAttribute('data-tray-restart')
                ? TRAY_MESSAGES.restart
                : trayElement.hasAttribute('data-tray-connect')
                  ? TRAY_MESSAGES.connect
                  : trayElement.hasAttribute('data-tray-quit')
                    ? TRAY_MESSAGES.quit
                    : null

      if (!message) return

      // Capture-phase listener (registered with `useCapture: true` on
      // mount below) so this handler runs *before* React's bubble-phase
      // synthetic onClick. `stopPropagation` here cancels the rest of
      // the chain, including any React onClick that would otherwise
      // POST through dam-web's HTTP path. The result: when an element
      // carries a `data-tray-*` attribute, the click goes through the
      // native IPC and ONLY through the native IPC.
      if (postTrayMessage(message)) {
        event.preventDefault()
        event.stopPropagation()
      }
    }

    document.addEventListener('click', onClick, true)
    return () => document.removeEventListener('click', onClick, true)
  }, [surface])
}

function postTrayMessage(message: string): boolean {
  const ipc = (window as TrayIpcWindow).ipc
  if (typeof ipc?.postMessage !== 'function') return false
  ipc.postMessage(message)
  return true
}
