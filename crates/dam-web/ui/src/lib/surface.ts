export type Surface = 'tray' | 'web'

type Bootstrap = {
  surface?: string
  tray_post_token?: string | null
  version?: string
}

let cachedBootstrap: Bootstrap | null = null

export function readBootstrap(): Bootstrap {
  if (cachedBootstrap) return cachedBootstrap

  const node = document.getElementById('dam-web-bootstrap')
  if (!node?.textContent) {
    cachedBootstrap = {}
    return cachedBootstrap
  }

  try {
    cachedBootstrap = JSON.parse(node.textContent) as Bootstrap
  } catch {
    cachedBootstrap = {}
  }

  return cachedBootstrap
}

export function resolveSurface(): Surface {
  return readBootstrap().surface === 'tray' ? 'tray' : 'web'
}

export function trayPostToken(): string | null {
  return readBootstrap().tray_post_token ?? null
}
