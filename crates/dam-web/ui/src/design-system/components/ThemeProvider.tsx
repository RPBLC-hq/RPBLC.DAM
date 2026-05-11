import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import type { Theme } from '../tokens/tokens'

type ThemeContextValue = {
  theme: Theme
  setTheme: (t: Theme) => void
  toggleTheme: () => void
}

const ThemeContext = createContext<ThemeContextValue | null>(null)

const STORAGE_KEY = 'rpblc-theme'

export type ThemeProviderProps = {
  children: ReactNode
  /** Controlled theme. If provided, the provider is controlled. */
  theme?: Theme
  /** Initial theme when uncontrolled. Defaults to "dark". */
  defaultTheme?: Theme
  /** Persist theme choice to localStorage. Defaults to true. */
  persist?: boolean
  /** Element to receive the data-theme attribute. Defaults to documentElement. */
  target?: HTMLElement | null
}

/**
 * ThemeProvider — wraps a subtree and controls the active RPBLC theme.
 *
 * Optional. Components work without it because tokens.css already defines
 * the default theme on :root.
 *
 * The provider sets `data-theme="<theme>"` on the target element (default:
 * <html>) and exposes the current theme + setters via useTheme().
 */
export function ThemeProvider({
  children,
  theme: controlledTheme,
  defaultTheme = 'dark',
  persist = true,
  target,
}: ThemeProviderProps) {
  const [uncontrolledTheme, setUncontrolledTheme] = useState<Theme>(() => {
    if (typeof window === 'undefined') return defaultTheme
    if (!persist) return defaultTheme
    const stored = window.localStorage.getItem(STORAGE_KEY)
    if (stored === 'dark' || stored === 'light') return stored
    return defaultTheme
  })

  const theme = controlledTheme ?? uncontrolledTheme

  const setTheme = useCallback(
    (next: Theme) => {
      if (controlledTheme === undefined) {
        setUncontrolledTheme(next)
        if (persist && typeof window !== 'undefined') {
          window.localStorage.setItem(STORAGE_KEY, next)
        }
      }
    },
    [controlledTheme, persist],
  )

  const toggleTheme = useCallback(() => {
    setTheme(theme === 'dark' ? 'light' : 'dark')
  }, [theme, setTheme])

  useEffect(() => {
    const el = target ?? (typeof document !== 'undefined' ? document.documentElement : null)
    if (!el) return
    if (theme === 'light') el.setAttribute('data-theme', 'light')
    else el.removeAttribute('data-theme')
  }, [theme, target])

  const value = useMemo<ThemeContextValue>(
    () => ({ theme, setTheme, toggleTheme }),
    [theme, setTheme, toggleTheme],
  )

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext)
  if (!ctx) {
    // Fallback when no ThemeProvider is mounted — read from documentElement.
    const current: Theme =
      typeof document !== 'undefined' && document.documentElement.getAttribute('data-theme') === 'light'
        ? 'light'
        : 'dark'
    return {
      theme: current,
      setTheme: (t) => {
        if (typeof document === 'undefined') return
        if (t === 'light') document.documentElement.setAttribute('data-theme', 'light')
        else document.documentElement.removeAttribute('data-theme')
      },
      toggleTheme: () => {
        if (typeof document === 'undefined') return
        const isLight = document.documentElement.getAttribute('data-theme') === 'light'
        if (isLight) document.documentElement.removeAttribute('data-theme')
        else document.documentElement.setAttribute('data-theme', 'light')
      },
    }
  }
  return ctx
}
