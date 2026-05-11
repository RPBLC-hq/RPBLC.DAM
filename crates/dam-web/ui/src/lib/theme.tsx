import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import type { Theme } from '@rpblc/design'

export type ThemePreference = 'system' | 'light' | 'dark'

const PREFERENCE_KEY = 'rpblc.dam.theme.preference'
const LEGACY_RESOLVED_KEY = 'rpblc-theme'

function readPreference(): ThemePreference {
  if (typeof window === 'undefined') return 'system'
  try {
    const stored = window.localStorage.getItem(PREFERENCE_KEY)
    if (stored === 'system' || stored === 'light' || stored === 'dark') return stored
  } catch {
    // ignore
  }
  return 'system'
}

function writePreference(value: ThemePreference) {
  if (typeof window === 'undefined') return
  try {
    window.localStorage.setItem(PREFERENCE_KEY, value)
    if (value === 'light' || value === 'dark') {
      window.localStorage.setItem(LEGACY_RESOLVED_KEY, value)
    } else {
      window.localStorage.removeItem(LEGACY_RESOLVED_KEY)
    }
  } catch {
    // ignore
  }
}

function systemTheme(): Theme {
  if (typeof window === 'undefined' || !window.matchMedia) return 'dark'
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
}

function resolveTheme(preference: ThemePreference): Theme {
  return preference === 'system' ? systemTheme() : preference
}

type ThemePreferenceContextValue = {
  preference: ThemePreference
  theme: Theme
  setPreference: (next: ThemePreference) => void
}

const ThemePreferenceContext = createContext<ThemePreferenceContextValue | null>(null)

export function ThemePreferenceProvider({ children }: { children: ReactNode }) {
  const [preference, setPreferenceState] = useState<ThemePreference>(readPreference)
  const [theme, setTheme] = useState<Theme>(() => resolveTheme(readPreference()))

  useEffect(() => {
    setTheme(resolveTheme(preference))
    if (preference !== 'system') return
    if (typeof window === 'undefined' || !window.matchMedia) return
    const media = window.matchMedia('(prefers-color-scheme: light)')
    const onChange = () => setTheme(media.matches ? 'light' : 'dark')
    media.addEventListener('change', onChange)
    return () => media.removeEventListener('change', onChange)
  }, [preference])

  const value = useMemo<ThemePreferenceContextValue>(
    () => ({
      preference,
      theme,
      setPreference: (next) => {
        writePreference(next)
        setPreferenceState(next)
      },
    }),
    [preference, theme],
  )

  return <ThemePreferenceContext.Provider value={value}>{children}</ThemePreferenceContext.Provider>
}

/**
 * useThemePreference — read or change the persisted system|light|dark
 * preference. The active design-system theme (the one passed to
 * `ThemeProvider`) is always derived from the preference and the OS
 * scheme, kept in sync across the whole app.
 *
 * Must be used inside `ThemePreferenceProvider`.
 */
export function useThemePreference(): ThemePreferenceContextValue {
  const ctx = useContext(ThemePreferenceContext)
  if (!ctx) {
    throw new Error('useThemePreference must be used inside ThemePreferenceProvider')
  }
  return ctx
}
