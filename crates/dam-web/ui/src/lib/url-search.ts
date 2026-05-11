import { useEffect, useState } from 'react'

/**
 * Bind a single `?key=` search param to a React state value, with the
 * URL as the source of truth (refresh, share, browser-back). When the
 * value matches `fallback`, the param is removed from the URL.
 *
 * `validate` narrows the runtime string to the typed value the caller
 * expects. The hook silently falls back when the URL holds an
 * unrecognised value, so old shares remain navigable as the schema
 * evolves.
 */
export function useUrlSearchParam<T extends string>(
  key: string,
  fallback: T,
  validate: (value: string) => value is T,
): [T, (next: T) => void] {
  const [value, setValue] = useState<T>(() => read(key, fallback, validate))

  useEffect(() => {
    const handler = () => setValue(read(key, fallback, validate))
    window.addEventListener('popstate', handler)
    return () => window.removeEventListener('popstate', handler)
  }, [fallback, key, validate])

  const setter = (next: T) => {
    setValue(next)
    const params = new URLSearchParams(window.location.search)
    if (next === fallback) params.delete(key)
    else params.set(key, next)
    const search = params.toString()
    const url = `${window.location.pathname}${search ? `?${search}` : ''}${window.location.hash}`
    window.history.replaceState(null, '', url)
  }

  return [value, setter]
}

/**
 * Free-form string variant — used for search queries where any string
 * is valid. Empty string clears the param.
 */
export function useUrlSearchString(
  key: string,
): [string, (next: string) => void] {
  const [value, setValue] = useState<string>(() => readString(key))

  useEffect(() => {
    const handler = () => setValue(readString(key))
    window.addEventListener('popstate', handler)
    return () => window.removeEventListener('popstate', handler)
  }, [key])

  const setter = (next: string) => {
    setValue(next)
    const params = new URLSearchParams(window.location.search)
    if (!next) params.delete(key)
    else params.set(key, next)
    const search = params.toString()
    const url = `${window.location.pathname}${search ? `?${search}` : ''}${window.location.hash}`
    window.history.replaceState(null, '', url)
  }

  return [value, setter]
}

function read<T extends string>(
  key: string,
  fallback: T,
  validate: (value: string) => value is T,
): T {
  if (typeof window === 'undefined') return fallback
  const raw = new URLSearchParams(window.location.search).get(key)
  if (raw && validate(raw)) return raw
  return fallback
}

function readString(key: string): string {
  if (typeof window === 'undefined') return ''
  return new URLSearchParams(window.location.search).get(key) ?? ''
}
