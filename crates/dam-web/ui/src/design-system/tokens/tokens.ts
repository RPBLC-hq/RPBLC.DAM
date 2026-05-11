/**
 * RPBLC.Design — Token TypeScript mirror
 *
 * This is a hand-maintained mirror of `tokens.css`. It exists so code
 * consumers can read token values at runtime (e.g. for canvas rendering,
 * inline SVG, conditional logic). The CSS file is the canonical source —
 * if these disagree, the CSS wins.
 *
 * See contracts/tokens-contract.md for the full reference.
 */

export const colorDark = {
  bg: '#0a0a08',
  panel: '#12120f',
  line: '#1e1d1a',
  lineDark: '#181714',
  dark: '#2c2a22',
  soft: '#3d3a32',
  secondary: '#6b6355',
  muted: '#78736a',
  text: '#dedad2',
  bright: '#ffffff',
  accent: '#b8965a',
  accentBright: '#d4ad68',
  accentStrong: '#b8965a',
  ctaBg: '#b8965a',
  ctaFg: '#0a0a08',
  ctaBorder: '#b8965a',
  ctaBgHover: '#0a0a08',
  ctaFgHover: '#b8965a',
  ctaBorderHover: '#b8965a',
  flashBg: '#f5f0e8',
  flashWarm: '#ede8de',
  navBg: 'rgba(10, 10, 8, 0.92)',
  alarm: '#b8523f',
  error: '#b8523f',
} as const

export const colorLight = {
  bg: '#faf8f2',
  panel: '#ffffff',
  line: '#e2ddd4',
  lineDark: '#e2ddd4',
  dark: '#d6d2ca',
  soft: '#c4bfb6',
  secondary: '#6b6355',
  muted: '#6b6355',
  text: '#2c2a22',
  bright: '#0a0a08',
  accent: '#b8965a',
  accentBright: '#8a6a36',
  accentStrong: '#6e5326',
  ctaBg: '#0a0a08',
  ctaFg: '#faf8f2',
  ctaBorder: '#0a0a08',
  ctaBgHover: '#b8965a',
  ctaFgHover: '#0a0a08',
  ctaBorderHover: '#b8965a',
  flashBg: '#f0ebe2',
  flashWarm: '#e2ddd4',
  navBg: 'rgba(250, 248, 242, 0.92)',
  alarm: '#9a3a26',
  error: '#9a3a26',
} as const

export const font = {
  mono: "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
  sans: "'Manrope', ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif",
} as const

export const weight = {
  regular: 400,
  medium: 500,
  semibold: 600,
  bold: 700,
  extrabold: 800,
} as const

export const space = {
  0: 0,
  1: 4,
  2: 8,
  3: 12,
  4: 16,
  5: 20,
  6: 24,
  7: 28,
  8: 32,
  9: 40,
  10: 48,
  12: 64,
} as const

export const duration = {
  fast: 120,
  base: 200,
  slow: 300,
  slower: 500,
} as const

export const easing = {
  base: 'ease',
  outExpo: 'cubic-bezier(0.16, 1, 0.3, 1)',
} as const

export const geometry = {
  radius0: 0,
  radius1: 2,
  border1: 1,
  border2: 2,
} as const

export type Theme = 'dark' | 'light'

export const tokens = {
  colorDark,
  colorLight,
  font,
  weight,
  space,
  duration,
  easing,
  geometry,
} as const
