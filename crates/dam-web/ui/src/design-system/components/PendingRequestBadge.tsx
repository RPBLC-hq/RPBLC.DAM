import { type HTMLAttributes, type ReactNode } from 'react'

export type PendingRequestBadgeProps = {
  /** Number of pending requests. Renders nothing when zero. */
  count: number
  /** Trailing label. Defaults to `"pending"`. Translate at the call site. */
  label?: ReactNode
  /** Visual size; `sm` is for menu-bar / brand-bar, `md` for in-page. */
  size?: 'sm' | 'md'
} & Omit<HTMLAttributes<HTMLSpanElement>, 'children'>

/**
 * PendingRequestBadge — the count pill for pending consent requests.
 *
 * A bracketed mono pill with a gold dot, count, and short label.
 * Renders nothing when `count` is zero.
 *
 * Used on the tray brand bar, on the web brand bar, and inside any
 * surface that surfaces "N pending" in a compact form.
 */
export function PendingRequestBadge({
  count,
  label = 'pending',
  size = 'sm',
  className,
  ...rest
}: PendingRequestBadgeProps) {
  if (count <= 0) return null
  return (
    <span
      className={join('rpblc-pending-badge', `rpblc-pending-badge--${size}`, className)}
      role="status"
      aria-live="polite"
      {...rest}
    >
      <span className="rpblc-pending-badge__dot" aria-hidden="true" />
      <span className="rpblc-pending-badge__count">{count}</span>
      <span className="rpblc-pending-badge__label">{label}</span>
    </span>
  )
}

function join(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
