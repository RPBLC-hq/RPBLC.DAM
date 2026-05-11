import { type CSSProperties, type HTMLAttributes, type ReactNode } from 'react'

export type RedactionLoaderProps = {
  /* When true, content is hidden behind redaction bars. When false, the
     bars resolve and content reveals. Drive this from your data state. */
  redacted?: boolean
  /* Number of bars to render in the redacted view. Drives layout width. */
  bars?: number
  /* Width of the redacted block. Number = px; string = any CSS length. */
  width?: number | string
  /* Height of each bar (also drives the band height). */
  size?: number | string
  /* Reason for redaction — surfaced as the aria-label and as an inline
     mono caption when verbose=true. Voice rules apply (brand/voice.md). */
  reason?: string
  /* Show the reason as a small caption beneath the bars. */
  verbose?: boolean
  /* Static — bars don't pulse. Useful for permission-denied states where
     the content will not arrive. Default: false (pulsing = "loading"). */
  static?: boolean
  /* The content that will appear once redacted=false. */
  children?: ReactNode
} & Omit<HTMLAttributes<HTMLSpanElement>, 'children'>

/* RedactionLoader — the canonical brand-as-interaction loading state.
   The same redaction bars that brand the company are the placeholders for
   data the company is in the middle of resolving (or refusing to surface).
   Pulsing = data inbound. Static = permission denied or vault sealed.
   See brand/redaction.md and ADR-008. */
export function RedactionLoader({
  redacted = true,
  bars = 3,
  width,
  size = '0.75em',
  reason,
  verbose,
  static: isStatic,
  children,
  className,
  style,
  'aria-label': ariaLabel,
  ...rest
}: RedactionLoaderProps) {
  const wrapperStyle: CSSProperties = {
    ...(width !== undefined
      ? { width: typeof width === 'number' ? `${width}px` : width }
      : null),
    ...style,
  }
  const barHeight = typeof size === 'number' ? `${size}px` : size

  if (!redacted) {
    return (
      <span
        className={joinClasses('rpblc-redaction-loader', 'rpblc-redaction-loader--revealed', className)}
        style={wrapperStyle}
        {...rest}
      >
        {children}
      </span>
    )
  }

  return (
    <span
      className={joinClasses(
        'rpblc-redaction-loader',
        'rpblc-redaction-loader--redacted',
        isStatic ? 'rpblc-redaction-loader--static' : 'rpblc-redaction-loader--pulsing',
        className,
      )}
      style={wrapperStyle}
      role="status"
      aria-live="polite"
      aria-busy={!isStatic ? true : undefined}
      aria-label={ariaLabel ?? reason ?? 'Loading redacted content'}
      {...rest}
    >
      <span className="rpblc-redaction-loader__bars" aria-hidden="true">
        {Array.from({ length: Math.max(1, bars) }, (_, i) => (
          <span
            key={i}
            className="rpblc-redaction-loader__bar"
            style={{ height: barHeight, animationDelay: `${i * 90}ms` }}
          />
        ))}
      </span>
      {verbose && reason ? (
        <span className="rpblc-redaction-loader__caption">{reason}</span>
      ) : null}
    </span>
  )
}

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
