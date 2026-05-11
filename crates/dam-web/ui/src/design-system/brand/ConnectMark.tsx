import { type CSSProperties, type ElementType, type HTMLAttributes, type ReactNode } from 'react'
import { BrandLockupGlyphs } from './BrandLockupGlyphs'

export type ConnectMarkProps = {
  /** What we're connecting to. Defaults to "DAM". The string after the colon. */
  target?: string
  /** Verb before the colon. Defaults to "CONNECT". */
  verb?: string
  /** Size of the stamp — becomes the wrapper's font-size; everything scales. */
  size?: number | string
  /** If provided, renders as an anchor with this href. */
  href?: string
  /** Underlying element. Overridden if href is provided. Defaults to "button". */
  as?: ElementType
  /** Optional caption rendered below the stamp in mono small. */
  caption?: ReactNode
} & Omit<HTMLAttributes<HTMLElement>, 'children'>

/**
 * ConnectMark — the canonical "connect to RPBLC" gesture, as a brand identity piece.
 *
 * This is NOT a Button. It is a **stamp** — a vault-frame around a typographic
 * lockup `[ <verb> : <target> ]` that says "the bank is taking custody."
 * The component lives in `src/brand/` because its visual identity is part of
 * the brand catalog, not a generic UI affordance.
 *
 * Visual logic:
 *   - Outer vault-frame in --bright (paired hairlines via box-shadow inset).
 *   - Inside, the bracket-mark register: brackets in --soft, verb in --bright,
 *     colon in --accent, target in --bright.
 *   - At rest: calm. On hover: outer frame, brackets, verb, and target
 *     become --accent; the colon is already --accent. The whole seal lights
 *     up to receive the connection.
 *
 * Scales like every other mark via `size`. All internal proportions are em.
 *
 * See brand/mark.md.
 */
export function ConnectMark({
  target = 'DAM',
  verb = 'CONNECT',
  size,
  href,
  as,
  caption,
  className,
  style,
  ...rest
}: ConnectMarkProps) {
  const Tag = (href ? 'a' : (as ?? 'button')) as ElementType
  const wrapperStyle: CSSProperties = {
    fontSize: typeof size === 'number' ? `${size}px` : size,
    ...style,
  }
  const tagProps: Record<string, unknown> = href
    ? { href }
    : { type: (rest as { type?: string }).type ?? 'button' }
  const ariaLabel = (rest as { 'aria-label'?: string })['aria-label'] ?? `${verb} to ${target}`
  return (
    <span className={joinClasses('rpblc-connect-wrap', className)} style={wrapperStyle}>
      <Tag
        className="rpblc-connect-mark"
        aria-label={ariaLabel}
        {...tagProps}
        {...rest}
      >
        <BrandLockupGlyphs
          classPrefix="rpblc-connect-mark"
          beforeColon={<span className="rpblc-connect-mark__verb">{verb}</span>}
          afterColon={<span className="rpblc-connect-mark__target">{target}</span>}
        />
      </Tag>
      {caption && <span className="rpblc-connect-mark__caption">{caption}</span>}
    </span>
  )
}

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
