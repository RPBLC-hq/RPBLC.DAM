import { type CSSProperties, type ElementType, type HTMLAttributes } from 'react'
import { BrandLockupGlyphs } from './BrandLockupGlyphs'

export type WordmarkInteractiveProps = {
  /** Size of the mark. Number = px; string = any CSS length. */
  size?: number | string
  /** If provided, renders as <a> with this href. Otherwise renders as <span>. */
  href?: string
  /** Underlying element. Overridden if `href` is provided. */
  as?: ElementType
} & Omit<HTMLAttributes<HTMLElement>, 'children'>

const LETTERS = ['R', 'P', 'B', 'L', 'C'] as const

/**
 * WordmarkInteractive — the wordmark with the canonical hover-scan effect.
 *
 * Hovering the mark dims all glyphs to --bg; hovering an individual glyph
 * re-brightens it; the colon snaps back to --accent.
 * Transition uses --dur-fast (120ms).
 *
 * Composes the shared internal bracket/colon glyph path (per ADR-007) and
 * adds the interactive class for hover behavior.
 *
 * See brand/mark.md.
 */
export function WordmarkInteractive({
  size,
  href,
  as,
  className,
  style,
  ...rest
}: WordmarkInteractiveProps) {
  const Tag = (href ? 'a' : (as ?? 'span')) as ElementType
  const wrapperStyle: CSSProperties = {
    fontSize: typeof size === 'number' ? `${size}px` : size,
    ...style,
  }
  const tagProps: Record<string, unknown> = href ? { href } : {}
  return (
    <Tag
      className={joinClasses('rpblc-wordmark', 'rpblc-wordmark--interactive', className)}
      style={wrapperStyle}
      aria-label={rest['aria-label'] ?? (href ? 'RPBLC' : undefined)}
      {...tagProps}
      {...rest}
    >
      <BrandLockupGlyphs
        classPrefix="rpblc-wordmark"
        beforeColon={LETTERS.map((l) => (
          <span key={l} className="rpblc-wordmark__letter">
            {l}
          </span>
        ))}
      />
    </Tag>
  )
}

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
