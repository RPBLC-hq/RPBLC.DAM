import { type CSSProperties, type ElementType, type HTMLAttributes } from 'react'
import { BrandLockupGlyphs } from './BrandLockupGlyphs'

export type BracketMarkProps = {
  /** Letter inside the brackets. Defaults to "R". For product-specific marks, use a dedicated component. */
  glyph?: string
  /** Size of the mark. Number = px; string = any CSS length. Becomes the wrapper's font-size. */
  size?: number | string
  /** Underlying element. Defaults to <span>. */
  as?: ElementType
} & Omit<HTMLAttributes<HTMLElement>, 'children'>

/**
 * BracketMark — the collapsed RPBLC mark `[R:]`.
 *
 * Used for favicon, app icon, single-letter contexts. Composed by FooterIcon,
 * Wordmark (via shared render path), and any product-specific lockup.
 *
 * Scales via wrapper `font-size`. All internal proportions are in `em`.
 *
 * See brand/mark.md and decisions/ADR-004.
 */
/* Below this size (in px), the colon dots collapse into the letterform.
   We auto-apply the --sm modifier so the colon shifts to --accent-bright. */
const OPTICAL_SMALL_THRESHOLD_PX = 24

export function BracketMark({
  glyph = 'R',
  size,
  as,
  className,
  style,
  ...rest
}: BracketMarkProps) {
  const Tag = (as ?? 'span') as ElementType
  const wrapperStyle: CSSProperties = {
    fontSize: typeof size === 'number' ? `${size}px` : size,
    ...style,
  }
  const isSmall = typeof size === 'number' && size <= OPTICAL_SMALL_THRESHOLD_PX
  return (
    <Tag
      className={joinClasses(
        'rpblc-bracket-mark',
        isSmall ? 'rpblc-bracket-mark--sm' : undefined,
        className,
      )}
      style={wrapperStyle}
      aria-hidden={rest['aria-label'] ? undefined : true}
      {...rest}
    >
      <BrandLockupGlyphs
        classPrefix="rpblc-bracket-mark"
        beforeColon={<span className="rpblc-bracket-mark__letter">{glyph}</span>}
      />
    </Tag>
  )
}

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
