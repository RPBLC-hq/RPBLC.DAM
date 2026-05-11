import { type CSSProperties, type ElementType, type HTMLAttributes } from 'react'
import { BrandLockupGlyphs } from './BrandLockupGlyphs'

export type WordmarkProps = {
  /** Size of the mark. Number = px; string = any CSS length. Becomes the wrapper's font-size. */
  size?: number | string
  /** Underlying element. Defaults to <span>. */
  as?: ElementType
} & Omit<HTMLAttributes<HTMLElement>, 'children'>

const LETTERS = ['R', 'P', 'B', 'L', 'C'] as const

/**
 * Wordmark — the canonical RPBLC wordmark `[RPBLC:]`.
 *
 * Static, no hover behavior. For interactive variants use WordmarkInteractive.
 * Scales via wrapper `font-size`. All internal proportions are in `em`.
 *
 * See brand/mark.md.
 */
export function Wordmark({ size, as, className, style, ...rest }: WordmarkProps) {
  const Tag = (as ?? 'span') as ElementType
  const wrapperStyle: CSSProperties = {
    fontSize: typeof size === 'number' ? `${size}px` : size,
    ...style,
  }
  return (
    <Tag
      className={joinClasses('rpblc-wordmark', className)}
      style={wrapperStyle}
      aria-hidden={rest['aria-label'] ? undefined : true}
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
