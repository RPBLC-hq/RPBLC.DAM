import { type CSSProperties, type HTMLAttributes } from 'react'

export type CornerBracketProps = {
  /** Which corner. Defaults to "tl" (top-left). */
  corner?: 'tl' | 'tr' | 'bl' | 'br'
  /** Size of the bracket. Becomes the wrapper's font-size; arm length is 1em. */
  size?: number | string
  /** Color override. Defaults to var(--soft). Pass var(--accent) to emphasize. */
  color?: string
} & Omit<HTMLAttributes<HTMLSpanElement>, 'children'>

/**
 * CornerBracket — the deco corner motif.
 *
 * Two perpendicular hairlines forming a 90° corner. Used to frame regions,
 * stamp documents, or suggest a "scan zone." Pair four for the full deco frame.
 *
 * See brand/ornament.md.
 */
export function CornerBracket({
  corner = 'tl',
  size,
  color,
  className,
  style,
  ...rest
}: CornerBracketProps) {
  const wrapperStyle: CSSProperties = {
    fontSize: typeof size === 'number' ? `${size}px` : size,
    ['--rpblc-corner-color' as string]: color,
    ...style,
  }
  return (
    <span
      className={joinClasses('rpblc-corner-bracket', `rpblc-corner-bracket--${corner}`, className)}
      style={wrapperStyle}
      aria-hidden="true"
      {...rest}
    />
  )
}

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
