import { type CSSProperties, type HTMLAttributes } from 'react'
import { BracketMark } from './BracketMark'

export type FooterIconProps = {
  /** Size of the icon (the box height/width). Becomes the wrapper's font-size; all internals scale. */
  size?: number | string
} & Omit<HTMLAttributes<HTMLDivElement>, 'children'>

/**
 * FooterIcon — the boxed `[R:]` identity for footers, sidebars, OG slots.
 *
 * A square box bordered with --bright containing a centered BracketMark.
 * Composes BracketMark (per ADR-007).
 *
 * Default box is 1em × 1em; setting `size` (or font-size on a parent)
 * scales the entire icon.
 *
 * See brand/mark.md.
 */
export function FooterIcon({ size, className, style, ...rest }: FooterIconProps) {
  const wrapperStyle: CSSProperties = {
    fontSize: typeof size === 'number' ? `${size}px` : size,
    ...style,
  }
  return (
    <div
      className={joinClasses('rpblc-footer-icon', className)}
      style={wrapperStyle}
      aria-hidden={rest['aria-label'] ? undefined : true}
      {...rest}
    >
      <BracketMark size="0.36em" />
    </div>
  )
}

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
