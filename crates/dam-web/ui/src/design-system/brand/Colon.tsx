import { type CSSProperties, type HTMLAttributes } from 'react'

export type ColonProps = {
  /** Size of the colon. Number = px; string = any CSS length. Inherits font-size by default. */
  size?: number | string
  /** Use the high-saturation variant (for small sizes / low-contrast surfaces). */
  bright?: boolean
} & Omit<HTMLAttributes<HTMLSpanElement>, 'children'>

/* Colon — the naked brand punctuation.
   The single chromatic atom of RPBLC. Drop it inline between words to
   stamp brand voice into a headline or label: "Privacy : enforced.",
   "Vault : open.", "Connect : DAM".
   See brand/grammar.md. */
export function Colon({ size, bright, className, style, ...rest }: ColonProps) {
  const wrapperStyle: CSSProperties = {
    fontSize: typeof size === 'number' ? `${size}px` : size,
    ...style,
  }
  return (
    <span
      className={joinClasses('rpblc-colon', bright ? 'rpblc-colon--bright' : undefined, className)}
      style={wrapperStyle}
      aria-hidden="true"
      {...rest}
    >
      :
    </span>
  )
}

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
