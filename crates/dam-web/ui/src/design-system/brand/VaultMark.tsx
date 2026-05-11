import { type CSSProperties, type HTMLAttributes } from 'react'
import { VaultFrame } from './VaultFrame'

export type VaultMarkProps = {
  /** Size of the vault. Becomes the wrapper's font-size; everything else scales. */
  size?: number | string
  /** Letter spacing of the wordmark. Defaults to 0.16em (≈ canonical 8px stamp). */
  letterSpacing?: number | string
  /** Wordmark text. Defaults to "RPBLC". */
  text?: string
} & Omit<HTMLAttributes<HTMLDivElement>, 'children'>

/**
 * VaultMark — the institutional seal: RPBLC stamped inside a vault frame.
 *
 * Composes VaultFrame (per ADR-007). No brackets or colon — this is the
 * wordmark inside the vault, not the bracket-flanked lockup.
 *
 * See brand/mark.md.
 */
export function VaultMark({
  size,
  letterSpacing = '0.16em',
  text = 'RPBLC',
  className,
  ...rest
}: VaultMarkProps) {
  const inner: CSSProperties = {
    letterSpacing: typeof letterSpacing === 'number' ? `${letterSpacing}px` : letterSpacing,
  }
  return (
    <VaultFrame
      size={size}
      inner={false}
      className={joinClasses('rpblc-vault-mark', className)}
      {...rest}
    >
      <span className="rpblc-vault-mark__text" style={inner}>
        {text}
      </span>
    </VaultFrame>
  )
}

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
