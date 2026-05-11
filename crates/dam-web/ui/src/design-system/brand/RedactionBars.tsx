import { type CSSProperties, type HTMLAttributes } from 'react'

export type RedactionBarsProps = {
  /** Size of the mark. Number = px; string = any CSS length. */
  size?: number | string
  /** Text to redact. Bars replace where vowels would be (between specific consonant pairs). Defaults to "RPBLC". */
  text?: string
} & Omit<HTMLAttributes<HTMLSpanElement>, 'children'>

/**
 * RedactionBars — `R̄P̄BL̄C` — the product mechanic as identifier.
 *
 * Letters interspersed with horizontal bars where the vowels were redacted.
 * Implemented as inline-block bars (not Unicode combining marks) for
 * cross-platform consistency.
 *
 * See brand/mark.md.
 */
export function RedactionBars({
  size,
  text = 'RPBLC',
  className,
  style,
  ...rest
}: RedactionBarsProps) {
  const wrapperStyle: CSSProperties = {
    fontSize: typeof size === 'number' ? `${size}px` : size,
    ...style,
  }
  // Place a redaction bar between every consonant pair that flanks a removed vowel.
  // For "RPBLC" → R[bar]P[bar]BL[bar]C reflects the redaction of REPUBLIC's three vowels.
  // Generalized: a bar after every odd-indexed letter except the last.
  const chars = text.split('')
  return (
    <span
      className={joinClasses('rpblc-redaction-bars', className)}
      style={wrapperStyle}
      aria-label={rest['aria-label'] ?? `${text} redacted`}
      {...rest}
    >
      {chars.map((c, i) => (
        <span key={i} className="rpblc-redaction-bars__group">
          <span className="rpblc-redaction-bars__letter">{c}</span>
          {shouldBarAfter(i, chars.length) && <span className="rpblc-redaction-bars__bar" aria-hidden="true" />}
        </span>
      ))}
    </span>
  )
}

function shouldBarAfter(index: number, length: number): boolean {
  if (index === length - 1) return false
  // After R(0), P(1), L(3) for "RPBLC" → R-bar-P-bar-BL-bar-C.
  // Pattern: bars after letters 0, 1, 3 — encoding REPUBLIC's vowel positions.
  return index === 0 || index === 1 || index === 3
}

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
