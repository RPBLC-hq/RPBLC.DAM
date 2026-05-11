import { type CSSProperties, type HTMLAttributes, type ReactNode } from 'react'

export type VaultFrameProps = {
  /** Content sealed inside the vault. */
  children: ReactNode
  /** Size of the frame. Becomes the wrapper's font-size; all internal dimensions are em. */
  size?: number | string
  /** Render the inner double-border. Defaults to true. */
  inner?: boolean
} & Omit<HTMLAttributes<HTMLDivElement>, 'children'>

/**
 * VaultFrame — the sealed enclave motif.
 *
 * Outer 2px border, gap, optional 2px inner border, content padding. All
 * em-scaled so a single `size` (or inherited font-size) drives the whole frame.
 *
 * See brand/mark.md.
 */
export function VaultFrame({
  children,
  size,
  inner = true,
  className,
  style,
  ...rest
}: VaultFrameProps) {
  const wrapperStyle: CSSProperties = {
    fontSize: typeof size === 'number' ? `${size}px` : size,
    ...style,
  }
  return (
    <div
      className={joinClasses('rpblc-vault-frame', inner ? undefined : 'rpblc-vault-frame--single', className)}
      style={wrapperStyle}
      {...rest}
    >
      {inner ? <div className="rpblc-vault-frame__inner">{children}</div> : children}
    </div>
  )
}

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
