import { type HTMLAttributes, type ReactNode } from 'react'

export type TrayShellProps = {
  /**
   * Brand bar content — typically a `[R:]` mark + product stamp + secondary
   * controls (open-in-browser, pending-request badge). The shell pins this
   * to the top, hairline border below.
   */
  brandBar: ReactNode
  /**
   * Page label slot. On root pages, the page title (no brackets, not interactive).
   * On non-root pages, a bracket-styled label like `[wallet]` that the consumer
   * makes interactive (the wallet-feel back affordance).
   *
   * Pass `undefined` to omit the label row entirely.
   */
  pageLabel?: ReactNode
  /**
   * Footer content — always visible. Typical: three items
   * (primary surface link, settings, an icon-only action).
   */
  footer: ReactNode
  /** Page content. */
  children: ReactNode
} & Omit<HTMLAttributes<HTMLDivElement>, 'children'>

/**
 * TrayShell — the wallet-feel tray container.
 *
 * Provides the four-region scaffold the tray surface needs:
 *
 *   ┌──────────────────────────┐
 *   │ brandBar                 │ ← pinned top
 *   ├──────────────────────────┤
 *   │ pageLabel (optional)     │ ← bracket-styled label / page title
 *   │                          │
 *   │ children                 │ ← scrollable
 *   │                          │
 *   ├──────────────────────────┤
 *   │ footer                   │ ← pinned bottom, always visible
 *   └──────────────────────────┘
 *
 * The component is a thin layout primitive. It does not own brand identity,
 * navigation logic, or page state — consumers compose those.
 *
 * Tray-friendly defaults:
 * - Fills the host width; the native shell owns the outer window.
 * - No scroll on the shell; the children region scrolls.
 * - No animation on region swaps (the wallet metaphor — see ADR-003 in
 *   `RPBLC.Architecture/dam/web/decisions/`).
 */
export function TrayShell({
  brandBar,
  pageLabel,
  footer,
  children,
  className,
  ...rest
}: TrayShellProps) {
  return (
    <div className={join('rpblc-tray-shell', className)} {...rest}>
      <header className="rpblc-tray-shell__brand-bar">{brandBar}</header>
      {pageLabel !== undefined && (
        <div className="rpblc-tray-shell__page-label">{pageLabel}</div>
      )}
      <main className="rpblc-tray-shell__content">{children}</main>
      <footer className="rpblc-tray-shell__footer">{footer}</footer>
    </div>
  )
}

function join(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
