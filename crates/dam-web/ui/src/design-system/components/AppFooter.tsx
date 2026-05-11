import { type HTMLAttributes, type ReactNode } from 'react'

export type AppFooterProps = {
  children: ReactNode
} & Omit<HTMLAttributes<HTMLElement>, 'children'>

/**
 * AppFooter — the wallet-feel app footer.
 *
 * The bottom edge of a wallet-style local surface (the DAM tray, future
 * RPBLC apps). Pinned to the bottom of its host (typically `TrayShell`
 * footer slot or an equivalent layout slot), with a hairline border on
 * top and `--panel` background.
 *
 * The component is a layout primitive — it owns the surface, padding,
 * and item spacing, but does not own which items appear. Consumers
 * compose `Link`, `Button`, or icon-only buttons inside.
 *
 * Distinct from `Footer`, which is the brand/marketing footer for
 * RPBLC.public and similar surfaces.
 *
 * Use `AppFooterSpacer` to push trailing items (typically an icon-only
 * destructive action) to the right edge.
 */
export function AppFooter({ children, className, ...rest }: AppFooterProps) {
  return (
    <footer className={join('rpblc-app-footer', className)} {...rest}>
      {children}
    </footer>
  )
}

/**
 * AppFooterSpacer — invisible flex spacer used to right-align trailing
 * items within an `AppFooter`. The spacer takes whatever horizontal
 * space is left after sized children are laid out.
 */
export function AppFooterSpacer({ className, ...rest }: HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={join('rpblc-app-footer__spacer', className)}
      aria-hidden="true"
      {...rest}
    />
  )
}

function join(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
