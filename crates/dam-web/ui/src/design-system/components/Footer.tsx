import { type HTMLAttributes, type ReactNode } from 'react'
import { FooterIcon } from '../brand/FooterIcon'

export type FooterLink = {
  label: string
  href: string
  icon?: ReactNode
}

export type FooterProps = {
  /* Tagline shown next to the brand. Defaults to the thesis line —
     "The republic builds." Per ADR-009, prefer this default; only
     override for surfaces that need a verbatim product label. */
  tagline?: ReactNode
  /** Optional brand name shown next to the icon. Defaults to "RPBLC". */
  name?: ReactNode
  /** Copyright string. Defaults to "© <current year> RPBLC". */
  copyright?: ReactNode
  /** Right-side social/external links. */
  links?: FooterLink[]
} & Omit<HTMLAttributes<HTMLElement>, 'children'>

/**
 * Footer — the canonical RPBLC footer.
 *
 * Composes FooterIcon (per ADR-007). Three columns: brand (icon + name +
 * tagline), copyright (centered), links (right-aligned).
 */
export function Footer({
  tagline = 'The republic builds.',
  name = 'RPBLC',
  copyright,
  links,
  className,
  ...rest
}: FooterProps) {
  const year = new Date().getFullYear()
  const copy = copyright ?? `© ${year} RPBLC`
  return (
    <footer className={joinClasses('rpblc-footer', className)} {...rest}>
      <div className="rpblc-footer__brand">
        <FooterIcon size="40px" />
        <div>
          <div className="rpblc-footer__name">{name}</div>
          {tagline && <div className="rpblc-footer__tagline">{tagline}</div>}
        </div>
      </div>
      <div className="rpblc-footer__copy">{copy}</div>
      <div className="rpblc-footer__links">
        {(links ?? []).map((link) => (
          <a
            key={link.href}
            className="rpblc-footer__link"
            href={link.href}
            target="_blank"
            rel="noopener noreferrer"
            aria-label={link.label}
          >
            {link.icon ?? link.label}
          </a>
        ))}
      </div>
    </footer>
  )
}

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
