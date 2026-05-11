import { type ReactNode } from 'react'

type BrandLockupGlyphsProps = {
  /** CSS class prefix, e.g. "rpblc-wordmark" or "rpblc-connect-mark". */
  classPrefix: string
  /** Content before the brand colon. */
  beforeColon: ReactNode
  /** Content after the brand colon, before the closing bracket. */
  afterColon?: ReactNode
}

/**
 * Internal bracket/colon renderer.
 *
 * Official marks stay as named public components, but the bracket walls and
 * brand colon are emitted from one place so the lockup grammar cannot drift.
 */
export function BrandLockupGlyphs({
  classPrefix,
  beforeColon,
  afterColon,
}: BrandLockupGlyphsProps) {
  return (
    <>
      <span className={`${classPrefix}__bracket`}>[</span>
      {beforeColon}
      <span className={`${classPrefix}__colon`}>:</span>
      {afterColon}
      <span className={`${classPrefix}__bracket`}>]</span>
    </>
  )
}
