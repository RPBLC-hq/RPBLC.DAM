import { type HTMLAttributes } from 'react'

export type RankBarTone = 'accent' | 'alarm' | 'soft' | 'bright' | 'muted'

export type RankBarSegment = {
  /** Segment value. Combined with `total` (or sum of all values) to compute width. */
  value: number
  /** Visual tone — drives the segment fill. Defaults to `accent`. */
  tone?: RankBarTone
  /** Optional accessible label naming the segment ("redacted", "allowed", "denied"). */
  label?: string
}

export type RankBarProps = {
  /** Segments rendered left-to-right. */
  segments: RankBarSegment[]
  /**
   * Optional total used to normalize. When absent, the bar normalizes to
   * the sum of all segment values (=100% utilization). When present, the
   * bar may be partially full when the sum is less than total.
   */
  total?: number
  /** Accessible label for the whole bar (e.g. "anthropic — 1,204 events"). */
  ariaLabel?: string
} & Omit<HTMLAttributes<HTMLDivElement>, 'children' | 'aria-label'>

/**
 * RankBar — horizontal segmented bar for breakdown leaderboards.
 *
 * Used on the privacy-dividend dashboard (Insights) to render rows like
 * "anthropic — 1,204 — [████████████░░] 92% redacted, 8% allowed".
 *
 * Each segment fills a fraction of the bar; tones use design-system
 * color tokens. The component is purely visual; the surrounding row
 * (label, count, legend) is the consumer's responsibility.
 */
export function RankBar({
  segments,
  total,
  ariaLabel,
  className,
  ...rest
}: RankBarProps) {
  const sum = segments.reduce((s, x) => s + x.value, 0)
  const denom = total ?? sum
  return (
    <div
      className={join('rpblc-rank-bar', className)}
      role="img"
      aria-label={ariaLabel}
      {...rest}
    >
      {segments.map((seg, i) => {
        const pct = denom > 0 ? (seg.value / denom) * 100 : 0
        const tone = seg.tone ?? 'accent'
        return (
          <span
            key={i}
            className={join('rpblc-rank-bar__segment', `rpblc-rank-bar__segment--${tone}`)}
            style={{ width: `${pct}%` }}
            aria-label={seg.label}
          />
        )
      })}
    </div>
  )
}

function join(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
