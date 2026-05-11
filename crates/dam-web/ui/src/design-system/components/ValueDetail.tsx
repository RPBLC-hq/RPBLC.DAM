import { useState, type HTMLAttributes, type ReactNode } from 'react'
import { Button } from './Button'
import { ProtectionMark, type ProtectionState } from './ProtectionMark'

export type ValueDetailParty = {
  /** Display name. Will be bracketed in the rendered roster. */
  name: string
  /** Free-text "since" or "as of" label. */
  since?: ReactNode
}

export type ValueDetailMetaItem = {
  key: ReactNode
  value: ReactNode
  /** Render the value in --bright with extra weight. */
  emphasis?: boolean
}

export type ValueDetailProps = {
  /** Short kind label (e.g. "primary email"). */
  kind: ReactNode
  /** The stored value — renders as the bracketed hero. */
  value: ReactNode
  /** Protection state. Drives the ProtectionMark in the header. */
  state: ProtectionState
  /** Extra rows shown in the meta grid (last seen, stored in, …). */
  meta?: ValueDetailMetaItem[]
  /** Parties currently allowed. Renders the sharing roster. */
  sharedWith?: ValueDetailParty[]
  /** Default candidate party for the "allow" action when state is
   *  protected/revoked and no party is explicit. */
  candidateParty?: string
  /** Called when the user confirms allowing a party. */
  onAllow?: (party: string) => void
  /** Called when the user confirms revoking a party's access. */
  onRevoke?: (party: string) => void
  /** Called when the user confirms protecting from everyone. */
  onProtectAll?: () => void
} & Omit<HTMLAttributes<HTMLElement>, 'children'>

type Pending =
  | null
  | { kind: 'allow'; party: string }
  | { kind: 'revoke'; party: string }
  | { kind: 'protect-all' }

/**
 * ValueDetail — the no-accident detail surface for one stored value.
 *
 * Wraps the wallet-detail pattern: kind eyebrow + ProtectionMark in
 * the header, the stored value as the bracketed hero, a meta block
 * (stored-in / last-seen), the sharing roster, and an action region
 * whose buttons spell out the consequence. Clicking any committing
 * action swaps the row in place for an inline confirm card that
 * names the actor and the real value before commit.
 *
 * The component owns the pending-confirm state internally so consumers
 * pass only the three commit handlers.
 */
export function ValueDetail({
  kind,
  value,
  state,
  meta,
  sharedWith = [],
  candidateParty = 'anthropic',
  onAllow,
  onRevoke,
  onProtectAll,
  className,
  ...rest
}: ValueDetailProps) {
  const [pending, setPending] = useState<Pending>(null)

  return (
    <article className={joinClasses('rpblc-value-detail', className)} {...rest}>
      <header className="rpblc-value-detail__head">
        <span className="rpblc-value-detail__kind">{kind}</span>
        <ProtectionMark state={state} />
      </header>

      <p className="rpblc-value-detail__hero">
        <span className="rpblc-value-detail__hero-bracket" aria-hidden="true">[</span>
        <span className="rpblc-value-detail__hero-value">{value}</span>
        <span className="rpblc-value-detail__hero-bracket" aria-hidden="true">]</span>
      </p>

      {meta && meta.length > 0 && (
        <dl className="rpblc-value-detail__meta">
          {meta.map((m, i) => (
            <div className="rpblc-value-detail__meta-row" key={i}>
              <dt>{m.key}</dt>
              <dd className={m.emphasis ? 'rpblc-value-detail__meta-value--em' : undefined}>
                {m.value}
              </dd>
            </div>
          ))}
        </dl>
      )}

      {sharedWith.length > 0 && (
        <ul className="rpblc-value-detail__sharing">
          {sharedWith.map((p) => (
            <li className="rpblc-value-detail__sharing-row" key={p.name}>
              <span>
                <span className="rpblc-value-detail__sharing-who">{p.name}</span>
                <span className="rpblc-value-detail__sharing-verb">has been reading this</span>
              </span>
              {p.since && (
                <span className="rpblc-value-detail__sharing-since">since {p.since}</span>
              )}
            </li>
          ))}
        </ul>
      )}

      {pending === null ? (
        <ActionRegion
          state={state}
          candidateParty={candidateParty}
          firstSharedParty={sharedWith[0]?.name}
          onChoose={setPending}
        />
      ) : (
        <ConfirmRegion
          pending={pending}
          value={value}
          onCancel={() => setPending(null)}
          onConfirm={() => {
            if (pending.kind === 'allow') onAllow?.(pending.party)
            else if (pending.kind === 'revoke') onRevoke?.(pending.party)
            else onProtectAll?.()
            setPending(null)
          }}
        />
      )}
    </article>
  )
}

function ActionRegion({
  state,
  candidateParty,
  firstSharedParty,
  onChoose,
}: {
  state: ProtectionState
  candidateParty: string
  firstSharedParty?: string
  onChoose: (p: Pending) => void
}) {
  if (state === 'allowed') {
    const party = firstSharedParty ?? candidateParty
    return (
      <div className="rpblc-value-detail__actions">
        <p className="rpblc-value-detail__hint">
          <b>{party}</b> can read this. Stop allowing them at any time — the next request
          from them will be blocked.
        </p>
        <div className="rpblc-value-detail__actions-row">
          <Button
            variant="danger"
            bracketed
            onClick={() => onChoose({ kind: 'revoke', party })}
          >
            stop allowing {party}
          </Button>
          <Button
            variant="secondary"
            bracketed
            onClick={() => onChoose({ kind: 'protect-all' })}
          >
            protect from everyone
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className="rpblc-value-detail__actions">
      <p className="rpblc-value-detail__hint">
        {state === 'protected'
          ? 'This value is protected. Nothing outside your local vault can read it.'
          : 'This value is protected again. Past sharing is logged in the audit trail.'}
      </p>
      <div className="rpblc-value-detail__actions-row">
        <Button
          variant="primary"
          bracketed
          onClick={() => onChoose({ kind: 'allow', party: candidateParty })}
        >
          allow {candidateParty} to read this
        </Button>
      </div>
    </div>
  )
}

function ConfirmRegion({
  pending,
  value,
  onCancel,
  onConfirm,
}: {
  pending: Exclude<Pending, null>
  value: ReactNode
  onCancel: () => void
  onConfirm: () => void
}) {
  let sentence: ReactNode
  let confirmLabel: string
  let tone: 'primary' | 'danger'
  if (pending.kind === 'allow') {
    sentence = (
      <>
        From now on, <b>{pending.party}</b> will see your real{' '}
        <em>{value}</em>. RPBLC will keep a signed log of every read.
      </>
    )
    confirmLabel = `yes — allow ${pending.party}`
    tone = 'primary'
  } else if (pending.kind === 'revoke') {
    sentence = (
      <>
        <b>{pending.party}</b> will stop receiving <em>{value}</em> on their next
        request. They keep what they already have in context.
      </>
    )
    confirmLabel = `yes — stop allowing ${pending.party}`
    tone = 'danger'
  } else {
    sentence = (
      <>
        Every party allowed today will be revoked. The value returns to{' '}
        <b>protected</b> for everyone.
      </>
    )
    confirmLabel = 'yes — protect from everyone'
    tone = 'danger'
  }
  return (
    <div className="rpblc-value-detail__confirm" role="alertdialog" aria-modal="false">
      <p className="rpblc-value-detail__confirm-sentence">{sentence}</p>
      <div className="rpblc-value-detail__confirm-row">
        <Button variant="ghost" onClick={onCancel} autoFocus>
          cancel
        </Button>
        <Button variant={tone} bracketed onClick={onConfirm}>
          {confirmLabel}
        </Button>
      </div>
    </div>
  )
}

function joinClasses(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(' ')
}
