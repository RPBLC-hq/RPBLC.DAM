import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  AppIntegrationCard,
  Button,
  Dropdown,
  ErrorTile,
  RedactionLoader,
  SegmentedControl,
  Section,
  Toggle,
  type AppIntegrationStatus,
} from '@rpblc/design'

import { ApiError, api, apiPost } from '@/lib/api/client'
import { useI18n, type Locale, type MessageKey } from '@/lib/i18n'
import { useThemePreference, type ThemePreference } from '@/lib/theme'

type StopResult = { ok: boolean }

type AppSetting = {
  id: string
  name: string
  purpose: string
  enabled: boolean
  profile: string
  profiles: string[]
  install_state: string
  target_path?: string
}

type NetworkSetting = {
  network_mode: string
  trust_mode: string
  ready: boolean
}

type DefaultsSetting = {
  auto_deny: string
  remember_grants: boolean
  mask_in_log: boolean
  system_notify: boolean
  auto_resolve_inbound: boolean
}

type DangerSetting = {
  can_stop_daemon: boolean
}

type SettingsView = {
  theme: string
  locale: string
  apps: AppSetting[]
  network: NetworkSetting
  defaults: DefaultsSetting
  danger: DangerSetting
}

const THEME_VALUES = ['system', 'light', 'dark'] as const
const LOCALE_VALUES = ['en', 'fr'] as const
const AUTO_DENY_VALUES = ['off', '30', '60', '300'] as const
const SETTINGS_QUERY_KEY = ['settings'] as const

export function SettingsPage() {
  const { t } = useI18n()
  const settings = useQuery({
    queryKey: SETTINGS_QUERY_KEY,
    queryFn: ({ signal }) => api<SettingsView>('/settings', { signal }),
  })

  return (
    <section className="dam-settings" aria-label={t('settings.aria')}>
      <h1 className="dam-settings__heading">{t('settings.heading')}</h1>
      <AppearanceSection />
      <LanguageSection />
      <AppsSection settings={settings.data} loading={settings.isPending} />
      <NetworkSection settings={settings.data} />
      <DefaultsSection settings={settings.data} />
      <ConnectionSection canStop={settings.data?.danger.can_stop_daemon ?? true} />
      <DangerSection />
    </section>
  )
}

function AppearanceSection() {
  const { t } = useI18n()
  const { preference, setPreference } = useThemePreference()

  const options = THEME_VALUES.map((value) => ({
    value,
    label: t(themeLabelKey(value)),
  }))

  return (
    <Section title={t('settings.appearance')} density="compact">
      <p className="dam-settings__hint">{t('settings.themeHint')}</p>
      <SegmentedControl<ThemePreference>
        value={preference}
        onValueChange={setPreference}
        options={options}
        aria-label={t('settings.themeAria')}
      />
    </Section>
  )
}

function LanguageSection() {
  const { t, locale, setLocale } = useI18n()

  const options = LOCALE_VALUES.map((value) => ({
    value,
    label: t(localeLabelKey(value)),
  }))

  return (
    <Section title={t('settings.language')} density="compact">
      <p className="dam-settings__hint">{t('settings.languageHint')}</p>
      <SegmentedControl<Locale>
        value={locale}
        onValueChange={setLocale}
        options={options}
        aria-label={t('settings.languageAria')}
      />
    </Section>
  )
}

function AppsSection({
  settings,
  loading,
}: {
  settings: SettingsView | undefined
  loading: boolean
}) {
  const { t } = useI18n()

  return (
    <Section id="apps" title={t('settings.apps')} density="compact">
      <p className="dam-settings__hint">{t('settings.appsHint')}</p>
      {loading ? (
        <RedactionLoader
          redacted
          bars={3}
          width="11em"
          reason={t('settings.appsLoading')}
          aria-label={t('settings.appsLoading')}
          verbose
        />
      ) : (
        <div className="dam-settings__apps">
          {settings?.apps.map((app) => (
            <AppRow key={app.id} app={app} />
          ))}
          {settings?.apps.length === 0 && (
            <p className="dam-settings__hint">{t('settings.appsEmpty')}</p>
          )}
        </div>
      )}
    </Section>
  )
}

function AppRow({ app }: { app: AppSetting }) {
  const { t } = useI18n()
  const queryClient = useQueryClient()
  const [optimistic, setOptimistic] = useState<boolean | null>(null)
  const checked = optimistic ?? app.enabled

  const enableApp = useMutation({
    mutationFn: () =>
      apiPost<SettingsView>(`/settings/apps/${app.id}`, { enabled: true }),
    onSuccess: (next) => {
      queryClient.setQueryData(SETTINGS_QUERY_KEY, next)
      setOptimistic(null)
    },
    onError: () => {
      setOptimistic(null)
    },
  })
  const disableApp = useMutation({
    mutationFn: () =>
      apiPost<SettingsView>(`/settings/apps/${app.id}`, { enabled: false }),
    onSuccess: (next) => {
      queryClient.setQueryData(SETTINGS_QUERY_KEY, next)
      setOptimistic(null)
    },
    onError: () => {
      setOptimistic(null)
    },
  })
  const setProfile = useMutation({
    mutationFn: (profile: string) =>
      apiPost<SettingsView>(`/settings/apps/${app.id}`, { profile }),
    onSuccess: (next) => {
      queryClient.setQueryData(SETTINGS_QUERY_KEY, next)
    },
  })

  const installLabel = appInstallLabel(app.install_state, t)
  const status = appStatus(app.install_state, checked)
  const blocked = app.install_state === 'modified'
  const error = enableApp.error ?? disableApp.error ?? setProfile.error
  const errorCode = error instanceof ApiError ? error.message : undefined

  return (
    <AppIntegrationCard
      name={app.name}
      purpose={app.purpose}
      status={status}
      hideStatusPill
      leading={leadingCode(app.id)}
      action={
        <Toggle
          size="sm"
          checked={checked}
          disabled={blocked || enableApp.isPending || disableApp.isPending}
          aria-label={
            checked ? t('settings.appsToggleOn') : t('settings.appsToggleOff')
          }
          onCheckedChange={(next) => {
            setOptimistic(next)
            if (next) enableApp.mutate()
            else disableApp.mutate()
          }}
        />
      }
      details={
        <div className="dam-settings__app-details">
          {app.profiles.length > 1 && (
            <Dropdown<string>
              size="sm"
              label={t('settings.appsProfile')}
              value={app.profile}
              items={app.profiles.map((p) => ({ value: p, label: p }))}
              onValueChange={(next) => setProfile.mutate(next)}
            />
          )}
          {app.target_path && (
            <p className="dam-settings__app-meta">
              <span>{t('settings.appsTarget')}</span>
              <code>{app.target_path}</code>
            </p>
          )}
          <p className="dam-settings__app-meta">
            <span>{t('settings.appsInstallState')}</span>
            <code>{installLabel}</code>
          </p>
          {blocked && (
            <p className="dam-settings__app-warning">{t('settings.appsModified')}</p>
          )}
          {errorCode && (
            <ErrorTile
              message={t(integrationErrorKey(errorCode))}
              action={
                <Button
                  variant="ghost"
                  size="sm"
                  type="button"
                  onClick={() => {
                    enableApp.reset()
                    disableApp.reset()
                    setProfile.reset()
                  }}
                >
                  {t('settings.dismiss')}
                </Button>
              }
            />
          )}
        </div>
      }
    />
  )
}

function NetworkSection({ settings }: { settings: SettingsView | undefined }) {
  const { t } = useI18n()

  return (
    <Section title={t('settings.network')} density="compact">
      <p className="dam-settings__hint">{t('settings.networkHint')}</p>
      <dl className="dam-settings__rows">
        <div className="dam-settings__row">
          <dt>{t('settings.networkMode')}</dt>
          <dd>{settings?.network.network_mode ?? '—'}</dd>
        </div>
        <div className="dam-settings__row">
          <dt>{t('settings.trustMode')}</dt>
          <dd>{settings?.network.trust_mode ?? '—'}</dd>
        </div>
        <div className="dam-settings__row">
          <dt>{t('settings.networkReady')}</dt>
          <dd>
            {settings
              ? settings.network.ready
                ? t('settings.networkYes')
                : t('settings.networkNo')
              : '—'}
          </dd>
        </div>
      </dl>
    </Section>
  )
}

function DefaultsSection({ settings }: { settings: SettingsView | undefined }) {
  const { t } = useI18n()
  const defaults = settings?.defaults

  if (!defaults) {
    return (
      <Section title={t('settings.defaults')} density="compact">
        <RedactionLoader redacted bars={3} width="11em" verbose />
      </Section>
    )
  }

  const autoDenyOptions = AUTO_DENY_VALUES.map((value) => ({
    value,
    label: t(autoDenyLabelKey(value)),
  }))

  return (
    <Section title={t('settings.defaults')} density="compact">
      <p className="dam-settings__hint">{t('settings.defaultsHint')}</p>
      <div className="dam-settings__rows">
        <div className="dam-settings__row dam-settings__row--block">
          <Dropdown<(typeof AUTO_DENY_VALUES)[number]>
            size="sm"
            label={t('settings.autoDeny')}
            helper={t('settings.autoDenyHint')}
            value={defaults.auto_deny as (typeof AUTO_DENY_VALUES)[number]}
            items={autoDenyOptions}
            disabled
            onValueChange={() => {}}
          />
        </div>
        <Toggle
          size="sm"
          label={t('settings.rememberGrants')}
          helper={t('settings.rememberGrantsHint')}
          checked={defaults.remember_grants}
          disabled
          onCheckedChange={() => {}}
        />
        <Toggle
          size="sm"
          label={t('settings.maskInLog')}
          helper={t('settings.maskInLogHint')}
          checked={defaults.mask_in_log}
          disabled
          onCheckedChange={() => {}}
        />
        <Toggle
          size="sm"
          label={t('settings.systemNotify')}
          helper={t('settings.systemNotifyHint')}
          checked={defaults.system_notify}
          disabled
          onCheckedChange={() => {}}
        />
        <Toggle
          size="sm"
          label={t('settings.autoResolveInbound')}
          helper={t('settings.autoResolveInboundHint')}
          checked={defaults.auto_resolve_inbound}
          disabled
          onCheckedChange={() => {}}
        />
      </div>
    </Section>
  )
}

function ConnectionSection({ canStop }: { canStop: boolean }) {
  const { t } = useI18n()
  const [confirming, setConfirming] = useState(false)

  const stop = useMutation({
    mutationFn: () => apiPost<StopResult>('/settings/danger/stop', {}),
    onSuccess: () => {
      setConfirming(false)
    },
  })

  const code = stop.error instanceof ApiError ? stop.error.message : undefined

  return (
    <Section title={t('settings.connection')} density="compact">
      <p className="dam-settings__hint">{t('settings.stopHint')}</p>
      {confirming ? (
        <div className="dam-settings__confirm">
          <p className="dam-settings__confirm-line">{t('settings.stopConfirm')}</p>
          <div className="dam-settings__confirm-actions">
            <Button
              variant="ghost"
              size="sm"
              type="button"
              disabled={stop.isPending}
              onClick={() => setConfirming(false)}
            >
              {t('settings.cancel')}
            </Button>
            <Button
              variant="danger"
              size="sm"
              type="button"
              disabled={stop.isPending}
              onClick={() => stop.mutate()}
            >
              {stop.isPending ? t('settings.stopping') : t('settings.confirmStop')}
            </Button>
          </div>
        </div>
      ) : (
        <Button
          variant="danger"
          size="sm"
          type="button"
          disabled={!canStop}
          onClick={() => setConfirming(true)}
        >
          {t('settings.stopDaemon')}
        </Button>
      )}
      {code && (
        <ErrorTile
          message={t(stopErrorKey(code))}
          action={
            <Button
              variant="ghost"
              size="sm"
              type="button"
              onClick={() => stop.reset()}
            >
              {t('settings.dismiss')}
            </Button>
          }
        />
      )}
    </Section>
  )
}

function DangerSection() {
  const { t } = useI18n()
  const [confirming, setConfirming] = useState<'reset' | 'uninstall' | null>(null)

  const reset = useMutation({
    mutationFn: () => apiPost<StopResult>('/settings/danger/reset', {}),
    onSuccess: () => setConfirming(null),
  })
  const uninstall = useMutation({
    mutationFn: () => apiPost<StopResult>('/settings/danger/uninstall', {}),
    onSuccess: () => setConfirming(null),
  })

  const error = reset.error ?? uninstall.error
  const code = error instanceof ApiError ? error.message : undefined

  return (
    <Section title={t('settings.danger')} density="compact">
      <p className="dam-settings__hint">{t('settings.dangerHint')}</p>

      <div className="dam-settings__danger-actions">
        {confirming === 'reset' ? (
        <ConfirmTile
          message={t('settings.resetConfirm')}
          confirmLabel={
            reset.isPending ? t('settings.resetting') : t('settings.confirmReset')
          }
          confirmDisabled={reset.isPending}
          onCancel={() => setConfirming(null)}
          onConfirm={() => reset.mutate()}
        />
      ) : (
        <Button
          variant="danger"
          size="sm"
          type="button"
          onClick={() => setConfirming('reset')}
        >
          {t('settings.resetSettings')}
        </Button>
      )}

      {confirming === 'uninstall' ? (
        <ConfirmTile
          message={t('settings.uninstallConfirm')}
          confirmLabel={
            uninstall.isPending
              ? t('settings.uninstalling')
              : t('settings.confirmUninstall')
          }
          confirmDisabled={uninstall.isPending}
          onCancel={() => setConfirming(null)}
          onConfirm={() => uninstall.mutate()}
        />
      ) : (
        <Button
          variant="danger"
          size="sm"
          type="button"
          onClick={() => setConfirming('uninstall')}
        >
          {t('settings.uninstall')}
        </Button>
      )}
      </div>

      {code && (
        <ErrorTile
          message={t(stopErrorKey(code))}
          action={
            <Button
              variant="ghost"
              size="sm"
              type="button"
              onClick={() => {
                reset.reset()
                uninstall.reset()
              }}
            >
              {t('settings.dismiss')}
            </Button>
          }
        />
      )}
    </Section>
  )
}

function ConfirmTile({
  message,
  confirmLabel,
  confirmDisabled,
  onCancel,
  onConfirm,
}: {
  message: string
  confirmLabel: string
  confirmDisabled: boolean
  onCancel: () => void
  onConfirm: () => void
}) {
  const { t } = useI18n()
  return (
    <div className="dam-settings__confirm">
      <p className="dam-settings__confirm-line">{message}</p>
      <div className="dam-settings__confirm-actions">
        <Button
          variant="ghost"
          size="sm"
          type="button"
          disabled={confirmDisabled}
          onClick={onCancel}
        >
          {t('settings.cancel')}
        </Button>
        <Button
          variant="danger"
          size="sm"
          type="button"
          disabled={confirmDisabled}
          onClick={onConfirm}
        >
          {confirmLabel}
        </Button>
      </div>
    </div>
  )
}

function themeLabelKey(value: ThemePreference): MessageKey {
  if (value === 'system') return 'settings.theme.system'
  if (value === 'light') return 'settings.theme.light'
  return 'settings.theme.dark'
}

function localeLabelKey(value: Locale): MessageKey {
  return value === 'fr' ? 'settings.language.fr' : 'settings.language.en'
}

function autoDenyLabelKey(value: (typeof AUTO_DENY_VALUES)[number]): MessageKey {
  if (value === 'off') return 'settings.autoDeny.off'
  if (value === '30') return 'settings.autoDeny.30s'
  if (value === '60') return 'settings.autoDeny.1m'
  return 'settings.autoDeny.5m'
}

function leadingCode(id: string): string {
  // Short mono identifier shown before the app name. Three characters
  // so the slot stays narrow against tray widths.
  return id
    .replace(/[^a-z0-9]/gi, '')
    .slice(0, 3)
    .toUpperCase()
}

function appStatus(installState: string, enabled: boolean): AppIntegrationStatus {
  if (installState === 'modified') return 'attention'
  if (installState === 'pending') return 'pending'
  return enabled ? 'enabled' : 'disabled'
}

function appInstallLabel(state: string, t: (key: MessageKey) => string): string {
  if (state === 'applied') return t('settings.installState.applied')
  if (state === 'modified') return t('settings.installState.modified')
  if (state === 'pending') return t('settings.installState.pending')
  return t('settings.installState.needsApply')
}

function integrationErrorKey(code: string): MessageKey {
  if (code === 'apply_modified_target') return 'settings.error.modifiedTarget'
  if (code === 'apply_target_unwritable') return 'settings.error.targetUnwritable'
  if (code === 'invalid_request') return 'settings.error.invalidRequest'
  if (code === 'not_implemented') return 'settings.error.notImplemented'
  return 'settings.error.unknown'
}

function stopErrorKey(code: string): MessageKey {
  return code === 'not_implemented'
    ? 'settings.error.notImplemented'
    : 'settings.error.unknown'
}
