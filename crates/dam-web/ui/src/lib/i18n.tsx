export type Locale = 'en' | 'fr'

export type MessageKey =
  | 'nav.rpblcHome'
  | 'nav.damHome'
  | 'nav.openDamInBrowser'
  | 'nav.content'
  | 'nav.protected'
  | 'nav.off'
  | 'nav.pendingRequests'
  | 'nav.insights'
  | 'nav.wallet'
  | 'nav.allowed'
  | 'nav.activity'
  | 'nav.more'
  | 'nav.settings'
  | 'nav.system'
  | 'nav.health'
  | 'allowed.aria'
  | 'allowed.heading'
  | 'allowed.empty'
  | 'allowed.searchAria'
  | 'allowed.searchPlaceholder'
  | 'allowed.tryAgain'
  | 'allowed.loadingReason'
  | 'allowed.expiredDisclosure'
  | 'allowed.stopAllowing'
  | 'allowed.until'
  | 'allowed.error.unknown'
  | 'insights.aria'
  | 'insights.heading'
  | 'insights.range.today'
  | 'insights.range.7d'
  | 'insights.range.30d'
  | 'insights.range.all'
  | 'insights.rangeAria'
  | 'insights.metricLabel'
  | 'insights.appsHeading'
  | 'insights.kindsHeading'
  | 'insights.eventsHeading'
  | 'insights.empty.title'
  | 'insights.empty.body'
  | 'insights.loadingReason'
  | 'insights.error.unknown'
  | 'insights.legendRedacted'
  | 'insights.legendAllowed'
  | 'insights.legendDenied'
  | 'health.aria'
  | 'health.heading'
  | 'health.summaryHealthy'
  | 'health.summaryDegraded'
  | 'health.summaryNotConnected'
  | 'health.section.daemon'
  | 'health.section.network'
  | 'health.section.trust'
  | 'health.section.integrations'
  | 'health.section.recent'
  | 'health.daemon.pid'
  | 'health.daemon.version'
  | 'health.daemon.listen'
  | 'health.daemon.connected'
  | 'health.network.mode'
  | 'health.trust.mode'
  | 'health.trust.localCa'
  | 'health.trust.installed'
  | 'health.trust.notInstalled'
  | 'health.installCa'
  | 'health.connectAction'
  | 'health.empty.recent'
  | 'health.unknown'
  | 'health.loadingReason'
  | 'health.error.unknown'
  | 'system.aria'
  | 'system.heading'
  | 'system.searchAria'
  | 'system.searchPlaceholder'
  | 'system.scope.issues'
  | 'system.scope.all'
  | 'system.scope.daemon'
  | 'system.scope.network'
  | 'system.scope.filter'
  | 'system.scope.mcp'
  | 'system.scope.provider'
  | 'system.scopeAria'
  | 'system.severity.info'
  | 'system.severity.warn'
  | 'system.severity.error'
  | 'system.empty.scope'
  | 'system.empty.clearFilter'
  | 'system.loadingReason'
  | 'system.error.unknown'
  | 'connect.mainLabel'
  | 'connect.loading'
  | 'connect.loadingReason'
  | 'connect.checkAgain'
  | 'connect.connectAria'
  | 'connect.connectCaption'
  | 'connect.disconnectedLede'
  | 'connect.disconnectedFine'
  | 'connect.protectedStatus'
  | 'connect.pausedStatus'
  | 'connect.degradedStatus'
  | 'connect.setupStatus'
  | 'connect.pauseProtection'
  | 'connect.resumeProtection'
  | 'connect.recoveryAction'
  | 'connect.nothingAsking'
  | 'connect.protectedFor'
  | 'connect.systemMode'
  | 'request.incoming'
  | 'request.toDecide'
  | 'request.aria'
  | 'request.decision'
  | 'request.wantsToReadYour'
  | 'request.purposePrefix'
  | 'request.allowOnce'
  | 'request.allowAlways'
  | 'request.deny'
  | 'connect.grants'
  | 'connect.grantsAria'
  | 'connect.blockedToday'
  | 'connect.blockedTodayAria'
  | 'connect.appsMediated'
  | 'connect.appsMediatedAria'
  | 'connect.countsLabel'
  | 'connect.setupHeading'
  | 'connect.stepDone'
  | 'connect.stepCurrent'
  | 'connect.stepFailed'
  | 'connect.stepBlocked'
  | 'connect.step.launch_at_login'
  | 'connect.step.ne_install'
  | 'connect.step.ne_config'
  | 'connect.step.ne_enable'
  | 'connect.step.ne_start'
  | 'connect.step.linux_capture'
  | 'connect.step.windows_capture'
  | 'connect.step.ne_reboot'
  | 'connect.step.ca_install'
  | 'connect.step.apply_profiles'
  | 'connect.step.daemon_start'
  | 'connect.step.unknown'
  | 'connect.hint.launch_at_login'
  | 'connect.hint.ne_install'
  | 'connect.hint.ne_config'
  | 'connect.hint.ne_enable'
  | 'connect.hint.ne_start'
  | 'connect.hint.linux_capture'
  | 'connect.hint.windows_capture'
  | 'connect.hint.ne_reboot'
  | 'connect.hint.ca_install'
  | 'connect.hint.apply_profiles'
  | 'connect.hint.daemon_start'
  | 'connect.hintAriaLabel'
  | 'connect.action.launch_at_login'
  | 'connect.action.launch_at_login_skip'
  | 'connect.action.ne_install'
  | 'connect.action.ne_config'
  | 'connect.action.ne_enable'
  | 'connect.action.ne_start'
  | 'connect.action.platform_capture'
  | 'connect.action.ne_reboot'
  | 'connect.action.ca_install'
  | 'connect.action.apply_profiles'
  | 'connect.action.daemon_start'
  | 'connect.action.unknown'
  | 'connect.error.load'
  | 'connect.error.not_implemented'
  | 'connect.error.ne_pending_user_approval'
  | 'connect.error.ne_reboot_required'
  | 'connect.error.ca_install_denied'
  | 'connect.error.daemon_already_running'
  | 'connect.error.apply_modified_target'
  | 'connect.error.apply_target_unwritable'
  | 'connect.error.unknown'
  | 'connect.error.daemon_starting'
  | 'connect.error.setup_step_failed'
  | 'connect.error.network_offline'
  | 'connect.error.invalid_request'
  | 'connect.notice.dismiss'
  | 'blank.aria'
  | 'blank.notReady'
  | 'blank.backToConnect'
  | 'settings.aria'
  | 'settings.heading'
  | 'settings.appearance'
  | 'settings.themeAria'
  | 'settings.themeHint'
  | 'settings.theme.system'
  | 'settings.theme.light'
  | 'settings.theme.dark'
  | 'settings.language'
  | 'settings.languageAria'
  | 'settings.languageHint'
  | 'settings.language.en'
  | 'settings.language.fr'
  | 'settings.apps'
  | 'settings.appsHint'
  | 'settings.appsLoading'
  | 'settings.appsEmpty'
  | 'settings.appsToggleOn'
  | 'settings.appsToggleOff'
  | 'settings.appsProfile'
  | 'settings.appsTarget'
  | 'settings.appsInstallState'
  | 'settings.appsModified'
  | 'settings.installState.applied'
  | 'settings.installState.modified'
  | 'settings.installState.pending'
  | 'settings.installState.needsApply'
  | 'settings.network'
  | 'settings.networkHint'
  | 'settings.networkMode'
  | 'settings.trustMode'
  | 'settings.networkReady'
  | 'settings.networkYes'
  | 'settings.networkNo'
  | 'settings.defaults'
  | 'settings.defaultsHint'
  | 'settings.autoDeny'
  | 'settings.autoDenyHint'
  | 'settings.autoDeny.off'
  | 'settings.autoDeny.30s'
  | 'settings.autoDeny.1m'
  | 'settings.autoDeny.5m'
  | 'settings.rememberGrants'
  | 'settings.rememberGrantsHint'
  | 'settings.maskInLog'
  | 'settings.maskInLogHint'
  | 'settings.systemNotify'
  | 'settings.systemNotifyHint'
  | 'settings.autoResolveInbound'
  | 'settings.autoResolveInboundHint'
  | 'settings.notifyPrompt.title'
  | 'settings.notifyPrompt.body'
  | 'settings.notifyPrompt.allow'
  | 'settings.notifyPrompt.notNow'
  | 'settings.danger'
  | 'settings.dangerHint'
  | 'settings.resetSettings'
  | 'settings.resetConfirm'
  | 'settings.confirmReset'
  | 'settings.resetting'
  | 'settings.uninstall'
  | 'settings.uninstallConfirm'
  | 'settings.confirmUninstall'
  | 'settings.uninstalling'
  | 'settings.error.modifiedTarget'
  | 'settings.error.targetUnwritable'
  | 'settings.connection'
  | 'settings.stopHint'
  | 'settings.stopDaemon'
  | 'settings.stopConfirm'
  | 'settings.confirmStop'
  | 'settings.stopping'
  | 'settings.cancel'
  | 'settings.dismiss'
  | 'settings.error.notImplemented'
  | 'settings.error.unknown'
  | 'footer.aria'
  | 'footer.wallet'
  | 'footer.settings'
  | 'footer.activity'
  | 'footer.pauseProtection'
  | 'footer.pauseFailed'
  | 'footer.backToConnect'
  | 'wallet.aria'
  | 'wallet.heading'
  | 'wallet.searchAria'
  | 'wallet.searchPlaceholder'
  | 'wallet.empty.first'
  | 'wallet.empty.searchPrefix'
  | 'wallet.clearSearch'
  | 'wallet.tryAgain'
  | 'wallet.loadingReason'
  | 'wallet.meta.sharedWith'
  | 'wallet.meta.revokedFrom'
  | 'wallet.meta.notShared'
  | 'wallet.meta.lastSeen'
  | 'wallet.error.unreachable'
  | 'wallet.error.daemon'
  | 'wallet.error.unknown'
  | 'walletDetail.aria'
  | 'walletDetail.back'
  | 'walletDetail.backToList'
  | 'walletDetail.tryAgain'
  | 'walletDetail.dismiss'
  | 'walletDetail.loadingReason'
  | 'walletDetail.lastSeen'
  | 'walletDetail.firstSeen'
  | 'walletDetail.reference'
  | 'walletDetail.error.missing'
  | 'walletDetail.error.grantFailed'
  | 'walletDetail.error.revokeFailed'
  | 'walletDetail.error.notImplemented'
  | 'walletDetail.error.unknown'
  | 'activity.aria'
  | 'activity.heading'
  | 'activity.hint'
  | 'activity.empty'
  | 'activity.tryAgain'
  | 'activity.loadingReason'
  | 'activity.from'
  | 'activity.add'
  | 'activity.allowOnce'
  | 'activity.actionParked'
  | 'activity.error.unknown'
  | 'activity.searchAria'
  | 'activity.searchPlaceholder'
  | 'activity.decisionAria'
  | 'activity.sinceAria'
  | 'activity.decision.all'
  | 'activity.decision.granted'
  | 'activity.decision.sealed'
  | 'activity.decision.denied'
  | 'activity.since.today'
  | 'activity.since.7d'
  | 'activity.since.30d'
  | 'activity.since.all'

const messages: Record<Locale, Record<MessageKey, string>> = {
  en: {
    'nav.rpblcHome': 'RPBLC home',
    'nav.damHome': 'DAM home',
    'nav.openDamInBrowser': 'Open DAM in browser',
    'nav.content': 'DAM content',
    'nav.protected': 'protected',
    'nav.off': 'off',
    'nav.pendingRequests': 'pending requests',
    'nav.insights': 'Insights',
    'nav.wallet': 'Wallet',
    'nav.allowed': 'Allowed',
    'nav.activity': 'Activity',
    'nav.more': 'more',
    'nav.settings': 'Settings',
    'nav.system': 'System log',
    'nav.health': 'Health',
    'allowed.aria': 'allowed data',
    'allowed.heading': 'Allowed Data',
    'allowed.empty': 'nothing allowed through',
    'allowed.searchAria': 'filter allowed values',
    'allowed.searchPlaceholder': 'actor, kind, value…',
    'allowed.tryAgain': 'try again',
    'allowed.loadingReason': 'reading allowed grants',
    'allowed.expiredDisclosure': 'show expired',
    'allowed.stopAllowing': 'stop allowing',
    'allowed.until': 'until',
    'allowed.error.unknown': 'we couldn’t read allowed grants. Try again.',
    'insights.aria': 'DAM insights',
    'insights.heading': 'Insights',
    'insights.range.today': 'today',
    'insights.range.7d': '7d',
    'insights.range.30d': '30d',
    'insights.range.all': 'all',
    'insights.rangeAria': 'time range',
    'insights.metricLabel': 'redactions in this range',
    'insights.appsHeading': 'apps',
    'insights.kindsHeading': 'kinds',
    'insights.eventsHeading': 'recent significant events',
    'insights.empty.title': 'No activity yet.',
    'insights.empty.body':
      'Once your AI tools start asking, DAM will keep track. You’ll see who asked for what, what was redacted, and what you allowed. Come back tomorrow.',
    'insights.loadingReason': 'reading insights',
    'insights.error.unknown': 'we couldn’t read insights right now. Try again.',
    'insights.legendRedacted': 'redacted',
    'insights.legendAllowed': 'allowed',
    'insights.legendDenied': 'denied',
    'health.aria': 'DAM health',
    'health.heading': 'Health',
    'health.summaryHealthy': 'DAM is healthy. Every check returned green.',
    'health.summaryDegraded': 'Protection needs attention. DAM is still here.',
    'health.summaryNotConnected': 'DAM is not running on this device.',
    'health.section.daemon': 'daemon',
    'health.section.network': 'network',
    'health.section.trust': 'trust',
    'health.section.integrations': 'integrations',
    'health.section.recent': 'recent',
    'health.daemon.pid': 'pid',
    'health.daemon.version': 'version',
    'health.daemon.listen': 'listen',
    'health.daemon.connected': 'connected',
    'health.network.mode': 'mode',
    'health.trust.mode': 'mode',
    'health.trust.localCa': 'local CA',
    'health.trust.installed': 'installed',
    'health.trust.notInstalled': 'not installed',
    'health.installCa': 'Install local CA',
    'health.connectAction': 'Connect',
    'health.empty.recent': 'no recent failures',
    'health.unknown': '—',
    'health.loadingReason': 'reading health',
    'health.error.unknown': 'we couldn’t read health right now. Try again.',
    'system.aria': 'DAM system log',
    'system.heading': 'System log',
    'system.searchAria': 'filter log entries',
    'system.searchPlaceholder': 'module or message…',
    'system.scope.issues': 'issues',
    'system.scope.all': 'all',
    'system.scope.daemon': 'daemon',
    'system.scope.network': 'network',
    'system.scope.filter': 'filter',
    'system.scope.mcp': 'mcp',
    'system.scope.provider': 'provider',
    'system.scopeAria': 'scope',
    'system.severity.info': 'info',
    'system.severity.warn': 'warn',
    'system.severity.error': 'error',
    'system.empty.scope': 'nothing in this scope',
    'system.empty.clearFilter': 'clear filter',
    'system.loadingReason': 'reading log',
    'system.error.unknown': 'we couldn’t read the system log. Try again.',
    'connect.mainLabel': 'DAM Connect',
    'connect.loading': 'Checking protection state.',
    'connect.loadingReason': 'Checking protection state',
    'connect.checkAgain': 'Check again',
    'connect.connectAria': 'Connect DAM',
    'connect.connectCaption': 'click to connect',
    'connect.disconnectedLede':
      'Reclaim control of what your apps know about you.',
    'connect.disconnectedFine':
      'Right now, every app on this device reads more than it needs — your name, your numbers, your address, the words you type. RPBLC.DAM stands between them and the open internet, so every share waits for your call. Every grant is signed; every value, revocable.',
    'connect.protectedStatus': 'Protected. DAM is mediating requests on this device.',
    'connect.pausedStatus': 'Protection is paused. Local clients can keep their endpoint.',
    'connect.degradedStatus': 'Protection needs attention. DAM is still here.',
    'connect.setupStatus': 'Finish local setup before DAM can protect this device.',
    'connect.pauseProtection': 'Pause protection',
    'connect.resumeProtection': 'Resume protection',
    'connect.recoveryAction': 'Try the recovery action',
    'connect.nothingAsking': 'no new requests',
    'connect.protectedFor': 'Protected for',
    'connect.systemMode': 'system proxy · local CA',
    'request.incoming': 'incoming request',
    'request.toDecide': 'to decide',
    'request.aria': 'Incoming consent request',
    'request.decision': 'Decision',
    'request.wantsToReadYour': 'wants to read your',
    'request.purposePrefix': 'for:',
    'request.allowOnce': 'allow once',
    'request.allowAlways': 'allow + remember',
    'request.deny': 'deny',
    'connect.grants': 'grants',
    'connect.grantsAria': 'open active grants',
    'connect.blockedToday': 'blocked today',
    'connect.blockedTodayAria': 'open activity',
    'connect.appsMediated': 'apps mediated',
    'connect.appsMediatedAria': 'open mediated apps',
    'connect.countsLabel': 'DAM counts',
    'connect.setupHeading': 'Setup',
    'connect.stepDone': 'done',
    'connect.stepCurrent': 'current',
    'connect.stepFailed': 'failed',
    'connect.stepBlocked': 'blocked',
    'connect.step.launch_at_login': 'Choose startup behavior',
    'connect.step.ne_install': 'Install network extension',
    'connect.step.ne_config': 'Add network configuration',
    'connect.step.ne_enable': 'Enable network extension',
    'connect.step.ne_start': 'Enable protection layer',
    'connect.step.linux_capture': 'Set up Linux routing',
    'connect.step.windows_capture': 'Set up Windows routing',
    'connect.step.ne_reboot': 'Restart macOS',
    'connect.step.ca_install': 'Install local CA',
    'connect.step.apply_profiles': 'Apply enabled profiles',
    'connect.step.daemon_start': 'Start DAM',
    'connect.step.unknown': 'Continue setup',
    'connect.hint.launch_at_login':
      'Add DAM to Open at Login so it comes back automatically after the setup restart, or skip it and continue manually. macOS lists this in System Settings > General > Login Items > Open at Login.',
    'connect.hint.ne_install':
      'Adds a system-level network extension so DAM can mediate every request your apps make to the open internet. macOS will ask you to approve the extension.',
    'connect.hint.ne_config':
      'Adds the DAM Network Protection configuration that routes protected traffic through DAM. macOS shows this consent separately from system extension approval.',
    'connect.hint.ne_enable':
      'macOS has added the DAM network configuration but has not started it yet. Enable DAM Network Protection in System Settings > General > Login Items & Extensions > Network Extensions, then continue setup.',
    'connect.hint.ne_start':
      'DAM Network Protection is enabled but not connected yet. Continue setup so DAM can start it and verify capture before moving to trust.',
    'connect.hint.linux_capture':
      'Linux transparent routing uses a different system setup path. It is planned; use explicit proxy mode on Linux for now.',
    'connect.hint.windows_capture':
      'Windows transparent routing uses Windows Filtering Platform instead of macOS Network Extension. It is planned; use explicit proxy mode on Windows for now.',
    'connect.hint.ne_reboot':
      'macOS needs a restart to finish the network extension system change. After restart, DAM checks the earlier setup steps again before continuing.',
    'connect.hint.ca_install':
      'Installs a local certificate authority so DAM can read your apps’ encrypted traffic on this device only. The CA never leaves your machine.',
    'connect.hint.apply_profiles':
      'Writes per-app config so DAM mediates the AI tools you use (Anthropic, OpenAI, Cursor, Perplexity).',
    'connect.hint.daemon_start':
      'Starts the DAM background process that mediates traffic. Runs locally; nothing leaves your device unless you allow it.',
    'connect.hintAriaLabel': 'more info',
    'connect.action.launch_at_login': 'Add DAM to Open at Login',
    'connect.action.launch_at_login_skip': 'Skip',
    'connect.action.ne_install': 'Install network extension',
    'connect.action.ne_config': 'Add network configuration',
    'connect.action.ne_enable': 'Enable network extension',
    'connect.action.ne_start': 'Enable protection layer',
    'connect.action.platform_capture': 'Use explicit proxy mode',
    'connect.action.ne_reboot': 'Restart macOS',
    'connect.action.ca_install': 'Trust local CA',
    'connect.action.apply_profiles': 'Apply enabled profiles',
    'connect.action.daemon_start': 'Start DAM',
    'connect.action.unknown': 'Continue setup',
    'connect.error.load': 'DAM could not read the connection state.',
    'connect.error.not_implemented': 'This connect action is not wired in this build yet.',
    'connect.error.ne_pending_user_approval':
      'macOS is waiting for your approval. Open System Settings > General > Login Items & Extensions > Network Extensions to allow it.',
    'connect.error.ne_reboot_required':
      'macOS needs a restart to finish the network extension system change.',
    'connect.error.ca_install_denied':
      'The local CA install was denied. Try again, or check System Settings.',
    'connect.error.daemon_already_running': 'DAM is already running. Resuming protection.',
    'connect.error.apply_modified_target':
      'A configuration file changed outside DAM. Review the change before applying.',
    'connect.error.apply_target_unwritable':
      "DAM couldn't write the configuration file. Check the file permissions.",
    'connect.error.unknown': 'Something did not work. Try again from here.',
    'connect.error.daemon_starting':
      'DAM is starting up. One moment, then try again.',
    'connect.error.setup_step_failed':
      'That setup step didn’t finish. Try once more, or open Health for details.',
    'connect.error.network_offline':
      'This device is offline. DAM will resume when the network returns.',
    'connect.error.invalid_request':
      'DAM didn’t recognise that request. Try again, and report it if this persists.',
    'connect.notice.dismiss': 'dismiss',
    'blank.aria': 'page placeholder',
    'blank.notReady': 'this page is being built —',
    'blank.backToConnect': 'back to connect',
    'settings.aria': 'DAM settings',
    'settings.heading': 'Settings',
    'settings.appearance': 'appearance',
    'settings.themeAria': 'theme',
    'settings.themeHint':
      'Match the system, or pin DAM to light or dark. System follows your device’s appearance and updates as it changes.',
    'settings.theme.system': 'system',
    'settings.theme.light': 'light',
    'settings.theme.dark': 'dark',
    'settings.language': 'language',
    'settings.languageAria': 'language',
    'settings.languageHint':
      'Choose the language DAM speaks. We start with English and French; more land as DAM is translated.',
    'settings.language.en': 'English',
    'settings.language.fr': 'Français',
    'settings.apps': 'apps',
    'settings.appsHint':
      'Toggle the apps DAM mediates. Turning an app on writes its profile; turning it off rolls the profile back.',
    'settings.appsLoading': 'reading apps',
    'settings.appsEmpty': 'no apps configured yet',
    'settings.appsToggleOn': 'turn off',
    'settings.appsToggleOff': 'turn on',
    'settings.appsProfile': 'profile',
    'settings.appsTarget': 'target',
    'settings.appsInstallState': 'state',
    'settings.appsModified':
      'A configuration file changed outside DAM. Review the file before applying or rolling back.',
    'settings.installState.applied': 'applied',
    'settings.installState.modified': 'modified outside DAM',
    'settings.installState.pending': 'pending',
    'settings.installState.needsApply': 'needs apply',
    'settings.network': 'network',
    'settings.networkHint':
      'How DAM is intercepting traffic. Read-only here; the deeper view lives on Health on web.',
    'settings.networkMode': 'mode',
    'settings.trustMode': 'trust',
    'settings.networkReady': 'ready',
    'settings.networkYes': 'yes',
    'settings.networkNo': 'no',
    'settings.defaults': 'defaults',
    'settings.defaultsHint':
      'Behaviour DAM falls back to when nothing else is specified. Each control writes immediately — no save button.',
    'settings.autoDeny': 'auto-deny pending requests',
    'settings.autoDenyHint':
      'Deny a pending request automatically if you don’t answer in time.',
    'settings.autoDeny.off': 'off',
    'settings.autoDeny.30s': '30 seconds',
    'settings.autoDeny.1m': '1 minute',
    'settings.autoDeny.5m': '5 minutes',
    'settings.rememberGrants': 'remember grants by default',
    'settings.rememberGrantsHint':
      'Default the consent prompt to allow + remember the actor.',
    'settings.maskInLog': 'mask values in audit log',
    'settings.maskInLogHint':
      'Replace stored values with their reference token in the activity log.',
    'settings.systemNotify': 'system notifications',
    'settings.systemNotifyHint':
      'Ping the OS notification centre when an actor asks to read something while DAM is closed.',
    'settings.autoResolveInbound': 'auto-resolve inbound references',
    'settings.autoResolveInboundHint':
      'Detokenize references in incoming responses without prompting.',
    'settings.notifyPrompt.title': 'Stay in the loop?',
    'settings.notifyPrompt.body':
      'RPBLC can ping you when an AI asks to read something while DAM is closed. You can change this any time.',
    'settings.notifyPrompt.allow': 'allow',
    'settings.notifyPrompt.notNow': 'not now',
    'settings.danger': 'danger zone',
    'settings.dangerHint':
      'Reset wipes UI preferences but keeps your wallet and consent state. Uninstall removes the local proxy and CA — your wallet stays on disk but DAM stops protecting it.',
    'settings.resetSettings': 'reset settings',
    'settings.resetConfirm':
      'Reset DAM’s preferences on this device? Your wallet and consent grants stay in place.',
    'settings.confirmReset': 'yes — reset',
    'settings.resetting': 'resetting…',
    'settings.uninstall': 'uninstall on this device',
    'settings.uninstallConfirm':
      'Uninstall DAM on this device? The local proxy and certificate are removed. Your wallet stays on disk but DAM stops protecting it.',
    'settings.confirmUninstall': 'yes — uninstall',
    'settings.uninstalling': 'uninstalling…',
    'settings.error.modifiedTarget':
      'A configuration file changed outside DAM. Review the change before applying.',
    'settings.error.targetUnwritable':
      'DAM couldn’t write the configuration file. Check the file’s permissions.',
    'settings.connection': 'connection',
    'settings.stopHint':
      'Stops DAM on this device — control surface, tray, and protection daemon. Running clients will lose the local DAM endpoint until you launch DAM again.',
    'settings.stopDaemon': 'stop DAM',
    'settings.stopConfirm': 'Stop DAM and the tray on this device?',
    'settings.confirmStop': 'yes — stop DAM',
    'settings.stopping': 'stopping…',
    'settings.cancel': 'cancel',
    'settings.dismiss': 'dismiss',
    'settings.error.notImplemented': 'this action is not wired in this build yet.',
    'settings.error.unknown': 'we could not stop DAM. Try once more.',
    'footer.aria': 'tray navigation',
    'footer.wallet': 'wallet',
    'footer.settings': 'settings',
    'footer.activity': 'activity',
    'footer.pauseProtection': 'pause protection',
    'footer.pauseFailed': 'pause failed — try again',
    'footer.backToConnect': '[connect]',
    'wallet.aria': 'wallet',
    'wallet.heading': 'Wallet',
    'wallet.searchAria': 'filter wallet values',
    'wallet.searchPlaceholder': 'email, phone, token…',
    'wallet.empty.first': 'nothing in your wallet yet',
    'wallet.empty.searchPrefix': 'no value matches',
    'wallet.clearSearch': 'clear',
    'wallet.tryAgain': 'try again',
    'wallet.loadingReason': 'loading your wallet',
    'wallet.meta.sharedWith': 'shared with',
    'wallet.meta.revokedFrom': 'revoked from',
    'wallet.meta.notShared': 'not shared with anyone',
    'wallet.meta.lastSeen': 'last seen',
    'wallet.error.unreachable': 'we couldn’t load your wallet.',
    'wallet.error.daemon': 'we can’t reach DAM right now.',
    'wallet.error.unknown': 'something didn’t work loading your wallet.',
    'walletDetail.aria': 'wallet value detail',
    'walletDetail.back': '[wallet]',
    'walletDetail.backToList': 'back to wallet',
    'walletDetail.tryAgain': 'try again',
    'walletDetail.dismiss': 'dismiss',
    'walletDetail.loadingReason': 'loading this value',
    'walletDetail.lastSeen': 'last seen',
    'walletDetail.firstSeen': 'first seen',
    'walletDetail.reference': 'reference',
    'walletDetail.error.missing': 'this value isn’t in your wallet anymore.',
    'walletDetail.error.grantFailed':
      'we couldn’t allow that — try once more.',
    'walletDetail.error.revokeFailed':
      'we couldn’t stop that grant — try once more.',
    'walletDetail.error.notImplemented':
      'this action isn’t wired in this build yet.',
    'walletDetail.error.unknown': 'something didn’t work. Try once more.',
    'activity.aria': 'wallet activity',
    'activity.heading': 'Activity',
    'activity.hint':
      'Values DAM has seen in recent traffic that aren’t in your wallet yet. Add a value to manage it like the rest, or allow it once for the actor that asked.',
    'activity.empty': 'nothing happening yet',
    'activity.tryAgain': 'try again',
    'activity.loadingReason': 'reading activity',
    'activity.from': 'from',
    'activity.add': 'add to wallet',
    'activity.allowOnce': 'allow once',
    'activity.actionParked':
      'this action ships when the DAM scanner can stream values to the surface.',
    'activity.error.unknown':
      'we couldn’t read activity right now. Try again.',
    'activity.searchAria': 'filter activity',
    'activity.searchPlaceholder': 'actor, kind, value…',
    'activity.decisionAria': 'decision',
    'activity.sinceAria': 'time range',
    'activity.decision.all': 'all',
    'activity.decision.granted': 'granted',
    'activity.decision.sealed': 'sealed',
    'activity.decision.denied': 'denied',
    'activity.since.today': 'today',
    'activity.since.7d': '7d',
    'activity.since.30d': '30d',
    'activity.since.all': 'all',
  },
  fr: {
    'nav.rpblcHome': 'Accueil RPBLC',
    'nav.damHome': 'Accueil DAM',
    'nav.openDamInBrowser': 'Ouvrir DAM dans le navigateur',
    'nav.content': 'Contenu DAM',
    'nav.protected': 'protégé',
    'nav.off': 'arrêt',
    'nav.pendingRequests': 'demandes en attente',
    'nav.insights': 'Aperçu',
    'nav.wallet': 'Portefeuille',
    'nav.allowed': 'Autorisés',
    'nav.activity': 'Activité',
    'nav.more': 'plus',
    'nav.settings': 'Réglages',
    'nav.system': 'Journal système',
    'nav.health': 'Santé',
    'allowed.aria': 'données autorisées',
    'allowed.heading': 'Données autorisées',
    'allowed.empty': 'rien n’est autorisé',
    'allowed.searchAria': 'filtrer les valeurs autorisées',
    'allowed.searchPlaceholder': 'acteur, type, valeur…',
    'allowed.tryAgain': 'réessayer',
    'allowed.loadingReason': 'lecture des autorisations',
    'allowed.expiredDisclosure': 'afficher les expirées',
    'allowed.stopAllowing': 'cesser d’autoriser',
    'allowed.until': 'jusqu’au',
    'allowed.error.unknown': 'lecture impossible pour l’instant. Réessayez.',
    'insights.aria': 'Aperçu DAM',
    'insights.heading': 'Aperçu',
    'insights.range.today': 'aujourd’hui',
    'insights.range.7d': '7 j',
    'insights.range.30d': '30 j',
    'insights.range.all': 'tout',
    'insights.rangeAria': 'plage de temps',
    'insights.metricLabel': 'rédactions sur cette plage',
    'insights.appsHeading': 'apps',
    'insights.kindsHeading': 'types',
    'insights.eventsHeading': 'événements notables récents',
    'insights.empty.title': 'Aucune activité.',
    'insights.empty.body':
      'Quand vos outils d’IA commenceront à demander, DAM en gardera trace. Vous verrez qui a demandé quoi, ce qui a été masqué et ce que vous avez autorisé. Revenez demain.',
    'insights.loadingReason': 'lecture de l’aperçu',
    'insights.error.unknown': 'lecture de l’aperçu impossible. Réessayez.',
    'insights.legendRedacted': 'masqués',
    'insights.legendAllowed': 'autorisés',
    'insights.legendDenied': 'refusés',
    'health.aria': 'Santé DAM',
    'health.heading': 'Santé',
    'health.summaryHealthy': 'DAM est en bonne santé. Tous les contrôles passent.',
    'health.summaryDegraded': 'La protection demande une attention. DAM reste présent.',
    'health.summaryNotConnected': 'DAM ne tourne pas sur cet appareil.',
    'health.section.daemon': 'démon',
    'health.section.network': 'réseau',
    'health.section.trust': 'confiance',
    'health.section.integrations': 'intégrations',
    'health.section.recent': 'récents',
    'health.daemon.pid': 'pid',
    'health.daemon.version': 'version',
    'health.daemon.listen': 'écoute',
    'health.daemon.connected': 'connecté',
    'health.network.mode': 'mode',
    'health.trust.mode': 'mode',
    'health.trust.localCa': 'AC locale',
    'health.trust.installed': 'installée',
    'health.trust.notInstalled': 'non installée',
    'health.installCa': 'Installer l’AC locale',
    'health.connectAction': 'Connecter',
    'health.empty.recent': 'aucun incident récent',
    'health.unknown': '—',
    'health.loadingReason': 'lecture de la santé',
    'health.error.unknown': 'lecture de la santé impossible. Réessayez.',
    'system.aria': 'Journal système DAM',
    'system.heading': 'Journal système',
    'system.searchAria': 'filtrer les entrées du journal',
    'system.searchPlaceholder': 'module ou message…',
    'system.scope.issues': 'incidents',
    'system.scope.all': 'tout',
    'system.scope.daemon': 'démon',
    'system.scope.network': 'réseau',
    'system.scope.filter': 'filtre',
    'system.scope.mcp': 'mcp',
    'system.scope.provider': 'fournisseur',
    'system.scopeAria': 'portée',
    'system.severity.info': 'info',
    'system.severity.warn': 'avert.',
    'system.severity.error': 'erreur',
    'system.empty.scope': 'rien dans cette portée',
    'system.empty.clearFilter': 'effacer le filtre',
    'system.loadingReason': 'lecture du journal',
    'system.error.unknown': 'lecture du journal impossible. Réessayez.',
    'connect.mainLabel': 'Connexion DAM',
    'connect.loading': 'Vérification de l’état de protection.',
    'connect.loadingReason': 'Vérification de l’état de protection',
    'connect.checkAgain': 'Revérifier',
    'connect.connectAria': 'Connecter DAM',
    'connect.connectCaption': 'cliquez pour connecter',
    'connect.disconnectedLede':
      'Reprenez le contrôle de ce que vos apps savent de vous.',
    'connect.disconnectedFine':
      'Aujourd’hui, chaque app de cet appareil lit plus qu’elle ne le doit — votre nom, vos numéros, votre adresse, les mots que vous écrivez. RPBLC.DAM se place entre elles et l’internet ouvert, pour que chaque partage attende votre décision. Chaque autorisation est signée ; chaque valeur, révocable.',
    'connect.protectedStatus': 'Protégé. DAM encadre les requêtes sur cet appareil.',
    'connect.pausedStatus': 'La protection est en pause. Les clients locaux gardent leur point d’accès.',
    'connect.degradedStatus': 'La protection demande une attention. DAM reste présent.',
    'connect.setupStatus': 'Terminez la configuration locale avant que DAM protège cet appareil.',
    'connect.pauseProtection': 'Mettre la protection en pause',
    'connect.resumeProtection': 'Reprendre la protection',
    'connect.recoveryAction': 'Tenter la correction',
    'connect.nothingAsking': 'aucune nouvelle demande',
    'connect.protectedFor': 'Protégé depuis',
    'connect.systemMode': 'proxy système · AC locale',
    'request.incoming': 'demande entrante',
    'request.toDecide': 'pour décider',
    'request.aria': 'Demande de consentement entrante',
    'request.decision': 'Décision',
    'request.wantsToReadYour': 'veut lire votre',
    'request.purposePrefix': 'pour :',
    'request.allowOnce': 'autoriser une fois',
    'request.allowAlways': 'autoriser et mémoriser',
    'request.deny': 'refuser',
    'connect.grants': 'autorisations',
    'connect.grantsAria': 'voir les autorisations actives',
    'connect.blockedToday': 'bloqués aujourd’hui',
    'connect.blockedTodayAria': 'voir l’activité',
    'connect.appsMediated': 'apps encadrées',
    'connect.appsMediatedAria': 'voir les apps encadrées',
    'connect.countsLabel': 'Compteurs DAM',
    'connect.setupHeading': 'Configuration',
    'connect.stepDone': 'terminé',
    'connect.stepCurrent': 'en cours',
    'connect.stepFailed': 'échec',
    'connect.stepBlocked': 'bloqué',
    'connect.step.launch_at_login': 'Choisir le démarrage',
    'connect.step.ne_install': 'Installer l’extension réseau',
    'connect.step.ne_config': 'Ajouter la configuration réseau',
    'connect.step.ne_enable': 'Activer l’extension réseau',
    'connect.step.ne_start': 'Activer la couche de protection',
    'connect.step.linux_capture': 'Configurer le routage Linux',
    'connect.step.windows_capture': 'Configurer le routage Windows',
    'connect.step.ne_reboot': 'Redémarrer macOS',
    'connect.step.ca_install': 'Installer l’AC locale',
    'connect.step.apply_profiles': 'Appliquer les profils activés',
    'connect.step.daemon_start': 'Démarrer DAM',
    'connect.step.unknown': 'Continuer la configuration',
    'connect.hint.launch_at_login':
      'Ajoutez DAM à l’ouverture pour qu’il revienne automatiquement après le redémarrage de configuration, ou ignorez cette étape et continuez manuellement. Visible dans Réglages Système > Général > Éléments d’ouverture > Ouvrir à l’ouverture de session.',
    'connect.hint.ne_install':
      'Ajoute une extension réseau au niveau du système pour que DAM puisse encadrer chaque requête que vos apps envoient sur l’internet ouvert. macOS vous demandera d’approuver l’extension.',
    'connect.hint.ne_config':
      'Ajoute la configuration DAM Network Protection qui route le trafic protégé via DAM. macOS demande ce consentement séparément de l’approbation de l’extension système.',
    'connect.hint.ne_enable':
      'macOS a ajouté la configuration réseau de DAM, mais ne l’a pas encore démarrée. Activez DAM Network Protection dans Réglages Système > Général > Ouverture et extensions > Extensions réseau, puis continuez la configuration.',
    'connect.hint.ne_start':
      'DAM Network Protection est activé, mais pas encore connecté. Continuez la configuration pour que DAM le démarre et vérifie la capture avant de passer à la confiance.',
    'connect.hint.linux_capture':
      'Le routage transparent Linux suit un parcours système différent. Il est prévu ; utilisez le mode proxy explicite sur Linux pour le moment.',
    'connect.hint.windows_capture':
      'Le routage transparent Windows utilise Windows Filtering Platform plutôt que l’extension réseau macOS. Il est prévu ; utilisez le mode proxy explicite sur Windows pour le moment.',
    'connect.hint.ne_reboot':
      'macOS doit redémarrer pour terminer le changement système de l’extension réseau. Après le redémarrage, DAM revérifie les étapes précédentes avant de continuer.',
    'connect.hint.ca_install':
      'Installe une autorité de certification locale pour que DAM puisse lire le trafic chiffré de vos apps, uniquement sur cet appareil. L’AC ne quitte jamais votre machine.',
    'connect.hint.apply_profiles':
      'Écrit la config pour les apps que DAM encadre (Anthropic, OpenAI, Cursor, Perplexity).',
    'connect.hint.daemon_start':
      'Démarre le processus DAM en arrière-plan qui encadre le trafic. Tout local ; rien ne quitte votre appareil sans votre accord.',
    'connect.hintAriaLabel': 'plus d’info',
    'connect.action.launch_at_login': 'Ajouter DAM à l’ouverture',
    'connect.action.launch_at_login_skip': 'Ignorer',
    'connect.action.ne_install': 'Installer l’extension réseau',
    'connect.action.ne_config': 'Ajouter la configuration réseau',
    'connect.action.ne_enable': 'Activer l’extension réseau',
    'connect.action.ne_start': 'Activer la couche de protection',
    'connect.action.platform_capture': 'Utiliser le proxy explicite',
    'connect.action.ne_reboot': 'Redémarrer macOS',
    'connect.action.ca_install': 'Faire confiance à l’AC locale',
    'connect.action.apply_profiles': 'Appliquer les profils activés',
    'connect.action.daemon_start': 'Démarrer DAM',
    'connect.action.unknown': 'Continuer la configuration',
    'connect.error.load': 'DAM n’a pas pu lire l’état de connexion.',
    'connect.error.not_implemented': 'Cette action de connexion n’est pas encore câblée dans cette version.',
    'connect.error.ne_pending_user_approval':
      'macOS attend votre approbation. Ouvrez Réglages Système > Général > Ouverture et extensions > Extensions réseau pour l’autoriser.',
    'connect.error.ne_reboot_required':
      'macOS doit redémarrer pour terminer le changement système de l’extension réseau.',
    'connect.error.ca_install_denied':
      'L’installation de l’AC locale a été refusée. Réessayez ou vérifiez Réglages Système.',
    'connect.error.daemon_already_running': 'DAM fonctionne déjà. La protection reprend.',
    'connect.error.apply_modified_target':
      'Un fichier de configuration a changé hors de DAM. Vérifiez le changement avant d’appliquer.',
    'connect.error.apply_target_unwritable':
      'DAM n’a pas pu écrire le fichier de configuration. Vérifiez ses permissions.',
    'connect.error.unknown': 'Une action n’a pas abouti. Réessayez depuis ici.',
    'connect.error.daemon_starting':
      'DAM démarre. Un instant, puis réessayez.',
    'connect.error.setup_step_failed':
      'Cette étape de configuration n’a pas abouti. Réessayez ou consultez Santé.',
    'connect.error.network_offline':
      'Cet appareil est hors-ligne. DAM reprendra dès que le réseau revient.',
    'connect.error.invalid_request':
      'DAM n’a pas reconnu cette requête. Réessayez et signalez-le si cela persiste.',
    'connect.notice.dismiss': 'rejeter',
    'blank.aria': 'page en attente',
    'blank.notReady': 'cette page est en construction —',
    'blank.backToConnect': 'retour à la connexion',
    'settings.aria': 'Réglages DAM',
    'settings.heading': 'Réglages',
    'settings.appearance': 'apparence',
    'settings.themeAria': 'thème',
    'settings.themeHint':
      'Suit le système ou fixe DAM en clair ou sombre. « Système » suit l’apparence de l’appareil et se met à jour automatiquement.',
    'settings.theme.system': 'système',
    'settings.theme.light': 'clair',
    'settings.theme.dark': 'sombre',
    'settings.language': 'langue',
    'settings.languageAria': 'langue',
    'settings.languageHint':
      'Choisissez la langue de DAM. Anglais et français au lancement ; d’autres suivront au fil des traductions.',
    'settings.language.en': 'English',
    'settings.language.fr': 'Français',
    'settings.apps': 'apps',
    'settings.appsHint':
      'Activez les apps que DAM encadre. Activer écrit leur profil ; désactiver le retire.',
    'settings.appsLoading': 'lecture des apps',
    'settings.appsEmpty': 'aucune app configurée',
    'settings.appsToggleOn': 'désactiver',
    'settings.appsToggleOff': 'activer',
    'settings.appsProfile': 'profil',
    'settings.appsTarget': 'cible',
    'settings.appsInstallState': 'état',
    'settings.appsModified':
      'Un fichier de configuration a changé hors de DAM. Vérifiez le fichier avant d’appliquer ou d’annuler.',
    'settings.installState.applied': 'appliqué',
    'settings.installState.modified': 'modifié hors de DAM',
    'settings.installState.pending': 'en cours',
    'settings.installState.needsApply': 'à appliquer',
    'settings.network': 'réseau',
    'settings.networkHint':
      'Comment DAM intercepte le trafic. Lecture seule ici ; la vue détaillée vit dans Santé sur le web.',
    'settings.networkMode': 'mode',
    'settings.trustMode': 'confiance',
    'settings.networkReady': 'prêt',
    'settings.networkYes': 'oui',
    'settings.networkNo': 'non',
    'settings.defaults': 'défauts',
    'settings.defaultsHint':
      'Comportements par défaut. Chaque contrôle s’enregistre immédiatement — pas de bouton enregistrer.',
    'settings.autoDeny': 'refus automatique des demandes en attente',
    'settings.autoDenyHint':
      'Refuse automatiquement une demande en attente si vous ne répondez pas à temps.',
    'settings.autoDeny.off': 'désactivé',
    'settings.autoDeny.30s': '30 secondes',
    'settings.autoDeny.1m': '1 minute',
    'settings.autoDeny.5m': '5 minutes',
    'settings.rememberGrants': 'mémoriser les autorisations',
    'settings.rememberGrantsHint':
      'Propose par défaut « autoriser et mémoriser » lors d’une demande.',
    'settings.maskInLog': 'masquer les valeurs dans le journal',
    'settings.maskInLogHint':
      'Remplace les valeurs par leur jeton de référence dans le journal d’activité.',
    'settings.systemNotify': 'notifications système',
    'settings.systemNotifyHint':
      'Notifie l’OS quand un acteur demande à lire une valeur alors que DAM est fermé.',
    'settings.autoResolveInbound': 'résoudre les références entrantes',
    'settings.autoResolveInboundHint':
      'Détokenise les références dans les réponses entrantes sans demander.',
    'settings.notifyPrompt.title': 'Rester dans la boucle ?',
    'settings.notifyPrompt.body':
      'RPBLC peut vous prévenir quand une IA demande à lire une valeur alors que DAM est fermé. Vous pouvez changer ce choix à tout moment.',
    'settings.notifyPrompt.allow': 'autoriser',
    'settings.notifyPrompt.notNow': 'plus tard',
    'settings.danger': 'zone à risque',
    'settings.dangerHint':
      'La remise à zéro efface les préférences mais garde le portefeuille et les consentements. La désinstallation retire le proxy et le certificat — votre portefeuille reste sur disque mais DAM ne le protège plus.',
    'settings.resetSettings': 'remettre à zéro',
    'settings.resetConfirm':
      'Remettre les préférences de DAM à zéro sur cet appareil ? Le portefeuille et les consentements sont conservés.',
    'settings.confirmReset': 'oui — remettre à zéro',
    'settings.resetting': 'remise à zéro…',
    'settings.uninstall': 'désinstaller sur cet appareil',
    'settings.uninstallConfirm':
      'Désinstaller DAM sur cet appareil ? Le proxy local et le certificat sont retirés. Votre portefeuille reste sur disque mais DAM ne le protège plus.',
    'settings.confirmUninstall': 'oui — désinstaller',
    'settings.uninstalling': 'désinstallation…',
    'settings.error.modifiedTarget':
      'Un fichier de configuration a changé hors de DAM. Vérifiez le changement avant d’appliquer.',
    'settings.error.targetUnwritable':
      'DAM n’a pas pu écrire le fichier de configuration. Vérifiez ses permissions.',
    'settings.connection': 'connexion',
    'settings.stopHint':
      'Arrête DAM sur cet appareil — surface de contrôle, plateau et démon de protection. Les clients en cours perdront le point d’accès DAM jusqu’au prochain lancement.',
    'settings.stopDaemon': 'arrêter DAM',
    'settings.stopConfirm': 'Arrêter DAM et le plateau sur cet appareil ?',
    'settings.confirmStop': 'oui — arrêter DAM',
    'settings.stopping': 'arrêt en cours…',
    'settings.cancel': 'annuler',
    'settings.dismiss': 'rejeter',
    'settings.error.notImplemented':
      'cette action n’est pas encore câblée dans cette version.',
    'settings.error.unknown': 'DAM n’a pas pu s’arrêter. Réessayez.',
    'footer.aria': 'navigation du plateau',
    'footer.wallet': 'portefeuille',
    'footer.settings': 'réglages',
    'footer.activity': 'activité',
    'footer.pauseProtection': 'mettre la protection en pause',
    'footer.pauseFailed': 'mise en pause échouée — réessayez',
    'footer.backToConnect': '[connexion]',
    'wallet.aria': 'portefeuille',
    'wallet.heading': 'Portefeuille',
    'wallet.searchAria': 'filtrer les valeurs du portefeuille',
    'wallet.searchPlaceholder': 'email, téléphone, jeton…',
    'wallet.empty.first': 'rien dans votre portefeuille pour l’instant',
    'wallet.empty.searchPrefix': 'aucune valeur ne correspond à',
    'wallet.clearSearch': 'effacer',
    'wallet.tryAgain': 'réessayer',
    'wallet.loadingReason': 'chargement du portefeuille',
    'wallet.meta.sharedWith': 'partagé avec',
    'wallet.meta.revokedFrom': 'révoqué pour',
    'wallet.meta.notShared': 'pas partagé',
    'wallet.meta.lastSeen': 'vu pour la dernière fois',
    'wallet.error.unreachable': 'le portefeuille n’a pas pu être chargé.',
    'wallet.error.daemon': 'DAM est injoignable pour l’instant.',
    'wallet.error.unknown':
      'le portefeuille n’a pas pu être chargé. Réessayez.',
    'walletDetail.aria': 'détail de la valeur',
    'walletDetail.back': '[portefeuille]',
    'walletDetail.backToList': 'retour au portefeuille',
    'walletDetail.tryAgain': 'réessayer',
    'walletDetail.dismiss': 'rejeter',
    'walletDetail.loadingReason': 'chargement de la valeur',
    'walletDetail.lastSeen': 'vu pour la dernière fois',
    'walletDetail.firstSeen': 'vu pour la première fois',
    'walletDetail.reference': 'référence',
    'walletDetail.error.missing':
      'cette valeur n’est plus dans le portefeuille.',
    'walletDetail.error.grantFailed':
      'l’autorisation n’a pas pu être enregistrée. Réessayez.',
    'walletDetail.error.revokeFailed':
      'la révocation n’a pas pu être enregistrée. Réessayez.',
    'walletDetail.error.notImplemented':
      'cette action n’est pas encore câblée dans cette version.',
    'walletDetail.error.unknown':
      'quelque chose n’a pas fonctionné. Réessayez.',
    'activity.aria': 'activité du portefeuille',
    'activity.heading': 'Activité',
    'activity.hint':
      'Valeurs que DAM a vues passer récemment et qui ne sont pas dans votre portefeuille. Ajoutez-les pour les gérer comme les autres, ou autorisez-les une fois pour l’acteur qui a demandé.',
    'activity.empty': 'rien à signaler',
    'activity.tryAgain': 'réessayer',
    'activity.loadingReason': 'lecture de l’activité',
    'activity.from': 'de la part de',
    'activity.add': 'ajouter',
    'activity.allowOnce': 'autoriser une fois',
    'activity.actionParked':
      'cette action sera disponible quand le scanneur DAM diffusera ses valeurs.',
    'activity.error.unknown':
      'lecture de l’activité impossible pour l’instant. Réessayez.',
    'activity.searchAria': 'filtrer l’activité',
    'activity.searchPlaceholder': 'acteur, type, valeur…',
    'activity.decisionAria': 'décision',
    'activity.sinceAria': 'plage de temps',
    'activity.decision.all': 'tout',
    'activity.decision.granted': 'autorisés',
    'activity.decision.sealed': 'scellés',
    'activity.decision.denied': 'refusés',
    'activity.since.today': 'aujourd’hui',
    'activity.since.7d': '7 j',
    'activity.since.30d': '30 j',
    'activity.since.all': 'tout',
  },
}

export function detectLocale(): Locale {
  const stored = safeStorageGet(LOCALE_KEY)
  if (stored === 'en' || stored === 'fr') return stored

  const languages = typeof navigator === 'undefined' ? [] : navigator.languages ?? [navigator.language]
  return languages.some((language) => language.toLowerCase().startsWith('fr')) ? 'fr' : 'en'
}

export function t(locale: Locale, key: MessageKey): string {
  return messages[locale][key] ?? messages.en[key]
}

const LOCALE_KEY = 'rpblc.dam.locale'

function safeStorageGet(key: string): string | null {
  try {
    return window.localStorage.getItem(key)
  } catch {
    return null
  }
}

function safeStorageSet(key: string, value: string) {
  try {
    window.localStorage.setItem(key, value)
  } catch {
    // ignore
  }
}

import {
  createContext,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from 'react'

type LocaleContextValue = {
  locale: Locale
  setLocale: (next: Locale) => void
  t: (key: MessageKey) => string
}

const LocaleContext = createContext<LocaleContextValue | null>(null)

export function LocaleProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(detectLocale)

  const value = useMemo<LocaleContextValue>(
    () => ({
      locale,
      setLocale: (next) => {
        safeStorageSet(LOCALE_KEY, next)
        setLocaleState(next)
      },
      t: (key) => t(locale, key),
    }),
    [locale],
  )

  return <LocaleContext.Provider value={value}>{children}</LocaleContext.Provider>
}

export function useI18n(): LocaleContextValue {
  const ctx = useContext(LocaleContext)
  if (!ctx) {
    // Fallback for components that may render before the provider mounts
    // (e.g., during the initial paint of router children). Returns a
    // detect-once snapshot.
    const fallbackLocale = detectLocale()
    return {
      locale: fallbackLocale,
      setLocale: () => undefined,
      t: (key) => t(fallbackLocale, key),
    }
  }
  return ctx
}
