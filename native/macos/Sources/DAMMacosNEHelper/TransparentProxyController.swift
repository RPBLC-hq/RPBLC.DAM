import DAMNetworkExtensionSupport
import Foundation
import NetworkExtension
import OSLog

struct TransparentProxyController {
    private let store = ManagerStore()
    private let logger = Logger(subsystem: "com.rpblc.dam.network-extension", category: "helper")

    func install(_ options: DAMHelperOptions) async throws -> String {
        let managers = try await store.loadManagers()
        let existingManager = store.manager(matching: options.bundleIdentifier, in: managers)
        let manager = existingManager ?? NETransparentProxyManager()
        let hadManager = existingManager != nil
        let wasEnabled = manager.isEnabled
        let previousRuntimeConfiguration = (existingManager?.protocolConfiguration as? NETunnelProviderProtocol)
            .map { DAMProxyRuntimeConfiguration(providerConfiguration: $0.providerConfiguration) }
        let runtimeConfigurationChanged = previousRuntimeConfiguration
            .map { $0 != options.runtimeConfiguration }
            ?? false
        let provider = NETunnelProviderProtocol()
        provider.providerBundleIdentifier = options.bundleIdentifier
        provider.serverAddress = "127.0.0.1"
        provider.providerConfiguration = options.runtimeConfiguration.providerConfiguration

        manager.localizedDescription = options.displayName
        manager.protocolConfiguration = provider
        let hasProtectedHosts = !options.runtimeConfiguration.protectedHosts.isEmpty
        manager.isEnabled = hasProtectedHosts
        manager.isOnDemandEnabled = hasProtectedHosts
        manager.onDemandRules = hasProtectedHosts ? [NEOnDemandRuleConnect()] : []

        try await store.save(manager)
        try await store.reload(manager)

        if !hasProtectedHosts {
            manager.connection.stopVPNTunnel()
            return installedMessage(options)
        }

        if !hadManager || !wasEnabled {
            return "needs_user_approval approve the DAM Network Protection configuration in System Settings, then click Connect/Resume again"
        }

        switch manager.connection.status {
        case .connected:
            if runtimeConfigurationChanged {
                return try await restartConnectedManager(manager, options)
            }
            return installedMessage(options)
        case .connecting, .reasserting:
            return try await waitForEnabledManager(manager, options)
        case .disconnected, .invalid:
            return try await startEnabledManager(manager, options)
        case .disconnecting:
            throw helperError("DAM Network Protection is still disconnecting. Wait a moment, then try again.")
        @unknown default:
            throw helperError("DAM Network Protection is enabled but macOS reports \(statusName(manager.connection.status)).")
        }
    }

    private func restartConnectedManager(_ manager: NETransparentProxyManager, _ options: DAMHelperOptions) async throws -> String {
        manager.connection.stopVPNTunnel()
        try await waitForDisconnected(manager)
        return try await startEnabledManager(manager, options)
    }

    func remove(_ options: DAMHelperOptions) async throws -> String {
        let managers = try await store.loadManagers()
        guard let manager = store.manager(matching: options.bundleIdentifier, in: managers) else {
            return "not installed \(options.bundleIdentifier)"
        }
        manager.connection.stopVPNTunnel()
        try await store.remove(manager)
        return "removed \(options.bundleIdentifier)"
    }

    func status(_ options: DAMHelperOptions) async throws -> String {
        let managers = try await store.loadManagers()
        guard let manager = store.manager(matching: options.bundleIdentifier, in: managers) else {
            return "not_installed \(options.bundleIdentifier)"
        }
        let state = manager.isEnabled ? "enabled" : "disabled"
        return "\(state) \(options.bundleIdentifier) \(statusName(manager.connection.status))"
    }

    private func statusName(_ status: NEVPNStatus) -> String {
        switch status {
        case .invalid:
            return "invalid"
        case .disconnected:
            return "disconnected"
        case .connecting:
            return "connecting"
        case .connected:
            return "connected"
        case .reasserting:
            return "reasserting"
        case .disconnecting:
            return "disconnecting"
        @unknown default:
            return "unknown"
        }
    }

    private func installedMessage(_ options: DAMHelperOptions) -> String {
        "installed \(options.bundleIdentifier) with \(options.runtimeConfiguration.protectedHosts.count) protected hosts after app-owned activation"
    }

    private func needsUserApproval(_ message: String) -> String {
        "needs_user_approval \(message)"
    }

    private func waitForEnabledManager(_ manager: NETransparentProxyManager, _ options: DAMHelperOptions) async throws -> String {
        do {
            try await waitForConnected(manager)
            return installedMessage(options)
        } catch {
            await disableAfterFailedStart(manager, error: error)
            throw helperError("DAM Network Protection is enabled but did not connect: \(error.localizedDescription)")
        }
    }

    private func startEnabledManager(_ manager: NETransparentProxyManager, _ options: DAMHelperOptions) async throws -> String {
        do {
            try manager.connection.startVPNTunnel(options: [:])
            try await waitForConnected(manager)
            return installedMessage(options)
        } catch {
            await disableAfterFailedStart(manager, error: error)
            throw helperError("DAM Network Protection is enabled but could not start automatically: \(error.localizedDescription)")
        }
    }

    private func disableAfterFailedStart(_ manager: NETransparentProxyManager, error: Error) async {
        logger.error("DAM Network Protection failed to connect; disabling manager to preserve normal networking: \(error.localizedDescription, privacy: .public)")
        manager.connection.stopVPNTunnel()
        manager.isEnabled = false
        do {
            try await store.save(manager)
            try await store.reload(manager)
        } catch {
            logger.error("Failed to disable DAM Network Protection after start failure: \(error.localizedDescription, privacy: .public)")
        }
    }

    private func waitForConnected(_ manager: NETransparentProxyManager) async throws {
        let deadline = Date().addingTimeInterval(20)
        while Date() < deadline {
            if manager.connection.status == .connected {
                return
            }
            if manager.connection.status == .invalid {
                throw NSError(
                    domain: "DAMMacosNEHelper",
                    code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "Network Extension tunnel became invalid before connecting"]
                )
            }
            try await Task.sleep(nanoseconds: 250_000_000)
        }
        throw NSError(
            domain: "DAMMacosNEHelper",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "Network Extension tunnel did not reach connected status before timeout"]
        )
    }

    private func waitForDisconnected(_ manager: NETransparentProxyManager) async throws {
        let deadline = Date().addingTimeInterval(8)
        while Date() < deadline {
            if manager.connection.status == .disconnected || manager.connection.status == .invalid {
                return
            }
            try await Task.sleep(nanoseconds: 250_000_000)
        }
        throw NSError(
            domain: "DAMMacosNEHelper",
            code: 3,
            userInfo: [NSLocalizedDescriptionKey: "Network Extension tunnel did not stop before restart"]
        )
    }

    private func helperError(_ message: String) -> NSError {
        NSError(
            domain: "DAMMacosNEHelper",
            code: 3,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }
}
