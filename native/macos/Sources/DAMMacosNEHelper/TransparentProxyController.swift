import DAMNetworkExtensionSupport
import Foundation
import NetworkExtension

struct TransparentProxyController {
    private let store = ManagerStore()

    func install(_ options: DAMHelperOptions) async throws -> String {
        let managers = try await store.loadManagers()
        let manager = store.manager(matching: options.bundleIdentifier, in: managers) ?? NETransparentProxyManager()
        let provider = NETunnelProviderProtocol()
        provider.providerBundleIdentifier = options.bundleIdentifier
        provider.serverAddress = "127.0.0.1"
        provider.providerConfiguration = options.runtimeConfiguration.providerConfiguration

        manager.localizedDescription = options.displayName
        manager.protocolConfiguration = provider
        manager.isEnabled = true

        try await store.save(manager)
        try await store.reload(manager)

        if manager.connection.status != .connected && manager.connection.status != .connecting {
            try manager.connection.startVPNTunnel(options: [:])
        }
        try await waitForConnected(manager)

        return "installed \(options.bundleIdentifier) with \(options.runtimeConfiguration.protectedHosts.count) protected hosts after app-owned activation"
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
}
