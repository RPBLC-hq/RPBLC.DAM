import Foundation

public enum DAMRoutingFailurePolicy: String, Equatable, Sendable {
    case failOpen = "fail_open"
    case failClosed = "fail_closed"

    public static let defaultPolicy: DAMRoutingFailurePolicy = .failOpen
}

public struct DAMProxyRuntimeConfiguration: Equatable, Sendable {
    public static let defaultProxyHost = "127.0.0.1"
    public static let defaultProxyPort: UInt16 = 7828

    public static let defaultProtectedHosts = [
        "api.openai.com",
        "api.anthropic.com",
        "chatgpt.com",
    ]

    public static let defaultExcludedSigningIdentifiers = [
        "com.rpblc.dam",
        "com.rpblc.dam.cli",
        "com.rpblc.dam.daemon",
        "com.rpblc.dam.helper",
        "com.rpblc.dam.mcp",
        "com.rpblc.dam.proxy",
        "com.rpblc.dam.tray",
        "com.rpblc.dam.web",
        "com.rpblc.dam.network-extension",
        "dam",
        "dam-daemon",
        "dam-macos-ne-helper",
        "dam-mcp",
        "dam-proxy",
        "dam-tray",
        "dam-web",
    ]

    public var proxyHost: String
    public var proxyPort: UInt16
    public var protectedHosts: [String]
    public var excludedSigningIdentifiers: [String]
    public var routingFailurePolicy: DAMRoutingFailurePolicy

    public init(
        proxyHost: String = Self.defaultProxyHost,
        proxyPort: UInt16 = Self.defaultProxyPort,
        protectedHosts: [String] = Self.defaultProtectedHosts,
        excludedSigningIdentifiers: [String] = Self.defaultExcludedSigningIdentifiers,
        routingFailurePolicy: DAMRoutingFailurePolicy = DAMRoutingFailurePolicy.defaultPolicy
    ) {
        self.proxyHost = normalizeProxyHost(proxyHost)
        self.proxyPort = proxyPort
        self.protectedHosts = normalizeHosts(protectedHosts)
        self.excludedSigningIdentifiers = normalizeIdentifiers(excludedSigningIdentifiers)
        self.routingFailurePolicy = routingFailurePolicy
    }

    public init(providerConfiguration: [String: Any]?) {
        guard let providerConfiguration else {
            self.init(protectedHosts: [])
            return
        }

        let proxyHost = providerConfiguration[DAMProviderConfigurationKey.proxyHost] as? String
        let proxyPort = providerConfiguration[DAMProviderConfigurationKey.proxyPort] as? Int
        let protectedHosts = providerConfiguration[DAMProviderConfigurationKey.protectedHosts] as? [String]
        let excludedSigningIdentifiers = providerConfiguration[DAMProviderConfigurationKey.excludedSigningIdentifiers] as? [String]
        let routingFailurePolicy = (providerConfiguration[DAMProviderConfigurationKey.routingFailurePolicy] as? String)
            .flatMap(DAMRoutingFailurePolicy.init(rawValue:))

        self.init(
            proxyHost: proxyHost ?? Self.defaultProxyHost,
            proxyPort: UInt16(clamping: proxyPort ?? Int(Self.defaultProxyPort)),
            protectedHosts: protectedHosts ?? [],
            excludedSigningIdentifiers: excludedSigningIdentifiers ?? Self.defaultExcludedSigningIdentifiers,
            routingFailurePolicy: routingFailurePolicy ?? DAMRoutingFailurePolicy.defaultPolicy
        )
    }

    public var providerConfiguration: [String: Any] {
        [
            DAMProviderConfigurationKey.proxyHost: proxyHost,
            DAMProviderConfigurationKey.proxyPort: Int(proxyPort),
            DAMProviderConfigurationKey.protectedHosts: protectedHosts,
            DAMProviderConfigurationKey.excludedSigningIdentifiers: excludedSigningIdentifiers,
            DAMProviderConfigurationKey.routingFailurePolicy: routingFailurePolicy.rawValue,
        ]
    }

    public func shouldBypassSource(signingIdentifier: String?, processPath: String? = nil) -> Bool {
        sourceCandidates(signingIdentifier: signingIdentifier, processPath: processPath).contains { candidate in
            excludedSigningIdentifiers.contains(candidate)
        }
    }

    public func shouldProtect(host: String) -> Bool {
        let normalized = normalizeHost(host)
        guard !normalized.isEmpty else {
            return false
        }
        return protectedHosts.contains { protectedHost in
            normalized == protectedHost || normalized.hasSuffix(".\(protectedHost)")
        }
    }
}

public enum DAMProviderConfigurationKey {
    public static let proxyHost = "damProxyHost"
    public static let proxyPort = "damProxyPort"
    public static let protectedHosts = "damProtectedHosts"
    public static let excludedSigningIdentifiers = "damExcludedSigningIdentifiers"
    public static let routingFailurePolicy = "damRoutingFailurePolicy"
}

public func normalizeHost(_ host: String) -> String {
    var trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    if trimmed.hasSuffix(".") {
        trimmed.removeLast()
    }
    return trimmed
}

func normalizeProxyHost(_ host: String) -> String {
    let normalized = host.trimmingCharacters(in: .whitespacesAndNewlines)
    return normalized.isEmpty ? DAMProxyRuntimeConfiguration.defaultProxyHost : normalized
}

func normalizeHosts(_ hosts: [String]) -> [String] {
    var result: [String] = []
    for host in hosts {
        let normalized = normalizeHost(host)
        if !normalized.isEmpty && !result.contains(normalized) {
            result.append(normalized)
        }
    }
    return result
}

func normalizeIdentifiers(_ identifiers: [String]) -> [String] {
    var result: [String] = []
    for identifier in identifiers {
        let normalized = identifier.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if !normalized.isEmpty && !result.contains(normalized) {
            result.append(normalized)
        }
    }
    return result
}

private func sourceCandidates(signingIdentifier: String?, processPath: String?) -> [String] {
    var candidates: [String] = []
    appendNormalized(signingIdentifier, to: &candidates)
    appendNormalized(processPath, to: &candidates)
    if let processPath {
        appendNormalized(URL(fileURLWithPath: processPath).lastPathComponent, to: &candidates)
    }
    return candidates
}

private func appendNormalized(_ value: String?, to candidates: inout [String]) {
    guard let value else {
        return
    }
    let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    if !normalized.isEmpty && !candidates.contains(normalized) {
        candidates.append(normalized)
    }
}
