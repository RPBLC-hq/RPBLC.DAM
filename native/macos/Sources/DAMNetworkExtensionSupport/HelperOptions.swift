import Foundation

public enum DAMHelperAction: String, Sendable {
    case install
    case remove
    case status
}

public struct DAMHelperOptions: Equatable, Sendable {
    public var action: DAMHelperAction
    public var bundleIdentifier: String
    public var teamIdentifier: String?
    public var displayName: String
    public var runtimeConfiguration: DAMProxyRuntimeConfiguration

    public init(
        action: DAMHelperAction,
        bundleIdentifier: String,
        teamIdentifier: String? = nil,
        displayName: String = "DAM Network Protection",
        runtimeConfiguration: DAMProxyRuntimeConfiguration = DAMProxyRuntimeConfiguration()
    ) {
        self.action = action
        self.bundleIdentifier = bundleIdentifier
        self.teamIdentifier = teamIdentifier
        self.displayName = displayName
        self.runtimeConfiguration = runtimeConfiguration
    }
}

public enum DAMHelperArgumentError: Error, CustomStringConvertible, Equatable {
    case missingAction
    case unknownAction(String)
    case missingValue(String)
    case missingBundleIdentifier
    case invalidProxyPort(String)
    case invalidRoutingFailurePolicy(String)
    case unknownArgument(String)

    public var description: String {
        switch self {
        case .missingAction:
            return "missing helper action: expected install, remove, or status"
        case .unknownAction(let value):
            return "unknown helper action: \(value)"
        case .missingValue(let flag):
            return "missing value for \(flag)"
        case .missingBundleIdentifier:
            return "missing required --bundle-id"
        case .invalidProxyPort(let value):
            return "invalid --proxy-port value: \(value)"
        case .invalidRoutingFailurePolicy(let value):
            return "invalid --routing-failure-policy value: \(value)"
        case .unknownArgument(let value):
            return "unknown argument: \(value)"
        }
    }
}

public func parseHelperOptions(_ arguments: [String]) throws -> DAMHelperOptions {
    guard let actionRaw = arguments.first else {
        throw DAMHelperArgumentError.missingAction
    }
    guard let action = DAMHelperAction(rawValue: actionRaw) else {
        throw DAMHelperArgumentError.unknownAction(actionRaw)
    }

    var bundleIdentifier: String?
    var teamIdentifier: String?
    var displayName = "DAM Network Protection"
    var proxyHost = DAMProxyRuntimeConfiguration.defaultProxyHost
    var proxyPort = DAMProxyRuntimeConfiguration.defaultProxyPort
    var protectedHosts: [String] = []
    var usesDefaultProtectedHosts = true
    var excludedSigningIdentifiers: [String] = []
    var routingFailurePolicy = DAMRoutingFailurePolicy.defaultPolicy

    var index = arguments.index(after: arguments.startIndex)
    while index < arguments.endIndex {
        let flag = arguments[index]
        index = arguments.index(after: index)

        func nextValue() throws -> String {
            guard index < arguments.endIndex else {
                throw DAMHelperArgumentError.missingValue(flag)
            }
            let value = arguments[index]
            index = arguments.index(after: index)
            return value
        }

        switch flag {
        case "--bundle-id":
            bundleIdentifier = try nextValue()
        case "--team-id":
            teamIdentifier = try nextValue()
        case "--display-name":
            displayName = try nextValue()
        case "--proxy-host":
            proxyHost = try nextValue()
        case "--proxy-port":
            let raw = try nextValue()
            guard let port = UInt16(raw) else {
                throw DAMHelperArgumentError.invalidProxyPort(raw)
            }
            proxyPort = port
        case "--protect-host":
            usesDefaultProtectedHosts = false
            protectedHosts.append(try nextValue())
        case "--no-protected-hosts":
            usesDefaultProtectedHosts = false
            protectedHosts.removeAll()
        case "--exclude-signing-id":
            excludedSigningIdentifiers.append(try nextValue())
        case "--routing-failure-policy":
            let raw = try nextValue()
            guard let policy = DAMRoutingFailurePolicy(rawValue: raw) else {
                throw DAMHelperArgumentError.invalidRoutingFailurePolicy(raw)
            }
            routingFailurePolicy = policy
        default:
            throw DAMHelperArgumentError.unknownArgument(flag)
        }
    }

    guard let bundleIdentifier, !bundleIdentifier.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
        throw DAMHelperArgumentError.missingBundleIdentifier
    }

    let runtimeConfiguration = DAMProxyRuntimeConfiguration(
        proxyHost: proxyHost,
        proxyPort: proxyPort,
        protectedHosts: usesDefaultProtectedHosts ? DAMProxyRuntimeConfiguration.defaultProtectedHosts : protectedHosts,
        excludedSigningIdentifiers: excludedSigningIdentifiers.isEmpty ? DAMProxyRuntimeConfiguration.defaultExcludedSigningIdentifiers : excludedSigningIdentifiers,
        routingFailurePolicy: routingFailurePolicy
    )

    return DAMHelperOptions(
        action: action,
        bundleIdentifier: bundleIdentifier,
        teamIdentifier: teamIdentifier,
        displayName: displayName,
        runtimeConfiguration: runtimeConfiguration
    )
}
