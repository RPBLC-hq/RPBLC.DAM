import DAMNetworkExtensionSupport
import Darwin
import Foundation
import Network
import NetworkExtension
import OSLog

public final class DAMTransparentProxyProvider: NETransparentProxyProvider, @unchecked Sendable {
    private static let healthPollInterval: TimeInterval = 0.5

    private let logger = Logger(subsystem: "com.rpblc.dam.network-extension", category: "provider")
    private let stateQueue = DispatchQueue(label: "com.rpblc.dam.network-extension.provider.state")
    private var activeFlows: [UUID: TCPFlowProxy] = [:]
    private var runtimeConfiguration = DAMProxyRuntimeConfiguration()
    private var healthTimer: DispatchSourceTimer?

    public override func startProxy(
        options: [String: Any]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let completion = SendableCompletion(completionHandler)
        let providerConfiguration = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        runtimeConfiguration = DAMProxyRuntimeConfiguration(providerConfiguration: providerConfiguration)
        logger.notice("Starting DAM transparent proxy provider for \(self.runtimeConfiguration.protectedHosts.count, privacy: .public) protected hosts")

        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.includedNetworkRules = Self.includedNetworkRules()

        setTunnelNetworkSettings(settings) { error in
            if let error {
                self.logger.error("Failed to apply transparent proxy network settings: \(error.localizedDescription, privacy: .public)")
            } else {
                self.logger.notice("DAM transparent proxy provider connected")
                self.stateQueue.async {
                    self.startHealthMonitor()
                }
            }
            completion.call(error)
        }
    }

    public override func stopProxy(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        stateQueue.sync {
            healthTimer?.cancel()
            healthTimer = nil
            for flow in activeFlows.values {
                flow.cancel()
            }
            activeFlows.removeAll()
        }
        logger.notice("Stopped DAM transparent proxy provider")
        completionHandler()
    }

    public override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        if runtimeConfiguration.shouldBypassSource(signingIdentifier: flow.metaData.sourceAppSigningIdentifier) {
            return false
        }
        guard let tcpFlow = flow as? NEAppProxyTCPFlow,
              let endpoint = FlowEndpoint(tcpFlow: tcpFlow),
              runtimeConfiguration.shouldProtect(host: endpoint.host)
        else {
            return false
        }

        switch Self.flowAction(runtimeConfiguration) {
        case .handle:
            break
        case .passThrough:
            logger.notice("Passing configured flow for \(endpoint.host, privacy: .public) outside DAM because protection is not ready")
            return false
        case .block:
            logger.error("Blocking configured flow for \(endpoint.host, privacy: .public) because protection is not ready")
            Self.closeBlocked(tcpFlow)
            return true
        }

        let proxy = TCPFlowProxy(
            flow: tcpFlow,
            endpoint: endpoint,
            runtimeConfiguration: runtimeConfiguration
        ) { [weak self] id in
            guard let provider = self else {
                return
            }
            provider.stateQueue.async {
                provider.activeFlows.removeValue(forKey: id)
            }
        }

        stateQueue.async {
            self.activeFlows[proxy.id] = proxy
            proxy.start()
        }
        return true
    }

    private enum FlowAction {
        case handle
        case passThrough
        case block
    }

    private func startHealthMonitor() {
        healthTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: stateQueue)
        timer.schedule(
            deadline: .now() + Self.healthPollInterval,
            repeating: Self.healthPollInterval,
            leeway: .milliseconds(100)
        )
        timer.setEventHandler { [weak self] in
            self?.enforceCurrentFlowAction()
        }
        healthTimer = timer
        timer.resume()
    }

    private func enforceCurrentFlowAction() {
        let action = Self.flowAction(runtimeConfiguration)
        guard action != .handle, !activeFlows.isEmpty else {
            return
        }
        logger.notice("Closing \(self.activeFlows.count, privacy: .public) active DAM flows because protection is not ready")
        let flows = Array(activeFlows.values)
        activeFlows.removeAll()
        for flow in flows {
            flow.cancel()
        }
    }

    private static func flowAction(_ configuration: DAMProxyRuntimeConfiguration) -> FlowAction {
        if localProxyIsProtected(configuration) {
            return .handle
        }
        switch configuration.routingFailurePolicy {
        case .failOpen:
            return .passThrough
        case .failClosed:
            return .block
        }
    }

    private static func includedNetworkRules() -> [NENetworkRule] {
        let ports: [UInt16] = [80, 443]
        let networks: [(host: String, prefix: Int)] = [
            ("0.0.0.0", 0),
            ("::", 0),
        ]
        return networks.flatMap { network in
            ports.map { port in
                let endpoint = NWEndpoint.hostPort(
                    host: NWEndpoint.Host(network.host),
                    port: NWEndpoint.Port(rawValue: port)!
                )
                return NENetworkRule(
                    remoteNetworkEndpoint: endpoint,
                    remotePrefix: network.prefix,
                    localNetworkEndpoint: nil,
                    localPrefix: 0,
                    protocol: .TCP,
                    direction: .outbound
                )
            }
        }
    }

    private static func localProxyIsProtected(_ configuration: DAMProxyRuntimeConfiguration) -> Bool {
        proxyHealthState(configuration) == "protected"
    }

    private static func proxyHealthState(_ configuration: DAMProxyRuntimeConfiguration) -> String? {
        guard let response = localProxyResponse(configuration) else {
            return nil
        }
        guard let separatorRange = response.range(of: "\r\n\r\n") else {
            return nil
        }
        let body = String(response[separatorRange.upperBound...])
        guard let data = body.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let state = json["state"] as? String
        else {
            return nil
        }
        return state
    }

    private static func localProxyResponse(_ configuration: DAMProxyRuntimeConfiguration) -> String? {
        let host = configuration.proxyHost.trimmingCharacters(in: .whitespacesAndNewlines)
        let ipv4Host = host == "localhost" ? "127.0.0.1" : host
        guard !ipv4Host.isEmpty else {
            return nil
        }

        let socketDescriptor = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard socketDescriptor >= 0 else {
            return nil
        }
        defer {
            Darwin.close(socketDescriptor)
        }
        setShortSocketTimeout(socketDescriptor)

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(configuration.proxyPort.bigEndian)
        guard inet_pton(AF_INET, ipv4Host, &address.sin_addr) == 1 else {
            return nil
        }

        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                Darwin.connect(
                    socketDescriptor,
                    sockaddrPointer,
                    socklen_t(MemoryLayout<sockaddr_in>.size)
                ) == 0
            }
        }
        guard connected else {
            return nil
        }

        let request = "GET /health HTTP/1.1\r\nHost: \(ipv4Host)\r\nConnection: close\r\n\r\n"
        let sent = request.utf8CString.withUnsafeBytes { rawBuffer -> Int in
            guard let baseAddress = rawBuffer.baseAddress else {
                return -1
            }
            return Darwin.send(socketDescriptor, baseAddress, request.utf8.count, 0)
        }
        guard sent == request.utf8.count else {
            return nil
        }

        var response = [UInt8]()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while response.count < 16_384 {
            let bufferCount = buffer.count
            let received = buffer.withUnsafeMutableBytes { rawBuffer -> Int in
                guard let baseAddress = rawBuffer.baseAddress else {
                    return -1
                }
                return Darwin.recv(socketDescriptor, baseAddress, bufferCount, 0)
            }
            if received <= 0 {
                break
            }
            response.append(contentsOf: buffer.prefix(received))
        }
        guard !response.isEmpty else {
            return nil
        }
        return String(bytes: response, encoding: .utf8)
    }

    private static func setShortSocketTimeout(_ socketDescriptor: Int32) {
        var timeout = timeval(tv_sec: 0, tv_usec: 250_000)
        _ = withUnsafePointer(to: &timeout) { pointer in
            pointer.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout<timeval>.size) { rawPointer in
                Darwin.setsockopt(
                    socketDescriptor,
                    SOL_SOCKET,
                    SO_RCVTIMEO,
                    rawPointer,
                    socklen_t(MemoryLayout<timeval>.size)
                )
            }
        }
        _ = withUnsafePointer(to: &timeout) { pointer in
            pointer.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout<timeval>.size) { rawPointer in
                Darwin.setsockopt(
                    socketDescriptor,
                    SOL_SOCKET,
                    SO_SNDTIMEO,
                    rawPointer,
                    socklen_t(MemoryLayout<timeval>.size)
                )
            }
        }
    }

    private static func closeBlocked(_ flow: NEAppProxyTCPFlow) {
        let error = NSError(
            domain: "DAMTransparentProxyProvider",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "DAM protection is not ready for this configured route"]
        )
        flow.closeReadWithError(error)
        flow.closeWriteWithError(error)
    }
}

private struct SendableCompletion: @unchecked Sendable {
    private let handler: (Error?) -> Void

    init(_ handler: @escaping (Error?) -> Void) {
        self.handler = handler
    }

    func call(_ error: Error?) {
        handler(error)
    }
}
