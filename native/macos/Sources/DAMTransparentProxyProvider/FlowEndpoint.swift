import Foundation
import Network
import NetworkExtension

struct FlowEndpoint: Equatable, Sendable {
    var host: String
    var port: UInt16

    var authority: String {
        if host.contains(":") && !(host.hasPrefix("[") && host.hasSuffix("]")) {
            return "[\(host)]:\(port)"
        }
        return "\(host):\(port)"
    }

    init?(tcpFlow: NEAppProxyTCPFlow) {
        let endpoint = tcpFlow.remoteFlowEndpoint
        guard case let .hostPort(endpointHost, endpointPort) = endpoint else {
            return nil
        }

        let host = tcpFlow.remoteHostname?.isEmpty == false
            ? tcpFlow.remoteHostname!
            : String(describing: endpointHost)
        self.host = host
        self.port = endpointPort.rawValue
    }
}
