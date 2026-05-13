import Darwin
import Foundation

struct DAMProcessInfo: Equatable, Sendable {
    var pid: UInt32
    var path: String?
}

private let DAMProcPidPathInfoMaxSize = UInt32(MAXPATHLEN * 4)

final class ProcessInfoCache: @unchecked Sendable {
    private static let shared = ProcessInfoCache()

    private let queue = DispatchQueue(label: "com.rpblc.dam.network-extension.process-info")
    private var cache: [Data: DAMProcessInfo] = [:]

    static func getInfo(fromAuditToken tokenData: Data?) -> DAMProcessInfo? {
        shared.getInfo(fromAuditToken: tokenData)
    }

    private func getInfo(fromAuditToken tokenData: Data?) -> DAMProcessInfo? {
        guard let tokenData else {
            return nil
        }

        if let cached = queue.sync(execute: { cache[tokenData] }) {
            return cached
        }

        guard tokenData.count == MemoryLayout<audit_token_t>.size else {
            return nil
        }

        let token = tokenData.withUnsafeBytes { buffer in
            buffer.baseAddress!.assumingMemoryBound(to: audit_token_t.self).pointee
        }
        let pid = audit_token_to_pid(token)
        let path = processPath(pid: pid)
        let info = DAMProcessInfo(pid: UInt32(pid), path: path)

        queue.sync {
            cache[tokenData] = info
        }
        return info
    }

    private func processPath(pid: pid_t) -> String? {
        let pathBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(DAMProcPidPathInfoMaxSize))
        defer {
            pathBuffer.deallocate()
        }

        guard proc_pidpath(pid, pathBuffer, DAMProcPidPathInfoMaxSize) > 0 else {
            return nil
        }
        return String(cString: pathBuffer)
    }
}
