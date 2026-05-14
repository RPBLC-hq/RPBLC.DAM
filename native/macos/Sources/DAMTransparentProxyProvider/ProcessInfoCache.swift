import Darwin
import Foundation

struct DAMProcessInfo: Equatable, Sendable {
    var pid: UInt32
    var path: String?
}

private let DAMProcPidPathInfoMaxSize = UInt32(MAXPATHLEN * 4)
private let DAMProcessInfoCacheLimit = 1024

final class ProcessInfoCache: @unchecked Sendable {
    private static let shared = ProcessInfoCache()

    private let queue = DispatchQueue(label: "com.rpblc.dam.network-extension.process-info")
    private var cache: [Data: DAMProcessInfo] = [:]
    private var cacheOrder: [Data] = []

    static func getInfo(fromAuditToken tokenData: Data?) -> DAMProcessInfo? {
        shared.getInfo(fromAuditToken: tokenData)
    }

    private func getInfo(fromAuditToken tokenData: Data?) -> DAMProcessInfo? {
        guard let tokenData else {
            return nil
        }

        if let cached = queue.sync(execute: {
            if let cached = cache[tokenData] {
                promoteCacheKey(tokenData)
                return cached
            }
            return nil
        }) {
            return cached
        }

        guard tokenData.count == MemoryLayout<audit_token_t>.size else {
            return nil
        }

        let token = tokenData.withUnsafeBytes { buffer in
            buffer.baseAddress!.assumingMemoryBound(to: audit_token_t.self).pointee
        }
        let pid = audit_token_to_pid(token)
        let path = processPath(token: token)
        let info = DAMProcessInfo(pid: UInt32(pid), path: path)

        queue.sync {
            cache[tokenData] = info
            promoteCacheKey(tokenData)
            evictCacheOverflow()
        }
        return info
    }

    private func processPath(token: audit_token_t) -> String? {
        let pathBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(DAMProcPidPathInfoMaxSize))
        defer {
            pathBuffer.deallocate()
        }

        var mutableToken = token
        let pathLength = withUnsafeMutablePointer(to: &mutableToken) { tokenPointer in
            proc_pidpath_audittoken(tokenPointer, pathBuffer, DAMProcPidPathInfoMaxSize)
        }
        guard pathLength > 0 else {
            return nil
        }
        return String(cString: pathBuffer)
    }

    private func promoteCacheKey(_ key: Data) {
        cacheOrder.removeAll { $0 == key }
        cacheOrder.append(key)
    }

    private func evictCacheOverflow() {
        while cache.count > DAMProcessInfoCacheLimit, !cacheOrder.isEmpty {
            let evicted = cacheOrder.removeFirst()
            cache.removeValue(forKey: evicted)
        }
    }
}
