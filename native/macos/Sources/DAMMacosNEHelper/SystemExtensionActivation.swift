import Foundation
import SystemExtensions

final class SystemExtensionActivation: NSObject, OSSystemExtensionRequestDelegate, @unchecked Sendable {
    private let semaphore = DispatchSemaphore(value: 0)
    private var result: Result<ActivationOutcome, Error>?
    private var bundleIdentifier = ""
    private var completed = false
    private var requiredUserApproval = false

    func activate(bundleIdentifier: String, timeout: TimeInterval = 20) throws -> ActivationOutcome {
        self.bundleIdentifier = bundleIdentifier
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: bundleIdentifier,
            queue: .main
        )
        request.delegate = self
        if Thread.isMainThread {
            OSSystemExtensionManager.shared.submitRequest(request)
        } else {
            DispatchQueue.main.async {
                OSSystemExtensionManager.shared.submitRequest(request)
            }
        }

        let deadline = Date().addingTimeInterval(timeout)
        while semaphore.wait(timeout: .now() + 0.1) == .timedOut {
            if Date() >= deadline {
                throw ActivationError.timedOut(bundleIdentifier)
            }
            RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.1))
        }

        switch result {
        case .success(let message):
            return message
        case .failure(let error):
            throw error
        case .none:
            throw ActivationError.missingResult
        }
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension replacement: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        requiredUserApproval = true
        complete(.success(.needsUserApproval(
            "needs_user_approval \(bundleIdentifier) open DAM and approve DAM Network Protection in System Settings, then click Connect/Resume again"
        )))
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        let approval = requiredUserApproval ? " after user approval" : ""
        complete(.success(.finished("system extension activation finished\(approval): \(result)")))
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        complete(.failure(error))
    }

    private func complete(_ result: Result<ActivationOutcome, Error>) {
        guard !completed else {
            return
        }
        completed = true
        self.result = result
        semaphore.signal()
    }

    enum ActivationOutcome: Equatable {
        case finished(String)
        case needsUserApproval(String)
    }

    enum ActivationError: Error, CustomStringConvertible {
        case missingResult
        case timedOut(String)

        var description: String {
            switch self {
            case .missingResult:
                return "system extension activation finished without a result"
            case .timedOut(let bundleIdentifier):
                return "system extension activation timed out before macOS registered \(bundleIdentifier); open DAM and click Connect/Resume to request approval from the app"
            }
        }
    }
}
