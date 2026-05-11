import DAMNetworkExtensionSupport
import Foundation

@main
struct DAMMacosNEHelper {
    static func main() async {
        do {
            let options = try parseHelperOptions(Array(CommandLine.arguments.dropFirst()))
            let controller = TransparentProxyController()
            let message: String
            switch options.action {
            case .install:
                message = try await controller.install(options)
            case .remove:
                message = try await controller.remove(options)
            case .status:
                message = try await controller.status(options)
            }
            print(message)
        } catch {
            fputs("dam-macos-ne-helper: \(error.localizedDescription)\n", stderr)
            Foundation.exit(1)
        }
    }
}
