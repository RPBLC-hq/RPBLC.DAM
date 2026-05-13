// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "DAMMacOSNetworkExtension",
    platforms: [
        .macOS(.v15),
    ],
    products: [
        .executable(
            name: "dam-macos-ne-helper",
            targets: ["DAMMacosNEHelper"]
        ),
        .executable(
            name: "DAMTransparentProxyProvider",
            targets: ["DAMTransparentProxyProvider"]
        ),
    ],
    targets: [
        .target(
            name: "DAMNetworkExtensionSupport"
        ),
        .executableTarget(
            name: "DAMTransparentProxyProvider",
            dependencies: ["DAMNetworkExtensionSupport"],
            linkerSettings: [
                .linkedFramework("Network"),
                .linkedFramework("NetworkExtension"),
                .linkedLibrary("bsm"),
            ]
        ),
        .executableTarget(
            name: "DAMMacosNEHelper",
            dependencies: ["DAMNetworkExtensionSupport"],
            linkerSettings: [
                .linkedFramework("Network"),
                .linkedFramework("NetworkExtension"),
            ]
        ),
        .testTarget(
            name: "DAMNetworkExtensionSupportTests",
            dependencies: ["DAMNetworkExtensionSupport"]
        ),
    ]
)
