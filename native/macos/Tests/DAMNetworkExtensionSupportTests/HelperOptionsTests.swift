import XCTest

@testable import DAMNetworkExtensionSupport

final class HelperOptionsTests: XCTestCase {
    func testParseInstallOptionsWithRuntimeConfiguration() throws {
        let options = try parseHelperOptions([
            "install",
            "--bundle-id", "com.rpblc.dam.network-extension",
            "--team-id", "TEAMID1234",
            "--display-name", "DAM Network Protection",
            "--proxy-host", "127.0.0.1",
            "--proxy-port", "7828",
            "--routing-failure-policy", "fail_closed",
            "--protect-host", "api.openai.com",
            "--protect-host", "api.anthropic.com",
            "--exclude-signing-id", "com.rpblc.dam.proxy",
        ])

        XCTAssertEqual(options.action, .install)
        XCTAssertEqual(options.bundleIdentifier, "com.rpblc.dam.network-extension")
        XCTAssertEqual(options.teamIdentifier, "TEAMID1234")
        XCTAssertEqual(options.displayName, "DAM Network Protection")
        XCTAssertEqual(options.runtimeConfiguration.proxyHost, "127.0.0.1")
        XCTAssertEqual(options.runtimeConfiguration.proxyPort, 7828)
        XCTAssertEqual(
            options.runtimeConfiguration.protectedHosts,
            [
                "api.openai.com",
                "api.anthropic.com",
            ])
        XCTAssertEqual(options.runtimeConfiguration.routingFailurePolicy, .failClosed)
        XCTAssertTrue(
            options.runtimeConfiguration.shouldBypassSource(
                signingIdentifier: "com.rpblc.dam.proxy",
                processPath: "/Applications/DAM.app/Contents/MacOS/dam-proxy"
            ))
    }

    func testParseRequiresBundleIdentifier() {
        XCTAssertThrowsError(try parseHelperOptions(["status"])) { error in
            XCTAssertEqual(error as? DAMHelperArgumentError, .missingBundleIdentifier)
        }
    }

    func testDefaultProtectedHostsIncludeMvpTargets() {
        let configuration = DAMProxyRuntimeConfiguration()

        XCTAssertTrue(configuration.shouldProtect(host: "api.openai.com"))
        XCTAssertTrue(configuration.shouldProtect(host: "api.anthropic.com"))
        XCTAssertTrue(configuration.shouldProtect(host: "chatgpt.com"))
        XCTAssertFalse(configuration.shouldProtect(host: "example.com"))
        XCTAssertEqual(configuration.routingFailurePolicy, .failOpen)
    }

    func testMissingProviderConfigurationIsInert() {
        let configuration = DAMProxyRuntimeConfiguration(providerConfiguration: nil)

        XCTAssertEqual(configuration.protectedHosts, [])
        XCTAssertFalse(configuration.shouldProtect(host: "api.openai.com"))
        XCTAssertFalse(configuration.shouldProtect(host: "api.anthropic.com"))
    }

    func testProviderConfigurationWithoutProtectedHostsIsInert() {
        let configuration = DAMProxyRuntimeConfiguration(providerConfiguration: [
            DAMProviderConfigurationKey.proxyHost: "127.0.0.1",
            DAMProviderConfigurationKey.proxyPort: 7828,
        ])

        XCTAssertEqual(configuration.protectedHosts, [])
        XCTAssertFalse(configuration.shouldProtect(host: "api.openai.com"))
    }

    func testDefaultSourceBypassRequiresSignedDamBundleSource() {
        let configuration = DAMProxyRuntimeConfiguration()

        XCTAssertTrue(
            configuration.shouldBypassSource(
                signingIdentifier: "com.rpblc.dam.proxy",
                processPath: "/Applications/DAM.app/Contents/MacOS/dam-proxy"
            ))
        XCTAssertTrue(
            configuration.shouldBypassSource(
                signingIdentifier: "com.rpblc.dam.web",
                processPath: "/Applications/DAM.app/Contents/MacOS/dam-web"
            ))
        XCTAssertFalse(configuration.shouldBypassSource(signingIdentifier: "com.rpblc.dam.proxy"))
        XCTAssertFalse(configuration.shouldBypassSource(signingIdentifier: "dam-proxy"))
        XCTAssertFalse(
            configuration.shouldBypassSource(
                signingIdentifier: nil, processPath: "/Applications/DAM.app/Contents/MacOS/dam-proxy"))
        XCTAssertFalse(
            configuration.shouldBypassSource(
                signingIdentifier: "com.rpblc.dam.proxy", processPath: "/Users/alex/dam-proxy"))
        XCTAssertFalse(
            configuration.shouldBypassSource(
                signingIdentifier: "com.example.app",
                processPath: "/Applications/Example.app/Contents/MacOS/example"))
    }

    func testParseNoProtectedHostsDisablesDefaultProtectedHosts() throws {
        let options = try parseHelperOptions([
            "install",
            "--bundle-id", "com.rpblc.dam.network-extension",
            "--no-protected-hosts",
        ])

        XCTAssertEqual(options.runtimeConfiguration.protectedHosts, [])
        XCTAssertFalse(options.runtimeConfiguration.shouldProtect(host: "api.anthropic.com"))
    }

    func testProviderConfigurationRoundTripsRoutingFailurePolicy() {
        let configuration = DAMProxyRuntimeConfiguration(
            routingFailurePolicy: .failClosed
        )

        let decoded = DAMProxyRuntimeConfiguration(
            providerConfiguration: configuration.providerConfiguration)

        XCTAssertEqual(decoded.routingFailurePolicy, .failClosed)
    }

    func testParseRejectsUnknownRoutingFailurePolicy() {
        XCTAssertThrowsError(
            try parseHelperOptions([
                "install",
                "--bundle-id", "com.rpblc.dam.network-extension",
                "--routing-failure-policy", "strict",
            ])
        ) { error in
            XCTAssertEqual(error as? DAMHelperArgumentError, .invalidRoutingFailurePolicy("strict"))
        }
    }
}
