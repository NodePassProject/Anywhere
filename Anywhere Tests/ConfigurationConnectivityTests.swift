//
//  ConfigurationConnectivityTests.swift
//  Anywhere
//
//  Created by NodePassProject on 6/21/26.
//

import Testing
import Foundation
@testable import Anywhere

@Suite(.enabled(if: TestEnvironment.isConfigured), .serialized)
struct ConfigurationConnectivityTests {
    static let requestTimeout: Double = 25

    init() {
        TestEnvironment.applyInsecureOverrideIfNeeded()
    }

    private func uniqueToken(_ tag: String) -> String {
        "\(tag)-\(UInt64.random(in: 0...UInt64.max))"
    }

    // MARK: - HTTP/1.1 over the proxy's plaintext TCP path

    @Test func http11PlaintextRoundTrips() async throws {
        let config = try TestEnvironment.proxyConfiguration()
        let host = try TestEnvironment.requireTargetHost()
        let port = TestEnvironment.httpPort
        let token = uniqueToken("h1")

        let response = try await withTimeout(Self.requestTimeout) { () async throws -> HTTPResponse in
            let tunnel = try await ProxyTunnel.open(configuration: config, host: host, port: port)
            do {
                let response = try await TunneledHTTP1Client.get(
                    stream: tunnel.rawStream, host: host, path: "/echo?token=\(token)")
                await tunnel.close()
                return response
            } catch {
                await tunnel.close()
                throw error
            }
        }

        #expect(response.statusCode == 200)
        let echo = try JSONDecoder().decode(EchoResponse.self, from: response.body)
        #expect(echo.marker == EchoResponse.expectedMarker)
        #expect(echo.proto == "HTTP/1.1")
        #expect(echo.tls == false)
        #expect(echo.token == token)
    }

    // MARK: - HTTP/1.1 over TLS (ALPN http/1.1) over the proxy

    @Test func http11OverTLSRoundTrips() async throws {
        TestEnvironment.applyInsecureOverrideIfNeeded()
        let config = try TestEnvironment.proxyConfiguration()
        let host = try TestEnvironment.requireTargetHost()
        let port = TestEnvironment.httpsPort
        let token = uniqueToken("h1tls")

        let response = try await withTimeout(Self.requestTimeout) { () async throws -> HTTPResponse in
            let tunnel = try await ProxyTunnel.open(configuration: config, host: host, port: port)
            do {
                let tls = try await tunnel.tlsStream(serverName: host, port: port, alpn: ["http/1.1"])
                let response = try await TunneledHTTP1Client.get(
                    stream: tls, host: host, path: "/echo?token=\(token)")
                await tunnel.close()
                return response
            } catch {
                await tunnel.close()
                throw error
            }
        }

        #expect(response.statusCode == 200)
        let echo = try JSONDecoder().decode(EchoResponse.self, from: response.body)
        #expect(echo.marker == EchoResponse.expectedMarker)
        #expect(echo.proto == "HTTP/1.1")
        #expect(echo.tls == true)
        #expect(echo.alpn == "http/1.1")
        #expect(echo.token == token)
    }

    // MARK: - HTTP/2 over TLS (ALPN h2) over the proxy

    @Test func http2RoundTrips() async throws {
        TestEnvironment.applyInsecureOverrideIfNeeded()
        let config = try TestEnvironment.proxyConfiguration()
        let host = try TestEnvironment.requireTargetHost()
        let port = TestEnvironment.httpsPort
        let token = uniqueToken("h2")

        let response = try await withTimeout(Self.requestTimeout) { () async throws -> HTTPResponse in
            let tunnel = try await ProxyTunnel.open(configuration: config, host: host, port: port)
            do {
                let tls = try await tunnel.tlsStream(serverName: host, port: port, alpn: ["h2"])
                let response = try await TunneledHTTP2Client.get(
                    stream: tls, authorityHost: host, port: port, path: "/echo?token=\(token)")
                await tunnel.close()
                return response
            } catch {
                await tunnel.close()
                throw error
            }
        }

        #expect(response.statusCode == 200)
        let echo = try JSONDecoder().decode(EchoResponse.self, from: response.body)
        #expect(echo.marker == EchoResponse.expectedMarker)
        #expect(echo.proto == "HTTP/2.0")
        #expect(echo.tls == true)
        #expect(echo.alpn == "h2")
        #expect(echo.token == token)
    }

    // MARK: - Byte-exact payload integrity through the tunnel

    @Test func http11PlaintextLargePayloadIsByteExact() async throws {
        let config = try TestEnvironment.proxyConfiguration()
        let host = try TestEnvironment.requireTargetHost()
        let port = TestEnvironment.httpPort
        let seed: UInt64 = 0xC0FFEE
        let count = 256 * 1024

        let response = try await withTimeout(Self.requestTimeout) { () async throws -> HTTPResponse in
            let tunnel = try await ProxyTunnel.open(configuration: config, host: host, port: port)
            do {
                let response = try await TunneledHTTP1Client.get(
                    stream: tunnel.rawStream, host: host, path: "/bytes?n=\(count)&seed=\(seed)")
                await tunnel.close()
                return response
            } catch {
                await tunnel.close()
                throw error
            }
        }

        #expect(response.statusCode == 200)
        #expect(response.body == DeterministicBytes.generate(seed: seed, count: count))
    }

    @Test func http2LargePayloadIsByteExact() async throws {
        TestEnvironment.applyInsecureOverrideIfNeeded()
        let config = try TestEnvironment.proxyConfiguration()
        let host = try TestEnvironment.requireTargetHost()
        let port = TestEnvironment.httpsPort
        let seed: UInt64 = 0xBADC0DE
        let count = 512 * 1024

        let response = try await withTimeout(Self.requestTimeout) { () async throws -> HTTPResponse in
            let tunnel = try await ProxyTunnel.open(configuration: config, host: host, port: port)
            do {
                let tls = try await tunnel.tlsStream(serverName: host, port: port, alpn: ["h2"])
                let response = try await TunneledHTTP2Client.get(
                    stream: tls, authorityHost: host, port: port, path: "/bytes?n=\(count)&seed=\(seed)")
                await tunnel.close()
                return response
            } catch {
                await tunnel.close()
                throw error
            }
        }

        #expect(response.statusCode == 200)
        #expect(response.body == DeterministicBytes.generate(seed: seed, count: count))
    }

    // MARK: - HTTP/3 over TLS (ALPN h3) over the proxy's UDP relay

    @Test func http3RoundTrips() async throws {
        let config = try TestEnvironment.proxyConfiguration()
        let host = try TestEnvironment.requireTargetHost()
        let port = TestEnvironment.httpsPort
        let token = uniqueToken("h3")

        let response = try await withTimeout(Self.requestTimeout) { () async throws -> HTTPResponse in
            let tunnel = try await ProxyTunnel.openUDP(configuration: config, host: host, port: port)
            do {
                let response = try await TunneledHTTP3Client.get(
                    proxyConnection: tunnel.connection, authorityHost: host, port: port,
                    path: "/echo?token=\(token)")
                await tunnel.close()
                return response
            } catch {
                await tunnel.close()
                throw error
            }
        }

        #expect(response.statusCode == 200)
        let echo = try JSONDecoder().decode(EchoResponse.self, from: response.body)
        #expect(echo.marker == EchoResponse.expectedMarker)
        #expect(echo.proto == "HTTP/3.0")
        #expect(echo.tls == true)
        #expect(echo.alpn == "h3")
        #expect(echo.token == token)
    }

    @Test func http3LargePayloadIsByteExact() async throws {
        let config = try TestEnvironment.proxyConfiguration()
        let host = try TestEnvironment.requireTargetHost()
        let port = TestEnvironment.httpsPort
        let seed: UInt64 = 0xF00D
        let count = 256 * 1024

        let response = try await withTimeout(Self.requestTimeout) { () async throws -> HTTPResponse in
            let tunnel = try await ProxyTunnel.openUDP(configuration: config, host: host, port: port)
            do {
                let response = try await TunneledHTTP3Client.get(
                    proxyConnection: tunnel.connection, authorityHost: host, port: port,
                    path: "/bytes?n=\(count)&seed=\(seed)")
                await tunnel.close()
                return response
            } catch {
                await tunnel.close()
                throw error
            }
        }

        #expect(response.statusCode == 200)
        #expect(response.body == DeterministicBytes.generate(seed: seed, count: count))
    }
}
