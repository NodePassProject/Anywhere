//
//  ClashProxyParser.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/2/26.
//

import Foundation

struct ClashProxyParser {
    struct ParseResult {
        let configurations: [ProxyConfiguration]
        let skippedCount: Int
    }

    enum ParseError: Error, LocalizedError {
        case invalidYAML(String)
        case missingProxiesKey

        var errorDescription: String? {
            switch self {
            case .invalidYAML(let reason):
                return "Invalid Clash YAML: \(reason)"
            case .missingProxiesKey:
                return "Clash YAML is missing 'proxies' key."
            }
        }
    }

    static func parse(yaml yamlString: String) throws -> ParseResult {
        let bytes = Array(yamlString.utf8)

        var parser = yaml_parser_t()
        guard yaml_parser_initialize(&parser) != 0 else {
            throw ParseError.invalidYAML("Failed to initialize YAML parser")
        }
        defer { yaml_parser_delete(&parser) }

        yaml_parser_set_input_string(&parser, bytes, bytes.count)

        var document = yaml_document_t()
        guard yaml_parser_load(&parser, &document) != 0 else {
            throw ParseError.invalidYAML("Failed to parse YAML document")
        }
        defer { yaml_document_delete(&document) }

        return try withUnsafeMutablePointer(to: &document) { doc in
            guard let root = yaml_document_get_root_node(doc),
                  root.pointee.type == YAML_MAPPING_NODE else {
                throw ParseError.invalidYAML("Root document is not a mapping")
            }

            guard let proxiesIdx = mappingLookup(doc, node: root, key: "proxies"),
                  let proxiesNode = yaml_document_get_node(doc, proxiesIdx),
                  proxiesNode.pointee.type == YAML_SEQUENCE_NODE else {
                throw ParseError.missingProxiesKey
            }

            var configurations: [ProxyConfiguration] = []
            var skippedCount = 0

            let items = proxiesNode.pointee.data.sequence.items
            var itemPtr = items.start
            while let ip = itemPtr, ip < items.top {
                let nodeIdx = ip.pointee
                if let proxyNode = yaml_document_get_node(doc, nodeIdx),
                   proxyNode.pointee.type == YAML_MAPPING_NODE,
                   let config = parseProxy(doc, node: proxyNode) {
                    configurations.append(config)
                } else {
                    skippedCount += 1
                }
                itemPtr = ip.advanced(by: 1)
            }

            return ParseResult(configurations: configurations, skippedCount: skippedCount)
        }
    }

    // MARK: - Document navigation helpers

    /// Returns the value node index for `key` in a YAML_MAPPING_NODE.
    private static func mappingLookup(
        _ doc: UnsafeMutablePointer<yaml_document_t>,
        node: UnsafeMutablePointer<yaml_node_t>,
        key: String
    ) -> Int32? {
        guard node.pointee.type == YAML_MAPPING_NODE else { return nil }
        let pairs = node.pointee.data.mapping.pairs
        var ptr = pairs.start
        while let p = ptr, p < pairs.top {
            if let keyNode = yaml_document_get_node(doc, p.pointee.key),
               scalarString(keyNode) == key {
                return p.pointee.value
            }
            ptr = p.advanced(by: 1)
        }
        return nil
    }

    /// Returns the UTF-8 string value of a YAML_SCALAR_NODE.
    private static func scalarString(_ node: UnsafeMutablePointer<yaml_node_t>) -> String? {
        guard node.pointee.type == YAML_SCALAR_NODE else { return nil }
        let s = node.pointee.data.scalar
        guard let ptr = s.value else { return nil }
        return String(bytes: UnsafeRawBufferPointer(start: ptr, count: s.length), encoding: .utf8)
    }

    /// Looks up a scalar string field by key in a mapping node.
    private static func getString(
        _ doc: UnsafeMutablePointer<yaml_document_t>,
        mapping: UnsafeMutablePointer<yaml_node_t>,
        key: String
    ) -> String? {
        guard let idx = mappingLookup(doc, node: mapping, key: key),
              let node = yaml_document_get_node(doc, idx) else { return nil }
        return scalarString(node)
    }

    /// Looks up an integer field by key in a mapping node.
    private static func getInt(
        _ doc: UnsafeMutablePointer<yaml_document_t>,
        mapping: UnsafeMutablePointer<yaml_node_t>,
        key: String
    ) -> Int? {
        guard let s = getString(doc, mapping: mapping, key: key) else { return nil }
        return Int(s)
    }

    /// Looks up a boolean field by key in a mapping node.
    /// Accepts true/false/yes/no (case-insensitive).
    private static func getBool(
        _ doc: UnsafeMutablePointer<yaml_document_t>,
        mapping: UnsafeMutablePointer<yaml_node_t>,
        key: String
    ) -> Bool? {
        guard let s = getString(doc, mapping: mapping, key: key) else { return nil }
        switch s.lowercased() {
        case "true", "yes", "1": return true
        case "false", "no", "0": return false
        default: return nil
        }
    }

    /// Collects string items from a YAML_SEQUENCE_NODE identified by key.
    private static func getStringSequence(
        _ doc: UnsafeMutablePointer<yaml_document_t>,
        mapping: UnsafeMutablePointer<yaml_node_t>,
        key: String
    ) -> [String]? {
        guard let idx = mappingLookup(doc, node: mapping, key: key),
              let seqNode = yaml_document_get_node(doc, idx),
              seqNode.pointee.type == YAML_SEQUENCE_NODE else { return nil }

        var result: [String] = []
        let items = seqNode.pointee.data.sequence.items
        var ptr = items.start
        while let ip = ptr, ip < items.top {
            if let node = yaml_document_get_node(doc, ip.pointee),
               let s = scalarString(node) {
                result.append(s)
            }
            ptr = ip.advanced(by: 1)
        }
        return result.isEmpty ? nil : result
    }

    // MARK: - Proxy parsing

    private static func parseProxy(
        _ doc: UnsafeMutablePointer<yaml_document_t>,
        node: UnsafeMutablePointer<yaml_node_t>
    ) -> ProxyConfiguration? {
        let proxyType = getString(doc, mapping: node, key: "type")
        if proxyType == "ss" {
            return parseShadowsocksProxy(doc, node: node)
        }
        guard proxyType == "vless" else { return nil }

        guard
            let name = getString(doc, mapping: node, key: "name"),
            let server = getString(doc, mapping: node, key: "server"),
            let uuidString = getString(doc, mapping: node, key: "uuid"),
            let uuid = UUID(uuidString: uuidString)
        else { return nil }

        guard
            let portInt = getInt(doc, mapping: node, key: "port"),
            portInt > 0, portInt <= Int(UInt16.max)
        else { return nil }
        let port = UInt16(portInt)

        // Transport: tcp (default) or ws; skip h2/grpc
        let network = getString(doc, mapping: node, key: "network") ?? "tcp"
        guard network != "h2" && network != "grpc" else { return nil }
        let transport = (network == "ws") ? "ws" : "tcp"

        let encryption = getString(doc, mapping: node, key: "encryption") ?? "none"
        let rawFlow = getString(doc, mapping: node, key: "flow")
        let flow: String? = (rawFlow?.isEmpty == false) ? rawFlow : nil

        // Security: reality > tls > none
        let tlsEnabled = getBool(doc, mapping: node, key: "tls") ?? false
        let realityOptsIdx = mappingLookup(doc, node: node, key: "reality-opts")
        let hasReality = realityOptsIdx.flatMap { yaml_document_get_node(doc, $0) }?.pointee.type == YAML_MAPPING_NODE

        let security: String
        if hasReality {
            security = "reality"
        } else if tlsEnabled {
            security = "tls"
        } else {
            security = "none"
        }

        // Common TLS/Reality fields
        let serverName = getString(doc, mapping: node, key: "servername")
            ?? getString(doc, mapping: node, key: "sni")
            ?? server
        let skipCertVerify = getBool(doc, mapping: node, key: "skip-cert-verify") ?? false
        let clientFP = getString(doc, mapping: node, key: "client-fingerprint")
        let fingerprint = TLSFingerprint(rawValue: mapFingerprint(clientFP)) ?? .chrome120
        let alpn = getStringSequence(doc, mapping: node, key: "alpn")

        // Build TLS configuration
        var tlsConfig: TLSConfiguration? = nil
        if security == "tls" {
            tlsConfig = TLSConfiguration(
                serverName: serverName,
                alpn: alpn,
                allowInsecure: skipCertVerify,
                fingerprint: fingerprint
            )
        }

        // Build Reality configuration
        var realityConfig: RealityConfiguration? = nil
        if security == "reality",
           let roIdx = realityOptsIdx,
           let roNode = yaml_document_get_node(doc, roIdx) {
            let pubKeyStr = getString(doc, mapping: roNode, key: "public-key") ?? ""
            let shortIdStr = getString(doc, mapping: roNode, key: "short-id") ?? ""
            guard let publicKey = Data(base64URLEncoded: pubKeyStr), publicKey.count == 32 else {
                return nil
            }
            realityConfig = RealityConfiguration(
                serverName: serverName,
                publicKey: publicKey,
                shortId: Data(hexString: shortIdStr) ?? Data(),
                fingerprint: fingerprint
            )
        }

        // Build WebSocket configuration
        var wsConfig: WebSocketConfiguration? = nil
        if transport == "ws" {
            var wsPath = "/"
            var wsHost = server
            var wsHeaders: [String: String] = [:]

            if let woIdx = mappingLookup(doc, node: node, key: "ws-opts"),
               let woNode = yaml_document_get_node(doc, woIdx),
               woNode.pointee.type == YAML_MAPPING_NODE {

                wsPath = getString(doc, mapping: woNode, key: "path") ?? "/"

                if let hIdx = mappingLookup(doc, node: woNode, key: "headers"),
                   let hNode = yaml_document_get_node(doc, hIdx),
                   hNode.pointee.type == YAML_MAPPING_NODE {
                    let hPairs = hNode.pointee.data.mapping.pairs
                    var hp = hPairs.start
                    while let p = hp, p < hPairs.top {
                        if let kNode = yaml_document_get_node(doc, p.pointee.key),
                           let vNode = yaml_document_get_node(doc, p.pointee.value),
                           let k = scalarString(kNode),
                           let v = scalarString(vNode) {
                            wsHeaders[k] = v
                            if k == "Host" { wsHost = v }
                        }
                        hp = p.advanced(by: 1)
                    }
                }
            }

            wsConfig = WebSocketConfiguration(host: wsHost, path: wsPath, headers: wsHeaders)
        }

        return ProxyConfiguration(
            name: name,
            serverAddress: server,
            serverPort: port,
            uuid: uuid,
            encryption: encryption,
            transport: transport,
            flow: flow,
            security: security,
            tls: tlsConfig,
            reality: realityConfig,
            websocket: wsConfig
        )
    }

    // MARK: - Shadowsocks proxy parsing

    private static func parseShadowsocksProxy(
        _ doc: UnsafeMutablePointer<yaml_document_t>,
        node: UnsafeMutablePointer<yaml_node_t>
    ) -> ProxyConfiguration? {
        guard
            let name = getString(doc, mapping: node, key: "name"),
            let server = getString(doc, mapping: node, key: "server"),
            let password = getString(doc, mapping: node, key: "password"),
            let cipher = getString(doc, mapping: node, key: "cipher")
        else { return nil }

        guard ShadowsocksCipher(method: cipher) != nil else { return nil }

        guard
            let portInt = getInt(doc, mapping: node, key: "port"),
            portInt > 0, portInt <= Int(UInt16.max)
        else { return nil }
        let port = UInt16(portInt)

        // Transport: tcp (default) or ws
        let network = getString(doc, mapping: node, key: "network") ?? getString(doc, mapping: node, key: "plugin-opts-network") ?? "tcp"
        guard network != "h2" && network != "grpc" else { return nil }
        let transport = (network == "ws") ? "ws" : "tcp"

        // TLS
        let tlsEnabled = getBool(doc, mapping: node, key: "tls") ?? false
        let security = tlsEnabled ? "tls" : "none"

        var tlsConfig: TLSConfiguration? = nil
        if tlsEnabled {
            let sni = getString(doc, mapping: node, key: "servername")
                ?? getString(doc, mapping: node, key: "sni")
                ?? server
            let skipCertVerify = getBool(doc, mapping: node, key: "skip-cert-verify") ?? false
            let alpn = getStringSequence(doc, mapping: node, key: "alpn")
            let clientFP = getString(doc, mapping: node, key: "client-fingerprint")
            let fingerprint = TLSFingerprint(rawValue: mapFingerprint(clientFP)) ?? .chrome120

            tlsConfig = TLSConfiguration(
                serverName: sni,
                alpn: alpn,
                allowInsecure: skipCertVerify,
                fingerprint: fingerprint
            )
        }

        // WebSocket
        var wsConfig: WebSocketConfiguration? = nil
        if transport == "ws" {
            var wsPath = "/"
            var wsHost = server
            var wsHeaders: [String: String] = [:]

            if let woIdx = mappingLookup(doc, node: node, key: "ws-opts"),
               let woNode = yaml_document_get_node(doc, woIdx),
               woNode.pointee.type == YAML_MAPPING_NODE {
                wsPath = getString(doc, mapping: woNode, key: "path") ?? "/"
                if let hIdx = mappingLookup(doc, node: woNode, key: "headers"),
                   let hNode = yaml_document_get_node(doc, hIdx),
                   hNode.pointee.type == YAML_MAPPING_NODE {
                    let hPairs = hNode.pointee.data.mapping.pairs
                    var hp = hPairs.start
                    while let p = hp, p < hPairs.top {
                        if let kNode = yaml_document_get_node(doc, p.pointee.key),
                           let vNode = yaml_document_get_node(doc, p.pointee.value),
                           let k = scalarString(kNode),
                           let v = scalarString(vNode) {
                            wsHeaders[k] = v
                            if k == "Host" { wsHost = v }
                        }
                        hp = p.advanced(by: 1)
                    }
                }
            }

            wsConfig = WebSocketConfiguration(host: wsHost, path: wsPath, headers: wsHeaders)
        }

        return ProxyConfiguration(
            name: name,
            serverAddress: server,
            serverPort: port,
            uuid: UUID(), // placeholder
            encryption: "none",
            transport: transport,
            security: security,
            tls: tlsConfig,
            websocket: wsConfig,
            outboundProtocol: .shadowsocks,
            ssPassword: password,
            ssMethod: cipher
        )
    }

    /// Maps Clash `client-fingerprint` strings to `TLSFingerprint` raw values.
    private static func mapFingerprint(_ fp: String?) -> String {
        switch fp?.lowercased() {
        case "chrome":  return TLSFingerprint.chrome120.rawValue
        case "firefox": return TLSFingerprint.firefox120.rawValue
        case "safari":  return TLSFingerprint.safari16.rawValue
        case "ios":     return TLSFingerprint.ios14.rawValue
        case "edge":    return TLSFingerprint.edge106.rawValue
        case "random":  return TLSFingerprint.random.rawValue
        default:        return fp ?? TLSFingerprint.chrome120.rawValue
        }
    }
}
