# AJSON Subscriptions — Developer Guide

AJSON is Anywhere's own subscription format: one JSON document that carries
the subscription's name, icon, and usage together with its proxies, written in
Anywhere's model rather than another client's. Compared with a Clash YAML
`proxies:` list it has unambiguous types, one shape for TLS and transports
across every protocol, every Anywhere-specific option (Nowhere, Sudoku, XHTTP),
reusable templates, and stable proxy identities that survive renames. This
guide covers how a subscription is recognized, the document format, and how a
refresh treats the proxies it contains.

## Contents

- [How it works](#how-it-works)
- [The document](#the-document)
- [Proxies](#proxies)
- [Security layers](#security-layers)
- [Transport layers](#transport-layers)
- [Protocols](#protocols)
- [Templates](#templates)
- [Stable identities](#stable-identities)
- [Worked example](#worked-example)
- [Behavior reference](#behavior-reference)

---

## How it works

Every subscription request carries

```
User-Agent: Anywhere
X-Anywhere-Format: ajson/1
```

A server that sees `X-Anywhere-Format` may answer with an AJSON document;
older versions of Anywhere do not send the header and should keep receiving a
format they understand.

A response is treated as AJSON when its body is UTF-8 and its first token,
after whitespace, a byte-order mark, and JSON5 comments, is `{`. This check
runs before base64, Clash, and link-list detection. From then on the body must
be a valid AJSON document: a syntax error, a missing or unsupported version, or
a missing `proxies` array fails the import or refresh with an `AJSON:` error,
and a document in which no proxy is valid fails with *No valid configurations
found in subscription*. An invalid proxy on its own is skipped silently, as in
the other subscription formats.

The body is parsed as **JSON5**: comments, trailing commas, unquoted keys, and
single-quoted strings are accepted. Values are typed strictly: a boolean is
`true` or `false` (not `1` or `"true"`), an integer is a JSON number with no
fraction (not a string), and a value of the wrong type makes the proxy that
carries it invalid. `null` is the same as leaving the key out. Unknown keys are
ignored everywhere, so a server may add fields that a later version will read.

---

## The document

```jsonc
{
  "anywhere": 1,
  "name": "Example Cloud",
  "icon": { "light": "iVBORw0KGgo…", "dark": "iVBORw0KGgo…" },
  "usage": { "upload": 0, "download": 1073741824, "total": 107374182400, "expire": 1798675200 },
  "templates": { … },
  "proxies": [ … ]
}
```

| Key         | Type    | Meaning |
| ----------- | ------- | ------- |
| `anywhere`  | integer | **Required.** Format version, currently `1`. A higher version is rejected with a request to update Anywhere. |
| `proxies`   | array   | **Required.** The subscription's proxies, in display order. See [Proxies](#proxies). |
| `name`      | string  | Subscription name. |
| `icon`      | object  | `light` and `dark`, each a base64 image of at most **256 KB** decoded. |
| `usage`     | object  | `upload`, `download`, `total` in bytes; `expire` in Unix seconds. |
| `templates` | object  | Named partial proxies. See [Templates](#templates). |

`name`, `icon`, and `usage` replace the `profile-title`, `aw-icon-light` /
`aw-icon-dark`, and `subscription-userinfo` response headers field by field:
a value in the document wins, and a value the document leaves out falls back to
the header. A metadata value of the wrong type is ignored. As with the header,
`name` never overrides a name the user changed in the app.

---

## Proxies

Each element of `proxies` takes one of three forms.

**A structured proxy:**

```jsonc
{ "id": "hk1", "name": "Hong Kong 01", "protocol": "trojan",
  "server": "hk1.example.com", "port": 443, "password": "secret" }
```

| Key        | Type    | Meaning |
| ---------- | ------- | ------- |
| `name`     | string  | **Required**, non-empty. Display name. |
| `server`   | string  | **Required** except for `direct`. Host name or IP address; brackets around an IPv6 address are removed. |
| `port`     | integer | **Required** except for `direct`. 1–65535. |
| `protocol` | string  | **Required.** One of `nowhere`, `vless`, `hysteria`, `sudoku`, `trojan`, `anytls`, `shadowsocks`, `socks5`, `rfc`, `direct`. |
| `id`       | string  | Stable key, unique in the document. See [Stable identities](#stable-identities). |
| `use`      | string  | Name of a template to start from. See [Templates](#templates). |

The remaining keys depend on `protocol`; see [Protocols](#protocols).

**A share link,** written as a plain string. It is read exactly like a line of
a link-list subscription: `nowhere://`, `vless://`, `hysteria2://`, `hy2://`,
`sudoku://`, `trojan://`, `anytls://`, `ss://`, `socks5://`, `socks://`,
`rfc://`, and `direct://`.

```jsonc
"ss://YWVzLTEyOC1nY206c2VjcmV0@ss.example.com:8388#Plain"
```

**A keyed share link,** an object with `link`, which may also carry `id` and
`name`. `name` replaces the link's fragment name; every other key is ignored.

```jsonc
{ "id": "tr1", "name": "Trojan", "link": "trojan://secret@tr.example.com:443" }
```

---

## Security layers

`security` is written either as an object with a `type`, or as the type name
alone when the defaults are enough (`"security": "tls"`).

**`tls`**

| Key           | Type            | Default | Meaning |
| ------------- | --------------- | ------- | ------- |
| `sni`         | string          | `server` | Server name. |
| `alpn`        | array of string | protocol default | ALPN list. |
| `fingerprint` | string          | Chrome 133 (Chrome 120 before iOS 26) | `chrome_133`, `chrome_120`, `chrome_106`, `firefox_148`, `firefox_120`, `safari_26`, `edge_106`, `plain`, or the family names `chrome`, `firefox`, `safari`, `edge`. |
| `minVersion`  | string          | — | `"1.0"`, `"1.1"`, `"1.2"`, or `"1.3"`. |
| `maxVersion`  | string          | — | As `minVersion`. |
| `insecure`    | boolean         | `false` | Skip certificate verification. |
| `ech`         | boolean or string | `false` | `true` fetches the ECH configuration from DNS HTTPS records; a string is an inline base64 ECHConfigList. |

**`reality`** (VLESS only)

| Key           | Type   | Default | Meaning |
| ------------- | ------ | ------- | ------- |
| `sni`         | string | **required** | Server name of the impersonated site. |
| `publicKey`   | string | **required** | X25519 public key, base64url, 32 bytes. |
| `shortId`     | string | empty | Hex, at most 8 bytes. |
| `fingerprint` | string | as for `tls` | |

**`none`** disables the layer.

Which types a protocol accepts, and its default, are listed under
[Protocols](#protocols).

---

## Transport layers

`transport` applies to VLESS only. Like `security`, it is an object with a
`type` or the type name alone. The default is `raw`.

| Type          | Keys (defaults) |
| ------------- | --------------- |
| `raw`         | — |
| `ws`          | `host` (`server`), `path` (`/`), `headers` (object of strings), `maxEarlyData` (`0`), `earlyDataHeaderName` (`Sec-WebSocket-Protocol`), `heartbeatPeriod` (seconds, `0`) |
| `httpupgrade` | `host` (`server`), `path` (`/`), `headers` |
| `grpc`        | `serviceName`, `authority`, `multiMode` (`false`), `userAgent`, `initialWindowsSize`, `idleTimeout`, `healthCheckTimeout`, `permitWithoutStream` (`false`) |
| `xhttp`       | `host`, `path` (`/`), `mode` (`auto`, `stream-one`, `stream-up`, `packet-up`), and the keys of an Xray XHTTP `extra` object |

For `xhttp`, `host` defaults to the TLS or Reality server name, then to
`server`. Every other key is read as in an Xray `extra` object, so one can be
pasted in unchanged: `headers`, `noGRPCHeader`, `scMaxEachPostBytes`,
`scMinPostsIntervalMs`, `xPaddingBytes`, `xPaddingObfsMode`, `xPaddingKey`,
`xPaddingHeader`, `xPaddingPlacement`, `xPaddingMethod`, `uplinkHTTPMethod`,
`sessionIDPlacement`, `sessionIDKey`, `seqPlacement`, `seqKey`,
`sessionIDTable`, `sessionIDLength`, `uplinkDataPlacement`, `uplinkDataKey`,
`uplinkChunkSize`, `xmux`, and `downloadSettings`. These keys follow Xray's
lenient rules, where an unusable value falls back to its default; only `mode`
is checked strictly.

---

## Protocols

| `protocol`    | Required | Optional (default) | `security` |
| ------------- | -------- | ------------------ | ---------- |
| `nowhere`     | `key` | `network`: `tcp` / `udp` (`tcp`); `morph` (`true`); `morphPrelude`: `fade` / `full8` / `low7` (`fade`) | fixed TLS 1.3, not configurable |
| `vless`       | `uuid` | `encryption` (`none`); `flow`; `transport` (`raw`) | `none`, `tls`, `reality`; default `none` |
| `hysteria`    | `password` | `sni` (`server`); `congestion`: `brutal` / `bbr`; `upMbps` (20); `downMbps` (50); `obfs` | always TLS via `sni` |
| `sudoku`      | `key` | `aeadMethod`; `paddingMin` (5); `paddingMax` (15); `asciiMode`; `customTables`; `enablePureDownlink` (`true`); `multiplex`; `httpMask` | — |
| `trojan`      | `password` | — | `none`, `tls`; default `tls` |
| `anytls`      | `password` | `idleCheckInterval` (30); `idleTimeout` (30); `minIdleSession` (0) | `none`, `tls`; default `tls` |
| `shadowsocks` | `method` | `password` (empty) | — |
| `socks5`      | — | `username`; `password` | — |
| `rfc`         | — | `username` (no `:`); `password` | `none`, `tls`; default `tls` |
| `direct`      | — | — | — |

Protocol notes:

- **VLESS** `uuid` takes a UUID, 32 hex digits, or a 1–30 character string that
  is mapped to a UUID the way Xray does.
- **Hysteria** `congestion` defaults to `brutal` when `upMbps` or `downMbps` is
  given and to `bbr` otherwise; both rates are clamped to 0–1000. `obfs` is
  `{ "type": "salamander" | "gecko", "password": …, "minPacketSize": …,
  "maxPacketSize": … }`, and the packet sizes apply to `gecko` only.
- **Sudoku** `aeadMethod` is `chacha20-poly1305` (default), `aes-128-gcm`, or
  `none`. `asciiMode` is `prefer_entropy` (default), `prefer_ascii`,
  `up_ascii_down_entropy`, or `up_entropy_down_ascii`. Padding is clamped to
  0–100. `multiplex` is `off` (default), `auto`, or `on`. `httpMask` is
  `{ "disable", "mode": "legacy" | "stream" | "poll" | "auto" | "ws",
  "tls", "host", "pathRoot" }`.
- **Shadowsocks** `method` is one of `aes-128-gcm`, `aes-256-gcm`,
  `chacha20-ietf-poly1305`, `2022-blake3-aes-128-gcm`,
  `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`, or `none`.
- **RFC** is an HTTP `CONNECT` proxy. With TLS and no `alpn`, it offers `h2`
  and `http/1.1`.
- **Direct** has no server. Requests assigned to it leave the device directly,
  as if routed `DIRECT`.

---

## Templates

`templates` maps a name to a partial proxy. A proxy with `"use": "<name>"`
starts from that template and overrides it:

- Keys of the proxy replace keys of the template.
- Where both sides hold an object (`security`, `transport`, `obfs`,
  `httpMask`, …), the two objects are merged by the same rule, recursively.
- An array, a string, or a number replaces the template's value as a whole, so
  `"security": "none"` replaces a template's whole `security` object.

Templates do not nest: `use`, `id`, and `link` inside a template are ignored.
A proxy that names a template that does not exist is skipped. The merged result
must form a complete proxy.

```jsonc
"templates": {
  "reality": {
    "protocol": "vless", "port": 443,
    "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "flow": "xtls-rprx-vision",
    "security": { "type": "reality", "sni": "www.apple.com",
                  "publicKey": "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw", "shortId": "6ba85179e30d4fc2" }
  }
},
"proxies": [
  { "id": "hk1", "name": "Hong Kong 01", "use": "reality", "server": "hk1.example.com" },
  { "id": "jp1", "name": "Japan 01", "use": "reality", "server": "jp1.example.com",
    "security": { "shortId": "a1b2" } }
]
```

---

## Stable identities

A proxy with an `id` gets an identity derived from the subscription and that
key (a name-based UUID). On every refresh the same key yields the same
identity, so the proxy keeps its selection, its latency result, and any
routing rule set assigned to it, even when the server renames or reorders it.

- `id` is a non-empty string. Within one document the first valid proxy with a
  key keeps it; a later proxy with the same key is skipped.
- A proxy without an `id` is matched to the previous refresh by name, in order,
  as in the other subscription formats.
- Identities are scoped to the subscription: the same key in two
  subscriptions names two different proxies.
- Moving an existing subscription to keyed AJSON gives each keyed proxy a new
  identity once, on the first refresh.

---

## Worked example

```jsonc
// Example Cloud — served when the request carries X-Anywhere-Format: ajson/1
{
  "anywhere": 1,
  "name": "Example Cloud",
  "usage": { "download": 1073741824, "total": 107374182400, "expire": 1798675200 },

  "templates": {
    "reality": {
      "protocol": "vless", "port": 443,
      "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "flow": "xtls-rprx-vision",
      "security": { "type": "reality", "sni": "www.apple.com",
                    "publicKey": "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw", "shortId": "6ba85179e30d4fc2" },
    },
  },

  "proxies": [
    { "id": "hk1", "name": "Hong Kong 01", "use": "reality", "server": "hk1.example.com" },
    { "id": "jp1", "name": "Japan 01", "use": "reality", "server": "jp1.example.com" },

    { "id": "us1", "name": "United States 01", "protocol": "hysteria",
      "server": "us1.example.com", "port": 443, "password": "secret",
      "upMbps": 50, "downMbps": 200,
      "obfs": { "type": "salamander", "password": "obfs-secret" } },

    { "id": "sg1", "name": "Singapore XHTTP", "protocol": "vless",
      "server": "sg1.example.com", "port": 443, "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
      "transport": { "type": "xhttp", "path": "/x", "mode": "auto", "xPaddingBytes": "100-1000" },
      "security": { "type": "tls", "alpn": ["h3"] } },

    { "id": "home", "name": "Home", "protocol": "nowhere",
      "server": "home.example.net", "port": 8443,
      "key": "0123456789abcdef0123456789abcdef", "network": "udp" },

    { "id": "tr1", "link": "trojan://secret@tr.example.com:443#Trojan" },
  ],
}
```

Subscribed, this yields one subscription named *Example Cloud* with six
proxies and the given usage. Renaming *Hong Kong 01* on the server later
leaves it selected on every device that had chosen it.

---

## Behavior reference

- **Detected by content.** A UTF-8 body that opens with `{` is AJSON; the URL
  and `Content-Type` play no part.
- **Whole-document errors fail the request.** Syntax errors, a missing or
  unsupported `anywhere` version, a missing `proxies` array, or no valid proxy
  at all leave the stored subscription unchanged.
- **Proxy errors skip the proxy.** A missing required key, an unknown
  `protocol`, a value outside its allowed set, or a value of the wrong type
  drops that proxy silently.
- **Unknown keys are ignored.** At the document, proxy, and layer level alike.
- **Document beats headers.** `name`, `icon`, and `usage` fall back to the
  response headers field by field.
- **Keys keep identities.** Keyed proxies keep their identity across
  refreshes; unkeyed ones are matched by name in order.
