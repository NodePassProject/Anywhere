# MITM Rewrite System — Developer Guide

Anywhere can terminate TLS for selected domains, inspect and rewrite the
HTTP traffic inside, and re-encrypt it to the upstream — a man-in-the-middle
(MITM) on traffic you control. This guide covers everything needed to author
rules and scripts. It is reference-level and assumes you are comfortable with
HTTP, regular expressions, and JavaScript. It does **not** cover the settings
UI.

> **Prerequisite.** Interception only works for clients that trust Anywhere's
> generated root CA. Install and trust it first. Apps that pin certificates
> cannot be intercepted (their TLS handshake to the minted leaf certificate
> will fail) — this is expected, not a bug.

## Contents

- [How it works](#how-it-works)
- [Rule sets](#rule-sets)
- [The import format](#the-import-format)
- [Rewrite actions](#rewrite-actions)
- [Rule operations](#rule-operations)
- [Scripting: `script`](#scripting-script)
- [Scripting: `stream-script`](#scripting-stream-script)
- [The `ctx` object](#the-ctx-object)
- [The `Anywhere` API](#the-anywhere-api)
- [Single-rule semantics](#single-rule-semantics)
- [Limits and safety](#limits-and-safety)
- [Worked examples](#worked-examples)
- [Behavior reference](#behavior-reference)

---

## How it works

A connection is intercepted when its TLS ClientHello SNI host matches a
configured rule set. Anywhere then:

1. Mints a leaf certificate for the requested host (cached) and completes the
   **inner** TLS handshake with the client.
2. Opens the **outer** leg to the upstream (or to a redirect target) and runs
   its own handshake there.
3. Decrypts each direction, runs the matching rules, and re-encrypts to the
   opposite leg.

Traffic is processed in two **phases**:

- **Request** (`httpRequest`) — the client→server direction, before the
  request leaves for upstream.
- **Response** (`httpResponse`) — the server→client direction, before the
  response reaches the client.

Both HTTP/1.1 and HTTP/2 are supported. For HTTP/2 the rewriter operates on
decoded header lists and whole-body buffers; for HTTP/1.1 it drives a byte-level
framing state machine. Either way the rule model below is identical.

A rule set's `hostname` suffixes gate **which hosts** are intercepted; each
rule's `pattern` regex gates **which requests** within those hosts it acts on.
A request that matches no rule is forwarded unchanged (its body is streamed
through without buffering), so the marginal cost of an intercepted-but-unrewritten
request is small — but interception itself (the extra TLS handshakes) is not
free. Scope `hostname` as tightly as you can.

> **Performance note.** All script execution across all connections runs on a
> single serial queue, and one JavaScript runtime is shared by every connection
> to the same rule set. A script that loops forever, recurses without bound, or
> triggers catastrophic regex backtracking will wedge **every** tunneled flow,
> not just its own connection — there is no execution-time watchdog. Keep
> scripts bounded.

---

## Rule sets

A rule set is the unit of configuration:

| Field            | Meaning                                                                 |
| ---------------- | ----------------------------------------------------------------------- |
| `name`           | Display name. Required, non-empty.                                      |
| `domainSuffixes` | Hosts to intercept, matched by **suffix**. `example.com` covers `www.example.com`. No wildcards. |
| `rewriteTarget`  | Optional upstream redirect / synthesized-response action (see [Rewrite actions](#rewrite-actions)). |
| `rules`          | Ordered list of rewrite rules.                                          |

Suffix matching is **most-specific-win**: if both `example.com` and
`api.example.com` are configured, a request to `api.example.com` uses only the
latter set. Each connection resolves to exactly one rule set.

Rule sets are authored as text (pasted or downloaded from a URL) and stored
internally as JSON. The text format below is the authoring interface.

---

## The import format

A rule set is a flat sequence of **header lines** and **rule lines**, in any
order. Blank lines are ignored; lines beginning with `#` or `//` are comments.
Parsing never hard-fails — a line that is neither a recognized header nor a
valid rule is dropped silently, so a partially valid file still imports what it
can.

```
# A complete example
name        = My Rule Set
hostname    = example.com, api.example.org
redirect    = upstream.example.com:443

# request: rewrite /old... to /new...
0, 0, ^/old/(.*), /new/$1
# request: add a header on /api/ paths
0, 1, ^/api/, X-Powered-By, Anywhere
```

### Header lines

Shape: `<key> = <value>`. Keys are case-insensitive; the value is trimmed and
otherwise kept verbatim.

| Key            | Meaning                                                                                  |
| -------------- | ---------------------------------------------------------------------------------------- |
| `name`         | Display name (required).                                                                 |
| `hostname`     | Comma-separated domain suffixes.                                                         |
| `redirect`     | Transparent upstream redirect: `host` or `host:port` (see [Rewrite actions](#rewrite-actions)). |
| `redirect-302` | Synthesize a `302 Found`: `host` or `host:port`.                                         |
| `reject-200`   | Synthesize a `200 OK`: `<kind>` or `<kind> <content>`.                                   |
| `content-type` | Content-Type override, applied to `reject-200` only.                                     |

`redirect`, `redirect-302`, and `reject-200` are mutually exclusive; if more
than one appears, the last wins. Unrecognized keys are ignored. For IPv6 hosts,
use bracket form (`[::1]` or `[::1]:443`); an unbracketed address with multiple
colons is treated as a host with no port.

### Rule lines

Shape:

```
<phase>, <operation>, <field1> [, <field2> [, <field3>]]
```

- **Phase**: `0` = request, `1` = response.
- **Operation** and its trailing fields:

| ID  | Operation        | Phase        | Fields                  |
| --- | ---------------- | ------------ | ----------------------- |
| `0` | `url-replace`    | request only | `pattern`, `replacement`|
| `1` | `header-add`     | both         | `pattern`, `name`, `value` |
| `2` | `header-delete`  | both         | `pattern`, `name`       |
| `3` | `header-replace` | both         | `pattern`, `name`, `value` |
| `4` | `script`         | both         | `pattern`, `base64`     |
| `5` | `stream-script`  | both         | `pattern`, `base64`     |

`url-replace` is always request-phase regardless of the phase column. A rule
whose field count does not match the table, or whose `pattern` is empty or
fails to compile as a regex, is dropped.

### Fields and quoting

Fields are separated by `,`. Whitespace around an unquoted field is trimmed. A
field beginning with `"` is read until the matching `"`, and `""` inside a
quoted field is a literal `"`. Quote any field that contains a comma or
significant leading/trailing whitespace:

```
0, 1, ^/, X-Note, "value, with a comma"
```

### The `pattern`

Every rule leads with a `pattern`: an `NSRegularExpression` (default Unicode
semantics) tested against the request target's **path-and-query** — e.g.
`/api/login?token=abc`. It does **not** see the host, scheme, method, or HTTP
version. Use `.*` to match every request. The rule fires only when the pattern
matches.

For `url-replace` the same `pattern` doubles as the substitution regex: every
match in the request target is replaced with the `replacement` template, which
may reference capture groups (`$1`, `$2`, …).

For **response**-phase rules, the gate is tested against the **originating
request's** path-and-query (response heads carry no path), so a request and its
response can be matched by the same pattern.

---

## Rewrite actions

Set on the rule set via `redirect` / `redirect-302` / `reject-200`. The latter
two synthesize the reply on the inner leg and **never open an upstream
connection**, so any rule lines in the same set never fire.

### `redirect` — transparent

```
redirect = upstream.example.com:8443
```

Dials the outer leg to `host[:port]` instead of the original destination and
rewrites the request authority (`Host` / `:authority`) to match. A nil port
keeps the original. The client still sees the **original** host on the leaf
certificate, so this is invisible to it. Rules still run normally.

### `redirect-302`

```
redirect-302 = www.example.com
```

Synthesizes a `302 Found` whose `Location` is
`https://<host>[:<port>]<original-request-target>` (the port is emitted only
when set and not 443).

### `reject-200`

```
reject-200   = gif
reject-200   = text Service unavailable
reject-200   = data QW55d2hlcmU=
content-type = application/json
```

Synthesizes a `200 OK`. The value is `<kind>` or `<kind> <content>`:

| Kind   | Content                | Default Content-Type            |
| ------ | ---------------------- | ------------------------------- |
| `text` | literal UTF-8 body     | `text/plain; charset=utf-8`     |
| `gif`  | ignored (1×1 GIF emitted) | `image/gif`                  |
| `data` | base64, decoded at send | `application/octet-stream`     |

Empty content yields a short non-empty default body (some apps treat an empty
200 as an error). `content-type` overrides the per-kind default.

---

## Rule operations

### `url-replace` (0) — request only

Regex substitution on the request target. Pattern is the match regex;
`replacement` is the template (`$1`…). Example — strip an API version prefix:

```
0, 0, ^/v1/(.*), /$1
```

### `header-add` (1)

Appends a header (does not replace an existing one of the same name):

```
0, 1, .*, X-Trace-Id, anywhere
```

### `header-delete` (2)

Removes every header with the given name (case-insensitive):

```
1, 2, .*, Set-Cookie
```

### `header-replace` (3)

Overwrites the value of every header with the given name (case-insensitive).
A header that is not present is left alone — it does **not** add it:

```
1, 3, .*, Cache-Control, no-store
```

### `script` (4) / `stream-script` (5)

JavaScript transforms. The field is base64-encoded UTF-8 source defining
`function process(ctx)`. See the next sections.

---

## Scripting: `script`

Use `script` whenever the rewrite needs the **whole message at once**: mutating
head fields (`ctx.url`, `ctx.method`, `ctx.status`, `ctx.headers`), rewriting a
body as a unit (JSON, protobuf, JWT, a regex over the full text), or
short-circuiting a request with `Anywhere.respond(...)`.

The rewriter buffers the body — auto-decoding `gzip` / `deflate` / `br` — runs
`process(ctx)` once, and re-emits with a corrected `Content-Length`. Because
nothing reaches the client until the body is complete, a `script` rule
**de-streams** the response; it is right for ordinary request/response APIs and
wrong for live streams (pointing one at a streaming media type still runs but
logs a warning recommending `stream-script`).

The body is held up to a **4 MiB** cap; larger Content-Length bodies fall back
to passthrough, and chunked bodies are truncated at the cap.

Authoring a script rule:

```
1, 4, ^/api/user, <base64 of the JS source>
```

To produce the base64 from a source file:

```bash
printf '%s' "$(cat process.js)" | base64
```

A rule whose base64 does not decode to syntactically valid UTF-8 JavaScript is
dropped at import; whether `process` is defined and callable is checked at
runtime (a missing/non-function `process` logs a warning and passes the message
through unchanged).

---

## Scripting: `stream-script`

Use `stream-script` when the response must keep flowing and must not stall:
Server-Sent Events (`text/event-stream`), chunked event / NDJSON feeds, gRPC or
HTTP/2 DATA streams, or any long-lived or very large body. `process(ctx)` runs
**once per frame** (HTTP/2 DATA frame or HTTP/1 chunked chunk) and the body is
**never buffered**, so bytes reach the client as they arrive.

The trade-off is a narrower contract:

- The head is **immutable** — `ctx.url` / `ctx.method` / `ctx.status` /
  `ctx.headers` are read-only (the head is already on the wire).
- **No HTTP-level decompression.** `ctx.body` is the raw frame payload.
- **No HTTP/1 `Content-Length` bodies** — the byte count is already committed
  and can't change mid-stream, so length-prefixed HTTP/1 bodies are skipped
  (chunked is required). HTTP/2 has no such restriction.

Per-frame context adds:

- `ctx.frame` — `{ index, end }`: the 0-based frame index and an `end` flag set
  on the final frame.
- `ctx.state` — a JS object persisted **across frames of the same stream**.
  Mutate it to accumulate state; it starts as `{}`.

Authoring is identical to `script` but with op `5`:

```
1, 5, ^/events, <base64>
```

---

## The `ctx` object

`process(ctx)` receives a mutable context object. Mutate fields in place or by
assignment; the runtime reads them back after the call.

| Field         | Type                      | Phase     | Mutable | Notes |
| ------------- | ------------------------- | --------- | ------- | ----- |
| `ctx.phase`   | `"request"` / `"response"`| both      | no      | Reassigning is a no-op. |
| `ctx.method`  | string or `null`          | both      | yes¹    | On response, the originating request's method. |
| `ctx.url`     | string or `null`          | both      | yes¹    | Absolute URL. On response, the originating request's URL. |
| `ctx.status`  | number or `null`          | response  | yes¹    | `null` on request. |
| `ctx.headers` | array of `[name, value]`  | both      | yes¹    | Pairs; preserves duplicates and order. |
| `ctx.body`    | `Uint8Array`              | both      | yes     | Backed by native memory; element-wise writes propagate. |

¹ Mutable in `script` only. In `stream-script` all head fields are read-only and
only `ctx.body` (plus `ctx.state`) is read back.

**Readback validation** (the wire must stay well-formed):

- `ctx.method` must be a valid HTTP token; otherwise it reverts with a warning.
- `ctx.url` must contain no spaces or control characters; otherwise it reverts.
- `ctx.status` must be a **number** in 100–599 (strings like `"200"` are
  rejected, not coerced); otherwise it reverts.
- `ctx.headers`: entries whose name isn't a valid token or whose value contains
  CR/LF/NUL are dropped with a warning. A non-array value leaves headers
  untouched (so a typo can't wipe them); set `ctx.headers = []` to intentionally
  clear all headers.
- An **uncaught exception** discards all mutations and emits the original
  message unchanged (use `try/catch`, or signal a directive before throwing, to
  keep partial work).

---

## The `Anywhere` API

A global `Anywhere` object exposes helpers. **Byte convention:** functions that
take "bytes" accept a `Uint8Array`, an `ArrayBuffer`, or a string (UTF-8
encoded); functions that return bytes return a `Uint8Array`.

### `Anywhere.codec`

Encoder/decoder pairs.

| Member                          | encode                       | decode                          |
| ------------------------------- | ---------------------------- | ------------------------------- |
| `Anywhere.codec.utf8`           | `encode(string) → Uint8Array`| `decode(bytes) → string`        |
| `Anywhere.codec.base64`         | `encode(bytes) → string`     | `decode(string) → Uint8Array`   |
| `Anywhere.codec.base64url`      | `encode(bytes) → string`     | `decode(string) → Uint8Array`   |
| `Anywhere.codec.hex`            | `encode(bytes) → string`     | `decode(string) → Uint8Array`   |
| `Anywhere.codec.gzip`           | `encode(bytes) → Uint8Array` | `decode(bytes) → Uint8Array`    |
| `Anywhere.codec.deflate`        | `encode(bytes) → Uint8Array` | `decode(bytes) → Uint8Array`    |
| `Anywhere.codec.brotli`         | `encode(bytes) → Uint8Array` | `decode(bytes) → Uint8Array`    |

`base64url` emits unpadded RFC 4648 §5; decode accepts either alphabet, padded
or not. The compression codecs are for payloads the pipeline doesn't already
handle (a gzipped blob nested in a JSON field, re-compressing a body for
`Anywhere.respond`, etc.) — the outer `Content-Encoding` is auto-decoded for
`script` rules already. `decode` throws on malformed input or output exceeding
the 4 MiB cap.

#### `Anywhere.codec.protobuf`

Schema-free protobuf wire-format codec.

- `decode(bytes) → [{ field, wire, value }]` — flat list preserving on-wire
  order (repeated fields appear as multiple entries).
- `encode(entries) → Uint8Array` — takes the same shape back.
- `encodeVarint(n) → Uint8Array`, `decodeVarint(bytes, offset?) → { value, consumed } | null`.

Value types by wire type: wire 0 (varint) is a **BigInt** (so 64-bit IDs round
trip); wire 1 / 5 (fixed64 / fixed32) are `Uint8Array` of length 8 / 4 (the
script picks the interpretation with a `DataView`); wire 2 (length-delimited) is
a `Uint8Array` — recurse with `decode` for nested messages. Group wire types
(3, 4) are rejected.

### `Anywhere.crypto`

Hashes and HMAC return raw digest bytes (`Uint8Array`); compose with
`Anywhere.codec.hex.encode` / `base64.encode` to format.

- `md5`, `sha1`, `sha256`, `sha384`, `sha512` — `(bytes) → Uint8Array`.
- `hmacSHA1`, `hmacSHA256`, `hmacSHA384`, `hmacSHA512` — `(key, data) → Uint8Array`.
- `randomBytes(n) → Uint8Array` — `n` in `[0, 65536]`; out-of-range / non-integer throws.
- `uuid() → string` — lowercased.
- `aesGCM.encrypt(spec) → { nonce, ciphertext, tag }` and
  `aesGCM.decrypt(spec) → Uint8Array`. The spec object:
  - `key`: `Uint8Array` of 16 / 24 / 32 bytes (AES-128/192/256).
  - `nonce`: 12-byte `Uint8Array`. On encrypt, omit it to have a fresh random
    nonce generated and returned in the result.
  - `plaintext` / `ciphertext`: bytes.
  - `tag`: 16-byte `Uint8Array` (decrypt only).
  - `aad`: optional additional authenticated data.
  - decrypt throws a catchable error on auth failure (wrong key, tampered data,
    mismatched AAD).

### `Anywhere.jwt`

JWT compact serialization (RFC 7519 / 7515). **Pure codec — no signature
verification or `alg` enforcement;** do that yourself with the crypto helpers.

- `decode(token) → { header, payload, signature, signingInput }`. `header` is
  parsed JSON; `payload` is parsed JSON or a `Uint8Array` for binary payloads;
  `signature` is bytes; `signingInput` is the `header.payload` octet string to
  recompute the signature over.
- `encode({ header, payload, signature? }) → string`. Object header/payload are
  `JSON.stringify`'d; bytes/string are used verbatim. `signature` is the raw
  signature bytes.

### `Anywhere.json`

Byte-oriented JSON editing: every method is **bytes-in / bytes-out** (first arg
is the body; returns a fresh `Uint8Array` of re-serialized compact JSON). The
contract is **total** — a body that isn't JSON, a path that doesn't resolve, a
type mismatch, or a non-serializable value all yield the body **unchanged**
rather than throwing.

- `add(body, path, value)` — upsert at a JSONPath.
- `replace(body, path, value)` — modify only if the member/index already exists.
- `replaceRecursive(body, key, value)` — replace every property named `key` at
  any depth (bare key name, not a path).
- `delete(body, path)` — remove the addressed member/element.
- `deleteRecursive(body, key)` — remove every property named `key` at any depth.
- `removeWhereKeyExists(body, path, key)` — at the array at `path`, drop objects
  containing `key`.
- `removeWhereFieldIn(body, path, field, values)` — at the array at `path`, drop
  objects whose `field` equals one of `values` (array or scalar).

Paths use JSONPath like `$.data.items[0].id` (leading `$` optional; dotted keys
and `[index]` / `["key"]` brackets). Recursive methods take a bare key name.

### `Anywhere.store`

Per-rule-set persistent key/value state, scoped by rule-set id.

- `get(key) → Uint8Array | undefined`
- `getString(key) → string | undefined`
- `set(key, value)` — value is bytes. **Throws** when the scope would exceed its
  1 MiB cap (catch it and shed entries with `delete`).
- `delete(key)`
- `keys() → [string]`

State is **in-memory only** (no disk persistence) and **shared across every
connection to the same rule set** — and across the rule set's `script` and
`stream-script` rules. It survives a rule-set edit and is cleared when the rule
set is removed or the extension restarts. Scripts must tolerate a missing key.

### `Anywhere.log`

`info(msg)`, `warning(msg)`, `error(msg)`, `debug(msg)` — written through the
shared logger, prefixed `[MITM][JS]`. `debug` is os.log-only.

### Control directives

- `Anywhere.done()` — commit the current `ctx` as the final result and skip any
  remaining rules. In `stream-script`, emit this frame's body and pass every
  subsequent frame through unchanged.
- `Anywhere.exit()` — discard this rule's mutations: revert to the message as it
  entered (buffered), or emit the original frame and stop scripting the stream.
- `Anywhere.respond({ status, headers, body })` — **request-phase only**. Drop
  the request before it reaches upstream and synthesize a response straight back
  to the client. All fields optional: `status` defaults to 200 (clamped to
  100–599), `headers` to `[]`, `body` to empty. Ignored (with a warning) on the
  response phase and in `stream-script`.

These set engine state and return; your code should `return` immediately after
calling one.

---

## Single-rule semantics

**At most one `script` and one `stream-script` fire per message**, by design
(it keeps the hot path lean and avoids state collisions). When several rules of
the same kind match a request's URL, the **last in rule order wins** — later
definitions overwrite earlier ones. When both a `script` and a `stream-script`
match, **`stream-script` wins**.

If you need composed behavior, consolidate the logic into a single
`process(ctx)` rather than splitting it across rules. Static operations
(`url-replace`, `header-*`) are not capped — all matching ones apply in order.

---

## Limits and safety

| Limit                              | Value        | Effect on exceed |
| ---------------------------------- | ------------ | ---------------- |
| Buffered body (`script`)           | 4 MiB        | Content-Length → passthrough; chunked → truncated |
| Per-scope `Anywhere.store`         | 1 MiB        | `set` throws `capacity exceeded` |
| `Anywhere.crypto.randomBytes`      | 64 KiB       | throws |
| Synthesized response body          | 4 MiB        | truncated |
| HTTP/1 request/response head       | 64 KiB       | stream downgrades to passthrough |
| Typed-array memory (all scripts)   | 16 MiB / 32 MiB | soft → GC hint; hard → empty `Uint8Array` returned |

Other safety properties:

- **Wire safety.** Header names, header values, methods, and request targets
  produced by scripts are validated; CR/LF/NUL and other smuggling vectors are
  rejected so a script can't split the wire framing.
- **No watchdog.** There is no way to preempt a running script. A pathological
  script blocks the shared serial queue and stalls the whole tunnel. Keep loops
  and regexes bounded.
- **Failure is safe-by-default.** A compile failure, a missing `process`, or an
  uncaught throw passes the original message through unchanged.

---

## Worked examples

### Inject a request header on API paths

```
name     = Add Trace
hostname = api.example.com
0, 1, ^/v2/, X-Trace-Id, anywhere
```

### Redirect an old path (request-phase URL rewrite)

```
name     = Path Migration
hostname = example.com
0, 0, ^/old/(.*)$, /new/$1
```

### Block a host with a 1×1 GIF

```
name       = Block Tracker
hostname   = tracker.example.com
reject-200 = gif
```

### Edit a JSON response body (`script`)

Source (`flag.js`):

```js
function process(ctx) {
  try {
    const obj = JSON.parse(Anywhere.codec.utf8.decode(ctx.body));
    obj.vip = true;
    ctx.body = Anywhere.codec.utf8.encode(JSON.stringify(obj));
  } catch (e) {
    Anywhere.log.warning("not JSON: " + e);
  }
}
```

Encode and author:

```bash
printf '%s' "$(cat flag.js)" | base64
# → eyAuLi4gfQ==   (example)
```

```
name     = VIP Flag
hostname = api.example.com
1, 4, ^/v1/profile, eyAuLi4gfQ==
```

### Mock an endpoint without hitting upstream (`Anywhere.respond`)

```js
function process(ctx) {
  Anywhere.respond({
    status: 200,
    headers: [["Content-Type", "application/json"]],
    body: '{"enabled":true}'
  });
}
```

```
0, 4, ^/api/feature-flags, <base64>
```

### Redact tokens in a live SSE stream (`stream-script`)

```js
function process(ctx) {
  let text = Anywhere.codec.utf8.decode(ctx.body);
  text = text.replace(/Bearer [A-Za-z0-9._-]+/g, "Bearer ***");
  ctx.body = Anywhere.codec.utf8.encode(text);
}
```

```
name     = Redact SSE
hostname = api.example.com
1, 5, ^/events, <base64>
```

### Count requests across connections (`Anywhere.store`)

```js
function process(ctx) {
  const prev = Anywhere.store.getString("count");
  const next = (prev ? parseInt(prev, 10) : 0) + 1;
  try { Anywhere.store.set("count", next.toString()); }
  catch (e) { Anywhere.log.warning("store full: " + e); }
  ctx.headers.push(["X-Request-Count", next.toString()]);
}
```

```
0, 4, .*, <base64>
```

---

## Behavior reference

- **Content-Encoding.** For `script` rules the body is decompressed before the
  script runs and re-emitted as identity with `Content-Encoding` dropped and a
  fresh `Content-Length`. `stream-script` rules see raw, still-compressed frames.
- **HEAD responses.** A response to `HEAD` never carries a body; its framing
  headers are preserved and a script that writes `ctx.body` has that write
  dropped on the wire.
- **Interim 1xx responses.** `100 Continue`, `103 Early Hints`, etc. are not the
  final response; scripts run only on the final response.
- **Pipelining order.** A request-phase `Anywhere.respond` on a pipelined
  connection is held until the in-flight response ahead of it finishes, so the
  client's request/response ordering is preserved.
- **Streaming media + `script`.** A buffered `script` on `text/event-stream`,
  `multipart/x-mixed-replace`, NDJSON, and similar de-streams the body; the rule
  still runs but logs a warning recommending `stream-script`.
- **Fail-closed URL gate.** If the request target can't be determined, every
  rule's URL gate fails closed (the rule is skipped) rather than firing blind.
- **Regex scope.** Patterns are matched against the path-and-query only, never
  the host (use `hostname`), method, scheme, or HTTP version.
