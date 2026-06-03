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
   **inner** TLS handshake with the client, negotiating ALPN from the client's
   own offer.
2. Reads the first request and applies the matching rules. A `rewrite` rule can
   answer on the inner leg (302 / reject) — no upstream at all — or change the
   destination host.
3. **Defers** opening the **outer** leg until the destination is known, then
   dials it (the rewritten host when set, otherwise the original) and runs its
   own handshake there, following the inner ALPN.
4. Decrypts each direction, runs the matching rules, and re-encrypts to the
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
rule's `url-pattern` regex gates **which requests** within those hosts it acts on.
A request that matches no rule is forwarded unchanged (its body is streamed
through without buffering), so the marginal cost of an intercepted-but-unrewritten
request is small — but interception itself (the extra TLS handshakes) is not
free. Scope `hostname` as tightly as you can.

> **Performance note.** All script execution across all connections runs on a
> single serial queue, and one JavaScript runtime is shared by every connection
> to the same rule set. A script that loops forever, recurses without bound, or
> triggers catastrophic regex backtracking will wedge **every** tunneled flow,
> not just its own connection — CPU-bound execution can't be preempted (the
> idle-async watchdog under [Limits](#limits-and-safety) doesn't cover a running
> loop). Keep scripts bounded. (Awaiting an [`Anywhere.http`](#anywherehttp) fetch is the
> exception: while it is in flight the connection is parked but the shared
> runtime is **free**, so other connections' scripts keep running — only
> CPU-bound work monopolizes the runtime.)

---

## Rule sets

A rule set is the unit of configuration:

| Field            | Meaning                                                                 |
| ---------------- | ----------------------------------------------------------------------- |
| `name`           | Display name. Required, non-empty.                                      |
| `domainSuffixes` | Hosts to intercept, matched by **suffix**. `example.com` covers `www.example.com`. No wildcards. |
| `rules`          | Ordered list of rewrite rules. Redirect / reject / host-rewrite are per-rule via the [`rewrite` operation](#rewrite-0--request-only). |

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

# request: transparently rewrite the whole URL to a new host (dials it + rewrites Host)
0, 0, ^https://example\.com/old, 0, https://upstream.example.com/new
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

Unrecognized keys are ignored. Redirect / reject / host-rewrite are configured
per-rule via the [`rewrite` operation](#rewrite-0--request-only), not as
set-level headers.

### Rule lines

Shape:

```
<phase>, <operation>, <field1> [, <field2> [, <field3>]]
```

- **Phase**: `0` = request, `1` = response.
- **Operation** and its trailing fields:

| ID    | Operation        | Phase        | Fields                                       |
| ----- | ---------------- | ------------ | -------------------------------------------- |
| `0`   | `rewrite`        | request only | `url-pattern`, `sub-mode`, `<sub-mode args>` |
| `1`   | `header-add`     | both         | `url-pattern`, `name`, `value` |
| `2`   | `header-delete`  | both         | `url-pattern`, `name`       |
| `3`   | `header-replace` | both         | `url-pattern`, `name`, `value` |
| `4`   | `body-replace`   | both         | `url-pattern`, `search`, `replacement` |
| `5`   | `body-json`      | both         | `url-pattern`, `action`, `<action args>`  |
| `100` | `script`         | both         | `url-pattern`, `base64`     |
| `101` | `stream-script`  | both         | `url-pattern`, `base64`     |

Scripting operations use a separate `100`+ id range, set apart from the native
edits.

`rewrite` (op `0`) is always request-phase regardless of the phase column. Its
second field is a numeric **sub-mode**; the remaining fields depend on it — see
[`rewrite` (0)](#rewrite-0--request-only). A rule whose field count does not
match, or whose `url-pattern` is empty or fails to compile as a regex, is
dropped. For `body-replace` the `search` field must also be a valid regex; for
`body-json` the trailing fields depend on `action` — see
[`body-json` (5)](#body-json-5).

### Fields and quoting

Fields are separated by `,`. Whitespace around an unquoted field is trimmed. A
field beginning with `"` is read until the matching `"`, and `""` inside a
quoted field is a literal `"`. Quote any field that contains a comma or
significant leading/trailing whitespace:

```
0, 1, ^/, X-Note, "value, with a comma"
```

### The `url-pattern`

Every rule leads with a `url-pattern`: an `NSRegularExpression` (default Unicode
semantics) tested against the **whole request URL** — e.g.
`https://api.example.com/login?token=abc`. It is purely a gate (the replace
operations carry their own `search` regex); it does **not** see the method or
HTTP version. Use `.*` to match every request, or anchor on the scheme/host
(`^https://api\.example\.com/`) to scope by origin. The rule fires only when the
URL pattern matches. The **host** is matched case-insensitively — it is
lowercased before the test, so write hosts in lowercase — while the path and
query keep their case.

For **response**-phase rules, the gate is tested against the **originating
request's** URL (response heads carry no path), so a request and its response
can be matched by the same URL pattern.

---

## Rule operations

### `rewrite` (0) — request only

The unified rewrite operation. Its second field is a numeric **sub-mode**; the
remaining field(s) depend on it. When the `url-pattern` gate matches, the
**first** matching `rewrite` rule wins.

| Sub-mode | Name             | Args          | Effect |
| -------- | ---------------- | ------------- | ------ |
| `0`      | transparent      | `<full-url>`  | Replace the whole request URL with `<full-url>` (literal). The request-target becomes the replacement's path+query; the outer leg is dialed to the replacement **host** and `Host` / `:authority` is rewritten to match it (a no-op in effect when the host is unchanged). The client still sees the **original** host on the leaf certificate. |
| `1`      | 302 redirect     | `<full-url>`  | Synthesize a `302 Found` whose `Location` is `<full-url>`. No upstream dial. |
| `2`      | reject 200 text  | `[<content>]` | Synthesize a `200 OK` with a `text/plain; charset=utf-8` body. Empty `<content>` → a short default line. No upstream dial. |
| `3`      | reject 200 gif   | *(none)*      | Synthesize a `200 OK` carrying the canned 1×1 `image/gif`. No upstream dial. |
| `4`      | reject 200 data  | `[<base64>]`  | Synthesize a `200 OK` with an `application/octet-stream` body decoded from `<base64>`. Empty → a default payload. No upstream dial. |

For sub-modes `0` and `1` the URL must be a full absolute URL with a host
(`https://host[:port]/path?query`); a URL with no path uses `/`. The replacement
is **literal** — there is no `$1` capture expansion, so every URL matching the
`url-pattern` maps to the one exact replacement URL. Author the `url-pattern`
specifically.

Because a transparent rewrite can change the dial target, the upstream dial is
**deferred**: the inner TLS handshake completes first (negotiating ALPN from the
client), the first request is read and rewritten, and only then is the upstream
dialed — to the rewritten host when one is set, otherwise the original. A `302` /
reject sub-mode answers on the inner leg and never dials. (Consequence: the
inner ALPN is client-driven; if the client negotiates `h2` but the upstream
can't, the connection is torn down and the client retries — typically
downgrading. The connection's upstream is fixed by the first request — for both
HTTP/1.1 and HTTP/2 — so a later request on the same connection whose transparent
rewrite resolves a *different* host/port can't be reached on the already-dialed
leg; rather than misroute it, the connection is torn down and the client retries
it on a fresh connection.)

Examples — transparently send one host's traffic to another, redirect with a
`302`, and block an ad path with a tiny GIF:

```
0, 0, ^https://a\.example\.com/, 0, https://b.example.com/
0, 0, ^https://old\.example\.com/page, 1, https://new.example.com/page
0, 0, .*/ads/, 3
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

### `body-replace` (4)

Regex find-and-replace over the text body in **native code**, without writing
any JavaScript. Its fields are `url-pattern` (the URL gate), a `search` regex,
and a `replacement`:

```
1, 4, .*, http://, https://
1, 4, .*, (?i)debug=true, debug=false
```

`search` is a Swift `Regex` (default Unicode semantics) matched against the
**whole decompressed body**, and every match is swapped for the **literal**
`replacement` (no `$1` capture expansion — the substitution runs through
`String.replacing`); an **empty** replacement deletes every match. A rule whose
`search` is empty or won't compile as a regex is dropped. Per the
[Fields and quoting](#fields-and-quoting) rules, quote either field when it
contains a comma or begins with `"`, doubling any inner `"` — so searching for
the literal text `"price":` is written as the field `"""price"":"`.

Like `script`, `body-replace` is a **buffered body transform**: the rewriter
accumulates the body (auto-decoding `gzip` / `deflate` / `br`, up to the same
**4 MiB** cap), edits it, and re-emits with a corrected `Content-Length`. The
contract is **total** — a body that isn't valid UTF-8, or a `search` that
matches nothing, leaves the body **unchanged**. Unlike `script`, **every**
matching `body-replace` rule fires, in rule order, so replacements compose.

When several body transforms match the same message they run in a fixed order:
`body-json` edits first, then `body-replace`, then a `script` (so the script
sees the fully-edited body).

### `body-json` (5)

Declarative JSON body editing in **native code** — the same edits as the
[`Anywhere.json`](#anywherejson) script API, without writing any JavaScript. One
rule carries one edit; its fields are `url-pattern`, an `action` token, and the
action's own fields:

| `action`                  | Trailing fields    | Effect                                                            |
| ------------------------- | ------------------ | ----------------------------------------------------------------- |
| `add`                     | `path`, `value`    | Upsert at `path` (create or overwrite; append at array end).      |
| `replace`                 | `path`, `value`    | Overwrite at `path` only if the member/index already exists.      |
| `delete`                  | `path`             | Remove the member/element at `path`.                              |
| `replace-recursive`       | `key`, `value`     | Overwrite every property named `key` at any depth.                |
| `delete-recursive`        | `key`              | Remove every property named `key` at any depth.                   |
| `remove-where-key-exists` | `path`, `key`      | At the array at `path`, drop objects containing `key`.            |
| `remove-where-field-in`   | `path`, `field`, `values` | At the array at `path`, drop objects whose `field` ∈ `values`. |

`path` is a JSONPath like `$.data.items[0].id` (leading `$` optional; dotted
keys and `[index]` / `["key"]` brackets). `value` / `values` are written as JSON
literals (`true`, `42`, `"text"`, `{"a":1}`, `["x","y"]`); a string that **isn't**
valid JSON is taken literally, so `value = Anywhere` means the string
`"Anywhere"`. Action tokens are case-insensitive and also accept the camelCase
spelling (`replaceRecursive`). A rule whose `path` can't be parsed is dropped.

Like `script`, `body-json` is a **buffered body transform**: the rewriter
accumulates the body (auto-decoding `gzip` / `deflate` / `br`, up to the same
**4 MiB** cap), edits it, and re-emits with a corrected `Content-Length`. The
contract is **total** — a body that isn't JSON, a path that doesn't resolve, or
a non-serializable result leaves the body **unchanged** (byte-for-byte; a rule
that matches but changes nothing never reshapes the body). A *successful* edit,
though, re-serializes the whole document, so a JSON integer beyond 2^53 anywhere
in it can lose precision. Unlike `script`,
**every** matching `body-json` rule fires, in rule order, so edits compose; when
a `script` rule also matches the same message, the JSON edits run **first** and
the script sees the already-edited body (after any `body-replace` edits).

Examples — flip a flag, drop a field, and filter an array on the response:

```
1, 5, ^/api/user, add, $.user.vip, true
1, 5, ^/api/user, delete, $.user.password
1, 5, ^/api/feed, remove-where-field-in, $.items, status, expired
```

A `value` / `values` that contains a comma — a multi-element array or a
multi-key object — has to be one quoted CSV field with each inner `"` doubled,
since the field separator is also `,`. So matching several values is either one
quoted array or one rule per value (they compose):

```
1, 5, ^/api/feed, remove-where-field-in, $.items, status, "[""expired"",""deleted""]"
1, 5, ^/api/profile, add, $.meta, "{""beta"":true,""tier"":2}"
```

Set a string value (CSV-quote it when it contains a comma) and redact a token
wherever it appears:

```
1, 5, ^/api/profile, replace, $.tier, "gold, platinum"
1, 5, .*, replace-recursive, access_token, "***"
```

### `script` (100) / `stream-script` (101)

JavaScript transforms. The field is base64-encoded UTF-8 source defining
`function process(ctx)`. See the next sections.

---

## Scripting: `script`

Use `script` whenever the rewrite needs the **whole message at once**: rewriting
a body as a unit (JSON, protobuf, JWT, a regex over the full text) or
short-circuiting a request with `Anywhere.respond(...)`. The head is read-only —
URL and header edits have dedicated rules (`rewrite`, `header-add` /
`header-delete` / `header-replace`), and `ctx.method` / `ctx.status` aren't
script-writable either — so a `script` rule's job is the body (plus the
`Anywhere.done` / `exit` / `respond` control directives).

The rewriter buffers the body — auto-decoding `gzip` / `deflate` / `br` — runs
`process(ctx)` once, and re-emits with a corrected `Content-Length`. Because
nothing reaches the client until the body is complete, a `script` rule
**de-streams** the response; it is right for ordinary request/response APIs and
wrong for live streams (pointing one at a streaming media type still runs but
logs a warning recommending `stream-script`).

`process` may be declared **`async`** and `await` an
[`Anywhere.http`](#anywherehttp) request mid-rewrite; the rewriter waits for the
returned Promise to settle before reading `ctx.body` back, so the connection
parks while the fetch is in flight (the shared script runtime stays free for
other connections). This is the one case where a `script` does more than
transform the bytes already in hand. `stream-script` has no such facility —
`Anywhere.http` is unavailable there.

The body is held up to a **4 MiB** cap; larger Content-Length bodies fall back
to passthrough, and chunked bodies are truncated at the cap.

Authoring a script rule:

```
1, 100, ^/api/user, <base64 of the JS source>
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

Authoring is identical to `script` but with op `101`:

```
1, 101, ^/events, <base64>
```

---

## The `ctx` object

`process(ctx)` receives a context object. Scripts read its fields freely, but the
only one read back is `ctx.body` — replace it or mutate it in place.

| Field         | Type                      | Phase     | Mutable | Notes |
| ------------- | ------------------------- | --------- | ------- | ----- |
| `ctx.phase`   | `"request"` / `"response"`| both      | no      | Reassigning is a no-op. |
| `ctx.method`  | string or `null`          | both      | no      | Read-only. On response, the originating request's method. |
| `ctx.url`     | string or `null`          | both      | no      | Read-only — use a `rewrite` rule. Absolute URL; on response, the originating request's URL. |
| `ctx.status`  | number or `null`          | response  | no      | Read-only. `null` on request. |
| `ctx.headers` | array of `[name, value]`  | both      | no      | Read-only — use `header-add` / `header-delete` / `header-replace` rules. Pairs; preserves duplicates and order. |
| `ctx.body`    | `Uint8Array`              | both      | yes     | Backed by native memory; element-wise writes propagate. |

Only `ctx.body` is mutable — in both `script` and `stream-script` (the latter
also reads back `ctx.state`). Every head field (`method`, `url`, `status`,
`headers`, `phase`) is **read-only**: assigning it is ignored on readback. URL
and header edits have dedicated rule operations — `rewrite` and `header-add`
/ `header-delete` / `header-replace` — so scripts don't duplicate them; `method`
and `status` have no script-side write at all. Keeping the head read-only also
lets the HTTP/2 path open a request stream in stream-ID order without waiting on
the script.

**Readback** (the wire stays well-formed by construction):

- Only `ctx.body` is adopted; every head-field assignment is ignored, so a script
  can't inject a malformed request line, status, or header.
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
(byte-for-byte) rather than throwing. A *successful* edit re-serializes the whole
document, so a JSON integer beyond 2^53 anywhere in it can lose precision.

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

> For these same edits **without** a script — declared as a rule and run in
> native code — use the [`body-json` (5)](#body-json-5) operation. A `script` is
> only needed when the edit must be conditional, computed, or combined with
> `Anywhere.respond` / control directives.

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

### `Anywhere.http`

Make an outbound HTTP(S) request from a script and `await` the response — to
fetch a token, look up data to splice into the body, or call a sidecar API
mid-rewrite. Available in **`script` rules only** (not `stream-script`), and the
result must be `await`ed, so declare `process` as `async`:

```js
async function process(ctx) {
  const r = await Anywhere.http.get("https://api.example.com/token");
  if (r.status === 200) {
    const token = Anywhere.codec.utf8.decode(r.body).trim();
    ctx.body = Anywhere.codec.utf8.encode(JSON.stringify({ token }));
  }
}
```

- `get(url[, options]) → Promise<Response>`
- `post(url[, options]) → Promise<Response>`
- `request(options) → Promise<Response>` — the all-options form; `url` is a
  field of `options`.

**Response**: `{ status, headers, body, url }` — `status` is the numeric HTTP
status; `headers` is `[[name, value], …]` like `ctx.headers` (URLSession
combines duplicate field names, and header order is not preserved); `body` is a
`Uint8Array`; `url` is the final URL after any followed redirects. The Promise
**rejects** with an `Error` on a transport failure, a timeout, a cap breach, or
a non-HTTP response — wrap the `await` in `try/catch` to handle it. An *uncaught*
rejection reverts the message unchanged, exactly like any other uncaught throw.

**`options`**:

| Field      | Default                 | Meaning |
| ---------- | ----------------------- | ------- |
| `method`   | `"GET"` / `"POST"`      | HTTP method. |
| `headers`  | none                    | `[[name, value], …]` or a `{ name: value }` object. Entries with an invalid field-name, a CR/LF/NUL value, or a forbidden name (`Host`, `Content-Length`, `Connection`, `Transfer-Encoding`, and other framing / hop-by-hop headers) are dropped. |
| `body`     | empty                   | Request body: `Uint8Array`, `ArrayBuffer`, or string. |
| `timeout`  | 10 000 ms               | Per-request timeout in milliseconds, clamped to 30 000. |
| `redirect` | `"follow"`              | `"follow"` chases 3xx; `"manual"` returns the 3xx response as-is. |
| `insecure` | global *Allow Insecure* | `true` accepts self-signed server certificates. |

**Execution model.** A script that `await`s a fetch is *parked* — its
connection waits for the response — but the shared script runtime is **not**
blocked: other connections' scripts keep running while this one is in flight
(unlike a CPU-bound loop, which still monopolizes the runtime — see the
[performance note](#how-it-works)). The request leaves as the extension's own
traffic and is **not** itself intercepted by the MITM, so a script may safely
call a host the rule set also intercepts without looping.

Because other invocations run during an `await`, another connection running the
**same** rule set can mutate shared `globalThis` state between your `await` and
its resumption — don't assume exclusive access across a suspension. Per-message
state lives on `ctx`; cross-connection state belongs in
[`Anywhere.store`](#anywherestore), whose sharing semantics are already explicit.

> **Security.** `Anywhere.http` refuses requests to `localhost`, `*.local`, and
> IP literals in loopback / link-local (incl. the cloud-metadata address) /
> private / ULA ranges, and re-checks every redirect hop — so a script can't
> pivot to internal services by literal address. A hostname that *resolves* to
> an internal address is **not** caught (resolution happens in URLSession), and
> a script can still exfiltrate data it has read to any public host. Author and
> import rule sets only from sources you trust.

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
(`rewrite`, `header-*`) are not capped — all matching ones apply in order.

---

## Limits and safety

| Limit                              | Value        | Effect on exceed |
| ---------------------------------- | ------------ | ---------------- |
| Buffered body (`script`)           | 4 MiB        | Content-Length → passthrough; chunked → truncated |
| Per-scope `Anywhere.store`         | 1 MiB        | `set` throws `capacity exceeded` |
| `Anywhere.crypto.randomBytes`      | 64 KiB       | throws |
| Synthesized response body          | 4 MiB        | truncated |
| `Anywhere.http` timeout            | 10 s default / 30 s max | Promise rejects |
| `Anywhere.http` per script         | 4 concurrent / 16 total | Promise rejects |
| `Anywhere.http` concurrent requests (all scripts) | 32 | Promise rejects |
| `Anywhere.http` in-flight body bytes (all scripts) | 16 MiB | Promise rejects |
| `Anywhere.http` response body      | 4 MiB        | Promise rejects |
| HTTP/1 request/response head       | 64 KiB       | stream downgrades to passthrough |
| Typed-array memory (all scripts)   | 16 MiB / 32 MiB | soft → GC hint; hard → empty `Uint8Array` returned |
| Idle suspended `async` script      | ~60 s no progress | reverted to original, released |

Other safety properties:

- **Wire safety.** Header names, header values, methods, and request targets
  produced by scripts are validated; CR/LF/NUL and other smuggling vectors are
  rejected so a script can't split the wire framing.
- **Watchdog (idle async only).** A suspended `async` script that stops making
  progress — a never-settling Promise or an abandoned `await` — is reverted to
  the original message and released after an idle stretch longer than the
  maximum per-fetch timeout (~60 s), so it can't park its connection forever. A
  **CPU-bound** loop is still *not* preemptible: it wedges its own connection
  and monopolizes the shared script runtime until it returns, so keep loops and
  regexes bounded. (Awaiting an [`Anywhere.http`](#anywherehttp) fetch does not
  monopolize the runtime — see its execution-model note.)
- **Outbound requests.** [`Anywhere.http`](#anywherehttp) lets a script make the
  extension issue HTTP(S) requests — an exfiltration surface bounded by the
  per-script and global caps above. Destinations are restricted: loopback,
  link-local (incl. cloud-metadata), private, and ULA addresses are refused by
  literal address (a name resolving to an internal IP is not caught). A script
  can still reach any public host, so only run rule sets from sources you trust.
- **Failure is safe-by-default.** A compile failure, a missing `process`, or an
  uncaught throw — including an unhandled `Anywhere.http` rejection — passes the
  original message through unchanged.

---

## Worked examples

### Inject a request header on API paths

```
name     = Add Trace
hostname = api.example.com
0, 1, ^/v2/, X-Trace-Id, anywhere
```

### Redirect an old path (transparent URL rewrite)

```
name     = Path Migration
hostname = example.com
0, 0, ^https://example\.com/old/, 0, https://example.com/new/
```

### Block a host with a 1×1 GIF

```
name     = Block Tracker
hostname = tracker.example.com
0, 0, .*, 3
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
1, 100, ^/v1/profile, eyAuLi4gfQ==
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
0, 100, ^/api/feature-flags, <base64>
```

### Enrich a response with a second request (`Anywhere.http`)

`process` is `async` so it can `await` a fetch. Here it pulls a profile from a
sidecar API and merges it into the JSON response body, leaving the body
unchanged if anything fails.

```js
async function process(ctx) {
  try {
    const obj = JSON.parse(Anywhere.codec.utf8.decode(ctx.body));
    const r = await Anywhere.http.get("https://sidecar.example.com/profile/" + obj.id, {
      headers: [["accept", "application/json"]],
      timeout: 3000
    });
    if (r.status === 200) {
      obj.profile = JSON.parse(Anywhere.codec.utf8.decode(r.body));
      ctx.body = Anywhere.codec.utf8.encode(JSON.stringify(obj));
    }
  } catch (e) {
    Anywhere.log.warning("enrich failed: " + e); // body left unchanged
  }
}
```

```
1, 100, ^/api/user, <base64>
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
1, 101, ^/events, <base64>
```

### Count requests across connections (`Anywhere.store`)

```js
function process(ctx) {
  const prev = Anywhere.store.getString("count");
  const next = (prev ? parseInt(prev, 10) : 0) + 1;
  try { Anywhere.store.set("count", next.toString()); }
  catch (e) { Anywhere.log.warning("store full: " + e); }
  Anywhere.log.info("request #" + next + " to " + ctx.url);
}
```

```
0, 100, .*, <base64>
```

> A script can't add the count as a request header (`ctx.headers` is read-only);
> to put a fixed header on the wire use a `header-add` rule instead.

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
- **Fail-closed URL gate.** If the request URL can't be determined, every
  rule's URL gate fails closed (the rule is skipped) rather than firing blind.
- **Regex scope.** URL patterns are matched against the whole request URL
  (`https://host/path?query`), so they can scope by scheme and host as well as
  path; they never see the method or HTTP version. The set's `hostname` suffixes
  still gate the host first.
