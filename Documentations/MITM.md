# MITM Rewrite System — Developer Guide

Anywhere can intercept the HTTP traffic of selected domains — terminating TLS
for HTTPS, or reading plain HTTP directly — then inspect, rewrite, and forward
it upstream: a man-in-the-middle on traffic you control. This guide covers
authoring rules and scripts. It assumes familiarity with HTTP, regular
expressions, and JavaScript, and does not cover the settings UI.

> **Prerequisite (HTTPS only).** Intercepting **HTTPS** works only for clients
> that trust Anywhere's generated root CA — install and trust it first. Apps
> that pin certificates cannot be intercepted (their handshake to the minted
> leaf fails); this is expected. Plain **HTTP** carries no certificate and needs
> no CA trust.

## Contents

- [How it works](#how-it-works)
- [Rule sets](#rule-sets)
- [The import format](#the-import-format)
- [Rule operations](#rule-operations)
- [Scripting: `script`](#scripting-script)
- [Scripting: `stream-script`](#scripting-stream-script)
- [Execution model](#execution-model)
- [The `ctx` object](#the-ctx-object)
- [The `Anywhere` API](#the-anywhere-api)
- [Subscriptions](#subscriptions)
- [Single-rule semantics](#single-rule-semantics)
- [Limits and safety](#limits-and-safety)
- [Worked examples](#worked-examples)
- [Behavior reference](#behavior-reference)
- [Code map](#code-map)

---

## How it works

Interception is gated on the host. **HTTPS** is intercepted when the TLS
ClientHello **SNI** matches a rule set's suffixes; **plain HTTP** is intercepted
when the first request's host matches — the fake-IP-resolved domain when the
connection was routed by fake IP, otherwise the request's authority
(absolute-form target, or the `Host` header). MITM must be enabled by the master
toggle, and the matching rule set must be enabled.

An intercepted **HTTPS** connection is handled in four steps:

1. Mint a leaf certificate for the requested host (cached, per host) and
   complete the **inner** TLS handshake with the client, negotiating ALPN from
   the client's own offer (intersected with `h2` / `http/1.1`).
2. Read the first request and apply the matching rules. A `rewrite` rule can
   answer on the inner leg (302 / reject — no upstream) or change the
   destination host.
3. **Defer** opening the **outer** leg until the destination is known, then dial
   it — the rewritten host when set, otherwise the original — and run its own TLS
   handshake. An HTTP/1.1 client goes to an HTTP/1.1 upstream; an HTTP/2 client
   is **bridged** to whatever the upstream speaks: HTTP/2 directly, or HTTP/1.1
   with on-the-fly translation (one short-lived upstream connection per request
   stream).
4. Decrypt each direction, run the matching rules, and re-encrypt to the
   opposite leg.

**Plain HTTP** follows the same pipeline without certificates or handshakes: the
upstream is dialed in cleartext, and `ctx.url` carries an `http://` scheme.
Cleartext is always treated as HTTP/1.1 — h2c is not intercepted (prior-knowledge
h2c is forwarded untouched; an `Upgrade`-based `101` becomes an opaque tunnel,
see [Behavior reference](#behavior-reference)).

Traffic is processed in two **phases**:

- **Request** (`httpRequest`) — client→server, before the request leaves for
  upstream.
- **Response** (`httpResponse`) — server→client, before the response reaches the
  client.

Both HTTP/1.1 and HTTP/2 are supported. For HTTP/2 the rewriter works on decoded
header lists and whole-body buffers; for HTTP/1.1 it drives a byte-level framing
state machine. The rule model is identical either way.

A rule set's `hostname` suffixes gate **which hosts** are intercepted; each
rule's `url-pattern` gates **which requests** within those hosts it acts on. A
request that matches no rule is forwarded unchanged (its body streamed through
unbuffered), so an intercepted-but-unrewritten request is cheap — but
interception itself (the extra TLS handshakes) is not. Scope `hostname` as
tightly as you can.

> **Performance note.** All script execution runs on a **single serial queue**,
> and a **single JavaScript VM is shared process-wide** — across every rule set
> and connection. A script that loops forever, recurses without bound, or
> triggers catastrophic regex backtracking stalls **every** other script, not
> just its own connection: CPU-bound execution can't be preempted. A watchdog
> crashes and relaunches the extension after a ~30 s synchronous span, so a
> runaway self-recovers rather than wedging for the process's life, but keep
> scripts bounded. Awaiting an [`Anywhere.http`](#anywherehttp) fetch is the
> exception — the connection parks while the shared runtime stays **free** for
> other scripts; only CPU-bound work monopolizes it.

---

## Rule sets

A rule set is the unit of configuration:

| Field            | Meaning |
| ---------------- | ------- |
| `name`           | Display name. |
| `domainSuffixes` | Hosts to intercept, matched by **suffix**. `example.com` covers `www.example.com`. No wildcards. |
| `enabled`        | Per-set toggle; a disabled set is skipped but keeps its data. |
| `rules`          | Ordered list of rewrite rules. Redirect / reject / host-rewrite are per-rule via the [`rewrite` operation](#rewrite-0--request-only). |
| `parameters`     | Optional user-editable values, exposed read-only to scripts via [`Anywhere.params`](#anywhereparams). See [Parameter lines](#parameter-lines). |

Suffix matching is **most-specific-wins**: with both `example.com` and
`api.example.com` configured, a request to `api.example.com` uses only the
latter. Each connection resolves to exactly one rule set, once, at connection
start — a transparent rewrite to another host does not re-resolve it. Duplicate
suffixes across sets are last-writer-wins.

Rule sets are created three ways: built rule-by-rule in the app, **imported**
from a `.amrs` file, or **subscribed** to a `.amrs` URL (see
[Subscriptions](#subscriptions)). The `.amrs` text format below is the
interchange and authoring format; sets are stored internally as JSON and
exported to the Network Extension as a compact binary. A set holds at most
**10,000 rules** and **256 parameters**.

---

## The import format

A rule set is a sequence of **header lines**, **rule lines**, and (optionally)
**parameter lines**, in any order. Blank lines are ignored; lines beginning with
`#` or `//` are comments. Parsing never hard-fails — a line that is neither a
recognized header nor a valid rule/parameter is dropped silently, so a partially
valid file still imports what it can.

Lines belong to a **section** introduced by a bracketed header. Sections are
optional and a file starts in `[Rule]`. `[Parameter]` begins the parameter
section; an unrecognized bracket header makes following lines ignored until the
next section.

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
otherwise kept verbatim. Header lines are recognized in any section.

| Key          | Meaning |
| ------------ | ------- |
| `name`       | Display name. |
| `hostname`   | Comma-separated domain suffixes. |
| `icon-light` | Base64-encoded image bytes for the icon shown in light appearance. |
| `icon-dark`  | Base64-encoded image bytes for the icon shown in dark appearance. |

Lines with unrecognized keys are dropped. Redirect / reject / host-rewrite are
configured per-rule via the [`rewrite` operation](#rewrite-0--request-only), not
as headers. An icon that is not valid base64 or decodes to more than **256 KB**
is dropped; when the current appearance has no icon, the other variant is used.

### Rule lines

Shape:

```
<phase>, <operation>, <field1> [, <field2> [, <field3>]]
```

- **Phase**: `0` = request, `1` = response.
- **Operation** and its trailing fields:

| ID    | Operation        | Phase        | Fields |
| ----- | ---------------- | ------------ | ------ |
| `0`   | `rewrite`        | request only | `url-pattern`, `sub-mode`, `<sub-mode args>` |
| `1`   | `header-add`     | both         | `url-pattern`, `name`, `value` |
| `2`   | `header-delete`  | both         | `url-pattern`, `name` |
| `3`   | `header-replace` | both         | `url-pattern`, `name`, `value` |
| `4`   | `body-replace`   | both         | `url-pattern`, `search`, `replacement` |
| `5`   | `body-json`      | both         | `url-pattern`, `action`, `<action args>` |
| `100` | `script`         | both         | `url-pattern`, `base64` |
| `101` | `stream-script`  | both         | `url-pattern`, `base64` |

Scripting uses a separate `100`+ id range. `rewrite` (op `0`) is always
request-phase regardless of the phase column; its second field is a numeric
**sub-mode** and the rest depend on it — see
[`rewrite` (0)](#rewrite-0--request-only). A rule whose field count does not
match, or whose `url-pattern` is empty or won't compile as a regex, is dropped.
`body-replace`'s `search` must also compile as a regex; `body-json`'s trailing
fields depend on `action`; `script` / `stream-script` base64 must decode to
syntactically valid UTF-8 JavaScript (checked at import).

### Fields and quoting

Fields are separated by `,`. Whitespace around an unquoted field is trimmed. A
field beginning with `"` is read to the matching `"`, and `""` inside a quoted
field is a literal `"`. Quote any field containing a comma or significant
leading/trailing whitespace:

```
0, 1, ^/, X-Note, "value, with a comma"
```

### The `url-pattern`

Every rule leads with a `url-pattern`: an `NSRegularExpression` (default Unicode
semantics) tested against the **whole request URL** — e.g.
`https://api.example.com/login?token=abc`. It is purely a gate (the replace
operations carry their own `search`); it does **not** see the method or HTTP
version. Use `.*` to match every request, or anchor on scheme/host
(`^https://api\.example\.com/`) to scope by origin — but an intercepted
**plain-HTTP** URL has an `http://` scheme, so anchor on `^https?://` (or just
the host) when a set also covers cleartext. The **host** is matched
case-insensitively (lowercased before the test); path and query keep their case.
A URL longer than 8 KB never matches, and if the URL can't be determined the
gate fails closed (the rule is skipped).

For **response**-phase rules the gate is tested against the **originating
request's** URL (response heads carry no path) — specifically its post-rewrite
URL — so a request and its response can share a pattern.

### Parameter lines

Parameters expose a few user-editable values that scripts read at runtime via
[`Anywhere.params`](#anywhereparams) — a country code, a feature flag, a token.
Declare them under `[Parameter]`; the app renders an editor for each, and the
chosen values are surfaced **read-only** to the set's scripts.

Shape:

```
<type>, <data-type>, <name>, <label>, <description>, <default> [, "[<option>, …]"]
```

| Field           | Meaning |
| --------------- | ------- |
| `type`          | `0` = free-text input, `1` = picker. |
| `data-type`     | `0` = string. The only type today. |
| `name`          | Lookup key for `Anywhere.params.get("<name>")`. ASCII letters/digits/`_`, ≤128 bytes, unique within the set. |
| `label`         | Label shown in the editor. Optional — falls back to `name`. |
| `description`   | Help text rendered as the editor's footer. Optional. |
| `default`       | Value used until the user changes it. |
| `"[option, …]"` | A picker's allowed values, as a bracketed list. Ignored for an input. |

A picker's options are the seventh field. Because the list contains commas,
**CSV-quote the whole field**: `"[US, JP, DE]"`. A picker needs at least one
option; a `default` not among them is added at the front, and an empty `default`
falls back to the first option. Duplicate names and malformed lines are dropped.

```
[Parameter]
# free-text input — empty label/description, empty default
0, 0, token, , ,
# input with a label and a footer description
0, 0, apiKey, API Key, Paste the key from your dashboard., 
# picker: US / JP / DE, default US (note the quotes around the options list)
1, 0, country, Country, Used for region-specific rewrites., US, "[US, JP, DE]"
```

User values **survive a subscription refresh**: an override is kept while its
parameter still exists (and, for a picker, is still one of the options);
otherwise it falls back to the new default.

---

## Rule operations

### `rewrite` (0) — request only

Its second field is a numeric **sub-mode**; the rest depend on it. When the
`url-pattern` gate matches, the **first** `rewrite` rule that resolves wins (a
rule that matches but fails to expand its target is skipped, so a later rule can
still win).

| Sub-mode | Name             | Args          | Effect |
| -------- | ---------------- | ------------- | ------ |
| `0`      | transparent      | `<full-url>`  | Replace the whole request URL. The request-target becomes the replacement's path+query (empty path → `/`, fragment dropped); the outer leg dials the replacement **host** and `Host` / `:authority` is rewritten to match. The client still sees the **original** host on the leaf certificate. A script reads the rewritten URL as `ctx.url`, the original as `ctx.originalUrl`. |
| `1`      | 302 redirect     | `<full-url>`  | Synthesize `302 Found` with `Location: <full-url>` (verbatim). No upstream dial. |
| `2`      | reject 200 text  | `[<content>]` | Synthesize `200 OK`, `text/plain; charset=utf-8`. Empty → a short default line. No upstream dial. |
| `3`      | reject 200 gif   | *(none)*      | Synthesize `200 OK` with a canned 1×1 `image/gif`. No upstream dial. |
| `4`      | reject 200 data  | `[<base64>]`  | Synthesize `200 OK`, `application/octet-stream`, body decoded from `<base64>`. Empty → a default payload. No upstream dial. |

For sub-modes `0` and `1` the URL must be a full absolute URL with a host
(validated at import). The replacement supports **capture references** to the
`url-pattern` match: `$0` is the whole match, `$1`–`$9` (and `${10}`, `${11}`, …)
are groups, `$$` is a literal `$`. A replacement with no reference is used
verbatim. References resolve **per request**, so one pattern with capture groups
can rewrite many URLs; a non-participating group expands to empty, and if the
expanded URL isn't a valid absolute URL the rule is skipped for that request.

A transparent rewrite can change the dial target, so the upstream dial is
**deferred**: the inner handshake completes, the first request is read and
rewritten, and only then is the upstream dialed. Consequences for divergent
targets on one connection:

- **HTTP/1.1** fixes its single upstream leg on the first request. A later
  request whose rewrite resolves a *different* host is reconnected transparently
  **if the leg is idle** (no response in flight); if a response is still in
  flight the connection is torn down and the client retries on a fresh one.
- A **bridged HTTP/2** client with an **HTTP/1.1** upstream dials per stream, so
  each stream generally follows its own resolved host. With an **HTTP/2**
  upstream, the connection is committed on the first request and later streams go
  to that committed upstream regardless of their rewrite.

Either way, avoid splitting one origin's traffic across several transparent
target hosts.

```
0, 0, ^https://a\.example\.com/, 0, https://b.example.com/
0, 0, ^https://old\.example\.com/(.*), 0, https://new.example.com/$1
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

> Unlike `header-add` / `header-replace`, which reject framing and hop-by-hop
> header names at load, `header-delete` is **not** guarded — deleting
> `Content-Length` or `Transfer-Encoding` changes how the body is framed. Don't.

### `header-replace` (3)

Overwrites the value of every header with the given name (case-insensitive), and
normalizes the name's spelling to the rule's. A header that is not present is
left alone — it does **not** add it:

```
1, 3, .*, Cache-Control, no-store
```

### `body-replace` (4)

Regex find-and-replace over the text body in **native code**, no JavaScript. Its
fields are `url-pattern`, a `search` regex, and a `replacement`:

```
1, 4, .*, http://, https://
1, 4, .*, (?i)debug=true, debug=false
1, 4, .*, (\d{4})-(\d{2})-(\d{2}), $3/$2/$1
```

`search` is a Swift `Regex` matched against the **whole decompressed body**, and
every match is replaced. `replacement` supports the same capture references as
`rewrite` (`$0`, `$1`–`$9`, `${10}`, `$$`); an **empty** replacement deletes
matches. A rule whose `search` is empty or won't compile is dropped. Quote a
field containing a comma or leading `"`, doubling inner quotes — so the literal
`"price":` is written `"""price"":"`.

The body is decoded as UTF-8, with a Latin-1 fallback that accepts **any** byte
sequence — there is no charset detection. A non-UTF-8 body (UTF-16, GBK, …) is
therefore seen as Latin-1 and round-trips only because nothing matches; a pattern
that *does* match such a body can corrupt it. Use `body-replace` on UTF-8 text.

Like `script`, `body-replace` is a **buffered** transform: the body is
accumulated (auto-decoding `gzip` / `deflate` / `br`, up to **4 MiB**), edited,
and re-emitted with a fresh `Content-Length`. The contract is otherwise
**total** — a `search` that matches nothing, or a `replacement` unrepresentable
in the body's bytes, leaves the body unchanged. **Every** matching `body-replace`
rule fires, in rule order, so replacements compose. (Body substitutions are
process-serialized: if two run at once, or one exceeds a 1 s soft deadline, that
message is left with its remaining edits unapplied.)

When several body transforms match one message they run in a fixed order:
`body-json` first, then `body-replace`, then a `script` (so the script sees the
fully-edited body).

### `body-json` (5)

Declarative JSON body editing in **native code** — the same edits as the
[`Anywhere.json`](#anywherejson) script API, without JavaScript. One rule, one
edit; fields are `url-pattern`, an `action` token, and the action's fields:

| `action`                  | Trailing fields           | Effect |
| ------------------------- | ------------------------- | ------ |
| `add`                     | `path`, `value`           | Upsert at `path` (create or overwrite; append at array end when index == length). |
| `replace`                 | `path`, `value`           | Overwrite at `path` only if the member/index already exists. |
| `delete`                  | `path`                    | Remove the member/element at `path`. |
| `replace-recursive`       | `key`, `value`            | Overwrite every property named `key` at any depth. |
| `delete-recursive`        | `key`                     | Remove every property named `key` at any depth. |
| `remove-where-key-exists` | `path`, `key`             | At the array at `path`, drop objects containing `key`. |
| `remove-where-field-in`   | `path`, `field`, `values` | At the array at `path`, drop objects whose `field` ∈ `values`. |

`path` is a JSONPath like `$.data.items[0].id` (leading `$` optional; dotted keys
and `[index]` / `["key"]` brackets; an empty path or `$` addresses the whole
document). `value` / `values` are JSON literals (`true`, `42`, `"text"`,
`{"a":1}`, `["x","y"]`); a string that **isn't** valid JSON is taken literally,
so `value = Anywhere` means `"Anywhere"`. Action tokens are case-insensitive and
accept the camelCase spelling. A rule whose `path` can't be parsed is dropped.

Like `script`, `body-json` is a **buffered** transform (auto-decoding, 4 MiB
cap). The contract is **total** — a body that isn't JSON, a path that doesn't
resolve, or an unserializable result leaves the body **byte-for-byte** unchanged.
A *successful* edit re-serializes the whole document, so object member order is
not preserved and slashes are not escaped; a document nested deeper than ~600
levels, or containing non-finite numbers, is left unchanged. **Every** matching
`body-json` rule fires in rule order; a matching `script` runs after them.

```
1, 5, ^/api/user, add, $.user.vip, true
1, 5, ^/api/user, delete, $.user.password
1, 5, ^/api/feed, remove-where-field-in, $.items, status, expired
```

A `value` / `values` containing a comma must be one quoted CSV field with inner
quotes doubled:

```
1, 5, ^/api/feed, remove-where-field-in, $.items, status, "[""expired"",""deleted""]"
1, 5, ^/api/profile, add, $.meta, "{""beta"":true,""tier"":2}"
1, 5, ^/api/profile, replace, $.tier, "gold, platinum"
1, 5, .*, replace-recursive, access_token, "***"
```

### `script` (100) / `stream-script` (101)

JavaScript transforms. The field is base64-encoded UTF-8 source defining
`function process(ctx)`. See the next sections.

---

## Scripting: `script`

Use `script` when the rewrite needs the **whole message at once**: rewriting a
body as a unit (JSON, protobuf, JWT, a regex over the full text) or
short-circuiting a request with `Anywhere.respond(...)`. The head is read-only —
URL and header edits have dedicated rules, and `ctx.method` / `ctx.status` aren't
script-writable — so a `script` rule's job is the body plus the control
directives.

The rewriter buffers the body (auto-decoding `gzip` / `deflate` / `br`), runs
`process(ctx)` once, and re-emits with a fresh `Content-Length`. Because nothing
reaches the client until the body is complete, a `script` **de-streams** the
response; it is right for ordinary request/response APIs and wrong for live
streams (pointing one at a streaming media type still runs, but logs a warning
recommending `stream-script`).

`process` may be **`async`** and `await` an [`Anywhere.http`](#anywherehttp)
request mid-rewrite; the rewriter waits for the Promise to settle before reading
`ctx.body` back. The connection parks while the fetch is in flight, and the
shared runtime stays free for other connections. `stream-script` has no such
facility — `Anywhere.http` is unavailable there.

The body is held up to a **4 MiB** cap: a larger `Content-Length` body falls back
to passthrough (the script is skipped), and a chunked body that reaches the cap
**fails closed** — the connection is torn down (request) or answered `502`
(response) rather than silently truncated.

```
1, 100, ^/api/user, <base64 of the JS source>
```

To produce the base64:

```bash
printf '%s' "$(cat process.js)" | base64
```

Base64 that doesn't decode to valid UTF-8 JavaScript is dropped at import;
whether `process` is defined and callable is checked at runtime (a
missing/non-function `process` logs a warning and passes the message through).

---

## Scripting: `stream-script`

Use `stream-script` when the response must keep flowing: Server-Sent Events, NDJSON
or chunked event feeds, gRPC / HTTP/2 DATA streams, or any long-lived or very
large body. `process(ctx)` runs **once per frame** (HTTP/2 DATA frame or HTTP/1
chunk) and the body is **never buffered**, so bytes reach the client as they
arrive.

The trade-off is a narrower contract:

- The head is **immutable** — `ctx.url` / `ctx.originalUrl` / `ctx.method` /
  `ctx.status` / `ctx.headers` are read-only.
- **No HTTP-level decompression.** `ctx.body` is the raw frame payload.
- **No HTTP/1 `Content-Length` bodies** — the byte count is already committed, so
  length-framed HTTP/1 bodies are skipped (chunked is required); HTTP/2 has no
  such restriction.
- **Not applied on the HTTP/2→HTTP/1.1 bridge.** When a bridged HTTP/2 client
  maps to an HTTP/1.1 upstream, a matching `stream-script` is **skipped** (body
  forwarded unscripted, with a warning) in both directions. On the bridge's
  **response** path this early exit also skips any buffered `script` /
  `body-replace` / `body-json` for that message; buffered rules still apply on
  the bridge when the response is `Content-Length`-framed.

Per-frame context adds:

- `ctx.frame` — `{ index, end }`: the 0-based frame index and an `end` flag on
  the final frame.
- `ctx.state` — a JS object shared by **every frame of the same stream**, and
  nothing else. It starts `{}` and is carried forward verbatim between frames, so
  it is where a stream-script accumulates: a partial line, a running count, a
  parser position.

```
1, 101, ^/events, <base64>
```

---

## Execution model

Every invocation runs in its **own JavaScript context**, created when the
invocation starts and destroyed when it ends. An invocation is:

| Rule                  | One invocation spans |
| --------------------- | -------------------- |
| `script`              | one message — a request, or a response |
| `script` with `await` | that same message, extended until the Promise settles |
| `stream-script`       | one **stream** — every frame of that body |

What it gives a script:

- **Fresh intrinsics.** `Object.prototype`, `JSON`, `Promise`, `RegExp`, and the
  whole `Anywhere` API are rebuilt per invocation. A script cannot patch a
  built-in to watch another's traffic.
- **A private global.** Top-level `var` / `let` / `function` belong to that
  script alone.
- **No crosstalk.** Two rule sets matching one flow share no objects, prototypes,
  or globals. (The single process-wide VM is shared, but each context is
  isolated; the one deliberate channel is [`Anywhere.store`](#anywherestore).)

What it costs:

- **No state outlives an invocation.** A top-level `let cache = {}` is empty again
  on the next message. State that must outlive one message belongs in
  [`Anywhere.store`](#anywherestore); state scoped to the message belongs on
  `ctx`; state scoped to a stream belongs on `ctx.state`.
- **Top-level code runs every time.** The source is compiled per invocation, so
  module scope is not a free place to precompute — build lookup tables and regexes
  inside the branch that needs them.

The one resource genuinely shared between invocations is the runtime's thread: a
CPU-bound loop blocks every other script (see
[Limits and safety](#limits-and-safety)).

---

## The `ctx` object

`process(ctx)` receives a context object. Scripts read its fields freely, but the
only field read back is `ctx.body`.

| Field         | Type                       | Phase    | Mutable | Notes |
| ------------- | -------------------------- | -------- | ------- | ----- |
| `ctx.phase`   | `"request"` / `"response"` | both     | no      | |
| `ctx.method`  | string or `null`           | both     | no      | On response, the originating request's method. |
| `ctx.url`     | string or `null`           | both     | no      | Absolute URL; reflects a transparent `rewrite`. On response, the originating request's URL. |
| `ctx.originalUrl` | string or `null`       | both     | no      | The request URL **before** a transparent rewrite; equal to `ctx.url` when none matched. |
| `ctx.status`  | number or `null`           | response | no      | `null` on request. |
| `ctx.headers` | array of `[name, value]`   | both     | no      | Preserves duplicates and order. |
| `ctx.body`    | `Uint8Array`               | both     | yes     | A copy of the body bytes; reassign it (to a typed array, `ArrayBuffer`, or string) or mutate it in place. |

Only `ctx.body` is mutable, in both `script` and `stream-script` (the latter also
reads back `ctx.state`). Every head field is **read-only** — assigning it is
ignored on readback. URL and header edits have dedicated rule operations
(`rewrite`, `header-*`); `method` and `status` have no script-side write at all.

**Readback** keeps the wire well-formed by construction:

- Only `ctx.body` is adopted; head-field assignments are ignored, so a script
  can't inject a malformed request line, status, or header.
- An **uncaught exception** discards mutations and emits the original message
  unchanged — **unless** a directive was already signalled (see below), in which
  case the directive wins. Use `try/catch`, or signal `Anywhere.done()` before
  throwing, to keep partial work.

---

## The `Anywhere` API

A global `Anywhere` object exposes helpers. **Byte convention:** functions that
take "bytes" accept a `Uint8Array`, `ArrayBuffer`, or string (UTF-8 encoded);
functions that return bytes return a `Uint8Array`.

### `Anywhere.codec`

Encoder/decoder pairs.

| Member                     | encode                        | decode |
| -------------------------- | ----------------------------- | ------ |
| `Anywhere.codec.utf8`      | `encode(string) → Uint8Array` | `decode(bytes) → string` |
| `Anywhere.codec.base64`    | `encode(bytes) → string`      | `decode(string) → Uint8Array` |
| `Anywhere.codec.base64url` | `encode(bytes) → string`      | `decode(string) → Uint8Array` |
| `Anywhere.codec.hex`       | `encode(bytes) → string`      | `decode(string) → Uint8Array` |
| `Anywhere.codec.gzip`      | `encode(bytes) → Uint8Array`  | `decode(bytes) → Uint8Array` |
| `Anywhere.codec.deflate`   | `encode(bytes) → Uint8Array`  | `decode(bytes) → Uint8Array` |
| `Anywhere.codec.brotli`    | `encode(bytes) → Uint8Array`  | `decode(bytes) → Uint8Array` |

`base64url` emits unpadded RFC 4648 §5; decode accepts either alphabet, padded or
not, ignoring whitespace. The compression codecs are for payloads the pipeline
doesn't already handle (a gzipped blob nested in a JSON field, re-compressing a
body for `Anywhere.respond`); the outer `Content-Encoding` is already
auto-decoded for `script` rules. Compression `decode` / `encode` **throw** on
malformed input or output past the 4 MiB cap; the text codecs (`utf8`, `base64`,
`base64url`, `hex`) never throw — a bad input yields empty or replacement output.

#### `Anywhere.codec.protobuf`

Schema-free protobuf wire-format codec.

- `decode(bytes) → [{ field, wire, value }]` — flat list in on-wire order
  (repeated fields appear multiple times); **throws** on malformed input.
- `encode(entries) → Uint8Array` — takes the same shape back.
- `encodeVarint(n) → Uint8Array`, `decodeVarint(bytes, offset?) → { value, consumed } | null`.

Value types by wire type: wire 0 (varint) is a **BigInt**; wire 1 / 5 (fixed64 /
fixed32) are `Uint8Array` of length 8 / 4 (interpret with a `DataView`); wire 2
(length-delimited) is a `Uint8Array` — recurse with `decode` for nested messages.
Group wire types (3, 4) are rejected.

### `Anywhere.crypto`

Hashes and HMAC return raw digest bytes; compose with `Anywhere.codec.hex.encode`
/ `base64.encode` to format.

- `md5`, `sha1`, `sha256`, `sha384`, `sha512` — `(bytes) → Uint8Array`.
- `hmacSHA1`, `hmacSHA256`, `hmacSHA384`, `hmacSHA512` — `(key, data) → Uint8Array`.
- `randomBytes(n) → Uint8Array` — `n` in `[0, 65536]`; out-of-range throws.
- `uuid() → string` — lowercased.
- `aesGCM.encrypt(spec) → { nonce, ciphertext, tag }` and
  `aesGCM.decrypt(spec) → Uint8Array`. The spec:
  - `key`: `Uint8Array` of 16 / 24 / 32 bytes (AES-128/192/256).
  - `nonce`: exactly 12 bytes; any other length throws. On encrypt, omit it to
    have a fresh random nonce generated and returned.
  - `plaintext` / `ciphertext`: bytes.
  - `tag`: 16-byte `Uint8Array` (decrypt only).
  - `aad`: optional additional authenticated data.
  - decrypt throws a catchable error on auth failure.

### `Anywhere.jwt`

JWT compact serialization (RFC 7519 / 7515). **Pure codec — no signature
verification or `alg` enforcement;** do that yourself with the crypto helpers.

- `decode(token) → { header, payload, signature, signingInput }`. `header` is
  parsed JSON; `payload` is parsed JSON or a `Uint8Array` for binary payloads;
  `signature` is bytes; `signingInput` is the `header.payload` octet string to
  recompute the signature over.
- `encode({ header, payload, signature? }) → string`. Object header/payload are
  `JSON.stringify`'d; bytes/string are used verbatim.

### `Anywhere.json`

Byte-oriented JSON editing: **bytes-in / bytes-out** (first arg is the body;
returns a fresh `Uint8Array` of compact JSON). The contract is **total** — a body
that isn't JSON, an unresolved path, a type mismatch, or an unserializable value
all yield the body **unchanged** rather than throwing. A *successful* edit
re-serializes the whole document, so member order is not preserved and a document
nested deeper than ~600 levels (or containing non-finite numbers) is left
unchanged.

- `add(body, path, value)` — upsert at a JSONPath.
- `replace(body, path, value)` — modify only if the member/index already exists.
- `replaceRecursive(body, key, value)` — replace every property named `key` at
  any depth (bare key, not a path).
- `delete(body, path)` — remove the addressed member/element.
- `deleteRecursive(body, key)` — remove every property named `key` at any depth.
- `removeWhereKeyExists(body, path, key)` — at the array at `path`, drop objects
  containing `key`.
- `removeWhereFieldIn(body, path, field, values)` — at the array at `path`, drop
  objects whose `field` equals one of `values` (array or scalar).

> For these same edits **without** a script — declared as a rule, run in native
> code — use [`body-json` (5)](#body-json-5). A `script` is only needed when the
> edit must be conditional, computed, or combined with `Anywhere.respond` /
> directives.

### `Anywhere.store`

Per-rule-set key/value state, scoped by rule-set id — and, because every
invocation gets a fresh context, the **only** place script state outlives a
single message.

- `get(key[, onDisk]) → Uint8Array | undefined`
- `getString(key[, onDisk]) → string | undefined`
- `set(key, value[, onDisk])` — value is bytes. **Throws** when the write would
  exceed the scope's 1 MiB cap or the 16 MiB process-wide cap (catch it and shed
  entries with `delete`).
- `delete(key[, onDisk])`
- `keys([onDisk]) → [string]`

Every method is **shared across every connection to the same rule set** — and
across its `script` and `stream-script` rules — and survives a rule-set edit.
Because concurrent invocations share it, treat read-modify-write as racy: another
connection can write between your `get` and `set`. State is cleared when the rule
set is **removed** (a disabled set keeps its data).

The **`onDisk`** flag (default `false`) selects the backing:

- **`onDisk: false`** — in-memory. Fast, **cleared when the extension restarts**
  (tunnel stop, reboot, NE relaunch). For per-session caches.
- **`onDisk: true`** — persisted to a file in the App Group container, so it
  **survives extension restarts**. For tokens, cookies, check-in state.

The two backings are **separate keyspaces** with **independent caps**; `keys()`
lists only the backing you ask for. Tolerate a missing key in either.

```js
// Persist a refreshed token across tunnel restarts; fall back to a fetch.
async function process(ctx) {
  let token = Anywhere.store.getString("token", true);
  if (!token) {
    const r = await Anywhere.http.get("https://api.example.com/token");
    if (r.status === 200) {
      token = Anywhere.codec.utf8.decode(r.body).trim();
      try { Anywhere.store.set("token", token, true); }
      catch (e) { Anywhere.log.warning("store full: " + e); }
    }
  }
  if (token) ctx.headers.push(["Authorization", "Bearer " + token]);
}
```

### `Anywhere.params`

Read-only access to the rule set's [parameters](#parameter-lines), scoped to the
running set. Each value is the user's choice, or the declared default.

- `get(name) → string | undefined` — the value, or `undefined` if undeclared.
- `keys() → [string]` — the declared parameter names.
- `all() → { [name]: string }` — every `name → value`.

Unlike [`Anywhere.store`](#anywherestore), parameters have **no setter** — they
are configured by the user. An undeclared name reads back `undefined`, so pair it
with a fallback:

```js
function process(ctx) {
  const country = Anywhere.params.get("country") || "US";
  Anywhere.log.info("country = " + country);
  return ctx;
}
```

### `Anywhere.log`

`info(msg)`, `warning(msg)`, `error(msg)`, `debug(msg)` — written through the
shared logger, prefixed `[MITM][JS]`. `debug` is **compiled out of release
builds**; the other three reach both os.log and the user-facing log.

### `Anywhere.http`

Make an outbound HTTP(S) request from a script and `await` the response — to
fetch a token, look up data to splice into the body, or call a sidecar API.
Available in **`script` rules only** (not `stream-script`); the result must be
`await`ed, so declare `process` as `async`:

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
- `request(options) → Promise<Response>` — the all-options form; `url` is a field
  of `options`.

**Response**: `{ status, headers, body, url }`. `headers` is `[[name, value], …]`,
preserving the origin's order and repeated names; `body` is a fully-buffered
`Uint8Array`, **best-effort** decoded for a `gzip` / `deflate` / `br` response
(with the stale `Content-Encoding` / `Content-Length` dropped, `Transfer-Encoding`
always dropped) — an unsupported or failed coding is handed back still compressed
with its headers intact; `url` is the final URL after any followed redirects. The
Promise **rejects** with an `Error` on a transport failure, timeout, cap breach,
or non-HTTP response; an *uncaught* rejection reverts the message unchanged.

**`options`**:

| Field      | Default                 | Meaning |
| ---------- | ----------------------- | ------- |
| `method`   | `"GET"` / `"POST"`      | HTTP method. |
| `headers`  | none                    | `[[name, value], …]` or `{ name: value }`. Entries with an invalid name, a CR/LF/NUL value, or a forbidden name (`Host`, `Content-Length`, `Connection`, `Transfer-Encoding`, and other framing / hop-by-hop headers) are dropped. `Accept-Encoding` is not settable — the client forces `gzip, deflate, br`. |
| `body`     | empty                   | `Uint8Array`, `ArrayBuffer`, or string. |
| `timeout`  | 10 000 ms               | **Inactivity** timeout (refreshed on each received chunk), clamped to 30 000 ms. An overall ~60 s idle cap and a 180 s absolute budget also apply. |
| `redirect` | `"follow"`              | `"follow"` chases up to 10 hops (301/302/303/307/308; cross-origin hops strip `Authorization` / `Cookie`); `"manual"` returns the 3xx as-is. |
| `insecure` | global *Allow Insecure* | A genuine `true` accepts self-signed server certificates. |

**Execution model.** A script that `await`s a fetch is *parked* — its connection
waits — but the shared runtime is **not** blocked: other scripts keep running.
The request is dialed through the tunnel's routing rules (direct / reject / proxy,
like any other connection) as the extension's own outbound traffic, and is **not**
re-intercepted by the MITM, so a script may call a host the set also intercepts
without looping. It is logged in the request log as a `protocol: unknown` entry.
Because other invocations run while you `await` but each has its own context,
nothing your script holds across the suspension can change underneath it — except
[`Anywhere.store`](#anywherestore), which is deliberately shared, so re-read a
store value after a fetch rather than caching it across one.

> **Security.** `Anywhere.http` follows the tunnel's routing rules — a `reject`
> rule blocks the fetch, a `proxy` rule routes it — but there is **no SSRF
> filtering** beyond those rules: any host not rejected is reachable, including
> `localhost`, `*.local`, and loopback / link-local (incl. the cloud-metadata
> address) / private / ULA ranges, which are dialed directly. It is both an
> exfiltration surface and a pivot into on-device and on-network services. Import
> rule sets only from sources you trust.

### Control directives

- `Anywhere.done()` — commit the current `ctx` as this script's result. Because
  at most one `script` runs per message it does not "skip" other scripts; its use
  is to lock in mutations before a possible throw, or in `stream-script` to emit
  this frame and pass every later frame through unchanged.
- `Anywhere.exit()` — discard this script's own changes: revert to the message as
  it entered the script (after native body edits), or in `stream-script` emit the
  original frame and stop scripting the stream.
- `Anywhere.respond({ status, headers, body })` — **request-phase only**. Drop the
  request before it reaches upstream and synthesize a response to the client. All
  fields optional: `status` defaults to 200 (a value outside 100–599, or a
  non-integer, is replaced with 200), `headers` to `[]`, `body` to empty. Anywhere
  owns framing, so `Content-Length` and hop-by-hop headers you set are dropped and
  a `Date` is stamped when absent. Ignored (with a warning) on the response phase
  and in `stream-script`.

Signal a directive and `return` immediately after.

---

## Subscriptions

A subscription is a `.amrs` file served over **http(s)** from a URL whose path
ends in `.amrs`. Anywhere fetches it (HTTP 2xx, UTF-8 body required), parses it
with the format above, and stores it as a rule set.

On **refresh**, the suffixes, rules, parameters, and icons are **replaced**
wholesale by the fetched file. The set's local **name**, **enabled** state, and
subscription URL are preserved, as are parameter overrides that remain valid (see
[Parameter lines](#parameter-lines)). The **10,000-rule** cap applies; a file
that exceeds it is rejected in full. Imported (non-subscribed) sets are edited in
the app rule-by-rule.

---

## Single-rule semantics

**At most one `script` and one `stream-script` fire per message**, by design.
When several rules of the same kind match a URL, the **last in rule order wins**.
When both a `script` and a `stream-script` match, **`stream-script` wins**.

Consolidate composed behavior into one `process(ctx)` rather than splitting it
across rules. Static operations (`rewrite`, `header-*`) and buffered body rules
(`body-replace`, `body-json`) are **not** capped — all matching ones apply, in
order.

---

## Limits and safety

| Limit                                                | Value        | Effect on exceed |
| ---------------------------------------------------- | ------------ | ---------------- |
| Rules per rule set                                   | 10,000       | import / subscription / refresh rejected; in-app add blocked |
| Parameters per rule set                              | 256          | extra parameter lines dropped at parse |
| Icon size (decoded)                                  | 256 KB       | icon dropped |
| Buffered body (`script` / `body-replace` / `body-json`) | 4 MiB     | `Content-Length` → passthrough; chunked → **fails closed** (connection closed / 502) |
| Per-scope `Anywhere.store` (memory / onDisk)         | 1 MiB each   | `set` throws |
| Total `Anywhere.store` (memory / onDisk)             | 16 MiB each  | `set` throws |
| `Anywhere.crypto.randomBytes`                        | 64 KiB       | throws |
| Synthesized response body                            | 4 MiB        | truncated |
| `Anywhere.http` timeout                              | 10 s idle default / 30 s max, ~60 s absolute | Promise rejects |
| `Anywhere.http` per script                           | 4 concurrent / 16 total | Promise rejects |
| `Anywhere.http` concurrent (all scripts)             | 32           | Promise rejects |
| `Anywhere.http` in-flight body bytes (all scripts)   | 16 MiB       | Promise rejects |
| `Anywhere.http` response body                        | 4 MiB        | Promise rejects |
| `Anywhere.http` redirects                            | 10 hops      | Promise rejects |
| HTTP/1 request/response head                         | 64 KiB       | connection closed (request) / 502 (response) |
| Body bytes pinned by suspended `async` scripts (all) | 16 MiB       | new flow passes through unmodified |
| Contexts pinned by unsettled scripts (all)           | 32           | new flow passes through unmodified; new stream runs unscripted |
| Idle suspended `async` script                        | ~60 s no progress | reverted to original, released |
| Runaway synchronous JS span                          | ~30 s        | extension crashes & relaunches clean |

Other safety properties:

- **Isolation.** Each invocation runs in its own JavaScript context, so a script
  cannot reach another's globals or patch a shared built-in. The boundary is per
  *invocation* — two connections running the same rule set are isolated too.
  [`Anywhere.store`](#anywherestore) is the one deliberate channel.
- **Wire safety.** Header names, values, methods, and request targets produced by
  scripts and rules are validated; CR/LF/NUL and other smuggling vectors are
  rejected. (The exception noted above: `header-delete` is not guarded against
  framing headers.)
- **Watchdogs.** *Idle async:* a suspended `async` script that stops making
  progress is reverted and released after ~60 s. *Runaway sync:* a CPU-bound loop
  or pathological regex can't be preempted, so it wedges its own connection and
  the scripts queued behind it — but a synchronous span past a ~30 s hard cap
  crashes the extension so the OS relaunches it clean. Keep loops and regexes
  bounded.
- **Failure is safe-by-default.** A compile failure, a missing `process`, or an
  uncaught throw (including an unhandled `Anywhere.http` rejection) passes the
  original message through unchanged.

---

## Worked examples

### Inject a request header on API paths

```
name     = Add Trace
hostname = api.example.com
0, 1, ^/v2/, X-Trace-Id, anywhere
```

### Redirect an old path, preserving the tail (transparent URL rewrite)

```
name     = Path Migration
hostname = example.com
0, 0, ^https://example\.com/old/(.*), 0, https://example.com/new/$1
```

### Block a host with a 1×1 GIF

```
name     = Block Tracker
hostname = tracker.example.com
0, 0, .*, 3
```

### Edit a JSON response body (`script`)

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

```bash
printf '%s' "$(cat flag.js)" | base64
```

```
name     = VIP Flag
hostname = api.example.com
1, 100, ^/v1/profile, <base64>
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
> use a `header-add` rule for a fixed header.

---

## Behavior reference

- **Content-Encoding.** For `script` rules the body is decompressed before the
  script runs and re-emitted as identity with `Content-Encoding` dropped and a
  fresh `Content-Length`. `stream-script` rules see raw, still-compressed frames.
  A concatenated multi-member `gzip` body — or one truncated or corrupt past its
  first member — is left compressed and forwarded unrewritten.
- **Transfer-Encoding content-codings.** A body whose `Transfer-Encoding` carries
  a content-coding (`gzip, chunked`, or a bare `gzip` framed by connection close)
  is forwarded verbatim: the buffered path decodes only `Content-Encoding` and
  the `chunked` framing. A framing header injected by a header rule is rejected at
  load, and any that slips through is dropped at emission, so a rule can't create
  the `Transfer-Encoding` + `Content-Length` pair that inbound messages are
  rejected for (RFC 9112 §6.3.3) — except via `header-delete`, which is unguarded.
- **Accept-Encoding.** Anywhere clamps the client's `Accept-Encoding` to the
  codings it can decode (`gzip`, `deflate`, `br`, `identity`) *only* when a
  response-phase body rule matches the request; a passthrough request forwards it
  untouched. A body that still arrives in an unsupported `Content-Encoding` is
  forwarded unrewritten.
- **HEAD responses.** A response to `HEAD` never carries a body; a script's
  `ctx.body` write is dropped on the wire.
- **Interim 1xx responses.** `100 Continue`, `103 Early Hints`, etc. are
  forwarded as-is; scripts run only on the final response.
- **Protocol upgrades & tunnels.** On **HTTP/1.1** a `101 Switching Protocols`, or
  a `2xx` to `CONNECT`, turns the connection into an opaque tunnel: both
  directions drop to verbatim passthrough and no rule sees the tunneled bytes. An
  **HTTP/2** `CONNECT` can't cross the bridge — a classic CONNECT is refused with
  `HTTP_1_1_REQUIRED` (the client retries over HTTP/1.1, where the tunnel path
  applies) and the RFC 8441 extended form is refused with `PROTOCOL_ERROR`.
- **Pipelining order.** A request-phase `Anywhere.respond` on a pipelined
  connection is held until the in-flight response ahead of it finishes, so the
  client's ordering is preserved.
- **Streaming media + `script`.** A buffered body rule on `text/event-stream` and
  similar de-streams the response; the rule still runs but logs a warning
  recommending `stream-script` (HTTP/1 response path only).
- **Fail-closed URL gate.** If the request URL can't be determined, every rule's
  URL gate is skipped rather than firing blind.
- **Regex scope.** URL patterns match the whole request URL, so they scope by
  scheme and host as well as path; they never see the method or HTTP version, and
  the set's `hostname` suffixes gate the host first.
- **Scripts never change the head.** In both `script` and `stream-script`, only
  `ctx.body` is adopted — header/method/URL/status edits come from rules, not
  scripts. On the HTTP/2 legs even a response-phase `Anywhere.respond` is ignored.

---

## Code map

| Area | Location |
| ---- | -------- |
| `.amrs` parsing (rules, params, sub-modes) | `Anywhere/Views/Pages/MITM/MITMRuleSetParser.swift` |
| Import / subscribe UI | `Anywhere/Views/Pages/MITM/MITMView.swift` |
| Rule / operation / parameter model, binary payload (`AMR1`) | `Shared/Models/MITMRule.swift` |
| Rule-set storage, 10,000-rule cap, refresh merge | `Shared/DataStore/MITMRuleSetStore.swift` |
| Subscription refresh | `Shared/Operations/MITMRuleSetOperations.swift` |
| Host gating, suffix trie, rule compilation | `Anywhere Network Extension/MITM/MITMRewritePolicy.swift` |
| TLS interception, leaf mint, deferred dial | `Anywhere Network Extension/MITM/MITMSession.swift`, `MITMLeafCertCache.swift` |
| HTTP/1.1 framing & rewrite | `Anywhere Network Extension/MITM/MITMHTTP1Stream.swift` |
| HTTP/2 rewrite & bridge | `Anywhere Network Extension/MITM/MITMHTTP2Rewriter.swift`, `MITMBridgeClientLeg.swift`, `MITMHTTP2UpstreamLeg.swift` |
| `rewrite` sub-modes, capture templates, gate regex | `MITMRewritePolicy.swift`, `MITMCaptureTemplate.swift`, `MITMGateRegex.swift` |
| `body-replace` / `body-json` native transforms | `MITMBodyReplace.swift`, `MITMJSONPatch.swift` |
| Synthesized `302` / reject / respond | `MITMRespondBuilder.swift`, `MITMSynthesizedResponse.swift` |
| Script engine, `ctx`, `Anywhere` API, watchdogs | `MITMScriptEngine.swift`, `MITMScriptTransform.swift`, `MITMScriptWatchdog.swift` |
| `Anywhere.store` backings | `MITMScriptStore.swift`, `MITMScriptDiskStore.swift` |
| `Anywhere.http` fetch path | `Anywhere Network Extension/MITM/Anywhere.http/` |
| Body (de)compression | `MITMBodyCodec.swift` |
