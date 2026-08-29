# Routing Rule System — Developer Guide

Anywhere decides, per connection, whether to send it **direct**, **reject**
it, or route it through a chosen **proxy**, based on the connection's
destination. Routing rules express that policy. This guide covers rule-set
authoring, the `.arrs` import format, and the exact matching semantics. It
assumes familiarity with domain names and CIDR notation.

> **The proxy target is not in the file.** A rule set's rules say *which*
> destinations it matches; the action — Default, PROXY, DIRECT, REJECT, or a
> specific proxy / chain — is assigned per set in the app, under **Routing**.
> A file may request an initial **Default / Direct / Reject** action through
> the optional `routing` header, but that seeds the assignment **only when the
> set is first created** — a subscription refresh never changes the action you
> chose locally.

## Contents

- [How it works](#how-it-works)
- [Rule sets](#rule-sets)
- [Rule types](#rule-types)
- [Matching: priority and specificity](#matching-priority-and-specificity)
- [The import format](#the-import-format)
- [Subscriptions](#subscriptions)
- [Limits](#limits)
- [Worked examples](#worked-examples)
- [Behavior reference](#behavior-reference)
- [Code map](#code-map)

---

## How it works

Routing rules apply only in **Rule** mode. In **Global** mode every connection
takes the default route and the rule tables are not even loaded; in **Direct**
mode everything bypasses the proxy. The **default route** is the selected
chain, else the selected configuration, else the tunnel's active
configuration.

Whenever routing configuration changes, the app compiles assignments, custom
sets, and bundled rules into a binary payload (magic `ARB2`). The Network
Extension decodes it into a five-tier matcher: per tier, one domain-suffix
trie, one keyword automaton, and a pair of CIDR tries.

A destination is classified at several points:

1. **DNS time.** DNS queries are intercepted and the queried domain is matched
   against domain rules immediately. A **reject** verdict answers `0.0.0.0` /
   `::` (NODATA for other query types) and the domain never resolves.
   Otherwise a fake IP is allocated and the verdict is cached with it, tagged
   with the rules version so a rules reload invalidates it.
2. **Connect time, fake IP.** A connection to a fake IP is routed by the
   cached domain verdict (re-matched if the rules changed since DNS time).
3. **Connect time, literal IP.** A connection to a real IP is matched against
   CIDR rules only.
4. **Resolved-IP fallback.** A domain connection that matches **no** domain
   rule has its real IPv4 (resolved through the dedicated IP-rule resolver)
   checked against CIDR rules — TCP applies this before dialing, UDP holds the
   first datagrams until resolution completes. Enabling **Prevent DNS Leak**
   disables this fallback.
5. **TLS SNI.** A sniffed SNI re-runs domain matching mid-connection and can
   change the route of a connection that was accepted by IP.

So domain rules always take precedence for a connection with a known host; IP
rules apply to literal-IP traffic and, as a fallback, to unmatched domains.
Rejected domains and IPs are additionally remembered, so follow-up packets to
them are dropped at intake.

A destination that matches **no** rule takes the default route. Rules only
override that default where they match — an empty or fully-unmatched rule base
changes nothing.

---

## Rule sets

A rule set is the unit of configuration: a **name**, a list of **rules**, and
one **assigned action** that applies to every rule in the set.

| Origin            | Editable rules | Source                                   |
| ----------------- | -------------- | ---------------------------------------- |
| Built-in services | no             | bundled rules database (per service)     |
| ADBlock           | no             | bundled rules database                   |
| Custom            | yes            | authored in-app, imported, or subscribed |

The action is one of **Default**, **PROXY**, **DIRECT**, **REJECT**, or a
specific proxy configuration / chain:

- **Default** places the set in the lowest authored priority tier
  (**Neutral** — see below). A neutral match routes to the default route
  target. A set on Default never overrides a set with an explicit action.
- **PROXY** routes to the default route target, but as an explicit action.
  No proxy is pinned into the payload — the target is resolved at match time.
- The action is per-*set*: a single set cannot both reject some hosts and
  proxy others. Split divergent policy across multiple sets.
- An assignment pointing at a deleted proxy or chain deactivates the set; the
  app also resets such orphaned assignments back to Default.

Custom sets are created three ways: built by hand in the app, **imported**
from a `.arrs` file, or **subscribed** to a `.arrs` URL (see
[Subscriptions](#subscriptions)). A custom set holds at most **100,000
rules**.

---

## Rule types

Every rule is a `(type, value)` pair. The type is an integer ID; the value is
a domain or a CIDR.

| ID  | Type           | Value example      | Matches against  |
| --- | -------------- | ------------------ | ---------------- |
| `0` | IPv4 CIDR      | `10.0.0.0/8`       | destination IP   |
| `1` | IPv6 CIDR      | `2001:db8::/32`    | destination IP   |
| `2` | Domain Suffix  | `example.com`      | destination host |
| `3` | Domain Keyword | `example`          | destination host |

### Domain Suffix (`2`)

Right-anchored, **label-aligned** match. `example.com` matches `example.com`
and any subdomain (`www.example.com`, `a.b.example.com`) but **not**
`myexample.com` — labels must align on the dots. A bare TLD like `com`
matches every `.com` host. This is the type to prefer: it is a fast
reverse-label trie walk and says exactly what it means.

### Domain Keyword (`3`)

Raw **substring** match anywhere in the host (an Aho–Corasick automaton).
`example` matches `example.com`, `myexample.net`, and `cdn.example-images.org`
alike. Far more prone to false positives than a suffix — reserve keywords for
tokens that float in the middle of the host.

### IPv4 / IPv6 CIDR (`0` / `1`)

Standard CIDR notation. A bare address is normalized to a single-host route
(`/32` for IPv4, `/128` for IPv6) at parse time. Host bits below the prefix
are zeroed when the rule is loaded, so `10.0.0.5/8` and `10.0.0.0/8` are
equivalent. A value that does not parse as a valid CIDR survives import but is
dropped silently at load, so it never matches.

---

## Matching: priority and specificity

Two things decide which rule wins: the **tier** it loads into, and its
**specificity** within that tier.

### Tier priority — first hit wins

Tiers are consulted in a fixed order; the first tier containing a match
decides, and lower tiers are not consulted.

| Order | Tier           | Contents                                       |
| ----- | -------------- | ---------------------------------------------- |
| 1     | ADBlock        | the bundled ad/tracker block list              |
| 2     | Built-in       | the per-service rule sets                      |
| 3     | User           | your custom rule sets                          |
| 4     | Neutral        | any set left on **Default**, whatever its origin |
| 5     | Country Bypass | direct-routes the selected region (implicit)   |

A set loads into the tier matching its origin only while it carries an
explicit action — **PROXY** included, even though it routes to the same target
Neutral does; on **Default** it drops into Neutral instead. Cross-tier
priority is by **tier, not specificity**: an ADBlock rule beats a
more-specific User rule for the same host. Country Bypass is driven by the
selected country code (bundled per-country rules, always **direct**) and is
off when no country is selected; neither it nor Neutral is authored through
`.arrs`.

### Specificity — within a tier

All sets in a tier share one matcher, so these comparisons cross set
boundaries:

- **Domain Suffix beats Domain Keyword.** Keywords are consulted only when no
  suffix matches.
- Among suffixes, the **deepest** (most labels) match wins: `api.example.com`
  beats `example.com`.
- Among keywords, the **longest** pattern wins; equal lengths go to the
  later-inserted pattern.
- Among CIDRs, the **longest prefix** wins: `10.0.0.0/24` beats `10.0.0.0/8`.
- **Identical patterns** resolve to the later-inserted one. Within a set,
  rules insert in file order; sets load in reverse list order, so of two sets
  in the same tier the one **higher in the Routing list** wins the tie.

Matching is **case-insensitive**: rule values and queried hosts are folded to
lowercase.

---

## The import format

A rule set file (`.arrs`) is a flat sequence of **header lines** and **rule
lines**, in any order. Blank lines are ignored; lines beginning with `#` or
`//` are comments. Parsing never hard-fails — a line that is neither a
recognized header nor a valid rule is dropped silently, so a partially valid
file still imports what it can.

```
# A complete example
name = My Rule Set
# routing: 0 Default · 1 Direct · 2 Reject (applied on first import only)
routing = 1

# Domain rules
2, example.com
3, example

# IP rules
0, 10.0.0.0/8
1, 2001:db8::/32
```

### Header lines

Shape: `<key> = <value>`. Keys are case-insensitive; the value is trimmed and
otherwise kept verbatim — there is **no** inline `#` comment after a value.

| Key          | Meaning                                                                       |
| ------------ | ----------------------------------------------------------------------------- |
| `name`       | Display name for the rule set.                                                |
| `routing`    | Initial action, applied on first import: `0` Default, `1` Direct, `2` Reject. |
| `icon-light` | Base64-encoded image bytes for the icon shown in light appearance.            |
| `icon-dark`  | Base64-encoded image bytes for the icon shown in dark appearance.             |

Lines with unrecognized keys are dropped. If `name` is absent or empty, the
importer falls back to the file (or URL) basename, then to `Imported` /
`Subscription`.

The `routing` value seeds the set's action when the set is created: `1`
assigns **DIRECT**, `2` assigns **REJECT**, and `0` — or an absent or
unrecognized value — leaves the set on **Default**. A subscription refresh
ignores it, so re-fetching never overrides the action set locally. A specific
proxy target cannot be expressed this way — assign one in the app.

The icon headers embed the image shown next to the rule set in the app. One
variant suffices: when the current appearance has no icon, the other variant
is used. A value that is not valid base64 or decodes to more than **256 KB**
(or to zero bytes) is dropped.

### Rule lines

Shape:

```
<type>, <value>
```

- **Type** is one of the IDs in [Rule types](#rule-types) (`0`–`3`).
- **Value** is the domain or CIDR. A bare IPv4 / IPv6 address is normalized to
  `/32` / `/128`; domains are kept verbatim.

A line whose type is not `0`–`3`, or whose value is empty, is dropped. CIDR
validity is not checked at import — a malformed CIDR survives parsing but is
discarded at load.

---

## Subscriptions

A subscription is a `.arrs` file served over **http(s)** from a URL whose path
ends in `.arrs`. Anywhere fetches it (HTTP 2xx, UTF-8 body required), parses
it with the format above, and stores the result as a custom set.

On **refresh**, the rules and icons are **replaced** wholesale by the fetched
file; the set's local name and assignment are untouched, and the `routing`
header is ignored. A refresh that changes nothing is a no-op. A subscribed
set's rules are read-only in the app — renaming and reassigning are allowed,
editing rules is not.

The **100,000-rule** cap applies; a file that exceeds it is rejected in full
rather than truncated.

---

## Limits

| Limit                    | Value             | Effect on exceed                                 |
| ------------------------ | ----------------- | ------------------------------------------------ |
| Rules per custom set     | 100,000           | import / subscription / refresh rejected in full |
| Rule value length        | 65,535 UTF-8 bytes | rule dropped when the payload is built           |
| Icon size (decoded)      | 256 KB            | icon dropped at parse                            |
| Set name in request log  | 64 characters     | truncated for attribution                        |

Other safety properties:

- **Lenient import.** Unrecognized headers, malformed rule lines,
  out-of-range types, and empty values are dropped silently; a partial file
  still imports what it can.
- **Deferred CIDR validation.** A syntactically invalid CIDR passes import but
  is discarded when the routing tables are built, so it simply never matches.
- **Corruption-tolerant storage.** An unreadable rule in a stored set is
  skipped on load rather than discarding the whole set.

---

## Worked examples

### Route a service through a proxy

```
name = Streaming
2, example-stream.com
2, examplecdn.net
```

Import, then assign the set to a proxy. Every host under those two domains now
egresses through it.

### Block trackers

```
name = Trackers
2, tracker.example.com
3, analytics
```

Assign the set to **REJECT**. The suffix blocks one tracker domain and its
subdomains; the keyword catches any host containing `analytics` — broad, per
the suffix-vs-keyword trade-off above. Rejected domains are blocked at DNS
time as well.

### Keep LAN ranges direct

```
name = Direct Nets
0, 10.0.0.0/8
0, 192.168.0.0/16
1, fd00::/8
```

Assign the set to **DIRECT**. The explicit action puts it in the User tier,
above any set left on Default — but below a built-in service set you assigned
a target. Leave built-ins on Default if a LAN rule must win.

### Prefer a specific subdomain over a broad one

If one set proxies `example.com` but `api.example.com` needs different
handling, put `api.example.com` in a **separate** set with its own action: the
deeper suffix wins within the tier regardless of set order.

---

## Behavior reference

- **Rule mode only.** Global mode routes everything through the default
  target without consulting rules; Direct mode bypasses the proxy entirely.
- **Domain rules win.** A connection with a known host (fake-IP DNS or
  sniffed SNI) is classified by suffix/keyword rules; CIDR rules apply to
  literal-IP traffic and, unless Prevent DNS Leak is on, to unmatched domains
  via their resolved IPv4.
- **Reject is enforced early.** Reject-matched domains get null DNS answers;
  reject-marked domains and IPs are dropped at packet intake.
- **First tier wins.** ADBlock > Built-in > User > Neutral > Country Bypass; a
  higher tier beats a more-specific rule in a lower one.
- **Most-specific wins within a tier.** Deepest suffix, longest keyword,
  longest CIDR prefix; suffix before keyword; identical patterns go to the
  later-inserted rule (the set higher in the Routing list).
- **Action is per set.** Every rule shares the set's assigned target; a set on
  Default matches from the Neutral tier and routes to the default target, and
  one on PROXY routes to that same default target from its own tier.
- **No-match fall-through.** Unmatched destinations take the default route:
  selected chain, else selected configuration, else the tunnel's
  configuration.
- **Case-insensitive.** Hosts and rule values are folded to lowercase.

---

## Code map

| Area | Location |
| ---- | -------- |
| `.arrs` parsing, `routing` header | `Anywhere/Views/Pages/Routing/RoutingRuleParser.swift` |
| Import / subscribe UI | `Anywhere/Views/Pages/Routing/RoutingView.swift` |
| Rule model, binary payload layout (`ARB2`) | `Shared/Models/RoutingRule.swift` |
| Set storage, 100,000-rule cap, assignments | `Shared/DataStore/RoutingRuleSetStore.swift` |
| Payload compilation, tier assignment | `Shared/Operations/RoutingExportOperation.swift` |
| Subscription refresh | `Shared/Operations/RoutingRuleSetOperations.swift` |
| Tiered matcher, keyword automaton, CIDR tries | `Shared/Networking/Routing/TieredRouteMatcher.swift` |
| Suffix trie | `Shared/Networking/Routing/FlatLabelTrie.swift` |
| Payload decoding, per-tier lookup | `Anywhere Network Extension/Routers/DomainRouter.swift` |
| Connection decisions, reject marks, IP fallback | `Anywhere Network Extension/Routers/ConnectionRouter.swift` |
| Bundled services / ADBlock / country rules | `Shared/DataStore/RoutingRulesDatabase.swift`, `Shared/Catalog/` |
