# Routing Rule System — Developer Guide

Anywhere decides, for every connection, whether to send it **direct**, to
**reject** it, or to route it through a chosen **proxy** — based on the
connection's destination. Routing rules are how you express that policy. This
guide covers authoring rule sets and the `.arrs` import format. It is
reference-level and assumes you are comfortable with domain names and CIDR
notation. It does **not** cover the settings UI beyond what authoring requires.

> **The action is not in the file.** A rule set's rules say *which*
> destinations it matches; the *action* (direct / reject / a specific proxy)
> is assigned to the whole set in the app, under **Routing Rules**. An
> imported or subscribed file therefore carries only a name and a list of
> rules — you wire it to a target after importing.

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

---

## How it works

When a new connection is accepted, Anywhere knows its destination as a
**domain** (resolved through fake-IP DNS, or read from the TLS SNI) and/or a
literal **IP address**. It asks the router to classify that destination:

- **Domain rules** (suffix, keyword) are tested against the destination host.
- **IP rules** (CIDR) are tested against the destination IP.

These are two independent lookups. A connection with a known host is matched
by domain rules; one routed by raw IP is matched by IP rules. When a
connection has *both* a host and an IP, the **domain decision wins** — a
later-resolved domain rule overrides a route an IP-CIDR rule tentatively set
at accept time.

The matching rule's **rule set** carries the action, so a match resolves to
one of:

- **direct** — bypass the proxy and connect straight to the destination.
- **reject** — drop the connection (TCP is closed / a TLS alert is sent).
- **proxy** — route through the configuration or chain assigned to that set.

A connection that matches **no** rule takes the app's **default route** (the
globally selected proxy, or direct in the relevant mode). Routing rules only
*override* that default for the destinations they match — an empty or
fully-unmatched rule base changes nothing.

---

## Rule sets

A rule set is the unit of configuration: a **name**, an ordered list of
**rules**, and one **assigned action** that applies to every rule in the set.

| Origin            | Editable rules | Source                                        |
| ----------------- | -------------- | --------------------------------------------- |
| Built-in services | no             | bundled per-service catalog                   |
| ADBlock           | no             | bundled database                              |
| Custom            | yes            | authored in-app, imported, or subscribed      |

The action is one of **Default**, **DIRECT**, **REJECT**, or a specific proxy
/ chain, chosen per set in **Routing Rules**:

- **Default** means the set is **inactive** — its rules are not loaded into the
  router and match nothing. A set only participates once you assign it a real
  target.
- Because the action is per-*set*, a single set cannot both reject some hosts
  and proxy others. Split divergent policy across multiple sets.

Custom sets are created three ways: built by hand in the app, **imported** from
a `.arrs` file, or **subscribed** to a `.arrs` URL (see
[Subscriptions](#subscriptions)). A custom set holds at most
**10,000 rules**.

---

## Rule types

Every rule is a `(type, value)` pair. The type is an integer ID; the value is
a domain or a CIDR.

| ID  | Type           | Value example      | Matches against |
| --- | -------------- | ------------------ | --------------- |
| `0` | IPv4 CIDR      | `10.0.0.0/8`       | destination IP  |
| `1` | IPv6 CIDR      | `2001:db8::/32`    | destination IP  |
| `2` | Domain Suffix  | `example.com`      | destination host|
| `3` | Domain Keyword | `example`          | destination host|

### Domain Suffix (`2`)

Right-anchored, **label-aligned** match. `example.com` matches `example.com`
and any subdomain (`www.example.com`, `a.b.example.com`) but **not**
`myexample.com` — labels must align on the dots. A bare TLD like `com` matches
every `.com` host. This is the type to reach for: it is fast (a reverse-label
trie walk) and says exactly what it means.

### Domain Keyword (`3`)

Raw **substring** match anywhere in the host. `example` matches `example.com`,
`myexample.net`, and `cdn.example-images.org` alike. It is both slower and far
more prone to false positives than a suffix, so **prefer Domain Suffix
whenever a suffix can express the intent**; reserve keywords for cases where
the meaningful token floats in the middle of the host.

### IPv4 / IPv6 CIDR (`0` / `1`)

Standard CIDR notation. A bare address with no prefix is normalized to a
single-host route — `/32` for IPv4, `/128` for IPv6 — at import. Host bits
below the prefix are zeroed when the rule is loaded, so `10.0.0.5/8` and
`10.0.0.0/8` are equivalent. A value that does not parse as a valid CIDR is
dropped silently when rules are loaded.

---

## Matching: priority and specificity

Two things decide which rule wins: which **source tier** it came from, and how
**specific** it is within that tier.

### Tier priority — first hit wins

Rules are grouped by source and the tiers are consulted in a fixed order; the
first tier that matches decides, and lower tiers are not consulted.

| Order | Tier           | Typical use                                  |
| ----- | -------------- | -------------------------------------------- |
| 1     | User (custom)  | your own rule sets                           |
| 2     | ADBlock        | the bundled ad/tracker block list            |
| 3     | Built-in       | the per-service rule sets                    |
| 4     | Country Bypass | direct-route the selected region (implicit)  |

Cross-tier priority is by **source, not specificity**: a User rule wins over a
*more-specific* Built-in rule for the same host. Country Bypass is driven by
the selected country code and always implies **direct**; it is not authored
through `.arrs`. All of your custom sets share the single **User** tier, so
between two custom sets the more-specific rule wins regardless of which set it
lives in.

### Specificity — within a tier

- **Domain Suffix beats Domain Keyword.** The keyword automaton is consulted
  only when no suffix matches.
- Among suffixes, the **deepest (most-specific) wins**: `api.example.com`
  beats `example.com`.
- Among keywords, the **longest pattern wins**; an exact-length tie is broken
  by the **last one defined**.
- Among CIDRs, **longest prefix wins**: `10.0.0.0/24` beats `10.0.0.0/8`.
- Two identical patterns are **last-write-wins**.

Matching is **case-insensitive**: hosts and rules are compared in lowercase.

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

# Domain rules
2, example.com
3, example

# IP rules
0, 10.0.0.0/8
1, 2001:db8::/32
```

### Header lines

Shape: `<key> = <value>`. Keys are case-insensitive; the value is trimmed and
otherwise kept verbatim.

| Key    | Meaning                                                              |
| ------ | ------------------------------------------------------------------- |
| `name` | Display name for the rule set. Unrecognized keys are ignored.       |

If `name` is absent or empty, the importer falls back to the file name (or
`Imported` / `Subscription`).

### Rule lines

Shape:

```
<type>, <value>
```

- **Type** is one of the IDs in [Rule types](#rule-types) (`0`–`3`).
- **Value** is the domain or CIDR. A bare IPv4 / IPv6 address is normalized to
  `/32` / `/128`; domains are kept verbatim.

A line whose type is not `0`–`3`, or whose value is empty, is dropped. CIDR
validity itself is not checked at import — a malformed CIDR survives parsing
but is discarded later when rules are loaded.

> **Remember:** the file sets the name and the rules only. After importing,
> open the set in **Routing Rules** and assign it a target (DIRECT, REJECT, or
> a proxy) — until you do, it is inactive.

---

## Subscriptions

A subscription is a `.arrs` file served over **http(s)** from a URL whose path
ends in `.arrs`. Anywhere fetches it, parses it with the format above, and
stores the result as a custom set. On **refresh**, the rules are **replaced**
wholesale by the freshly fetched file, while the name you gave the set locally
is **preserved** across refreshes — so a remote rename does not clobber yours,
and you keep editing the assignment, not the rules.

The same **10,000-rule** cap applies; a file that exceeds it is rejected in
full rather than truncated.

---

## Limits

| Limit                          | Value   | Effect on exceed                       |
| ------------------------------ | ------- | -------------------------------------- |
| Rules per custom set           | 10,000  | import / subscription rejected in full |
| Domain pattern length          | 65,535 B| pattern dropped (effectively never hit)|

Other safety properties:

- **Lenient import.** Unrecognized header keys, malformed rule lines,
  out-of-range types, and empty values are dropped silently; a partial file
  still imports what it can.
- **Deferred CIDR validation.** A syntactically odd CIDR passes import but is
  discarded when the routing tables are built, so it simply never matches.
- **Corruption-tolerant storage.** A single unreadable rule in a stored set is
  skipped on load rather than discarding the whole set.

---

## Worked examples

### Route a service through a proxy

```
name = Streaming
2, example-stream.com
2, examplecdn.net
```

Import, then assign the set to your proxy. Every host under those two domains
now egresses through it.

### Block trackers (reject)

```
name = Trackers
2, tracker.example.com
3, analytics
```

Assign the set to **REJECT**. The suffix blocks one tracker domain and all its
subdomains; the keyword catches any host containing `analytics` (broad — see
the suffix-vs-keyword trade-off above).

### Keep LAN and a CIDR direct

```
name = Direct Nets
0, 10.0.0.0/8
0, 192.168.0.0/16
1, fd00::/8
```

Assign the set to **DIRECT** so private ranges bypass the proxy. Because User
rules outrank built-in tiers, this wins over any service rule that would
otherwise proxy an address in these ranges.

### Prefer a specific subdomain over a broad one

```
name = Split Example
2, example.com
2, api.example.com
```

If this set proxies `example.com` but you want `api.example.com` handled
differently, put `api.example.com` in a **separate** set with its own action:
the more-specific suffix wins within the User tier regardless of set order.

---

## Behavior reference

- **Domain vs IP are separate lookups.** A connection resolved to a host is
  classified by suffix/keyword rules; one routed by raw IP, by CIDR rules.
  When both apply, the domain decision overrides the IP-derived route.
- **Suffix is label-aligned.** `example.com` covers `example.com` and its
  subdomains, never `myexample.com`.
- **Keyword is a raw substring.** Broader and slower than a suffix; prefer a
  suffix when one expresses the intent.
- **First tier wins.** User > ADBlock > Built-in > Country Bypass; a User rule
  beats a more-specific rule in a lower tier.
- **Most-specific wins within a tier.** Deepest suffix, longest keyword,
  longest CIDR prefix; identical patterns are last-write-wins.
- **Action is per set.** Every rule in a set shares the set's assigned target;
  a set assigned **Default** is inactive.
- **No-match fall-through.** Unmatched destinations follow the app's default
  route; rules only override it where they match.
- **Case-insensitive.** Hosts and rules are folded to lowercase before
  comparison.
