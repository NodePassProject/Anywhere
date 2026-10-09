# Modules — Developer Guide

A module bundles several **routing rule sets** and **MITM rule sets** into one
unit that is created in the app, **imported** from a `.amod` file, or
**subscribed** to a `.amod` URL. It lets an author ship a complete behavior
for a service (what to proxy, what to block, what to rewrite) as a single
file, and lets a user switch all of it on or off, update it, or delete it in
one place. This guide covers the module model, the `.amod` format, and how a
module's rule sets take part in routing and MITM. It assumes familiarity with
the [Routing](Routing.md) and [MITM](MITM.md) guides, whose rule formats a
module reuses unchanged.

## Contents

- [How it works](#how-it-works)
- [The module](#the-module)
- [The import format](#the-import-format)
- [Subscriptions](#subscriptions)
- [Limits](#limits)
- [Worked example](#worked-example)
- [Behavior reference](#behavior-reference)
- [Code map](#code-map)

---

## How it works

A module **owns** its rule sets. They are stored inside the module record,
have no subscription URL, icon, or sync identity of their own, and are only
reachable through the module. One module is one sync item: it is written,
synced, and conflict-resolved as a whole, so another device never sees a
module with some of its rule sets missing.

When routing or MITM configuration changes, the app compiles two payloads for
the Network Extension, and a module's rule sets ride in the same payloads as
the standalone ones:

- **Routing.** Each routing rule set in an **enabled** module becomes one
  entry in the `ARB2` payload, exactly like a custom set: its assigned action
  places it in the **User** tier, and a set left on **Default** drops into
  **Neutral**. A disabled module contributes nothing. The entry carries the
  module-qualified name (`Module · Set`) so request logs can attribute a
  match.
- **MITM.** Each MITM rule set in an **enabled** module ships in the `AMR1`
  payload under its module-qualified name. A set is active only when both the
  module switch and the set's own switch are on, and only while MITM itself
  is enabled.

Where a module set and a standalone set tie exactly (an identical routing
pattern in the same tier, or the same MITM host suffix), the **standalone set
wins**: the user's own configuration beats anything distributed. Among
modules, the one higher in the Modules list wins, and within a module the set
listed first.

A module's routing sets are assigned a target one by one, under the module's
detail page, with the same **Default / PROXY / DIRECT / REJECT / proxy /
chain** choices as any other set. Assignments are device-local, like all
routing assignments, and are stored apart from the standalone ones.

---

## The module

| Field             | Meaning |
| ----------------- | ------- |
| `name`            | Display name. Kept locally; a subscription refresh never renames the module. |
| `enabled`         | Master switch. Off, the module's rule sets leave both payloads but keep their data. |
| `subscriptionURL` | Set when the module was subscribed; its rule sets are then read-only. |
| `iconLight` / `iconDark` | Optional icons from the file, at most **64 KB** each. |
| `routingRuleSets` | Ordered list of `{ id, name, rules }`. |
| `mitmRuleSets`    | Ordered list of `{ id, name, enabled, domainSuffixes, rules, parameters, parameterValues }`. |

A rule set's `id` is stable across refreshes (see [Subscriptions](#subscriptions)),
which is what keeps its routing assignment, its switch, and its parameter
values attached. A module created in the app starts empty; add routing and
MITM rule sets from its detail page and edit them rule by rule, as with
standalone sets.

---

## The import format

A module file (`.amod`) is a sequence of **sections**, each introduced by a
bracketed marker on its own line. Three markers are recognized, case-
insensitively:

| Marker      | Body |
| ----------- | ---- |
| `[Module]`  | Module header lines (below). Lines before the first marker also belong here. |
| `[Routing]` | One routing rule set, in the `.arrs` format of the [Routing guide](Routing.md#the-import-format). |
| `[MITM]`    | One MITM rule set, in the `.amrs` format of the [MITM guide](MITM.md#the-import-format). |

Each section body is handed **verbatim** to the corresponding rule set parser,
so everything those formats allow applies unchanged. In particular a MITM
body may contain its own `[Parameter]` sub-section: any bracketed line that is
not one of the three markers above stays inside the current body. A section
may appear any number of times, in any order.

### Module header lines

Shape: `<key> = <value>`, case-insensitive key, trimmed value.

| Key          | Meaning |
| ------------ | ------- |
| `name`       | Display name for the module. Falls back to the file or URL basename. |
| `icon-light` | Base64-encoded image for light appearance, at most **64 KB** decoded. |
| `icon-dark`  | Base64-encoded image for dark appearance, same cap. |

Unrecognized keys are dropped. An icon that is not valid base64 or exceeds the
cap is dropped; when the current appearance has no icon the other is used.

### Rule set sections

Inside a `[Routing]` or `[MITM]` section the rule set's own headers apply:
`name`, `routing` (routing sets), `hostname` (MITM sets). A set's own
`icon-light` / `icon-dark` are ignored: rule sets inside a module carry no
icon. A section without a `name` is named by position, `Routing 1`, `MITM 2`,
and so on. A section with no rule, header, or parameter line at all is
skipped.

The `routing` header of a routing section seeds that set's assignment the
first time the set appears, exactly as for a standalone `.arrs` import; a
refresh never changes an assignment made in the app.

---

## Subscriptions

A subscription is a `.amod` file served over **http(s)** from a URL whose path
ends in `.amod`. Anywhere fetches it (HTTP 2xx, UTF-8 body required), parses
it, validates the [limits](#limits), and stores the result as one module.

On **refresh** the file is fetched once and the module's content is replaced
as a whole, in one write:

1. Each incoming rule set is matched to the module's existing set of the
   **same kind and name** (duplicates pair up in order). A matched set keeps
   its `id`, so its routing assignment, its switch, and its parameter values
   survive. Parameter overrides are kept while the parameter still exists
   and, for a picker, still offers that value.
2. A set that appears for the first time gets a new `id` and, for a routing
   set, its `routing` seed.
3. A set that disappeared is gone, and its assignment is dropped.
4. The module's **name**, **switch**, and subscription URL are untouched; its
   icons are replaced.

A refresh whose result is identical to what is stored is a no-op. A file that
fails the limits is rejected in full and the stored module is left as it was.
A subscribed module's rule sets are read-only in the app: their switches,
parameter values, and routing assignments can be changed, their rules and
names cannot.

A module can also be offered through the `anywhere://add-module?link=…` deep
link, where `link` is the `.amod` URL. The app previews the module's rule
sets and, on confirmation, subscribes to it.

---

## Limits

| Limit                         | Value |
| ----------------------------- | ----- |
| Rule sets per module          | **64**, routing and MITM combined |
| Rules per routing rule set    | 100,000 (as for a standalone set) |
| Rules per MITM rule set       | 10,000, and 256 parameters (as for a standalone set) |
| Icon, per variant             | **64 KB** decoded |
| Encoded module                | **900 KB** of JSON |

The last line is the one to design for. A module syncs as a single record and
a record larger than the sync payload limit never leaves the device, so an
import or refresh that would exceed it is **rejected outright** rather than
stored in a state that silently stops syncing. Icons count toward the budget
at four thirds of their byte size (they are base64 inside the JSON); a
domain-suffix rule costs roughly 35 bytes.

---

## Worked example

```
# My Service module
name = My Service
icon-light = iVBORw0KGgo…

[Routing]
name = My Service Direct
# 1 = DIRECT on first import
routing = 1
2, cdn.myservice.example
0, 203.0.113.0/24

[Routing]
name = My Service Trackers
# 2 = REJECT on first import
routing = 2
3, myservice-telemetry

[MITM]
name = My Service API
hostname = api.myservice.example
# request: add a header on API paths
0, 1, ^/v1/, X-Client, anywhere
# response: drop a cookie
1, 2, .*, Set-Cookie
[Parameter]
1, 0, region, Region, Used for region-specific rewrites., US, "[US, JP, DE]"
```

Imported, this yields one module with two routing rule sets (one seeded to
DIRECT, one to REJECT) and one MITM rule set with a `region` picker. Toggling
the module off removes all three from the Network Extension; turning it back
on restores them with their assignments and the chosen region intact.

---

## Behavior reference

- **One record.** A module and its rule sets are stored, synced, and merged
  as a single item; last writer wins for the whole module.
- **Module switch gates everything.** A disabled module contributes no
  routing entries and no MITM sets; a MITM set also needs its own switch.
- **Same tiers, same specificity.** Module routing sets load into User (or
  Neutral on Default) and compete by the rules in the Routing guide; on an
  exact tie a standalone set beats a module set, an earlier module beats a
  later one, and an earlier set beats a later one in the same module.
- **Standalone MITM wins duplicates.** For an identical host suffix the
  standalone set is the last writer and wins.
- **Assignments are per set and per device.** Seeded by `routing` on first
  appearance only, kept across refreshes by name matching, dropped when the
  set disappears or the module is deleted, and reset to Default when the
  assigned proxy or chain is deleted.
- **Subscribed is read-only.** Rules and names come from the file; switches,
  parameter values, and assignments are yours.
- **Limits are hard.** A module that cannot sync is not imported.

---

## Code map

| Area | Location |
| ---- | -------- |
| Module, rule set, and content model; limits; `ModuleImportError` | `Shared/Models/Module.swift` |
| Storage, child edits, assignments, refresh merge, MITM export projection | `Shared/DataStore/ModuleStore.swift` |
| Add / remove / edit / refresh, import helpers, export scheduling | `Shared/Operations/ModuleOperations.swift` |
| `.amod` section splitting | `Anywhere/Views/Pages/Modules/ModuleParser.swift` |
| Routing payload, module entries and tie order | `Shared/Operations/RoutingExportOperation.swift` |
| MITM payload, module sets and tie order | `Shared/Operations/MITMExportOperation.swift` |
| Module list, import / subscribe UI | `Anywhere/Views/Pages/Modules/ModulesView.swift` |
| Module detail, per-set assignment and switches | `Anywhere/Views/Pages/Modules/ModuleDetailView.swift` |
| Rule set editors shared with standalone sets | `Anywhere/Views/Pages/Routing/CustomRuleSetDetailView.swift`, `Anywhere/Views/Pages/MITM/MITMRuleSetDetailView.swift` |
| Deep-link preview and import | `Anywhere/Views/ImportModuleView.swift`, `Anywhere/DeepLinkManager.swift` |
| Device-local assignment storage | `Shared/AWCore.swift` (`moduleRuleSetAssignments`) |
