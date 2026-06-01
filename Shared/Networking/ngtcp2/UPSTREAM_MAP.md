# ngtcp2 Vendoring Map & Upgrade Guide

This directory is a **vendored, flattened** copy of [ngtcp2](https://github.com/ngtcp2/ngtcp2)
plus a custom Apple/CryptoKit crypto backend and a "brutal" congestion-control add-on.

- **Current version:** `1.23.0` (see `ngtcp2/version.h`)
- **Upstream layout** (`lib/`, `crypto/`, `lib/includes/`) is **flattened** into this single
  directory. Header search path is just `$(SRCROOT)/Shared/Networking/ngtcp2`.

The single rule that makes upgrades mechanical:

> **Custom files carry a `// Created by NodePassProject` header.
> Stock files carry a `/* Copyright (c) <year> ngtcp2 contributors */` header.**
>
> Stock files are pristine upstream and are replaced wholesale on every upgrade.
> Custom files are hand-maintained and must be preserved.

---

## 1. File classification

### Custom files — NEVER overwrite from upstream (6 files)

| File | Role | Upstream equivalent it stands in for |
|------|------|--------------------------------------|
| `config.h`                | Hand-written Apple config (replaces generated `config.h`) | `cmakeconfig.h.in` / `configure` output |
| `ngtcp2/version.h`        | Hand-written version header (bump on each upgrade)         | `lib/includes/ngtcp2/version.h.in` |
| `ngtcp2_crypto_apple.c`   | **Custom TLS/crypto backend** (CommonCrypto + Swift CryptoKit callbacks) | a backend file like `crypto/quictls/quictls.c` |
| `ngtcp2_bridge.h`         | C↔Swift bridge: AEAD callback typedefs + Apple cipher IDs  | — (project glue) |
| `ngtcp2_swift_bridge.h`   | C↔Swift bridge declarations                                | — (project glue) |
| `ngtcp2_swift_brutal.c`   | "Brutal" congestion control, calls into Swift              | — (project add-on) |

### Stock files — replace wholesale from upstream

Everything else — i.e. every top-level `.c`/`.h` except the 4 custom ones above (the directory
holds 49 `.c` + 55 `.h` in total, of which 2 `.c` + 3 `.h` are custom), plus `ngtcp2/ngtcp2.h`
and `ngtcp2/ngtcp2_crypto.h`. The mapping from this directory → upstream tree:

| Vendored path                | Upstream source path                          |
|------------------------------|-----------------------------------------------|
| `ngtcp2_*.c`, `ngtcp2_*.h`   | `lib/ngtcp2_*.c`, `lib/ngtcp2_*.h`            |
| `shared.c`, `shared.h`       | `crypto/shared.c`, `crypto/shared.h`          |
| `ngtcp2/ngtcp2.h`            | `lib/includes/ngtcp2/ngtcp2.h`                |
| `ngtcp2/ngtcp2_crypto.h`     | `crypto/includes/ngtcp2/ngtcp2_crypto.h`      |

> Note: `ngtcp2_crypto.c` / `ngtcp2_crypto.h` at the **top level** are the *lib-internal*
> crypto files (`lib/ngtcp2_crypto.{c,h}`), NOT the crypto helper. The crypto **helper**
> is `shared.{c,h}` + `ngtcp2/ngtcp2_crypto.h`. Don't confuse them.

---

## 2. Crypto backend architecture (why there's no symbol clash)

Upstream splits the `libngtcp2_crypto` helper into two halves:

- **Backend-agnostic** glue → `crypto/shared.c` → vendored as `shared.c` (stock).
- **Backend-specific** primitives + a few high-level functions → one backend file per TLS
  stack (`quictls.c`, `boringssl.c`, `gnutls.c`, …). **`ngtcp2_crypto_apple.c` is our backend.**

`shared.c` and `ngtcp2_crypto_apple.c` define **disjoint** symbol sets, so both can compile
into the same target without duplicate-symbol errors. The Apple backend provides, among
others: `ngtcp2_crypto_aead_init`, `ngtcp2_crypto_{encrypt,decrypt,hp_mask}`,
`ngtcp2_crypto_hkdf*`, `ngtcp2_crypto_ctx_{initial,tls,tls_early}`,
`ngtcp2_crypto_read_write_crypto_data`, `ngtcp2_crypto_set_{remote,local}_transport_params`,
`ngtcp2_crypto_get_path_challenge_data{,2}_cb`, `ngtcp2_crypto_random`.

**If a future upstream adds a new backend primitive**, every stock backend file gains it, but
`ngtcp2_crypto_apple.c` will NOT — you must implement it by hand. The symbol check in §5
catches this (it shows up as an undefined `ngtcp2_crypto_*`).

### Swift-provided symbols (resolved at link time by the Swift side, not by C)

The C code calls into Swift for these (declared in `ngtcp2_swift_bridge.h`):
`ngtcp2_swift_brutal_{reset,on_pkt_sent,on_pkt_acked,on_pkt_lost,on_ack_recv}`.
They are expected to be undefined in the C objects — that is normal.

---

## 3. Build wiring (Xcode)

- `GCC_PREPROCESSOR_DEFINITIONS` includes `HAVE_CONFIG_H=1` → stock headers `#include <config.h>`,
  which resolves to our hand-written `config.h`.
- `HEADER_SEARCH_PATHS = $(SRCROOT)/Shared/Networking/ngtcp2` → makes both `<ngtcp2/ngtcp2.h>`
  and `<config.h>` resolve.
- Project uses **file-system-synchronized groups**. All `.c` here are members of the
  **Anywhere** and **Anywhere TV** targets, and are *excluded* from the **Network Extension**
  target via a `membershipExceptions` list in `project.pbxproj`.
- **When upstream adds or removes a file**, the synchronized group picks it up automatically,
  BUT you must add/remove it from the Network-Extension `membershipExceptions` list so it stays
  excluded there. (Between 1.22.90 → 1.23.0 there were no added/removed files.)

`config.h` currently provides: `HAVE_ARPA_INET_H`, `HAVE_NETINET_IN_H`, `HAVE_UNISTD_H`,
`HAVE_MEMSET_S`, `HAVE_DECL_BE64TOH=0`, `HAVE_DECL_BSWAP_64=0`; everything else
(`HAVE_ENDIAN_H`, `HAVE_SYS_ENDIAN_H`, `HAVE_BYTESWAP_H`, `WORDS_BIGENDIAN`, `HAVE_LIBBROTLI`,
`HAVE_EXPLICIT_BZERO`, `DEBUGBUILD`, …) is intentionally undefined for Apple/arm64.

---

## 4. Upgrade procedure

Set `UP` to the unpacked upstream release, then run from this directory.

```sh
cd /Volumes/Work/Anywhere/Shared/Networking/ngtcp2
UP=/Volumes/Work/ngtcp2-<NEW_VERSION>     # e.g. ngtcp2-1.24.0
CUSTOM="config.h ngtcp2_bridge.h ngtcp2_crypto_apple.c ngtcp2_swift_bridge.h ngtcp2_swift_brutal.c"
```

**Step 1 — sanity: detect added/removed files (handle these manually).**
```sh
# Files upstream added to lib/ that we don't have yet:
for f in "$UP"/lib/*.c "$UP"/lib/*.h; do b=$(basename "$f"); [ -e "$b" ] || echo "ADDED upstream: lib/$b"; done
# Vendored stock files that no longer exist upstream (removed/renamed):
for f in *.c *.h; do case " $CUSTOM " in *" $f "*) continue;; esac;
  [ -e "$UP/lib/$f" ] || [ -e "$UP/crypto/$f" ] || echo "ORPHAN (removed upstream?): $f"; done
```
If anything prints, resolve it by hand (vendor the new file / drop the old one, and update
the Network-Extension `membershipExceptions` in `project.pbxproj`).

**Step 2 — copy all stock files (custom files are skipped).**
```sh
for f in *.c *.h; do
  case " $CUSTOM " in *" $f "*) continue;; esac
  case "$f" in shared.c|shared.h) src="$UP/crypto/$f";; *) src="$UP/lib/$f";; esac
  [ -e "$src" ] && cp "$src" "$f"
done
cp "$UP/lib/includes/ngtcp2/ngtcp2.h"             ngtcp2/ngtcp2.h
cp "$UP/crypto/includes/ngtcp2/ngtcp2_crypto.h"   ngtcp2/ngtcp2_crypto.h
```

**Step 3 — bump `ngtcp2/version.h`** (keep the NodePassProject header).
`NGTCP2_VERSION_NUM` is `0xMMmmpp` (major/minor/patch as 2-hex-digit each), matching
`AC_INIT` in `$UP/configure.ac`. e.g. `1.24.0` → `0x011800`.

**Step 4 — re-check config macros** (make sure no newly-referenced macro is missing):
```sh
grep -rhoE "HAVE_[A-Z0-9_]+|WORDS_BIGENDIAN|DEBUGBUILD" *.c *.h ngtcp2/*.h | sort -u \
  | while read m; do grep -q "$m" config.h || [ "$m" = HAVE_CONFIG_H ] || echo "MISSING in config.h: $m"; done
```

**Step 5 — reconcile the Apple backend** (`ngtcp2_crypto_apple.c`): see §2 + verify in §5.
If the helper interface (`ngtcp2/ngtcp2_crypto.h` / `shared.h`) changed signatures or added
backend primitives, port them into `ngtcp2_crypto_apple.c` by hand.

---

## 5. Verification (no full Xcode build required)

```sh
SDK=$(xcrun --sdk macosx --show-sdk-path)
OUT=/tmp/ngtcp2_obj; rm -rf "$OUT"; mkdir -p "$OUT"

# Compile every TU against the updated headers:
for f in *.c; do
  xcrun --sdk macosx clang -c -arch arm64 -DHAVE_CONFIG_H -I. -isysroot "$SDK" \
        -Wno-everything "$f" -o "$OUT/${f%.c}.o" || echo "COMPILE FAIL: $f"
done

# (a) Duplicate symbol definitions — must be empty:
nm -A "$OUT"/*.o | awk '$2 ~ /^[TtDdSsBb]$/{print $3}' | grep '^_ngtcp2' | sort | uniq -d

# (b) Unresolved ngtcp2_* symbols — must list ONLY the 5 ngtcp2_swift_brutal_* funcs:
nm "$OUT"/*.o | awk '$1=="U"{print $2}' | grep '^_ngtcp2' | sort -u > /tmp/u.txt
nm "$OUT"/*.o | awk '$2 ~ /^[TtDdSsBbR]$/{print $3}' | grep '^_ngtcp2' | sort -u > /tmp/d.txt
comm -23 /tmp/u.txt /tmp/d.txt
```

Expected clean result:
- (a) prints nothing.
- (b) prints exactly:
  `_ngtcp2_swift_brutal_on_ack_recv`, `_ngtcp2_swift_brutal_on_pkt_acked`,
  `_ngtcp2_swift_brutal_on_pkt_lost`, `_ngtcp2_swift_brutal_on_pkt_sent`,
  `_ngtcp2_swift_brutal_reset` (all Swift-implemented — fine).

Anything else in (b) is a **missing backend function** to implement in `ngtcp2_crypto_apple.c`.

Finally, confirm only stock files + `version.h` changed and the 5 other custom files are untouched:
```sh
git -C /Volumes/Work/Anywhere status --short -- Shared/Networking/ngtcp2
for f in config.h ngtcp2_bridge.h ngtcp2_crypto_apple.c ngtcp2_swift_bridge.h ngtcp2_swift_brutal.c; do
  git -C /Volumes/Work/Anywhere diff --quiet -- "Shared/Networking/ngtcp2/$f" || echo "REVIEW: $f changed"
done
```

---

## 6. History

| Date       | From      | To       | Notes |
|------------|-----------|----------|-------|
| 2026-06-01 | 1.22.90   | 1.23.0   | 34 stock files refreshed + version bump. No files added/removed upstream; no Apple-backend changes needed. |
