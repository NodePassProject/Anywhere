# Anywhere downstream modifications to wolfSSL

This directory contains a vendored copy of **wolfSSL 5.9.1** (upstream:
<https://github.com/wolfSSL/wolfssl>, GPLv2-or-later).

wolfSSL is distributed under the GPL. Any source-level modification we make
downstream must be clearly marked per GPLv2 §2(a). This file is the canonical
index of such modifications. When bumping wolfSSL, every file listed below
has to be re-audited and the hunks re-applied.

All downstream code is additive and gated by the single compile-time define

```c
#define ANYWHERE_CUSTOM_CLIENT_HELLO
```

set in `user_settings.h`. With that define unset, every modified file below
compiles to the exact upstream behavior (the patches consist only of `#ifdef`
branches, declarations, and new setter functions — no upstream line is deleted
or rewritten outside an `#ifdef` block).

Every downstream hunk is bracketed with the sentinel pair

```
/* --- BEGIN ANYWHERE PATCH: <short reason> ----------------------------- */
...
/* --- END ANYWHERE PATCH ---------------------------------------------- */
```

so `grep -n 'ANYWHERE PATCH'` over the wolfSSL tree lists every site.

---

## Feature: uTLS-style custom ClientHello injection

Purpose: let the application provide the raw ClientHello body bytes built by
`Protocols/TLS/TLSClientHelloBuilder.swift` (our uTLS port) while wolfSSL
drives the rest of the handshake — ServerHello processing, key schedule,
Certificate / CertificateVerify / Finished, record layer, session tickets.
wolfSSL upstream exposes no hook for this; the standard `wolfSSL_connect`
path builds its own ClientHello from internal state and never asks the
caller for the wire bytes.

### Files modified

| File | Sections | Upstream-diff sentinel |
|---|---|---|
| `user_settings.h`           | adds `ANYWHERE_CUSTOM_CLIENT_HELLO` define                                | n/a (project-owned file)          |
| `wolfssl/ssl.h`             | public API declarations for the four new setter/cb functions              | `ANYWHERE PATCH: custom-CH API`   |
| `wolfssl/internal.h`        | two fields on `struct WOLFSSL` (callback pointer + user ctx)              | `ANYWHERE PATCH: custom-CH state` |
| `src/tls13.c`               | two branches in `SendTls13ClientHello` (body substitution + PSK binder guard) | `ANYWHERE PATCH: custom-CH emit`, `ANYWHERE PATCH: skip PSK binders for custom-CH` |

### Files added

| File | Purpose |
|---|---|
| `src/anywhere_customch.c`   | Implements the four setter/cb functions. All-new file; entirely downstream. No upstream changes required. |

### Functions modified

| Symbol | File | Upstream line (v5.9.1) | Change |
|---|---|---|---|
| `SendTls13ClientHello`      | `src/tls13.c`               | 4572 | **Body substitution (custom-CH emit):** Inside `TLS_ASYNC_FINALIZE`, right after the in-tree body write, branch on `ssl->anywhereChCb`. If set, invoke callback, grow the output buffer if needed, re-stamp headers via `AddTls13Headers`, `memcpy` custom body into place, adjust `args->idx`/`args->length`/`args->sendSz`. Then **re-copy the 32 random bytes from the custom body into `ssl->arrays->clientRandom`** so every downstream path that hashes client_random (1.3 key schedule, Finished, 1.2 PRF after downgrade, ECDHE SignatureVerify) sees what actually went on the wire — wolfSSL's `CONNECT_BEGIN` branch earlier in the same function regenerates a fresh random into `clientRandom` that the injected body has since replaced. |
| `SendTls13ClientHello`      | `src/tls13.c`               | 5049 | **PSK binder skip (custom-CH binder guard):** Immediately before the `WritePSKBinders` branch, guard on `ssl->anywhereChCb`. When set, skip binders and fall through to `HashOutput`. `TLSX_PopulateExtensions` may add `TLSX_PRE_SHARED_KEY` to `ssl->extensions` (e.g. for session resumption). The upstream `WritePSKBinders` subtracts the binder length from `args->idx` to locate the binder slot — but the injected body has no `pre_shared_key` extension, so the write lands inside the custom body and corrupts it (server responds with `decode_error`). |

### Functions added (entirely downstream)

All in `src/anywhere_customch.c`:

- `wolfSSL_UseClientHelloRaw` — installs the build callback on a `WOLFSSL*`.
- `wolfSSL_SetClientHelloRandom` — overrides `ssl->arrays->clientRandom` so
  key derivation matches the random bytes the caller put into the injected
  ClientHello. Must be called before `wolfSSL_connect`.
- `wolfSSL_OfferKeyShare` — pushes a caller-owned public+private key pair
  onto `ssl->extensions` as a `KeyShareEntry`. Bypasses `TLSX_KeyShare_GenKey`
  so the group + keypair in the wire ClientHello matches the one wolfSSL
  later uses for ECDH when the server picks that group.
- `wolfSSL_OfferCipherSuites` — rewrites `ssl->suites->suites` from a
  wire-formatted list so wolfSSL's transcript / suite validation sees the
  same set the server does.
- `wolfSSL_SetClientHelloLegacySessionId` — parks `session_id` bytes on
  `ssl->session->sessionID` / `sessionIDSz`. The TLS 1.3 ServerHello
  validator (`tls13.c:5701`) compares the echoed ID against these fields;
  without this setter the mismatch between our custom body's ID and
  wolfSSL's internally-generated one trips an `INVALID_PARAMETER` (-425).

### Data-flow summary

```
   caller                                          wolfSSL
   ------                                          -------
   wolfSSL_OfferKeyShare(X25519, pub, priv)   ───► ssl->extensions += KeyShareEntry
   wolfSSL_OfferCipherSuites(...)             ───► ssl->suites->suites[]
   wolfSSL_SetClientHelloRandom(r32)          ───► ssl->arrays->clientRandom
   wolfSSL_UseClientHelloRaw(cb, ctx)         ───► ssl->anywhereChCb
   wolfSSL_connect(ssl)                       ───► SendTls13ClientHello
                                                     ├── cb(&body, &len)
                                                     ├── memcpy to output buf
                                                     ├── HashOutput (unchanged)
                                                     └── SendBuffered
   DoTls13ServerHello (wolfSSL)                     ◄── reads key_share, uses
                                                         KeyShareEntry.privKey
                                                         for ECDH (unchanged)
```

### Invariants the caller must preserve

1. Whatever `random32` is passed to `wolfSSL_SetClientHelloRandom` **must** be
   the same 32 bytes embedded at offset 2 of the injected body (right after
   `legacy_version`).
2. Every cipher suite announced in the injected body must also be present in
   the list supplied to `wolfSSL_OfferCipherSuites`. Order doesn't have to
   match, but the *set* does — otherwise the server may pick a suite that
   wolfSSL refuses at ServerHello parse time.
3. For each `key_share` entry in the injected body, `wolfSSL_OfferKeyShare`
   must have pushed a matching `(group, pubKey, privKey)` beforehand. The
   public key announced must equal what wolfSSL would derive from the private
   key, otherwise ECDH yields a mismatched shared secret and Finished fails.
4. The `legacy_session_id` in the injected body must equal what
   `wolfSSL_SetClientHelloLegacySessionId` was called with. Or both empty.
   Mismatch → `INVALID_PARAMETER` on ServerHello.

### Extensions the caller must strip before injection

wolfSSL 5.9.1 does not implement every TLS extension that browsers advertise.
If the injected body announces an extension whose server-side response is a
message type wolfSSL doesn't recognise, the handshake fails with
`OUT_OF_ORDER_E` (-394). The caller (`TLSHandler.buildSession`) strips these
from the builder output before storing the body:

| Extension | Type ID | Why strip |
|---|---|---|
| `compress_certificate` (RFC 8879) | 0x001B | Server responds with `CompressedCertificate` (msg type 25). wolfSSL 5.9.1 has no `HAVE_CERTIFICATE_COMPRESSION` support — the message is rejected as "Unknown message type." Fingerprint impact is negligible: JA3/JA4 changes slightly but DPI systems tolerate this since Chrome itself varies this extension across OS/version combos. |

When wolfSSL is upgraded to a version with `HAVE_CERTIFICATE_COMPRESSION`,
remove 0x001B from the strip list and enable the feature in `user_settings.h`.

### What we do NOT support (yet)

- HelloRetryRequest. If a server sends HRR we currently bail — the callback
  would need to be re-invoked with HRR context. Left as a follow-up.
- DTLS 1.3. Out of scope.
- ECH. The upstream ECH path constructs its own inner ClientHello; we don't
  attempt to interoperate with it.

---

## Historical note: 5.9.1 ARMv8 HW-crypto workaround

Separately from the above, `user_settings.h` sets
`WOLFSSL_ARMASM_NO_HW_CRYPTO` on `__aarch64__` to force AES and SHA-256 onto
the NEON-only paths. This is a **configuration-level** workaround, not a
source patch — no wolfSSL file is modified. See `user_settings.h` for the
full rationale. When wolfSSL ships a fix, drop the define; no patches here
depend on that behavior.
