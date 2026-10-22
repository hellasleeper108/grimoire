# 1Password core binary — symbol-guided analysis

Target: `resources/app.asar.unpacked/index.node` (180 MB, Node/NAPI addon) and
`libop_sdk_lib_core.so` (23 MB) from 1Password 8.12.42 for Linux (build dated 2026-10-20).

**Method, and its honest limits up front.** This is not a decompilation. It is symbol-table
archaeology on two **unstripped** binaries, plus `objdump` call-target extraction for eight
selected functions. Evidence tiers are labelled per section:

| Tier | Meaning | Trust |
|---|---|---|
| **S** | symbol table (`nm`), exact names as the compiler emitted them | high for *what exists*, weak for *behaviour* |
| **D** | disassembly call targets (`objdump`) | good for *which routines a function reaches*, blind to indirect calls |
| **R** | REA/Ghidra decompiler evidence | **not used for this 180 MB target** — available only for the companion binaries: `evidence/rea-ghidra-1password-mcp.json` (4,587 procedures) and `evidence/rea-ghidra-browsersupport.json` (6,485 procedures, `ev_d711ea77…`) |
| **I** | inference from naming — clearly marked | hypothesis, not fact |

No decompiler was run on the 180 MB binary. Why: 138,828 functions, of which only 2,965 unique
`op_*` symbols (**2.3 %**) are AgileBits' own code; the rest is `core::` (36,069), `tokio::`
(10,033), `anyhow::` (1,738), `async_graphql` (536), `serde`, `futures`. At the throughput
measured on the 3.7 MB companion binary (4,587 procedures in ~9 min), a full pass is ≈4.5 h and
gigabytes of evidence for a 2 % yield. The symbol table answers the design questions faster.

Scale: **2,965 unique `op_*` symbols across 323 crates.**

---

## 1. Crate map — what the product is made of (tier S)

Top crates by defined-symbol count. The "reads as" column is **inference (I)** from names only.

| Crate | Syms | Reads as |
|---|---|---|
| `op_app` | 743 | the backend service layer (accounts, backend, flex API, SSO) |
| `op_edit_item` / `op_view_item` | 132 / 102 | item editor and item viewer models (UI-side) |
| `op_import_export` (+`_ui`) | 88 (+47) | migration is a first-class subsystem, not a bolt-on |
| `op_encoding` | 71 | wire/at-rest codecs |
| `op_settings_ui` / `op_settings` | 54 / 14 | settings surface + store |
| `op_service_developer_environment` | 53 | the Environments feature seen in the MCP server |
| `op_model_credential_exchange` | 52 | passkey/credential exchange formats |
| `op_model_item` | 38 | the item model (see §2) |
| `op_service_machine_identity` | 34 | workload/OIDC identity |
| `op_db_queue_worker` / `op_db` | 27 / 22 | SQLite persistence + a write queue |
| `op_b5_client` | 26 | sync client ("B5") |
| `op_crypto` (+`_aes`, `_jwe`, `_kdf`, `_stl`) | 24 (+few) | crypto primitives, layered |
| `op_account_management` | 24 | account lifecycle, MFA, SSO migration |
| `op_url_classification` | 24 | which site is which (autofill routing) |
| `op_keeper_api` / `op_keeper_crypto` | 23 / 16 | "keeper" — key/service layer (I) |
| `op_auth_prompt_ui` / `op_signin_ui` | 23 / 18 | biometric/OS-auth prompt surfaces |
| `op_watchtower` (+`_ui`) | 14 (+16) | breach/weak-password auditing |
| `op_auto_lock` | 15 | idle/lock detection (see §5) |
| `op_search` | 15 | local search |
| `op_trusted_device_enrollment` | 14 | device enrollment (see §4) |
| `op_system_auth_enclave` | 15 | OS keychain/enclave integration |
| `op_qr` | 13 | QR scan/render (TOTP, device pairing) |
| `op_mycelium` / `op_mycelium_auth` | 5 / 5 | "Mycelium" — device-to-device auth flow (see §4) |
| `op_webauthn`, `op_webauthn_authentication(+_ui)` | 4 | passkeys |
| `op_model_vault` / `op_model_template` | 6 / 2 | vault + item templates — **templates are a separate crate** |
| `op_model_rich_icon` / `op_model_item_icon` | 12 / 2 | icon pipeline |

Read: the app is **not** one monolith with a crypto corner. It is ~320 crates with the UI models
(`edit_item`, `view_item`, `settings_ui`) cleanly separated from services (`service_*`) and from
model types (`model_*`), and persistence isolated behind `op_db`. That layering is what makes a
180 MB Electron app maintainable, and it is the structure §2 of `DESIGN.md` should echo.

---

## 2. Item model: two tiers, and a cache between them (tier S + D)

Type names observed in `op_model_item` and in destructor edges of two functions:

```
op_model_item::{Item, ItemMetadata, ItemOverview, ItemDetails, Section, Passkey,
                HtmlForm, DocumentAttributes, Category}
op_model_item::decrypted_item_overview        (18 symbols — its own module)
op_account_ext_items::{try_decrypt_item_overview, decrypt_item_from_row}
op_account_ext_items::ItemCache::get          (D: called from try_decrypt_item_overview)
op_crypto_jwe::JweB                            (D: in decrypt_item_from_row)
```

**The finding that matters:** `ItemOverview` and `ItemDetails` are distinct types, overview
decryption has its own module, and the row decryptor produces `JweB` values. So a stored item is
(at least) two independently encrypted payloads — a small *overview* for list rendering and a
larger *detail* blob — and overview decryption is cached in an `ItemCache`.

Why that is clever: the sidebar and item list never decrypt item bodies. Rendering 5,000 rows
touches only overview ciphertext, and the expensive decrypt happens per selected item.

**GRIMOIRE change:** our schema in `DESIGN.md` §5 puts title/subtitle in encrypted columns on
`items` and every field in `fields`. Adopt the observed split instead:

```sql
items(id, vault_id, category, template_version, overview_enc BLOB, detail_enc BLOB, ...)
-- overview_enc: {title, subtitle, icon_ref, url_host, tags}  one small AEAD value
-- detail_enc:   {sections[], fields[], notes, attachments[]}  one larger AEAD value
```

Consequences: list rendering decrypts one small blob per item; per-field envelope keys still wrap
the whole item key; and `ItemCache` becomes an obvious P0 component (bounded LRU keyed by
`(item_id, version)`), not an afterthought.

---

## 3. Crypto chain (tier S + D)

Observed symbols:

```
op_crypto::keychain::{decrypt_keyset_using_bytes, decrypt_vault_key, KeychainError}
op_crypto::keys::derive_new_key_id::<16>, ::<32>
op_crypto::secret_key_serde            (Secret Key has its own serializer)
op_crypto::secret_key::try_parse
op_crypto::secret_key_serde::obfuscation::{deobfuscate, obfuscate_key}
op_crypto::secret_key_serde::less_safe_secret_key_serde::deserialize  (JSON, "less safe" variant)
op_crypto::ec, ::digest, ::uuid, ::trusted_device_auth::cpace_kdf
op_crypto_aes::AesKey::decrypt_jwe_b_with_aad     (D: called by keychain decrypt)
op_crypto_jwe::JweB, op_jose::jwk::{ec, symmetric}::Jwk
```

Call-target evidence for the keychain unwrap (`decrypt_keyset_using_bytes` @ `0x79c1260`,
`decrypt_vault_key` @ `0x79c0e50`):

```
decrypt_jwe_b_with_aad ×2 (decrypt_keyset) · AesKey · RsaKeyPair (legacy path) · Jwk (EC)
```

Facts: the keyset is **JOSE JWE with AAD binding**, decrypted with an `AesKey`, with EC JWKs in
the key material and an RSA keypair still present (legacy import/compat path).

The KDF primitives are linked from `ring`, visible in the same symbol table:

```
ring::pbkdf2::PBKDF2_HMAC_SHA256        the passphrase KDF
ring::pbkdf2::PBKDF2_HMAC_SHA512
ring::hmac::{HMAC_SHA256, HMAC_SHA384, HMAC_SHA512, HMAC_SHA1_FOR_LEGACY_USE_ONLY}
ring::hkdf::{HKDF_SHA256, HKDF_SHA384}
scrypt (crate)                          legacy import path
aws_lc_rs::hkdf                         TLS only (rustls), not the vault chain
```

With the error variants already catalogued (`InvalidPbkdf2Iterations`,
`SecretKey(BadFields | version | length)`, `DecryptionHashMismatch`,
`UnexpectedEncryptionVersion`) and the tier-D finding that no iteration count is hard-coded at
either keychain call site, the shape is: **PBKDF2-HMAC-SHA256(passphrase, salt, iterations read
from the keyset) → HMAC-SHA256 mix with the Secret Key → unwrap the JOSE keyset → vault keys →
per-item JWE-B**. The *order* in that sentence is inference from the primitives plus 1Password's
published two-secret design, not a decompiler read-back — §7 says so explicitly.

Key ids are
derived at 16 and 32 bytes, and the Secret Key is a bespoke serialized type with its own serde
module — i.e. versioned and length-checked, not a base32 string with a parser bolted on later.
The serde module has an explicit `obfuscation::{obfuscate_key, deobfuscate}` pair (the masking
that their own source comment admits is obfuscation, not protection), a `less_safe` JSON
variant for export paths, and a `try_parse` entry point on the type itself.

**GRIMOIRE decision update:** our spec uses XChaCha20-Poly1305 for values, which stands — but the
*wrapping* layer should be JWE-shaped (`alg`/`enc` headers, AAD-bound, algorithm-agile) rather
than `AEAD(K, IK)` with a hand-rolled AAD convention. Same security property, and it buys key
rotation and cross-implementation verification for free. If we stay in Rust, `josekit` covers it.

---

## 4. Pairing and auth (tier S + D + I)

```
op_crypto::trusted_device_auth::cpace_kdf
op_mycelium_auth::state_machine::reverse40::Same…      (seen in cpace_kdf's type edges)
op_trusted_device_enrollment::{device_enrollment, enrollment}
op_b5_client::internal::keyed_server_connection
op_b5_client::internal::unauthorized_session::auth_flow::{mk_kdf_params, parse_totp_submission}
op_b5_client::{b5_client, reauth, connect_transport}
op_webauthn_authentication::models::error::Passkey…    (seen in device_enrollment edges)
```

**CPace** is a balanced PAKE — password-authenticated key exchange with *mutual* authentication
and no offline dictionary attack. Its presence in `trusted_device_auth`, wired into a Mycelium
state machine (`reverse40`), tells us device pairing is not "send a QR code and trust the
network": it is a PAKE handshake where the human-transferred code is the low-entropy secret.

`mk_kdf_params` is pure `serde_json`/`IndexMap` construction (no crypto calls in range) — it
*emits* KDF parameters for the auth exchange; the derivation itself lives elsewhere. Consistent
with SRP-style auth, as the `Srp*` error variants in the SDK core already suggested
(`EVIDENCE-1PASSWORD.md` §4.2).

**GRIMOIRE change:** for P2 device enrollment, replace "X25519 sealed box carrying the vault key"
with a **CPace handshake keyed by the printed pairing code**, and only then transfer the wrapped
vault key. That closes an offline-guessing weakness in our current spec's `K_share` path.

---

## 5. Auto-lock is an OS-integration problem (tier S)

```
op_auto_lock::lock_if_needed · auto_lock_supported
op_auto_lock::linux::{
  wayland_idle::{idle_time, start}, x_monitor_start, x_monitor_poll::<x11rb::RustConnection>,
  gnome_kde_active_changed_handler, xfce_active_changed_handler,
  gnome_wake_up_screen_handler, sleep_monitor_prepare_for_sleep_handler, check_idle_time }
```

They do not trust a timer alone. On Linux they read **compositor idle time (Wayland
`ext-idle-notify` via `wayland_idle`, X11 `x11rb` polling)**, watch **session-active state** on
GNOME/KDE/XFCE, and hook **logind's `PrepareForSleep`**. That is why `op_auto_lock` is 15 symbols
and has a per-desktop tree.

**GRIMOIRE change:** our §6.3 says "idle timer" as if a `Duration` were enough. Adopt the same
three signals — compositor idle, session lock/unlock, system sleep — and treat "no idle source
available" as its own UI state (a TUI on a serial console has no compositor). This also gives a
better default than a fixed 10 minutes.

---

## 6. Feature surface confirmed by symbols (tier S)

`op_watchtower` (+ui) — breach/weak/reused-password auditing, a real subsystem.
`op_password_generator_ui`, `op_search`, `op_qr`, `op_url_classification` — expected, and each is
its own crate rather than a helper module.
`op_import_export` (+ui) — 135 symbols between them: importers are heavyweight, and LastPass/CSV
parsing gets its own UI. Matches our P1 being a whole phase, not a commit.
`op_service_developer_environment` (53) — the Environments feature behind `1password-mcp`.
`op_system_auth_enclave` (15) — OS keychain/enclave (Touch ID, libsecret, etc.).
`op_log` (131) — logging is the third-largest crate. Observability was budgeted for deliberately.
`op_sys_info` (29), `op_linux` (20), `op_native_core_integration`, `op_core_node` — platform seams.

---

## 7. What this analysis did **not** settle

1. **Exact derivation order.** Partially settled. The primitives are observed
   (`ring::pbkdf2::PBKDF2_HMAC_SHA256`, `ring::hmac::HMAC_SHA256`, `ring::hkdf::HKDF_SHA256`,
   `scrypt` for legacy imports), the container formats are observed (JOSE JSON keyset carrying its
   own KDF params, `oct` JWK wrapping the vault key, JWE-B per item row), and the passphrase is
   observed to be Unicode-normalised before use. The **sequence** is inference from those plus
   the published two-secret design. Three decompile attempts failed on tooling, not on the target —
   see §9 — so the residue is explicitly: *which function calls which, in what order*. For
   GRIMOIRE this costs nothing, because our chain is Argon2id + HKDF rather than theirs.
2. **Wire format.** `libop_sdk_lib_core.so` links `prost`/`prost_reflect`, so sync uses protobuf, but
   the embedded file descriptors are compressed inside the binary; only `google.proto` option types
   surfaced from strings. Naming the message types needs descriptor extraction (prost-reflect
   dump), not strings.
3. **Behaviour of any function**, generally. Indirect calls resolve to GOT slots and destructors
   here, not to named callees; LTO complicates inlining. Tier D shows *reachability*, not control
   flow.
4. **Anything about their server.** Not touched, not inferred.

---

## 8. Reproduce

```bash
S=~/rea-work/1password/1password-*/.x64/resources/app.asar.unpacked/index.node
nm -C --defined-only "$S" | sed -E 's/^[0-9a-f]+ [Tt] //' | grep '^op_' | sort -u > /tmp/op_syms.txt
cut -d: -f1 /tmp/op_syms.txt | sort | uniq -c | sort -rn          # crate map
nm -C "$S" | grep -F 'decrypt_vault_key' | head -1                 # address
objdump -d --start-address=0x79c0e50 --stop-address=0x79c2650 "$S" \
  | grep -E '\bcall' | grep -oE '<[^>]+>' | sort | uniq -c | sort -rn   # call targets
```

Raw symbol dumps: `/tmp/op_syms_index.txt` (2,965), `/tmp/op_syms_sdk.txt` (190) in WSL.

---

## 9. Tooling pitfall: `GccExceptionAnalyzer` on large Rust binaries

Two attempts to decompile a single function from the 180 MB core both ended in
`provider_timeout` — the second after a **7,200,000 ms** deadline. The 17 MB diagnostic bundle
explains why, and the cause is not "the binary is big":

```
stdout log lines:        210,910
distinct ERROR sources:  3, of which two are:
  52,650 × "Function body does not fully contain the call site area (LSDACallSiteTable)"
  52,650 × "Function body does not contain the landing pad (LSDACallSiteTable)"
```

That is Ghidra's `GccExceptionAnalyzer` walking Rust's unwind tables: two failed diagnostics per
function body, ~105k log lines, in a binary where most functions have no LSDA to find. The run was
still emitting them when the deadline fired.

**Fix:** `REA_GHIDRA_DISABLED_ANALYZERS=...` — the env var REA's own remediation text points at.
Worth recording because the trap applies to any large non-C++ binary (Rust, Go, a stripped C blob),
and because "raise the timeout" is the wrong first instinct when the log shows a repeating analyzer
failure rather than slow progress.

**But the flag itself is hard to use, and that is the real finding.** REA validates the value with
`bridge/ghidra/ReaGhidraAnalysisOptions.java`, which calls `analysis.getAnalyzer(name)` and
requires `options.containsKey(name)` — i.e. it matches on Ghidra's **analysis-option name**, not the
analyzer's Java class. Three attempts:

| Value tried | Result |
|---|---|
| `GccExceptionAnalyzer` | `IllegalArgumentException: Unknown Ghidra analyzer for this program` |
| `GCC Exception Analyzer` | same rejection |
| enumerate the real names with a custom `GhidraScript` reading `currentProgram.getOptions("Analyzer")` | compiled and ran, printed **zero** option names |

So the accepted string is undiscoverable from outside the running bridge, and a failed value aborts
the whole run at pre-script time (cheap — 22 s — but useless). Two honest options remain: budget
~5–6 h for an untouched run (52,650 of ~138,828 function bodies were processed in the first 2 h), or
report the discoverability gap upstream. Separately, the reported deadline did not reconcile with
observed wall clock (7,200,000 ms configured, ~35 min elapsed at last measurement), which also looks
like a REA-side accounting bug worth filing.
