# GRIMOIRE — a TUI-first password manager

> *A grimoire is a book of secret names. That is all a password manager is.*
> Binary: `grim`. Daemon: `grimd`.
> Design study derived from a static reverse-engineering pass over 1Password 8.12.42 for Linux
> plus its `1password-mcp` and `1Password-BrowserSupport` companions. See `EVIDENCE-1PASSWORD.md`
> for the receipts and `README.md` for orientation.

**Status:** design only. No code yet.

---

## 0. Name

**GRIMOIRE** (binary `grim`) — the book of secret names and their uses. Fits the product
literally (a searchable book of secrets), fits the retro-terminal aesthetic, and gives clean
CLI verbs: `grim get github`, `grim totp github`, `grim add`.

Alternates considered, in case you want a different flavor:

| Name | Reading | Why not chosen |
|---|---|---|
| SIGIL | a seal that binds and protects | collides with the EPUB editor; weaker as a noun for a *collection* |
| PHYLACTERY | the amulet case that holds a protective text | best etymology of the three, but unsayable in a terminal 3 times a day |
| MOAT | the barrier you build | too defensive-cute, no sense of contents |

The metaphor stays in the **copy and the TUI chrome**, never in the data model. Tables are
`items`, not `spells`. Naming a password "a spell" gets cute fast and then gets in the way.

---

## 1. What the 1Password analysis actually taught us

Seven structural lessons, each tied to something observed rather than guessed. Evidence file
paths and `evidence_id`s are in `EVIDENCE-1PASSWORD.md`.

### 1.1 Thin view, fat core
The Electron bundle is 40 MB of UI; the actual product is a 188 MB Rust node addon plus a
23 MB `libop_sdk_lib_core.so`, with Tokio, rustls, ring and a bundled SQLite behind it. The
renderer holds **no** crypto and **no** keys. The UI can be killed, reloaded, or replaced
without touching the unlock state.

**Adopt:** the TUI is a *client*. It renders and forwards intents. A separate `grimd` owns
keys, does all crypto, owns the clipboard timer, and owns auto-lock. This is the single most
important decision in this document, and it is what makes a TUI viable at all: unlock once,
and the CLI, the TUI, a future browser helper and an agent all share one unlocked session.

### 1.2 Enumerate capabilities, never expose a generic eval
1Password's `preload.js` is 3 KB and is essentially a security document: a literal object of
~90 allowed IPC verbs (`generateTotp`, `secureCopy`, `setSecureInput`, `showLargeType`,
`webauthnSign`, `parseClipboardQr`, …) that a runtime loop converts into `ipcRenderer.invoke`
wrappers, plus exactly one generic-looking escape hatch — `executeGql` — which is itself a
typed GraphQL channel rather than arbitrary code.

**Adopt:** a closed verb list (§3.2). No "run this query" RPC. Anything new is a new verb,
reviewed once, revoked like a capability. Note the corollary REA exposed: because that list is
built in a loop at runtime, static analysis reported `exposed_api_members: 0` — the shape is
invisible to tooling. In GRIMOIRE the capability table is a **data file** (`capabilities.toml`)
that both the daemon and the docs are generated from, so it is auditable by `diff`, not by
execution.

### 1.3 One data plane, GraphQL-flavored
The renderer talks to the core through `executeGql` plus `gqlSubscriptionRequest` /
`gqlSubscriptionResponse`. 33 distinct operations appear in the bundle (15 queries, 12
mutations, 6 subscriptions) — and the subscriptions are all *shell state*: sidebar, toolbar,
accounts, collections. Item data is queried; **chrome is pushed**.

**Adopt:** a typed request/response plane (JSON-RPC over a Unix socket is enough; GraphQL is a
fine choice too) plus a small subscription set: `sidebar_changed`, `accounts_changed`,
`session_locked`, `item_changed`. Do not stream vault contents.

### 1.4 Typed items, not key/value blobs
Item categories observed in the bundle: `login`, `password`, `securenote`, `creditcard`,
`identity`, `document`, `sshkey`, `server`, `database`, `passport`, `driverlicense`,
`medicalrecord`, `bankaccount`, `membership`, `softwarelicense`, `person`. In the Rust core the
model vocabulary is `vault / item / section / field / category / template / share / trash /
overview / detail`.

**Adopt:** three-level item structure — **category → sections → typed fields**. Field types
drive rendering, masking, copy behaviour and TOTP/date/menu widgets. A category is a template
(a schema), and templates are versioned so old items still render after a template change.

### 1.5 Two secrets, and the server is blind
Auth vocabulary in the core: `Srp*` errors, `InvalidPbkdf2Iterations`, `MasterPassword`,
`SecretKey(...)` with length/version errors, plus `aes-256-gcm`, `hkdf`, `hmac-sha256`,
`ed25519`, `x25519`, `scrypt`, `pbkdf2`, `rsa-oaep`, `pasetors`. The design is the documented
1Password one: master password **and** a high-entropy account Secret Key, combined via KDF so
that the server stores only a verifier and ciphertext. SRP means the password itself never
crosses the wire.

There is also a wonderfully honest string in `libop_sdk_lib_core.so`:

> "This is an obfuscation key used to mask the secret key in the local database and nothing
> more. If this seems interesting to you, come work with us :)"

**Adopt:** two-secret derivation (§4.1) with Argon2id, envelope encryption, and a sync server
that sees only ciphertext plus the minimum metadata. We will document our own obfuscation key
with the same honesty.

### 1.6 Local-first, encrypted at rest, searchable without leaking
A local SQLite store (`1password.sqlite`) with WAL, an `op_sdk_b5_client` (B5 = their sync
plane), item versions, trash, and per-item sharing. Nothing about the local store is
plaintext-by-default.

**Adopt:** SQLCipher-style page encryption for the store, **plus** per-field envelope
encryption for values, plus a *separate* encrypted index for fuzzy search. Two layers because
the page layer protects the file and the envelope layer protects values from a live-but-locked
process and from future sync.

### 1.7 The agent surface is scoped leases, not the vault
`1password-mcp` does not expose your vault. Its tool surface is
`list_environments`, `create_environment`, `list_variables`, and secret mounts — i.e.
**environments and variables**, with workload identity (GitHub Actions, OIDC) and grants.
The lesson: what an agent needs is a short-lived, narrowly-scoped secret, not read access to
the book.

**Adopt:** `grim mcp` exposes **leases**: `lease_request(name, ttl, purpose)` → a handle the
agent can use through `lease_read`, audited, expiring, revocable, never the item body.

---

## 2. Architecture

```
                      ┌───────────────────────────────────────────────┐
   TUI (grim)         │  grimd  — the only process that holds keys    │
  ┌────────────┐      │                                               │
  │ ratatui    │◄────►│  session   : unlock state, idle timer, mlock  │
  │ 3-pane UI  │ unix │  vault     : items, templates, versions       │
  │ cmd palette│ sock │  crypto    : AEAD, KDF, envelope keys         │
  └────────────┘ JSON │  index     : encrypted fuzzy index            │
  ┌────────────┐  -RPC│  clipboard : TTL timer + clear                │
  │ CLI (grim) │◄────►│  sync      : op log, push/pull (P2)           │
  └────────────┘      │  audit     : local append-only log            │
  ┌────────────┐      └───────────┬───────────────────────────┬───────┘
  │ grim mcp   │◄─────────────────┘                           │
  │ (leases)   │                        ┌─────────────────────▼──────┐
  └────────────┘                        │ SQLCipher store + blobs    │
  ┌────────────┐                        │ (ciphertext only on disk)  │
  │ browser    │◄── native messaging ──►│                            │
  │ helper(P4) │                        └────────────────────────────┘
  └────────────┘
```

Rules that fall out of the diagram:

1. `grimd` is the trust boundary. If `grim` crashes, the session survives; if `grimd` dies, keys
   die with it (no core dumps, `PR_SET_DUMPABLE=0`, `mlockall` best-effort).
2. Transport: Unix socket at `$XDG_RUNTIME_DIR/grimd.sock`, mode `0600`, peer-credential check
   (`SO_PEERCRED` → same UID), plus a per-session token in a `0600` file for defense in depth.
3. Every request carries a capability verb from `capabilities.toml`. Unknown verb = closed.
4. A locked daemon answers exactly four verbs: `status`, `unlock`, `lock`, `quit`.

---

## 3. Interfaces

### 3.1 Surfaces

| Surface | v1 | Notes |
|---|---|---|
| `grim` TUI | yes | fully keyboard driven |
| `grim get/totp/copy` CLI | yes | scriptable, no TUI |
| `grim import` | yes | CSV, 1PUX, Bitwarden JSON, KeePass XML |
| `grim mcp` | P4 | leases only |
| browser native-messaging host | P4 | same verbs as CLI |
| GUI | never | out of scope by design |

### 3.2 Capability verbs (the whole API, v1)

```
session:    status  unlock  lock  quit  set_idle_timeout
vault:      list_vaults  list_items  get_item  search
items:      create_item  update_item  delete_item  restore_item  duplicate_item
fields:     reveal_field  copy_field  generate_password  generate_passphrase
totp:       totp_now  totp_scan
sharing:    share_item  list_shares  revoke_share        (P3)
sync:       sync_status  sync_now                        (P2)
leases:     lease_request  lease_read  lease_revoke      (P4)
admin:      export_vault  audit_tail  rotate_keys
```

That is 27 verbs. 1Password needs ~90 because it also owns windows, dialogs, printing, camera
permissions and OS integrations; a terminal client needs far less, and that is a feature.

Two verbs belong in the table that the list above implies but does not name, and one more in P4:

```
consent:   authorize_client  revoke_client  list_clients      (P0 — see §3.3)
leases:    lease_request  lease_read  lease_revoke            (P4)
```

### 3.3 Clients get projections, not the vault

This is the strongest lesson in the whole study, and it came out of the browser-helper symbols
(`EVIDENCE-1PASSWORD.md` §8.2). 1Password's native-messaging layer never hands the browser a
vault. It hands it *projections*, one message type per need: an item-list section for the current
page, one item overview, credentials for one confirmed fill, a username suggestion list, a passkey
assertion. The CLI is treated the same way — `cli_integration` issues a time-boxed
**authorization** carrying command metadata, so the app knows which command is asking before it
consents.

GRIMOIRE therefore has **four client tiers**, each with its own projection:

| Tier | Client | Sees | Lifetime | Consent |
|---|---|---|---|---|
| T0 | TUI (`grim`) | full item bodies | session | implicit — you are the human |
| T1 | CLI (`grim get`) | one field, one item, one call | single call | prompt in TUI, or `--yes` for 5 min |
| T2 | browser host | list sections, item overviews, one fill's credentials, TOTP | 60 s lease per fill | click in the extension, shown in TUI |
| T3 | agent (`grim mcp`) | leased fields only, never notes, never attachments | TTL lease (default 5 min) | policy file + audit, revocable live |

Mechanically: every request carries a `tier` and an `intent` (`intent = read_field(item, field,
purpose)`). The daemon answers with the *smallest* projection that satisfies the intent, and
writes one audit row per projection with `TOOL_CALL`-style accounting — one record per read, not
per connected client.

The CLI consent flow, in full, because it is the piece most password managers get wrong:

```
$ grim get github
  ┌ grimd ──────────────────────────────────┐
  │ grim requests the password for:         │
  │   github.com  (personal/login)          │
  │   client: pid 4242 grim get             │
  │   [a]llow once  [5] min  [d]eny  [D]eny always │
  └─────────────────────────────────────────┘
```
`[5]` mints a lease, not a trust relationship. `[D]eny always` writes to the policy file and is
visible in `grim clients list` — reversible in the TUI, never silently permanent.

### 3.4 Transport: Unix socket, plus a D-Bus façade

Observed: 1Password's Linux helper is a D-Bus client (`zbus`/`zvariant`) of the desktop app.
Adopt the same split, because it buys three things a bare socket does not: a bus policy for
who may connect, credential-based peer identity, and the ability for the browser host and the
CLI to share one authorization model.

- **Primary**: Unix socket at `$XDG_RUNTIME_DIR/grimd.sock`, JSON-RPC, `SO_PEERCRED` check.
- **Façade (P4)**: `org.grimoire.Daemon` on the *session* bus with the same verb set, so a
  native-messaging host and a future editor plugin do not each invent a transport.
- Never on the system bus. Never TCP. No HTTP listener, in any phase.

---

## 4. Cryptography

### 4.1 Key hierarchy (two secrets, envelope encryption)

```
passphrase ──Argon2id(salt, m=64MiB t=3 p=4)──► KDF key (32 B)
account key (128-bit random, base32 + CRC) ───► AK  (stored on device, escrowed in recovery kit)
                        │
                        ▼
        Master Key  MK = HKDF-SHA256(KDF key ‖ AK, "grimoire/mk/v1")
                        │
        ┌───────────────┼────────────────┬────────────────────┐
        ▼               ▼                ▼                    ▼
   K_enc (AEAD)    K_mac (audit)    K_index (search)     K_share (X25519)
        │
        ▼
   Vault Key VK (per vault, 32 B random)  ← wrapped by K_enc
        │
        ▼
   Item Key IK (per item, 32 B random)    ← wrapped by VK
        │
        ▼
   values encrypted with IK                (AEAD, per-field AAD)
```

Properties this buys us:

- Changing the passphrase rewraps `MK` only — no item re-encryption.
- Removing a device or rotating the account key rewraps `VK`s only.
- Revoking a share rewraps `IK` for remaining recipients.
- A backup of one item does not require the whole vault key.

### 4.2 Primitives

| Purpose | Choice | Why |
|---|---|---|
| Passphrase KDF | Argon2id, m=64 MiB, t=3, p=4, 32 B out | memory-hard; store params with the blob so they can rise over time |
| Value AEAD | XChaCha20-Poly1305 (libsodium) | 24-byte nonce makes random nonces safe — no counter management, no GCM nonce-reuse footgun. 1Password uses AES-256-GCM; we deviate deliberately and document it |
| Subkey derivation | HKDF-SHA256, per-purpose labels | one root, many keys, no key reuse across purposes |
| Item/value wrapping | **JWE-shaped** (`alg`/`enc` headers, AAD = `vault_id ‖ item_id ‖ field_id`) instead of bare `AEAD(K_enc, IK)` | binds ciphertext to its slot, and buys algorithm agility + rotation for free; their keyset is JWE/AAD (`docs/analysis-core.md` §3) |
| Signing (devices, audit) | Ed25519 | small, fast, audited |
| Sharing envelopes | **CPace** PAKE keyed by the human-transferred pairing code, then X25519-wrapped vault key | P3 — a PAKE closes the offline-guessing gap a bare sealed box leaves; matches their `trusted_device_auth::cpace_kdf` |
| Leases / agent tokens | PASETO v4.public | 1Password uses PASETO in their SDK; it is the right shape: signed, versioned, no JWT footguns |
| TOTP | RFC 6238, SHA-1/256/512, 6–8 digits, 30 s ±1 | interoperability with existing seeds |
| Password generation | rejection-sampled CSPRNG, per-class rules, entropy readout | never modulo-biased |
| Comparison | constant-time everywhere it matters | |
| Memory hygiene | `zeroize` on every key buffer, `mlock`, no swap, `PR_SET_DUMPABLE=0` | best-effort, documented as such |

### 4.3 Account key format

```
GR1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
```
`GR1` version tag, 30 base32 chars (150 bits, 128 used), CRC-16 tail to catch transcription
errors, no ambiguous characters (Crockford base32). Printed on the recovery kit; entering it is
the difference between "my passphrase was `hunter2`" and "my vault is unbreakable".

### 4.4 Unlock flow (local, no server)

1. `grim` → `unlock` verb → daemon derives `KDF key`, combines with `AK`, derives `MK`.
2. Daemon unwraps the vault keyring, verifies a **canary blob** (AEAD of a fixed plaintext) —
   wrong passphrase fails here, not later.
3. Session timer starts; `mlock` the key buffers; publish `session_unlocked`.
4. Locking is driven by OS state, not a bare timer — compositor idle (Wayland
   `ext-idle-notify` / X11 screensaver), session lock, and logind `PrepareForSleep` — with the
   idle timeout (default 5 min) as the fallback when no compositor is present. Any of them, or
   `Ctrl-L` → zero keys, drop clipboard, publish `session_locked`. On a bare TTY with no idle
   source, the TUI says so in the status bar rather than pretending it will auto-lock.

### 4.5 Auth flow (when sync exists, P2)

SRP-6a (or OPAQUE) over TLS: the server stores `verifier`, never a password hash. The session
token is a PASETO signed by the server; the client proves possession of `MK` for decryption
locally. The server **cannot** decrypt anything, ever — it sees `vault_id`, opaque item ids,
sizes and timestamps. We minimise even that: item ids are random, not sequential, and
timestamps are coarsened to the day.

---

## 5. Data model

```sql
-- store is SQLCipher-encrypted; every *_enc column is additionally sealed with IK/VK
vaults   (id, name_enc, icon, created_at, updated_at, version)
items    (id, vault_id, category, template_version,
          overview_enc BLOB,      -- {title, subtitle, icon_ref, url_host, tags}  1 small AEAD value
          detail_enc   BLOB,      -- {sections[], fields[], notes, attachments}   1 larger AEAD value
          created_at, updated_at, version, deleted_at NULL, favorite)
item_keys(id, item_id, wrapped_ik BLOB)          -- IK wrapped by VK
fields   (id, item_id, section_id, name_enc, field_type, value_enc,
          aad BLOB, sort_order, conceal BOOL)
sections (id, item_id, name_enc, sort_order, collapsed BOOL)
tags     (item_id, tag_enc)
shares   (id, item_id, recipient_pubkey, wrapped_ik BLOB, permissions, created_at)
oplog    (seq INTEGER PK, item_id, op, payload_enc, device_id, ts, applied)
leases   (id, item_id, field_id, issued_at, expires_at, purpose, revoked)
audit    (seq INTEGER PK, ts, device_id, verb, item_id, mac)   -- MAC'd with K_mac
index    (item_id, token_enc, weight)                           -- K_index, separate table
```

Notes:

- **Templates.** `category` + `template_version` select a JSON schema that defines sections,
  field names, field types and generators. 16 categories copied in *shape* from the categories
  observed in 1Password (§1.4) — the taxonomy is the useful part, the content is ours.
- **Overview/detail split** (lesson from 1Password's `ItemOverview` / `ItemDetails` types and its
  `ItemCache`): `overview_enc` is decrypted for every list row, `detail_enc` only for the selected
  item. A bounded LRU keyed `(item_id, version)` sits in front of it, so a 5,000-row redraw costs
  5,000 small AEAD opens and nothing else.
- **Fields table is the grantable projection.** `detail_enc` is the authoritative body; the
  `fields` rows carry individually wrapped values so a T1/T3 read can hand out exactly one field's
  ciphertext without ever decrypting the item body.
- **Search without leaking.** The `index` table holds encrypted tokens (HMAC'd trigrams under
  `K_index`). Fuzzy search runs over decrypted-in-memory tokens. Prefix search, typo distance ≤1,
  and no server-side index ever (P2 server holds no index at all).
- **Versions.** Every item write bumps `version` and appends to `oplog`. Conflicts resolve
  per-field last-writer-wins with a Lamport counter, and any losing value is kept in
  `field_history` so nothing silently disappears. "Nothing silently disappears" is a design
  requirement, not a nicety.

Template example (`category = login`):

```json
{ "category": "login", "template_version": 2,
  "sections": [
    { "id": "core", "fields": [
        { "name": "username", "type": "text",     "conceal": false },
        { "name": "password", "type": "password", "conceal": true,
          "generator": { "kind": "charset", "len": 24, "classes": "upper,lower,digit,symbol" } },
        { "name": "totp",     "type": "totp",     "conceal": true },
        { "name": "url",      "type": "url",      "conceal": false } ] },
    { "id": "notes", "fields": [ { "name": "notes", "type": "markdown" } ] } ] }
```

---

## 6. The TUI

### 6.1 Layout (minimum 80×24, grows gracefully)

```
┌ GRIMOIRE ── locked? no ── personal ▾ ─────────────────────────────── 14:02 ┐
│ VAULTS        │ ITEMS (34)                    │ github.com                   │
│ ▸ personal  12│ / git                         │ ── login ───────────────────  │
│ ▸ work      22│   github.com          login   │ user    hella_sdhhxly        │
│ ▸ shared     0│   gitlab.com          login   │ pass    ••••••••••  [r]eveal │
│               │   gitea.local         login   │ totp    ▓▓▓▓▓▓░░░░  21s      │
│ TAGS          │   ssh: deploy@vps     sshkey  │ url     https://github.com   │
│ #infra     4  │                               │                              │
│ #bank      2  │                               │ ── notes ───────────────────  │
│               │                               │ 2FA enrolled 2026-03         │
├───────────────┴───────────────────────────────┴──────────────────────────────┤
│ [y] copy pw  [t] totp  [r] reveal  [e] edit  [n] new  [d] del  [:] cmd  [^L] lock│
└──────────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Interaction

| Key | Action |
|---|---|
| `Tab` / `Shift-Tab` | move pane focus |
| `/` | fuzzy search (index-backed, instant) |
| `j/k`, `g/G`, `Ctrl-D/U` | vim movement, `gg`/`G` top/bottom |
| `y` / `Y` | copy password / copy username (toast + clipboard TTL) |
| `t` | copy current TOTP (with countdown in status) |
| `r` | reveal field, auto-hide after 10 s or on focus loss |
| `L` | large-type print of a secret in a bordered box (shoulder-surfing mode) |
| `e` / `n` / `d` | edit / new / delete (delete → trash with undo line) |
| `:` | command palette — every CLI verb is reachable as `:call lease_request …` |
| `Ctrl-L` | lock now |
| `q` | quit view (daemon stays unlocked) |

### 6.3 States the TUI must render honestly

- **locked** (dim, no item list, single unlock prompt)
- **unlocked-idle** (idle timer visible in status bar, colour shifts under 60 s)
- **offline / sync-pending** (per-item badge, never blocking)
- **conflict** (side-by-side field diff, both values kept)
- **read-only** (shared items), **expired lease** (agent view)

### 6.4 Aesthetics

Monochrome-safe by default: every state is distinguishable without colour. Themes:
`phosphor` (green on black), `amber`, `paper` (light, high-contrast), `mono`. No animations
except the TOTP countdown and a single-line toast. Truecolor is optional, never required.

---

## 7. Sync protocol (P2)

- Client keeps an `oplog` of encrypted operations; `sync_now` pushes unseen ops, pulls the
  server's since-cursor, applies idempotently by `(device_id, seq)`.
- Server stores: `vault_id`, opaque item ids, `version`, `ciphertext`, day-coarsened `ts`.
- No server-side search, no server-side dedupe by content, no plaintext field names.
- Devices authenticate with Ed25519 device keys; a device list is signed by `MK` so a rogue
  device can be spotted and revoked by rewrapping — the classic 1Password model, and the right
  one.
- Self-hostable reference server in the same repo: a few hundred lines of Rust + Postgres, or
  SQLite for single-user.

---

## 8. Threat model

| Adversary | Defended? | How |
|---|---|---|
| Thief with the disk / backup | yes | everything at rest is AEAD + SQLCipher; `AK` is not on disk (recovery kit), so a stolen disk alone cannot be brute-forced |
| Weak passphrase + stolen encrypted blob | yes | `AK` adds 128 bits of entropy the attacker does not have |
| Malicious/compromised sync server | yes | server holds only ciphertext + opaque ids; it cannot decrypt or forge items (AEAD AAD binds ids) |
| Network attacker | yes | TLS + PASETO-pinned server identity |
| Another local user / other process | mostly | `0600` socket + `SO_PEERCRED` + `0600` token file |
| Root on the unlocked host | **no** | root can ptrace or read `/proc/<pid>/mem`; we mitigate with `PR_SET_DUMPABLE=0` and `mlock`, and we say plainly that this is not a defense against root |
| Clipboard scrape by other apps | partly | TTL clear (default 20 s) + `xclip`-owner handoff; we cannot stop a keylogger |
| Shoulder surfing | partly | `conceal` defaults, `L` large-type mode, reveal auto-hide |
| Supply chain | partly | pinned deps, `cargo deny`, reproducible builds, signed releases |
| Coercion ("open it") | **no** | out of scope for v1; a deniable second vault is a possible P5 |
| Malicious agent | yes | leases with TTL + verb allowlist + audit, never raw item reads |

Explicit non-goals: defeating root on an unlocked machine, defeating hardware keyloggers,
protecting data the user pastes into other apps, and any form of "AI that reads your vault for
you" — that is what leases are for.

---

## 9. Performance targets

| Operation | Target |
|---|---|
| daemon start → unlock prompt | < 50 ms |
| unlock (Argon2id 64 MiB t=3) | 250–500 ms, shown as a progress tick, not a hang |
| item list render, 5 000 items | < 16 ms/frame |
| fuzzy search over 5 000 items | < 30 ms keystroke-to-paint |
| TOTP fetch | < 5 ms (no daemon round-trip on same machine) |
| idle memory, unlocked, 5 000 items | < 120 MB RSS |

Argon2id at 64 MiB is the deliberate reason unlock is not instant; that is the point.

---

## 10. Roadmap

| Phase | Scope | Done when |
|---|---|---|
| **P0 — local vault** | `grimd` + `grim` TUI, create/unlock/lock, 6 item categories, fields, TOTP, password gen, copy with TTL, reveal, search | you can replace your daily driver for local-only use for a week without a "where did that go" moment |
| **P1 — import & polish** | CSV / 1PUX / Bitwarden / KeePass import, audit log, conflict-free trash, key rotation, recovery kit print | import of a 2 000-item vault is byte-auditable: every input row accounted for |
| **P2 — sync** | oplog sync, self-hosted server, device list + revocation | two devices converge after 500 offline edits with zero lost values |
| **P3 — sharing** | X25519 envelopes, collections, read-only shares, revoke-by-rewrap | a revoked recipient cannot decrypt a subsequent version (proved by test) |
| **P4 — agents & browser** | `grim mcp` leases, T2 browser host (native messaging → `org.grimoire.Daemon` on the session bus), CLI consent prompt in the TUI, one audit row per projection | an agent gets a 5-minute lease, the audit log shows exactly what it read, and `grim get` prompts before the first read rather than trusting the socket |
| **P5 — stretch** | deniable vault, hardware-key unlock (FIDO2 hmac-secret), passkeys | — |

---

## 11. Deliberate departures from 1Password

| Their choice | Ours | Reason |
|---|---|---|
| Electron + 188 MB Rust addon | single Rust binary + daemon | a terminal app should be ~10 MB and start in milliseconds |
| AES-256-GCM | XChaCha20-Poly1305 | nonce safety by construction; no counter discipline |
| GraphQL data plane | JSON-RPC + subscriptions | same shape, less machinery for 27 verbs |
| ~90 IPC verbs incl. windows/print/camera | 27 verbs | no OS chrome to own |
| PBS-style local obfuscation key | documented the same way, with the same honesty | hiding a key in the binary is obfuscation, and we will say so in the code comment |
| Agent access via Environments | leases + audit | least privilege for machines, not for humans |

**What we did not copy, on purpose:** no code, no bundled assets, no item templates verbatim,
no server protocol bytes, no reverse-engineered sync format. The value taken from the study is
*shape*: where the trust boundary sits, what belongs in the UI versus the core, and which
primitives a modern credential store needs.

---

## 12. Open questions

1. Argon2id 64 MiB on a Pi Zero 2 W takes how long? (Probably ~4 s — the Pi target may need a
   reduced-cost profile, with the cost parameters recorded per-vault.)
2. Do we need a "session agent" ala ssh-agent for browser autofill, or can the native-messaging
   host talk to `grimd` directly? (Prefer direct.)
3. Should the audit log be MAC'd per device and mergeable, or is a local append-only file enough
   for P0? (Local file for P0, MAC from P2.)
4. Does `grim` need a `--print` mode that never touches the clipboard, for CI use? (Yes, probably
   `grim get --stdout`.)
5. Which 16 categories ship in P0? Recommend 6: login, password, securenote, creditcard,
   identity, sshkey.
```
