# GRIMOIRE

A TUI-first password manager. Design study, not code.

```
grimoire/
├── README.md              ← you are here
├── DESIGN.md              ← the design: crypto, data model, TUI, sync, threat model, roadmap
├── EVIDENCE-1PASSWORD.md  ← what the 1Password reverse-engineering pass actually found
├── docs/analysis-core.md  ← symbol-guided analysis of the 180 MB core binary (crate map, crypto, pairing)
├── evidence/              ← small verifiable receipts (REA output, inventories); raw 205 MB stays out
├── crates/grim-core/      ← crypto + encrypted store (the fat core)
├── crates/grim/           ← CLI client
├── Cargo.toml             ← workspace
└── .gitignore             ← vendor artifacts and raw evidence are never committed
```

**Name:** GRIMOIRE — *a book of secret names*. Binary `grim`, daemon `grimd`.

**Thesis:** the useful thing to learn from 1Password 8 is not its UI and not its crypto
primitives (all public). It is where they put the trust boundary: a fat Rust core that owns
keys and crypto, a thin client that owns nothing, and a *closed, enumerated* capability list
between them. A TUI can only be a serious password manager if it is built the same way — one
unlocked daemon shared by the terminal, the CLI and (later) agents, with the view disposable.

Read in this order:

1. `DESIGN.md` §1 — seven lessons from the analysis, each tied to evidence.
2. `DESIGN.md` §2–§4 — architecture, 27-verb capability API, key hierarchy.
3. `DESIGN.md` §6 — the actual TUI: layout, keys, states.
4. `EVIDENCE-1PASSWORD.md` — the receipts, including where the tooling came up short.

**Status:** design + **P0a implemented**. `grim-core` and the `grim` CLI work end to end for a
local vault; no TUI, no daemon, no sync yet. Phases P0–P5 in `DESIGN.md` §10.

## Build and run

```bash
cargo test                                  # 9 tests: crypto, store, AAD binding, TOTP vector
cargo build --release
export GRIM_PASSPHRASE='…'                  # or omit to be prompted
./target/release/grim init                  # prints the recovery kit ONCE
./target/release/grim add --title github --username you --password '…' \
    --url https://github.com --totp JBSWY3DPEHPK3PXP
./target/release/grim list                  # overviews only — the cheap half
./target/release/grim get github            # fields masked
GRIM_REVEAL=1 ./target/release/grim get github --field password
./target/release/grim totp github
```

What P0a actually does: Argon2id + account-key derivation (§4.1), canary unlock, XChaCha20-Poly1305
with per-slot AAD, overview/detail split with per-item keys (§5), RFC 6238 TOTP, owner-only file
permissions.

What it does **not** do yet: `grimd` and the capability/socket layer, the ratatui TUI, search
index, import/export, sync, shares, leases. Each is a phase, not a stub.

**Reproduce the study:** `EVIDENCE-1PASSWORD.md` §6. REA evidence lives in
`~/rea-work/1password/evidence/` inside WSL.

**Scope note:** the 1Password study covered publicly distributed client artifacts only. The
user's encrypted vault database was never opened, and no code, asset, template or protocol
byte from 1Password appears in this design — see `EVIDENCE-1PASSWORD.md` §7.

## Repository

- Remote: `git@github.com:hellasleeper108/grimoire.git` (SSH, key already trusted by GitHub)
- Branch: `main`
- **Licence: TBD.** Nothing is granted yet. Note that most shipping password managers are
  copyleft (KeePass GPL-2.0, Bitwarden GPL-3.0, `pass` GPL-2.0+), and this project is a study of
  a proprietary product — pick deliberately, not by default.
- Commit style: subject line ≤ 72 chars, imperative, body explains *why*.

## Provenance

Derived from a static study of 1Password 8.12.42 (Linux build dated 2026-10-20) using REA 6.7.0
with Ghidra 12.1.4 as the native provider. Every claim in `DESIGN.md` §1 traces to a section of
`EVIDENCE-1PASSWORD.md`; every claim there traces to a command, an `evidence_id`, or a symbol
table. Where evidence is weak (`strings` output, minified bundles, a timed-out decompile), it is
labelled as weak rather than smoothed over.
