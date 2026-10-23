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

**Status:** design + **P0c + P1 (import)**. `grim-core` (crypto, store, import parsers), `grimd`
(daemon that owns keys and answers a closed verb set over a Unix socket), `grim` (CLI + ratatui TUI,
no keys, no SQL). No sync yet. Phases P0–P5 in `DESIGN.md` §10.

## Build and run

```bash
cargo test                                  # 32 tests: crypto, store, import, daemon, TUI
cargo build --release

export GRIM_PASSPHRASE='…'                  # or omit to be prompted
./target/release/grim init                  # prints the recovery kit ONCE

./target/release/grimd &                    # the only process that holds keys
./target/release/grim status                # -> locked
./target/release/grim unlock
./target/release/grim add --title github --username you --password '…' \
    --url https://github.com --totp JBSWY3DPEHPK3PXP
./target/release/grim list                  # overviews only — the cheap half
./target/release/grim get github            # fields masked
GRIM_REVEAL=1 ./target/release/grim get github --field password
./target/release/grim totp github
./target/release/grim lock                  # drops the keys; every data verb then refuses
./target/release/grim quit                  # stops the daemon
```

A locked daemon answers exactly four verbs (`status`, `unlock`, `quit`, and its own error), and the
socket lives at `$XDG_RUNTIME_DIR/grimoire/grimd.sock` with mode `0600` inside a `0700` directory.
`grim` fails loudly if the daemon is not running — it never falls back to opening the vault itself.

## The TUI

`grim tui` — three panes, keyboard only, no mouse, no colours required.

| Key | Action |
|---|---|
| `j` / `k`, `↓` / `↑` | move selection |
| `g` / `G` | first / last |
| `/` | fuzzy-ish filter (title, subtitle, host); `Enter` accept, `Esc` clear |
| `y` | copy the password via `wl-copy`/`xclip`/`xsel`/`clip.exe`, toast names the tool |
| `t` | TOTP now, copied, with the seconds remaining |
| `r` | reveal concealed fields for 10 s, then auto-hide |
| `Ctrl-L` | lock the daemon (keys dropped, panes cleared) |
| `q` | leave the view (the daemon stays as it was) |

```
 GRIMOIRE  ~/.local/share/grimoire/vault.db   3 item(s)
┌ items ─────────────────────────────────────┐┌ detail ────────────────────────────────────────────┐
│37c06b16  login      github                 ││github  [login]                                     │
│93ec3ade  login      gitea                  ││id 37c06b16                                         │
│4278c105  sshkey     deploy@vps             ││username   hella                                    │
│                                            ││password   ••••••••…  (12 chars, r to reveal)       │
│                                            ││totp       ••••••••…  (16 chars, r to reveal)       │
│                                            ││url        https://github.com                       │
└────────────────────────────────────────────┘└────────────────────────────────────────────────────┘
 j/k move · / search · y copy · t totp · r reveal · ^L lock · q quit
```

`grim tui --snapshot` renders one frame to stdout instead of the terminal, so the layout can be
reviewed in a PR, diffed in CI, or pasted into a bug report.

Clipboard support is best-effort and named: `y` reports *which* tool accepted the value, or says
plainly that no helper was found rather than pretending the copy worked. `DESIGN.md` §6.3 called for
honest state rendering; that applies to failures too.

## Import

`grim import <file> [--dry-run]` reads a CSV (any of the common column spellings: `name`/`title`,
`url`/`website`/`login_uri`, `username`/`login_username`, `password`/`login_password`, `totp`,
`notes`, `folder`, `type`) or a Bitwarden JSON export. The format is guessed from the extension and
then from the first byte.

The rule it enforces is the one that makes an import trustworthy: **every row is either imported or
explained with a line number and a reason**, and a file that isn't recognisable is refused outright
rather than half-read. The whole batch then lands in one transaction — if the write fails, nothing is
imported, so a retry can't double-populate.

```
$ grim import messy.csv
4 row(s): 3 importable, 1 skipped
  by category: login 2, securenote 1
  skipped row 3     no title

imported 3 of 3 item(s)

$ grim import bitwarden.json
2 row(s): 1 importable, 1 skipped
  by category: login 1
  skipped row 2     unsupported Bitwarden type 3 (card/identity)

$ grim import not-an-export.csv ; echo $?
0 row(s): 0 importable, 0 skipped
  refused: no name/title column recognised in the header
grim: daemon: import refused: no name/title column recognised in the header
1
```

1PUX (the 1Password zip export) is **not** supported yet — it needs a zip reader and a second
schema, and it is the obvious next thing for anyone migrating off 1Password.

What P0a–P1 actually do: Argon2id + account-key derivation (§4.1), canary unlock, XChaCha20-Poly1305
with per-slot AAD, overview/detail split with per-item keys (§5), RFC 6238 TOTP, owner-only file
permissions, and a daemon/socket split where the client cannot touch the store (§2, §3.2).

What it does **not** do yet: search index, import/export, sync, shares, leases, and a CLI-consent
prompt for one-shot reads (today a client that can open the socket may read any field the daemon
will hand it). Each is a phase, not a stub.

Access control, in order of application: the socket is `0600` inside a `0700` directory, **and**
every accepted connection is checked with `SO_PEERCRED` against the daemon's effective uid before a
single byte of the request is parsed.

**Reproduce the study:** `EVIDENCE-1PASSWORD.md` §6. REA evidence lives in
`~/rea-work/1password/evidence/` inside WSL.

**Scope note:** the 1Password study covered publicly distributed client artifacts only. The
user's encrypted vault database was never opened, and no code, asset, template or protocol
byte from 1Password appears in this design — see `EVIDENCE-1PASSWORD.md` §7.

## Repository

- Remote: `git@github.com:hellasleeper108/grimoire.git` (SSH, key already trusted by GitHub)
- Branch: `main`
- **Licence: GPL-3.0-or-later.** Chosen deliberately: a password manager is a security tool people
  are asked to trust with their whole digital life, and the copyleft guarantees that any version
  they run can be audited. It also matches the field (Bitwarden GPL-3.0, KeePass GPL-2.0, `pass`
  GPL-2.0+). If you need to embed `grim-core` in something proprietary, MIT/Apache-2.0 would have
  been the choice — that trade was made deliberately, not by default.
- **The study is not the product.** `EVIDENCE-1PASSWORD.md` and `docs/analysis-core.md` record an
  independent reverse-engineering study of a proprietary product. No code, assets, templates or
  protocol bytes from 1Password are included; the licence above covers only original work here.
- Commit style: subject line ≤ 72 chars, imperative, body explains *why*.

## Provenance

Derived from a static study of 1Password 8.12.42 (Linux build dated 2026-10-20) using REA 6.7.0
with Ghidra 12.1.4 as the native provider. Every claim in `DESIGN.md` §1 traces to a section of
`EVIDENCE-1PASSWORD.md`; every claim there traces to a command, an `evidence_id`, or a symbol
table. Where evidence is weak (`strings` output, minified bundles, a timed-out decompile), it is
labelled as weak rather than smoothed over.
