# Evidence receipts

Small, verifiable artifacts from the 1Password study. Nothing in this directory is vendor
code — it is either REA's own output or a fact extracted from the binary (file inventory,
GraphQL operation names).

| File | What it is | Provenance |
|---|---|---|
| `rea-ghidra-1password-mcp.json` | REA binary-layout Evidence for `1password-mcp` (8.7 KB): 37 segments, 4,587 procedures, 7,476 strings | `rea analyze ./1password-mcp --provider ghidra --format json`, `evidence_id: ev_beae63f7…` |
| `asar-inventory.txt` | the 486-entry file list of `app.asar` | `asar list resources/app.asar` |
| `graphql-operations.txt` | 33 GraphQL operation names recovered from the bundle (15 query / 12 mutation / 6 subscription) | grep over the extracted asar |

## What is deliberately NOT here

- **`asar.json` — 205 MB** of canonical Evidence JSON for the 40.7 MB Electron bundle
  (`evidence_id: ev_d84fe808…`, 61 s runtime). Too large for a repo and fully reproducible; the
  numbers and structure are transcribed in `../EVIDENCE-1PASSWORD.md` §2.1.
- **The extracted asar itself** (`/tmp/asar-x`, 220 MB) and the 1Password tarball (580 MB) — vendor
  artifacts, not ours to redistribute.
- **`preload.js`**, which names the ~90-verb IPC allowlist. The verb *list* is quoted in
  `../EVIDENCE-1PASSWORD.md` §3 as study notes; the file itself is theirs and is not committed.
- Full diagnostics bundle from the two timed-out runs (16 MB of embedded Ghidra logs).

## Reproduce

```bash
# WSL, REA 6.7.0 + Ghidra 12.1.4 + JDK 21
cd ~/rea-work/1password
curl -fsSLO https://downloads.1password.com/linux/tar/stable/x86_64/1password-latest.tar.gz
tar -xzf 1password-latest.tar.gz && cd 1password-*/.x64

rea analyze-javascript-application resources/app.asar --format json > ~/evidence/asar.json
REA_GHIDRA_STARTUP_TIMEOUT_MS=1800000 \
  rea analyze ./1password-mcp --provider ghidra --format json > ~/evidence/mcp.json
```

The `REA_GHIDRA_STARTUP_TIMEOUT_MS` override is not optional on this box: the 330 s default times
out on a ~4 600-procedure Rust binary. See `../EVIDENCE-1PASSWORD.md` §2.2.
