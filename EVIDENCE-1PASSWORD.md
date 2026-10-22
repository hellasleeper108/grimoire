# Evidence log — 1Password 8.12.42 static study

All work done with **REA 6.7.0** (`rea`) inside WSL Ubuntu 26.04, Ghidra 12.1.4 + Temurin JDK 21
as the native provider. Target: the public Linux tarball from `downloads.1password.com`
(build dated 2026-10-20), plus the installed Windows MSIX binaries for comparison of file roles.

**Scope discipline:** I analysed *distributed client artifacts only* — the Electron bundle, the
shipped native libraries, and the two companion binaries. I did **not** open, decrypt, or
attempt to open the local vault database `%LOCALAPPDATA%\1Password\1password.sqlite`. It is
encrypted user data; its contents are out of scope for a design study, and no attempt was made.

---

## 1. Artifacts analysed

| Path (inside `1password-8.12.42.x64/`) | Size | Role |
|---|---|---|
| `resources/app.asar` | 40.7 MB | entire Electron UI + app logic (423 JS files) |
| `resources/app.asar.unpacked/index.node` | 188 MB | Rust node addon — the real engine |
| `libop_sdk_lib_core.so` | 23.5 MB | shared Rust SDK core (`op_crypto`, `op_sdk_core`, …) |
| `1password-mcp` | 3.7 MB | MCP server (environments/variables surface) |
| `1Password-BrowserSupport` | 7.7 MB | native-messaging host for browser integration |
| `1password` | 220 MB | Electron main binary (stock Chromium + app entry) |
| `op-ssh-sign`, `1Password-LastPass-Exporter` | 0.1 / 10 MB | SSH signing agent, importer |

---

## 2. REA runs and their receipts

### 2.1 Application graph (complete)

```bash
rea analyze-javascript-application resources/app.asar --format json > evidence/asar.json
```
- **`evidence_id: ev_d84fe808e095d92e3eb021887072fe4fa733ef9b96109a98ed3a45e85bf1faf2`**
- output: 205,112,149 bytes of canonical Evidence JSON (205 MB) on disk
- runtime: **61 s wall clock** for the 40.7 MB / 423-file asar — worth knowing as the baseline for future passes
- integrity: `integrity_contradictions: []` (0), `parse_failures: 0`

Statistics (REA-reported):

| Metric | Value |
|---|---|
| relevant files / parsed | 423 / 414 (1 skipped: `CREDITS.html` inline script) |
| text bytes read | 16,168,669 |
| AST nodes visited | 1,087,030 |
| modules | 422 |
| findings | 5,148 |
| graph | 4,475 nodes, 4,611 edges |

Graph node census — this is the structural map of the app:

```
javascript-module 2478   javascript-chunk 1068   javascript-asset 415
asar-entry 423           ipc-channel 16          ipc-handler 13
electron-renderer 5      browser-window 4        endpoint 16
artifact 8               unknown 8               electron-main 1
electron-preload 1       context-bridge-api 1    native-addon 1
package 1
```

Electron boundary summary (REA):

```yaml
browser_windows: 4
explicit_web_preferences: 3
context_bridge_apis: 1
ipc: { operations: 20, literal_channels: 12, dynamic_channel_operations: 4,
       renderer_transmissions: 7, renderer_listeners: 3, main_handlers: 10,
       paired_renderer_transmissions: 3, unpaired_literal_renderer_transmissions: 2 }
sender_validation_observations: 1
```

**Where REA's static view hit its own documented limit:** `preload_entrypoints: 0` and
`exposed_api_members: 0`, even though a preload with a ~90-verb API exists. Reason: the API is
built by a runtime loop over an object literal, and REA resolves only statically provable
members (`limitations`: *"Dynamic IPC channel expressions remain unresolved and are never paired
by textual similarity"*, *"Runtime registration … remain unproven"*). So the capability list in
§3 below is from a **manual read** of `preload.js`, not from REA — the two are complementary,
and both are reported here rather than pretending REA saw it.

### 2.2 Native binaries (Ghidra) — deadline finding

```bash
rea analyze ./1password-mcp            --format json > evidence/mcp.json
rea analyze ./1Password-BrowserSupport --format json > evidence/browsersupport.json
```

Both first attempts returned **`provider_timeout`** at REA's default 330 000 ms deadline
(`REA_GHIDRA_STARTUP_TIMEOUT_MS`): *"Ghidra did not finish importing and analyzing the target
within its 330000 ms startup deadline"*. This is a tooling fact worth recording — the 16 KB
control binary finished in 11 s, but a 3.7 MB Rust binary carries ~4 300 functions and a 7.7 MB
one ~6 000, and REA's profile decompiles them all. Both runs were relaunched with
`REA_GHIDRA_STARTUP_TIMEOUT_MS=1800000` (`evidence/mcp2.json`, `browsersupport2.json`).

Because both binaries are **not stripped**, the symbol tables gave better design evidence than
decompilation would, immediately and for free. Everything in §8 is symbol-table evidence —
labelled as such, distinct from REA's decompiler output.

**Relaunch result — `1password-mcp` completed:**

```yaml
evidence_id: ev_beae63f7c2c8609b469aa84045a26672eaac9536a202d4dbaf311693e11fb1ba
subject:     1password-mcp · sha256 0ad09696ddf69266e8db2cf6694bcb0471f73c76e7f7ba7efe3624be18125972
provider:    rea-workflow → upstream ghidra 12.1.4
format/arch: elf / x86_64 (image base 0x100000)
segments:    37
procedures:  4,587
strings:     7,476
```
~9 minutes of Ghidra under a 30-minute deadline, versus the 330 s default that killed it.
`1Password-BrowserSupport` (7.7 MB, ~6 040 symbols) relaunched second in the same job.

**Relaunch result — `1Password-BrowserSupport` also completed** (job total 1 752 s for both):

```yaml
evidence_id: ev_d711ea77928fd6f9eb270acc23b9019715a9184e5efead43acf6dbe253b5390b
subject:     1Password-BrowserSupport · sha256 fd733e9b00ca639e55f4bb39c4c62fa1b84ddd80698b62ea731813729c6a56b1
provider:    rea-workflow → upstream ghidra 12.1.4
format/arch: elf / x86_64
segments:    37
procedures:  6,485
strings:     10,910
confidence:  derived · 8 documented limitations
```
Both receipts are committed under `evidence/` as `rea-ghidra-1password-mcp.json` and
`rea-ghidra-browsersupport.json`. These two runs are the only decompiler-tier (R) evidence in the
study; everything about the 180 MB core in `docs/analysis-core.md` is symbol-table tier (S/D) by
design.

---

## 3. The IPC surface (manual read of `preload.js`, 2,994 bytes)

`contextBridge.exposeInMainWorld("op", …)` over a literal allowlist, converted to
`ipcRenderer.invoke` wrappers in a loop, plus four generic channels:

```
invoke · executeGql · gqlSubscriptionRequest · gqlSubscriptionResponse
SendPendingEvent · CoreLog · pathFromFile
```

The ~90 named verbs, grouped by what they reveal about the product:

| Group | Verbs |
|---|---|
| **Vault / item** | `setSelectedItemSpecifiers`, `onItemActionSelected`, `onFieldActionSelected`, `notifyCreateItemFinish`, `showShareMenu`, `showQXCollectionsMenu` |
| **Secrets** | `generateTotp`, `scanTotp`, `secureCopy`, `showLargeType`, `setRevealStatus`, `parseClipboardQr`, `captureSignInComponents` |
| **Unlock / auth** | `getLockScreen`, `showAuthPrompt`, `authPromptUnlock`, `authPromptApprove`, `authPromptFallbackApprovalMethod`, `authPromptSetEmbeddedAuthEnabled`, `sendMfaSubmission`, `sendMyceliumConfirmationCode`, `sendSameDeviceOnboardingConfirmationResponse`, `captureTrustedDeviceSignInResponse`, `generateSsoRedirectUrl`, `dismissSsoEnrollmentCodeModal` |
| **Passkeys / WebAuthn** | `showPasskeyPrompt`, `webauthnSign`, `registerPasskeySelection`, `signInPasskeySelection`, `getCameraAccessStatus` |
| **Accounts** | `addAccountFromFile`, `addAccountFromOpenDialog`, `fetchResource`, `getFrontEndConfig` |
| **Dev secrets** | `selectDotEnvFileMountPath`, `getDotEnvFilePath` |
| **Window/OS chrome** | `showCurrentWindow`, `hideCurrentWindow`, `setSecureInput`, `isOsWindowFocused`, `showMenuForCurrentWindow`, `setModalStatus`, `print`, `hasPrinter`, `showInFileBrowser`, `saveContentToFile`, `openSystemCameraPermissions`, `openSystemTouchIDSettings`, `openSystemNotificationPermissions`, `downloadHtmlAsImage`, `showLargeQrCodeWindow` |
| **i18n / misc** | `localize`, `getLocale`, `openLink`, `openCredits`, `quit`, `closeCurrentWindow` |

Design read: roughly **two thirds** of that surface exists only because the client is a
*desktop GUI* (windows, modals, printers, camera, Touch ID, tray). A terminal client genuinely
needs about a quarter of it — which is the argument for GRIMOIRE's 27-verb API.

### 3.1 Data plane

`executeGql` + a request/response subscription pair. Operation names recovered from the bundle
(33 distinct; 15 query / 12 mutation / 6 subscription):

```
queries:       Sidebar, ToolbarContainer, QuickFindSearch, ManageCollections,
               CreateEditVault, ImportModalVaultSelector, PrimaryRoutes, AdminStatus,
               EnvironmentsTable, GetEnvironmentWorkloads, ActivationHubDeveloperExperience,
               GithubActionsWorkloadCardFeatureFlags, GetGenericOidcWorkloadIdentityProviders,
               GetGithubActionsWorkloadIdentityProviders, Foo
mutations:     CreateVault, UpdateVault, WorkloadCreate, WorkloadUpdate, WorkloadGrantAccess,
               CreateGithubActionsWorkload, GrantGithubActionsWorkloadAccess,
               DeleteGithubActionsWorkload, RevokeGithubActionsWorkloadAccess,
               OtpAuthPickerItemEditBegin, OtpAuthPickerItemEditCancel, OtpAuthPickerItemSave
subscriptions: AccountsSubscription, SidebarAccounts, SidebarCollection, ToolbarAccounts,
               ToolbarCollection, ManageCollectionsChanged
```

Every subscription is **shell chrome**, not item data. Item data is queried on demand.

### 3.2 Item category vocabulary (bundle + SDK strings)

```
login · password · securenote · creditcard · identity · document · sshkey · server ·
database · passport · driverlicense · medicalrecord · bankaccount · membership ·
softwarelicense · person
```
SDK-side nouns: `vault · item · section · field · category · template · share · trash ·
overview · detail` (field 150, item 92, vault 44, section 27, collection 14 in the string census).

---

## 4. Native core observations (`strings`, weaker than REA evidence)

### 4.1 Rust crate/module names

```
op_crypto · op_sdk_core · op_sdk_lib_core · op_sdk_b5_client · op_sdk_service_account ·
op_sdk_throttle_token · pasetors (PASETO) · elliptic_curve::p256 (NIST P-256)
```
Stack: `tokio` ×115, `rustls` ×81, `ring` ×64, `sqlite` ×64, `openssl` ×25.

`op_sdk_b5_client` names their sync plane ("B5"); `op_sdk_service_account` and
`op_sdk_throttle_token` show service accounts and rate-limit tokens are first-class.

### 4.2 Crypto vocabulary (error enums are a primitive inventory)

```
aes-256-gcm · hkdf · hmac-sha256 · sha256 · pbkdf2 · scrypt · ed25519 · x25519 ·
rsa-oaep / rsa-oaep256 · ecdh-es · srp · MasterPassword · SecretKey · GcmBadNonceLen ·
InvalidPbkdf2Iterations · DecryptionHashMismatch · UnexpectedEncryptionVersion
```
SRP present in force (multiple `Srp*` error variants) → zero-knowledge password auth.
`SecretKey` carries length/version/`BadFields` errors → the account Secret Key is a parsed,
versioned type, not an opaque string.

### 4.3 Notable literal

> "This is an obfuscation key used to mask the secret key in the local database and nothing
> more. If this seems interesting to you, come work with us :)"

Their own comment concedes the local obfuscation key is obfuscation. GRIMOIRE's spec says the
same thing in §11 rather than implying it is protection.

### 4.4 Credential-broker environment keys

`1P_CREDENTIAL_BROKER_CLIENT_AUTH_KEY`, `1P_CREDENTIAL_BROKER_AUTH_KEY_` → an SSH-agent-style
broker with per-client auth, not just a plain socket.

---

## 5. Agent surface (`1password-mcp`)

Tool names recoverable from the binary: `list_environments`, `create_environment`,
`list_variables` (+ workload create/grant/update and secret-mount verbs mirrored from the GQL
operations). The MCP server exposes **Environments and variables**, not vault items — the
single most load-bearing insight for GRIMOIRE's lease design.

---

## 6. Reproduce

```bash
# in WSL, with rea + GHIDRA_INSTALL_DIR + JAVA_HOME set
cd ~/rea-work/1password
curl -fsSLO https://downloads.1password.com/linux/tar/stable/x86_64/1password-latest.tar.gz
tar -xzf 1password-latest.tar.gz
cd 1password-*/.x64
rea analyze-javascript-application resources/app.asar --format json > ~/rea-work/1password/evidence/asar.json
~/.local/lib/node_modules/rea-agents/node_modules/.bin/asar extract resources/app.asar /tmp/asar-x
grep -rhoE "(query|mutation|subscription) [A-Z][A-Za-z0-9_]{2,45}" /tmp/asar-x --include="*.js" | sort -u
strings -n 4 libop_sdk_lib_core.so | grep -oiE "srp|2skd|argon2|hkdf|aes-?256-?gcm|ed25519|x25519|paseto"
rea doctor --json      # expect healthy: true with ghidra provider
```

Artifacts kept: `~/rea-work/1password/evidence/{asar.json, asar.err, mcp.json, browsersupport.json}`.

---

## 7. Limits of this study, stated plainly

1. **Static only.** Nothing was executed; no account was signed into; no network calls to
   AgileBits infrastructure were made by the analysed code.
2. **Minified bundles.** JS analysis gives module/export/boundary shape, not readable source.
   Variable names are lost; behaviour is inferred from call shape and strings.
3. **No decompilation of the Rust core** in this pass — the 188 MB addon and 23 MB SDK core were
   read as strings only. If you want behaviour-level evidence (e.g. exact KDF chain order),
   that needs a symbolic-execution or targeted Ghidra pass, and that is a separate, larger job.
4. **The local vault DB was not opened** (see scope note at top).
5. **REA's own caveats stand**: its evidence says *"Graph coverage is incomplete; unavailable
   facts remain explicit and must not be read as absence"* and one primitive string budget was
   exceeded (`max 1,048,576 estimated JSON bytes`). Absence of a string in this document is not
   evidence of absence in the product.
6. **Legal/ethical line taken:** study of publicly distributed client artifacts for
   architecture learning; no code, assets, templates or protocol bytes were copied into the
   GRIMOIRE design, and no protection was circumvented. 1Password's licence is proprietary —
   if GRIMOIRE ever ships, this document should be read as *prior-art study*, and legal review
   of the differences in §11 of `DESIGN.md` is the appropriate next step before any release.

---

## 8. Addendum — symbol-table findings (evidence tier: symbol table, not decompiler)

Both companion binaries ship **unstripped**, so the Rust symbol tables are readable. Function
census: `1password-mcp` ≈ 4 314, `1Password-BrowserSupport` ≈ 6 040 defined `T`/`t` symbols.

### 8.1 `1password-mcp` — what the MCP server actually is

```
op_mcp_server::services::developer_environments::api::DeveloperEnvironmentsMcpService
op_mcp_server::ipc::AppConnection
op_mcp_server::ipc::TOOL_CALL_ACCOUNT      (static, per-call)
op_mcp_server::ipc::TOOL_CALL_OUTCOME      (static, per-call)
```
Argument types (serde/`schemars` schema types, i.e. the tool signatures):

```
CreateEnvironmentArgs · RenameEnvironmentArgs · ListEnvironmentArgs · ListVariablesArgs
AppendVariablesArgs · CreateLocalEnvFileArgs · ListLocalEnvFilesArgs · VariableInput
```
Transport: `rmcp` (the official Rust MCP SDK) `ToolRoute` table, `tokio`, `serde_json`, `chrono`.

Two design facts fall out of this that `strings` alone could not establish:

1. The service is **`developer_environments`** — the MCP server is a secrets-automation surface
   (environments, variables, local `.env` files), not a vault reader. Confirms §5.
2. Every tool call is **accounted**: a per-call account key plus an outcome static. Billing or
   audit is attached to the *call*, not to the session. GRIMOIRE's lease audit should do the
   same — one audit record per leased read, not one per connected agent.

### 8.2 `1Password-BrowserSupport` — the three-tier client chain

Transport stack in symbols: `zbus` ×233 and `zvariant` ×240 → the helper is a **D-Bus client**
of the desktop application, not a peer that shares memory or a socket file. Above it sits
`op_nm_models` with four namespaces:

```
op_nm_models::filling_and_saving   (63+ refs — the largest)
op_nm_models::configuration        (20 refs)
op_nm_models::cli_integration      (8 refs)
op_nm_models::oph_integration      (13 refs)
op_nm_models::b5_connection        (9 refs)
```

Message types recovered per namespace:

| Namespace | Types |
|---|---|
| `filling_and_saving` | `NativeAutofillItemListResponse`, `NativeAutofillItemListSection`, `NativeAutofillItemOverview`, `NativeAutofillItemCredentialsRequest/Response/Error`, `NativeAutofillConfirmFillRequest/Response`, `NativeAutofillUsernameSuggestionsResponse`, `NativeAutofillPasskeyAuthenticate/Register/SaveResponse`, `NativeAutofillUnlockSingleAccountResponse`, `NativeAutofillInlineUnlockResponse`, `NmCollectedPageDetailsRequest`, `NmAcknowledgeFillItemRequest`, `NmNativeAutofillRequest/Response`, `NativeAutofillCollection(Type)` |
| `configuration` | `NmLockStateResponse`, `NmRequestAccountsRequest/Response`, `NmOfflineStatusResponse`, `NmCurrentStatusState`, `NmDesktopApplicationDeviceInfoResponse`, `NmPromptToAddAccountRequest`, `NmShouldPromptToAddAccountRequest/Response` |
| `cli_integration` | `NmRequestAuthorizationRequest`, `NmAuthorizationResponse`, `NmDropAuthorizationRequest`, `NmCliCommandMetadata` |
| `oph_integration` | `LockState`, `NmCreateItemRequest`, `NmAcknowledgeCheckExtensionPinStatusRequest`, `NmAcknowledgeCheckExtensionFirstSsoFlowRequest` |

**The architectural lesson, and the best one in this study:** the browser is never handed a
vault. It receives *projections* — an item list section for the current page, one item overview,
credentials for one confirmed fill, a username suggestion list, a passkey assertion. The CLI
does not get credentials either: `cli_integration` issues and drops an **authorization** carrying
`NmCliCommandMetadata`, so the desktop app knows *which command* is asking before it consents.

GRIMOIRE adopts this wholesale: one daemon, several projections, consent scoped to
(intent, not identity of the client). See `DESIGN.md` §3.3 and §7.
