//! End-to-end: spawn the real `grimd` binary, talk to it over a real Unix socket.
//!
//! This is the test that matters for the architecture — if the locked gate leaks, or the client
//! path drifts from the verbs, it fails here.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use grim_core::protocol::{call, ItemRow, Request, Response};
use grim_core::{AccountKey, Detail, Field, FieldKind, KdfParams, Overview, Vault, VaultParams};

struct Fixture {
    dir: PathBuf,
    vault: PathBuf,
    keyfile: PathBuf,
    socket: PathBuf,
    child: Option<Child>,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("grimd-test-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Self {
            vault: dir.join("vault.db"),
            keyfile: dir.join("account.key"),
            socket: dir.join("grimd.sock"),
            dir,
            child: None,
        }
    }

    /// Create a vault with the fast KDF profile and write the account key next to it.
    fn make_vault(&self, passphrase: &str) -> AccountKey {
        let params = VaultParams { kdf: KdfParams::fast_for_tests() };
        let (vault, account_key) = Vault::create(&self.vault, passphrase, params).unwrap();
        vault.lock();
        std::fs::write(&self.keyfile, account_key.to_recovery_string()).unwrap();
        account_key
    }

    fn start_daemon(&mut self) {
        let exe = env!("CARGO_BIN_EXE_grimd");
        let child = Command::new(exe)
            .arg("--vault").arg(&self.vault)
            .arg("--key").arg(&self.keyfile)
            .arg("--socket").arg(&self.socket)
            .spawn()
            .expect("spawn grimd");
        self.child = Some(child);

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.socket.exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("grimd did not create {} within 10s", self.socket.display());
    }

    fn call(&self, req: Request) -> Response {
        call(&self.socket, &req).expect("socket call")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // polite shutdown, then make sure
        let _ = call(&self.socket, &Request::Quit);
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn login() -> (Overview, Detail) {
    let overview = Overview {
        title: "GitHub".into(),
        subtitle: "hella".into(),
        url_host: "github.com".into(),
        tags: vec![],
        favorite: false,
    };
    let detail = Detail {
        fields: vec![
            Field { name: "username".into(), kind: FieldKind::Text, value: "hella".into(), conceal: false },
            Field { name: "password".into(), kind: FieldKind::Password, value: "hunter2".into(), conceal: true },
            Field { name: "totp".into(), kind: FieldKind::Totp, value: "JBSWY3DPEHPK3PXP".into(), conceal: true },
        ],
        notes: String::new(),
    };
    (overview, detail)
}

fn expect_error(resp: Response) -> String {
    match resp {
        Response::Error { message } => message,
        other => panic!("expected an error, got {other:?}"),
    }
}

#[test]
fn daemon_lifecycle_and_locked_gate() {
    let mut fx = Fixture::new("lifecycle");
    fx.make_vault("correct horse battery staple");
    fx.start_daemon();

    // 1. starts locked, with nothing readable
    match fx.call(Request::Status) {
        Response::Status { locked, items, vault } => {
            assert!(locked, "daemon must start locked");
            assert_eq!(items, 0);
            assert!(vault.ends_with("vault.db"));
        }
        other => panic!("unexpected {other:?}"),
    }

    // 2. every data verb is refused while locked
    for req in [
        Request::ListItems,
        Request::GetItem { needle: "github".into() },
        Request::RevealField { needle: "github".into(), field: "password".into() },
        Request::TotpNow { needle: "github".into() },
    ] {
        let msg = expect_error(fx.call(req));
        assert!(msg.contains("locked"), "expected a locked refusal, got {msg:?}");
    }

    // 3. wrong passphrase is refused and leaves the daemon locked
    let msg = expect_error(fx.call(Request::Unlock { passphrase: "nope".into() }));
    assert!(msg.contains("passphrase"), "got {msg:?}");
    assert!(matches!(fx.call(Request::Status), Response::Status { locked: true, .. }));

    // 4. right passphrase unlocks
    assert!(matches!(
        fx.call(Request::Unlock { passphrase: "correct horse battery staple".into() }),
        Response::Ok
    ));
    assert!(matches!(fx.call(Request::Status), Response::Status { locked: false, .. }));

    // 5. add, list, read one field, totp
    let (ov, dt) = login();
    let id = match fx.call(Request::AddItem { category: "login".into(), overview: ov, detail: dt }) {
        Response::Added { id } => id,
        other => panic!("unexpected {other:?}"),
    };

    match fx.call(Request::ListItems) {
        Response::Items { items } => {
            assert_eq!(items.len(), 1);
            let row: &ItemRow = &items[0];
            assert_eq!(row.title, "GitHub");
            assert_eq!(row.category, "login");
            assert_eq!(row.url_host, "github.com");
            assert_eq!(row.id, id);
        }
        other => panic!("unexpected {other:?}"),
    }

    match fx.call(Request::RevealField { needle: "github".into(), field: "password".into() }) {
        Response::Value { value } => assert_eq!(value, "hunter2"),
        other => panic!("unexpected {other:?}"),
    }

    match fx.call(Request::TotpNow { needle: "github".into() }) {
        Response::Totp { code, remaining } => {
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
            assert!((1..=30).contains(&remaining));
        }
        other => panic!("unexpected {other:?}"),
    }

    // 6. lock drops the keys, and the gate closes again
    assert!(matches!(fx.call(Request::Lock), Response::Ok));
    let msg = expect_error(fx.call(Request::ListItems));
    assert!(msg.contains("locked"), "got {msg:?}");

    // 7. re-unlock works (the vault is still on disk)
    assert!(matches!(
        fx.call(Request::Unlock { passphrase: "correct horse battery staple".into() }),
        Response::Ok
    ));
    assert!(matches!(fx.call(Request::ListItems), Response::Items { items } if items.len() == 1));
}

#[test]
fn daemon_survives_a_client_that_disconnects_without_reading() {
    let mut fx = Fixture::new("rude");
    fx.make_vault("pw");
    fx.start_daemon();

    // connect, send nothing, close — the accept loop must not die
    {
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        let mut s = UnixStream::connect(&fx.socket).unwrap();
        let _ = s.write_all(b"\n");
    }
    // and a garbage line
    {
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        let mut s = UnixStream::connect(&fx.socket).unwrap();
        let _ = s.write_all(b"not json\n");
    }

    assert!(matches!(fx.call(Request::Status), Response::Status { locked: true, .. }));
    assert!(matches!(fx.call(Request::Unlock { passphrase: "pw".into() }), Response::Ok));
}

#[test]
fn socket_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let mut fx = Fixture::new("perms");
    fx.make_vault("pw");
    fx.start_daemon();

    let mode = std::fs::metadata(&fx.socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "socket mode {mode:o}");
    let dir_mode = std::fs::metadata(Path::new(&fx.dir)).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700, "socket dir mode {dir_mode:o}");
}
