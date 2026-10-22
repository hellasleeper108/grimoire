//! grimd — the only process that holds keys.
//!
//! The daemon owns the unlocked vault, answers a closed set of capability verbs over a
//! same-user Unix socket, and never exposes SQL. A locked daemon answers exactly four verbs
//! (DESIGN §2 rule 4, §3.2).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use grim_core::protocol::{read_request, ItemRow, Request, Response};
use grim_core::{AccountKey, Category, Vault};

pub struct State {
    vault_path: PathBuf,
    account_key: AccountKey,
    vault: Option<Vault>,
}

impl State {
    pub fn new(vault_path: PathBuf, account_key: AccountKey) -> Self {
        Self { vault_path, account_key, vault: None }
    }

    pub fn is_locked(&self) -> bool {
        self.vault.is_none()
    }

    /// Handle one request. Returns the response and whether the daemon should stop.
    pub fn handle(&mut self, req: Request) -> (Response, bool) {
        if grim_core::protocol::allowed_while_locked(&req) || !self.is_locked() {
            return self.dispatch(req);
        }
        (Response::Error { message: "vault is locked; send `unlock` first".into() }, false)
    }

    fn dispatch(&mut self, req: Request) -> (Response, bool) {
        match req {
            Request::Status => {
                let items = self.vault.as_ref().and_then(|v| v.count().ok()).unwrap_or(0);
                (
                    Response::Status {
                        locked: self.is_locked(),
                        items,
                        vault: self.vault_path.display().to_string(),
                    },
                    false,
                )
            }
            Request::Unlock { passphrase } => {
                if self.vault.is_some() {
                    return (Response::Ok, false);
                }
                match Vault::open(&self.vault_path, &passphrase, &self.account_key) {
                    Ok(v) => {
                        self.vault = Some(v);
                        (Response::Ok, false)
                    }
                    Err(e) => (Response::Error { message: e.to_string() }, false),
                }
            }
            Request::Lock => {
                // dropping the Vault zeroizes its key material
                self.vault = None;
                (Response::Ok, false)
            }
            Request::ListItems => {
                let v = self.vault.as_ref().expect("unlocked");
                match v.list() {
                    Ok(rows) => (
                        Response::Items {
                            items: rows
                                .into_iter()
                                .map(|(id, cat, ov)| ItemRow {
                                    id,
                                    category: cat.as_str().to_string(),
                                    title: ov.title,
                                    subtitle: ov.subtitle,
                                    url_host: ov.url_host,
                                })
                                .collect(),
                        },
                        false,
                    ),
                    Err(e) => (Response::Error { message: e.to_string() }, false),
                }
            }
            Request::GetItem { needle } => {
                let v = self.vault.as_ref().expect("unlocked");
                match v.get(&needle) {
                    Ok((id, cat, overview, detail)) => (
                        Response::Item { id, category: cat.as_str().to_string(), overview, detail },
                        false,
                    ),
                    Err(e) => (Response::Error { message: e.to_string() }, false),
                }
            }
            Request::RevealField { needle, field } => {
                let v = self.vault.as_ref().expect("unlocked");
                match v.field(&needle, &field) {
                    Ok(value) => (Response::Value { value }, false),
                    Err(e) => (Response::Error { message: e.to_string() }, false),
                }
            }
            Request::TotpNow { needle } => {
                let v = self.vault.as_ref().expect("unlocked");
                match v.totp(&needle) {
                    Ok((code, remaining)) => (Response::Totp { code, remaining }, false),
                    Err(e) => (Response::Error { message: e.to_string() }, false),
                }
            }
            Request::AddItem { category, overview, detail } => {
                let cat = match Category::parse(&category) {
                    Some(c) => c,
                    None => {
                        return (
                            Response::Error { message: format!("unknown category {category:?}") },
                            false,
                        )
                    }
                };
                let v = self.vault.as_mut().expect("unlocked");
                match v.insert(cat, &overview, &detail) {
                    Ok(id) => (Response::Added { id }, false),
                    Err(e) => (Response::Error { message: e.to_string() }, false),
                }
            }
            Request::Quit => (Response::Ok, true),
        }
    }
}

/// The effective uid of this process (Linux/Unix).
pub fn own_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// uid of the process on the other end of a connected AF_UNIX socket.
///
/// `0600` on the socket is a filesystem check performed once, at connect time, by the kernel; this
/// is the same check re-asserted on the accepted connection, so a path swapped or a pre-opened
/// descriptor can't outlive a change in ownership.
#[cfg(target_os = "linux")]
pub fn peer_uid(stream: &std::os::unix::net::UnixStream) -> std::io::Result<u32> {
    use std::os::unix::io::AsRawFd;

    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: cred/len are valid for writes for the duration of the call, and SO_PEERCRED on a
    // connected AF_UNIX socket writes exactly one ucred.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// Accept loop. One thread per connection, one request per connection.
///
/// Connections from a different uid are refused before any request is parsed.
#[cfg(unix)]
pub fn serve(listener: std::os::unix::net::UnixListener, state: Arc<Mutex<State>>) {
    for conn in listener.incoming() {
        let mut stream = match conn {
            Ok(s) => s,
            Err(_) => continue,
        };

        #[cfg(target_os = "linux")]
        {
            let allowed = matches!(peer_uid(&stream), Ok(uid) if uid == own_uid());
            if !allowed {
                let msg = serde_json::to_string(&Response::Error {
                    message: "peer rejected: socket is owner-only".into(),
                })
                .unwrap_or_else(|_| "{\"kind\":\"error\"}".to_string());
                let _ = writeln!(stream, "{msg}");
                continue;
            }
        }

        let shared = Arc::clone(&state);
        std::thread::spawn(move || {
            let snapshot = match stream.try_clone() {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut reader = std::io::BufReader::new(snapshot);
            let mut writer = stream;

            let (resp, stop) = match read_request(&mut reader) {
                Ok(req) => {
                    let mut guard = shared.lock().unwrap_or_else(|p| p.into_inner());
                    guard.handle(req)
                }
                Err(e) => (Response::Error { message: e.to_string() }, false),
            };

            if let Ok(line) = serde_json::to_string(&resp) {
                let _ = writeln!(writer, "{line}");
                let _ = writer.flush();
            }
            if stop {
                std::process::exit(0);
            }
        });
    }
}

/// Prepare the socket path: private directory, no stale socket, owner-only file (DESIGN §2).
#[cfg(unix)]
pub fn prepare_socket(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        let mut p = std::fs::metadata(dir)?.permissions();
        p.set_mode(0o700);
        std::fs::set_permissions(dir, p)?;
    }
    if path.exists() {
        // only remove a socket we own; a regular file here is a mistake worth surfacing
        let meta = std::fs::symlink_metadata(path)?;
        if meta.file_type().is_socket() {
            std::fs::remove_file(path)?;
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn peer_uid_reports_this_process() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a).unwrap(), own_uid());
    }

    #[test]
    fn locked_state_refuses_data_verbs_but_answers_status() {
        let mut st = State::new("/nonexistent/vault.db".into(), AccountKey::generate());
        assert!(st.is_locked());

        match st.handle(Request::ListItems).0 {
            Response::Error { message } => assert!(message.contains("locked"), "{message}"),
            other => panic!("expected a locked refusal, got {other:?}"),
        }
        assert!(matches!(
            st.handle(Request::Status).0,
            Response::Status { locked: true, .. }
        ));
    }

    #[test]
    fn unlock_against_a_missing_vault_fails_and_stays_locked() {
        let mut st = State::new("/nonexistent/vault.db".into(), AccountKey::generate());
        let (resp, stop) = st.handle(Request::Unlock { passphrase: "x".into() });
        assert!(matches!(resp, Response::Error { .. }));
        assert!(!stop);
        assert!(st.is_locked());
    }

    #[test]
    fn quit_stops_the_daemon() {
        let mut st = State::new("/nonexistent/vault.db".into(), AccountKey::generate());
        assert!(st.handle(Request::Quit).1);
    }
}
