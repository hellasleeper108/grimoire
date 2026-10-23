//! Wire protocol between `grimd` (the only process that holds keys) and its clients.
//!
//! One request per connection, newline-delimited JSON, then the daemon closes. Deliberately
//! boring: no multiplexing, no framing state machine, trivial to fuzz and to read in `socat`.
//!
//! Every request carries a **capability verb**, never a query. The daemon answers with the
//! smallest projection that satisfies it (DESIGN §3.2, §3.3).

use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{Detail, Overview, Result};

/// A request from a client. `passphrase` is the only secret that ever crosses this socket;
/// item values travel back only for the verbs that are allowed to return them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum Request {
    Status,
    Unlock { passphrase: String },
    Lock,
    ListItems,
    GetItem { needle: String },
    RevealField { needle: String, field: String },
    TotpNow { needle: String },
    AddItem {
        category: String,
        overview: Overview,
        detail: Detail,
    },
    /// Write a parsed import batch in one transaction (see `import::NewItem`).
    ImportBatch {
        items: Vec<crate::import::NewItem>,
    },
    Quit,
}

/// What a list row needs — the cheap projection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ItemRow {
    pub id: String,
    pub category: String,
    pub title: String,
    pub subtitle: String,
    pub url_host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Error { message: String },
    Status {
        locked: bool,
        items: usize,
        vault: String,
    },
    Items {
        items: Vec<ItemRow>,
    },
    Item {
        id: String,
        category: String,
        overview: Overview,
        detail: Detail,
    },
    Value {
        value: String,
    },
    Totp {
        code: String,
        remaining: u64,
    },
    Added {
        id: String,
    },
    Imported {
        count: usize,
    },
}

/// Client side: connect, ask, read one line, close. Used by `grim`.
#[cfg(unix)]
pub fn call(socket: &Path, req: &Request) -> Result<Response> {
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket).map_err(|e| {
        crate::Error::Io(std::io::Error::new(
            e.kind(),
            format!(
                "cannot reach grimd at {} ({e}); start it with `grim daemon`",
                socket.display()
            ),
        ))
    })?;
    let line = serde_json::to_string(req)?;
    stream.write_all(line.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut buf = String::new();
    reader.read_line(&mut buf)?;
    if buf.trim().is_empty() {
        return Err(crate::Error::Decrypt("daemon closed the connection"));
    }
    Ok(serde_json::from_str(buf.trim())?)
}

/// Server side helper: read exactly one request line.
#[cfg(unix)]
pub fn read_request(input: &mut impl BufRead) -> Result<Request> {
    let mut buf = String::new();
    input.read_line(&mut buf)?;
    if buf.trim().is_empty() {
        return Err(crate::Error::Decrypt("empty request"));
    }
    Ok(serde_json::from_str(buf.trim())?)
}

/// The four verbs a locked daemon will answer (DESIGN §2, rule 4).
pub fn allowed_while_locked(req: &Request) -> bool {
    matches!(req, Request::Status | Request::Unlock { .. } | Request::Quit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip() {
        for req in [
            Request::Status,
            Request::Lock,
            Request::ListItems,
            Request::GetItem { needle: "github".into() },
            Request::RevealField { needle: "github".into(), field: "password".into() },
            Request::TotpNow { needle: "github".into() },
            Request::Unlock { passphrase: "pw".into() },
            Request::Quit,
        ] {
            let json = serde_json::to_string(&req).unwrap();
            let back: Request = serde_json::from_str(&json).unwrap();
            assert_eq!(format!("{req:?}"), format!("{back:?}"));
        }
    }

    #[test]
    fn locked_gate_allows_only_four_verbs() {
        assert!(allowed_while_locked(&Request::Status));
        assert!(allowed_while_locked(&Request::Unlock { passphrase: "x".into() }));
        assert!(allowed_while_locked(&Request::Quit));
        assert!(!allowed_while_locked(&Request::ListItems));
        assert!(!allowed_while_locked(&Request::GetItem { needle: "x".into() }));
        assert!(!allowed_while_locked(&Request::RevealField {
            needle: "x".into(),
            field: "password".into()
        }));
    }

    #[test]
    fn wire_shape_is_a_tagged_verb() {
        let json = serde_json::to_string(&Request::ListItems).unwrap();
        assert!(json.contains("\"verb\":\"list_items\""), "got {json}");
    }
}
