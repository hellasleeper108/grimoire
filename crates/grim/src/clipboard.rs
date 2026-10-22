//! Clipboard: best-effort, and honest when it can't.
//!
//! A terminal password manager has no business pulling in a GUI toolkit to copy a string, so this
//! shells out to whichever clipboard helper the session actually has. Returning the tool name (or a
//! clear failure) is more useful than a silent no-op — DESIGN §6.3 says render states honestly.

use std::io::Write;
use std::process::{Command, Stdio};

/// Try the usual helpers in order. Returns the tool that accepted the text.
pub fn copy(text: &str) -> Result<String, String> {
    // (program, args) — wayland first, then X11 helpers
    let candidates: [(&str, &[&str]); 4] = [
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
        ("xsel", &["--clipboard", "--input"]),
        ("clip.exe", &[]),
    ];

    let mut tried = Vec::new();
    for (prog, args) in candidates {
        let child = Command::new(prog)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();

        match child {
            Ok(mut child) => {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(text.as_bytes());
                }
                match child.wait() {
                    Ok(st) if st.success() => return Ok(prog.to_string()),
                    _ => tried.push(format!("{prog} (failed)")),
                }
            }
            Err(_) => tried.push(prog.to_string()),
        }
    }
    Err(format!("no clipboard tool found (tried {})", tried.join(", ")))
}

/// Seconds the clipboard should keep the value before the user clears it — the TUI shows a
/// countdown so `y` is never a silent, permanent clipboard leak.
pub const CLEAR_HINT_SECS: u64 = 20;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_never_panics_and_reports_a_tool_or_an_error() {
        // in CI/WSL there is usually no clipboard helper; either outcome is fine, a panic is not
        match copy("grimoire-test") {
            Ok(tool) => assert!(!tool.is_empty()),
            Err(msg) => assert!(msg.contains("tried"), "unhelpful error: {msg}"),
        }
    }
}
