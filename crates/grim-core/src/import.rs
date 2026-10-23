//! Import: turn somebody else's export into `NewItem`s, and account for every row.
//!
//! The rule this module exists to enforce (README, P1 acceptance): **total == imported + skipped**.
//! A row that can't be understood is reported with a line number and a reason — never dropped
//! silently, never guessed at.

use serde::{Deserialize, Serialize};

use crate::{Category, Detail, Field, FieldKind, Overview};

/// One item ready to be written.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewItem {
    pub category: Category,
    pub overview: Overview,
    pub detail: Detail,
}

/// A row we refused to import, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Skipped {
    /// 1-based row number as the user sees it in their file (header = row 1).
    pub row: usize,
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub struct ImportReport {
    pub total: usize,
    pub imported: Vec<NewItem>,
    pub skipped: Vec<Skipped>,
    /// Set when the file as a whole was refused (unreadable header, not an export at all). When
    /// present there are no per-row counts to reconcile, because no row was read.
    pub file_error: Option<String>,
}

impl ImportReport {
    /// The invariant: nothing is lost between reading and writing. Either every row is accounted
    /// for, or the file was refused outright.
    pub fn accounted(&self) -> bool {
        self.file_error.is_some() || self.imported.len() + self.skipped.len() == self.total
    }

    pub fn push_skip(&mut self, row: usize, reason: impl Into<String>) {
        self.skipped.push(Skipped { row, reason: reason.into() });
    }

    pub fn refuse(&mut self, why: impl Into<String>) {
        self.file_error = Some(why.into());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Csv,
    Bitwarden,
}

impl Format {
    /// Guess from the file name first, then from the first non-space byte.
    pub fn detect(name: &str, content: &str) -> Format {
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".json") {
            return Format::Bitwarden;
        }
        if lower.ends_with(".csv") {
            return Format::Csv;
        }
        if content.trim_start().starts_with('{') {
            Format::Bitwarden
        } else {
            Format::Csv
        }
    }
}

pub fn parse(name: &str, content: &str) -> ImportReport {
    match Format::detect(name, content) {
        Format::Csv => parse_csv(content),
        Format::Bitwarden => parse_bitwarden(content),
    }
}

// ------------------------------------------------------------------ CSV

fn norm(h: &str) -> String {
    h.trim()
        .to_ascii_lowercase()
        .replace([' ', '-'], "_")
}

/// Column aliases seen in the wild (1Password, Bitwarden, LastPass, KeePass, Chrome, Firefox).
fn field_for(header: &str) -> Option<&'static str> {
    Some(match norm(header).as_str() {
        "name" | "title" | "item" | "account" | "entry" => "title",
        "url" | "website" | "login_uri" | "uri" | "web_site" | "link" => "url",
        "username" | "login_username" | "user" | "login" | "email" | "user_name" => "username",
        "password" | "login_password" | "pass" => "password",
        "totp" | "otp" | "one_time_password" | "otpauth" | "one-time_password" => "totp",
        "notes" | "note" | "extra" | "comments" => "notes",
        "type" | "category" | "kind" => "type",
        "folder" | "grouping" | "collection" | "group" | "vault" => "folder",
        _ => return None,
    })
}

pub fn parse_csv(content: &str) -> ImportReport {
    let mut report = ImportReport::default();
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(content.as_bytes());

    let headers = match reader.headers() {
        Ok(h) => h.clone(),
        Err(e) => {
            report.refuse(format!("unreadable header row: {e}"));
            return report;
        }
    };
    let cols: Vec<Option<&'static str>> = headers.iter().map(field_for).collect();
    if !cols.iter().any(|c| *c == Some("title")) {
        report.refuse("no name/title column recognised in the header");
        return report;
    }

    for (i, record) in reader.records().enumerate() {
        let row = i + 2; // header is row 1
        report.total += 1;
        let record = match record {
            Ok(r) => r,
            Err(e) => {
                report.push_skip(row, format!("malformed row: {e}"));
                continue;
            }
        };

        let get = |want: &str| -> Option<String> {
            cols.iter()
                .position(|c| *c == Some(want))
                .and_then(|idx| record.get(idx))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };

        let title = match get("title") {
            Some(t) => t,
            None => {
                report.push_skip(row, "no title");
                continue;
            }
        };
        let url = get("url");
        let username = get("username");
        let password = get("password");
        let totp = get("totp");
        let notes = get("notes");
        let folder = get("folder");
        let kind = get("type");

        let category = match kind.as_deref().map(Category::parse) {
            Some(Some(c)) => c,
            // unknown/absent type: infer from the shape of the row
            _ => {
                if password.is_some() {
                    Category::Login
                } else if notes.is_some() && username.is_none() {
                    Category::SecureNote
                } else {
                    Category::Login
                }
            }
        };

        let mut fields = Vec::new();
        if let Some(u) = &username {
            fields.push(Field { name: "username".into(), kind: FieldKind::Text, value: u.clone(), conceal: false });
        }
        if let Some(p) = &password {
            fields.push(Field { name: "password".into(), kind: FieldKind::Password, value: p.clone(), conceal: true });
        }
        if let Some(t) = &totp {
            fields.push(Field { name: "totp".into(), kind: FieldKind::Totp, value: t.clone(), conceal: true });
        }
        if let Some(u) = &url {
            fields.push(Field { name: "url".into(), kind: FieldKind::Url, value: u.clone(), conceal: false });
        }

        let mut tags = Vec::new();
        if let Some(f) = folder {
            tags.push(f);
        }

        report.imported.push(NewItem {
            category,
            overview: Overview {
                title,
                subtitle: username.unwrap_or_default(),
                url_host: url.as_deref().map(host_of).unwrap_or_default(),
                tags,
                favorite: false,
            },
            detail: Detail { fields, notes: notes.unwrap_or_default() },
        });
    }

    report
}

// ------------------------------------------------------------------ Bitwarden JSON

#[derive(Debug, Deserialize)]
struct BwExport {
    #[serde(default)]
    items: Vec<BwItem>,
}

#[derive(Debug, Deserialize)]
struct BwItem {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "type")]
    kind: u8,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    login: Option<BwLogin>,
    #[serde(default)]
    folder_id: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct BwLogin {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    uris: Vec<BwUri>,
}

#[derive(Debug, Deserialize)]
struct BwUri {
    #[serde(default)]
    uri: Option<String>,
}

pub fn parse_bitwarden(content: &str) -> ImportReport {
    let mut report = ImportReport::default();
    let export: BwExport = match serde_json::from_str(content) {
        Ok(e) => e,
        Err(e) => {
            report.refuse(format!("not a Bitwarden JSON export: {e}"));
            return report;
        }
    };
    if export.items.is_empty() {
        report.refuse("export contains no items (locked exports cannot be read)");
        return report;
    }

    for (i, item) in export.items.into_iter().enumerate() {
        let row = i + 1;
        report.total += 1;

        let category = match item.kind {
            1 => Category::Login,
            2 => Category::SecureNote,
            3 | 4 => {
                report.push_skip(row, format!("unsupported Bitwarden type {} (card/identity)", item.kind));
                continue;
            }
            other => {
                report.push_skip(row, format!("unknown Bitwarden type {other}"));
                continue;
            }
        };
        if item.name.trim().is_empty() {
            report.push_skip(row, "no name");
            continue;
        }

        let login = item.login.unwrap_or_default();
        let url = login.uris.iter().find_map(|u| u.uri.clone());
        let mut fields = Vec::new();
        if let Some(u) = &login.username {
            if !u.is_empty() {
                fields.push(Field { name: "username".into(), kind: FieldKind::Text, value: u.clone(), conceal: false });
            }
        }
        if let Some(p) = &login.password {
            if !p.is_empty() {
                fields.push(Field { name: "password".into(), kind: FieldKind::Password, value: p.clone(), conceal: true });
            }
        }
        if let Some(t) = &login.totp {
            if !t.is_empty() {
                fields.push(Field { name: "totp".into(), kind: FieldKind::Totp, value: t.clone(), conceal: true });
            }
        }
        if let Some(u) = &url {
            fields.push(Field { name: "url".into(), kind: FieldKind::Url, value: u.clone(), conceal: false });
        }

        report.imported.push(NewItem {
            category,
            overview: Overview {
                title: item.name.trim().to_string(),
                subtitle: login.username.clone().unwrap_or_default(),
                url_host: url.as_deref().map(host_of).unwrap_or_default(),
                tags: item.folder_id.into_iter().collect(),
                favorite: false,
            },
            detail: Detail { fields, notes: item.notes.unwrap_or_default() },
        });
    }

    report
}

fn host_of(url: &str) -> String {
    url.split("://").nth(1).unwrap_or(url).split('/').next().unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CSV: &str = "name,url,username,password,notes,type\n\
GitHub,https://github.com,hella,hunter2,2fa on,login\n\
,https://nope.example,,,missing title,\n\
Gitea,https://gitea.local,deploy,pw,,\n";

    #[test]
    fn csv_imports_parsable_rows_and_explains_the_rest() {
        let r = parse_csv(CSV);
        assert_eq!(r.total, 3);
        assert_eq!(r.imported.len(), 2);
        assert_eq!(r.skipped.len(), 1);
        assert!(r.accounted(), "every row must be imported or explained");
        assert_eq!(r.skipped[0].row, 3);
        assert!(r.skipped[0].reason.contains("no title"));

        let gh = &r.imported[0];
        assert_eq!(gh.overview.title, "GitHub");
        assert_eq!(gh.overview.url_host, "github.com");
        assert_eq!(gh.overview.subtitle, "hella");
        assert_eq!(gh.category, Category::Login);
        assert!(gh.detail.fields.iter().any(|f| f.name == "password" && f.conceal));
    }

    #[test]
    fn csv_column_aliases_are_understood() {
        let alt = "Title,Website,Login,Pass\nEmail,https://mail.example,me@example,pw\n";
        let r = parse_csv(alt);
        assert_eq!(r.imported.len(), 1);
        assert_eq!(r.imported[0].overview.title, "Email");
        assert_eq!(r.imported[0].overview.url_host, "mail.example");
    }

    #[test]
    fn csv_without_a_title_column_is_refused_not_guessed() {
        let r = parse_csv("url,password\nhttps://x,abc\n");
        assert_eq!(r.imported.len(), 0);
        assert!(r.accounted(), "a refused file is accounted for");
        assert!(
            r.file_error.as_deref().unwrap_or_default().contains("no name/title column"),
            "got {:?}",
            r.file_error
        );
    }

    #[test]
    fn secure_note_inferred_when_only_notes_present() {
        let csv = "name,notes\nRecovery codes,one two three\n";
        let r = parse_csv(csv);
        assert_eq!(r.imported[0].category, Category::SecureNote);
    }

    #[test]
    fn bitwarden_export_imports_logins_and_notes_and_skips_cards() {
        let json = r#"{
          "items": [
            {"type": 1, "name": "GitHub", "login": {"username": "hella", "password": "hunter2",
              "totp": "JBSWY3DPEHPK3PXP", "uris": [{"uri": "https://github.com"}]}},
            {"type": 2, "name": "Codes", "notes": "one two three"},
            {"type": 3, "name": "Visa", "notes": "card"}
          ]
        }"#;
        let r = parse_bitwarden(json);
        assert_eq!(r.total, 3);
        assert_eq!(r.imported.len(), 2);
        assert_eq!(r.skipped.len(), 1);
        assert!(r.accounted());
        assert!(r.skipped[0].reason.contains("unsupported Bitwarden type 3"));
        assert_eq!(r.imported[0].overview.url_host, "github.com");
        assert!(r.imported[0].detail.fields.iter().any(|f| f.name == "totp"));
        assert_eq!(r.imported[1].category, Category::SecureNote);
    }

    #[test]
    fn garbage_json_is_a_skip_not_a_panic() {
        let r = parse("export.json", "{not json");
        assert_eq!(r.total, 0);
        assert_eq!(r.skipped.len(), 0);
        assert!(r.accounted());
        assert!(
            r.file_error.as_deref().unwrap_or_default().contains("not a Bitwarden"),
            "got {:?}",
            r.file_error
        );
    }

    #[test]
    fn format_detection_prefers_extension_then_content() {
        assert_eq!(Format::detect("export.csv", "{}"), Format::Csv);
        assert_eq!(Format::detect("export.json", "name,url\n"), Format::Bitwarden);
        assert_eq!(Format::detect("mystery", "  {\"items\":[]}"), Format::Bitwarden);
        assert_eq!(Format::detect("mystery", "name,url\n"), Format::Csv);
    }
}
