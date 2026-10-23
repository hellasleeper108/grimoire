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
    /// 1Password's `.1pux` archive: a zip whose `export.data` is the JSON export.
    OnePux,
}

impl Format {
    /// Guess from the file name first, then from the first non-space byte.
    pub fn detect(name: &str, content: &str) -> Format {
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".1pux") || lower.ends_with(".1pif") {
            return Format::OnePux;
        }
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

/// Read a file and parse it, handling the binary 1PUX case.
pub fn parse_path(path: &std::path::Path) -> std::io::Result<ImportReport> {
    let bytes = std::fs::read(path)?;
    let name = path.to_string_lossy().to_ascii_lowercase();
    // zip magic: "PK\x03\x04" — trust the bytes over the extension
    if name.ends_with(".1pux") || bytes.starts_with(b"PK\x03\x04") {
        return Ok(parse_1pux(&bytes));
    }
    let text = String::from_utf8_lossy(&bytes);
    Ok(parse(&name, &text))
}

pub fn parse(name: &str, content: &str) -> ImportReport {
    match Format::detect(name, content) {
        Format::Csv => parse_csv(content),
        Format::Bitwarden => parse_bitwarden(content),
        Format::OnePux => {
            // a .1pux is a zip: it cannot be read from a &str
            let mut report = ImportReport::default();
            report.refuse("a .1pux archive is binary; use import::parse_path to read it");
            report
        }
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

// ------------------------------------------------------------------ 1PUX

#[derive(Debug, Deserialize)]
struct PuxExport {
    #[serde(default)]
    accounts: Vec<PuxAccount>,
}

#[derive(Debug, Deserialize)]
struct PuxAccount {
    #[serde(default)]
    vaults: Vec<PuxVault>,
}

#[derive(Debug, Deserialize)]
struct PuxVault {
    #[serde(default)]
    items: Vec<PuxItem>,
}

#[derive(Debug, Deserialize, Default)]
struct PuxItem {
    #[serde(default, rename = "categoryUuid")]
    category_uuid: Option<String>,
    #[serde(default)]
    overview: PuxOverview,
    #[serde(default)]
    details: PuxDetails,
    #[serde(default)]
    trashed: bool,
}

#[derive(Debug, Deserialize, Default)]
struct PuxOverview {
    #[serde(default)]
    title: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    urls: Vec<PuxUrl>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct PuxUrl {
    #[serde(default)]
    url: String,
}

#[derive(Debug, Deserialize, Default)]
struct PuxDetails {
    #[serde(default, rename = "loginFields")]
    login_fields: Vec<PuxField>,
    #[serde(default, rename = "notesPlain")]
    notes_plain: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    sections: Vec<PuxSection>,
}

#[derive(Debug, Deserialize, Default)]
struct PuxSection {
    #[serde(default)]
    fields: Vec<PuxField>,
}

#[derive(Debug, Deserialize, Default)]
struct PuxField {
    #[serde(default)]
    designation: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    value: String,
}

/// 1PUX: a zip containing `export.data`.
///
/// Category UUIDs are trusted only where their meaning is unambiguous (`001` login, `002` password,
/// `003` secure note). Everything else is inferred from the shape of the item, and refused with a
/// reason when that fails — guessing that a credit card is a login is how people silently lose data.
pub fn parse_1pux(bytes: &[u8]) -> ImportReport {
    use std::io::Read;

    let mut report = ImportReport::default();

    let mut archive = match zip::ZipArchive::new(std::io::Cursor::new(bytes)) {
        Ok(a) => a,
        Err(e) => {
            report.refuse(format!("not a 1PUX archive: {e}"));
            return report;
        }
    };

    let mut data = String::new();
    match archive.by_name("export.data") {
        Ok(mut entry) => {
            if let Err(e) = entry.read_to_string(&mut data) {
                report.refuse(format!("export.data unreadable: {e}"));
                return report;
            }
        }
        Err(_) => {
            report.refuse("1PUX archive has no export.data (is this a 1Password export?)");
            return report;
        }
    }

    let export: PuxExport = match serde_json::from_str(&data) {
        Ok(e) => e,
        Err(e) => {
            report.refuse(format!("export.data is not valid 1PUX JSON: {e}"));
            return report;
        }
    };

    let mut row = 0usize;
    for account in export.accounts {
        for vault in account.vaults {
            for item in vault.items {
                row += 1;
                report.total += 1;

                if item.trashed {
                    report.push_skip(row, "in the trash");
                    continue;
                }

                let title = item.overview.title.trim().to_string();
                if title.is_empty() {
                    report.push_skip(row, "no title");
                    continue;
                }

                let url = if !item.overview.url.is_empty() {
                    Some(item.overview.url.clone())
                } else {
                    item.overview.urls.iter().map(|u| u.url.clone()).find(|u| !u.is_empty())
                };

                let find_field = |wanted: &str| -> Option<String> {
                    item.details
                        .login_fields
                        .iter()
                        .find(|f| {
                            f.designation.as_deref() == Some(wanted) || f.name.as_deref() == Some(wanted)
                        })
                        .map(|f| f.value.clone())
                        .filter(|v| !v.is_empty())
                };

                let username = find_field("username");
                let password_field = find_field("password")
                    .or_else(|| item.details.password.clone())
                    .filter(|v| !v.is_empty());
                let totp = item
                    .details
                    .login_fields
                    .iter()
                    .find(|f| f.kind.as_deref() == Some("OTP"))
                    .map(|f| f.value.clone())
                    .or_else(|| {
                        item.details
                            .sections
                            .iter()
                            .flat_map(|s| s.fields.iter())
                            .find(|f| f.kind.as_deref() == Some("OTP"))
                            .map(|f| f.value.clone())
                    })
                    .filter(|v| !v.is_empty());

                let category = match item.category_uuid.as_deref() {
                    Some("001") => Some(Category::Login),
                    Some("002") => Some(Category::Password),
                    Some("003") => Some(Category::SecureNote),
                    // A category we recognise as out of scope (cards, identities…) is never
                    // re-interpreted from its fields: doing so would quietly turn a credit card into
                    // a secure note, and the user would only find out when they needed the card.
                    Some(_) => None,
                    None => {
                        if password_field.is_some() || username.is_some() || url.is_some() {
                            Some(Category::Login)
                        } else if item.details.notes_plain.as_deref().unwrap_or("").trim().is_empty() {
                            None
                        } else {
                            Some(Category::SecureNote)
                        }
                    }
                };

                let Some(category) = category else {
                    report.push_skip(
                        row,
                        format!(
                            "unsupported 1PUX item (category {:?}) — not imported rather than guessed",
                            item.category_uuid
                        ),
                    );
                    continue;
                };

                let mut fields = Vec::new();
                if let Some(u) = &username {
                    fields.push(Field {
                        name: "username".into(),
                        kind: FieldKind::Text,
                        value: u.clone(),
                        conceal: false,
                    });
                }
                if let Some(p) = &password_field {
                    fields.push(Field {
                        name: "password".into(),
                        kind: FieldKind::Password,
                        value: p.clone(),
                        conceal: true,
                    });
                }
                if let Some(t) = &totp {
                    fields.push(Field {
                        name: "totp".into(),
                        kind: FieldKind::Totp,
                        value: t.clone(),
                        conceal: true,
                    });
                }
                if let Some(u) = &url {
                    fields.push(Field {
                        name: "url".into(),
                        kind: FieldKind::Url,
                        value: u.clone(),
                        conceal: false,
                    });
                }

                let tags: Vec<String> =
                    item.overview.tags.iter().filter(|t| !t.trim().is_empty()).cloned().collect();

                report.imported.push(NewItem {
                    category,
                    overview: Overview {
                        title,
                        subtitle: username.clone().unwrap_or_default(),
                        url_host: url.as_deref().map(host_of).unwrap_or_default(),
                        tags,
                        favorite: false,
                    },
                    detail: Detail {
                        fields,
                        notes: item.details.notes_plain.clone().unwrap_or_default(),
                    },
                });
            }
        }
    }

    if report.total == 0 {
        report.refuse("export contained no items");
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

    // ---------------------------------------------------------------- 1PUX

    fn make_1pux(export: &str) -> Vec<u8> {
        use std::io::Write;
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut buf);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            w.start_file("export.data", opts).unwrap();
            w.write_all(export.as_bytes()).unwrap();
            w.finish().unwrap();
        }
        buf.into_inner()
    }

    #[test]
    fn one_pux_imports_logins_and_explains_the_rest() {
        let json = r#"{"accounts":[{"vaults":[{"items":[
          {"categoryUuid":"001","overview":{"title":"GitHub","urls":[{"url":"https://github.com"}],"tags":["work"]},
           "details":{"loginFields":[
              {"designation":"username","name":"username","value":"hella"},
              {"designation":"password","name":"password","value":"hunter2"},
              {"designation":"","name":"one-time password","type":"OTP","value":"JBSWY3DPEHPK3PXP"}],
             "notesPlain":"2fa on"}},
          {"categoryUuid":"004","overview":{"title":"Visa"},"details":{"notesPlain":"card"}},
          {"categoryUuid":"003","overview":{"title":"Codes"},"details":{"notesPlain":"x"},"trashed":true}
        ]}]}]}"#;

        let report = parse_1pux(&make_1pux(json));
        assert_eq!(report.total, 3);
        assert_eq!(report.imported.len(), 1, "skipped: {:?}", report.skipped);
        assert_eq!(report.skipped.len(), 2);
        assert!(report.accounted());

        let gh = &report.imported[0];
        assert_eq!(gh.overview.title, "GitHub");
        assert_eq!(gh.overview.url_host, "github.com");
        assert_eq!(gh.overview.tags, vec!["work".to_string()]);
        assert!(gh.detail.fields.iter().any(|f| f.name == "totp" && f.conceal));
        assert_eq!(gh.detail.notes, "2fa on");

        assert!(report.skipped.iter().any(|s| s.reason.contains("unsupported 1PUX")));
        assert!(report.skipped.iter().any(|s| s.reason.contains("trash")));
    }

    #[test]
    fn one_pux_that_is_not_a_zip_is_refused() {
        let report = parse_1pux(b"definitely not a zip");
        assert!(report.accounted());
        assert!(report.file_error.as_deref().unwrap_or_default().contains("not a 1PUX archive"));
    }

    #[test]
    fn one_pux_without_export_data_is_refused() {
        use std::io::Write;
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut buf);
            w.start_file("other.txt", zip::write::SimpleFileOptions::default()).unwrap();
            w.write_all(b"hi").unwrap();
            w.finish().unwrap();
        }
        let report = parse_1pux(&buf.into_inner());
        assert!(report.accounted());
        assert!(report.file_error.as_deref().unwrap_or_default().contains("no export.data"));
    }

    #[test]
    fn zip_magic_beats_a_misleading_extension() {
        let dir = std::env::temp_dir().join(format!("grim-1pux-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("misnamed.csv");
        std::fs::write(&path, make_1pux(r#"{"accounts":[]}"#)).unwrap();
        let report = parse_path(&path).unwrap();
        assert!(
            report.file_error.as_deref().unwrap_or_default().contains("no items"),
            "zip magic should win over the extension, got {:?}",
            report.file_error
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
