//! End-to-end store tests: the paths `grim` actually walks.

use grim_core::{
    AccountKey, Category, Detail, Error, Field, FieldKind, KdfParams, Overview, Vault, VaultParams,
};

fn temp_path(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut p = std::env::temp_dir();
    p.push(format!("grim-test-{tag}-{}-{nanos}.db", std::process::id()));
    p
}

fn login() -> (Overview, Detail) {
    let overview = Overview {
        title: "GitHub".into(),
        subtitle: "hella".into(),
        url_host: "github.com".into(),
        tags: vec!["work".into()],
        favorite: false,
    };
    let detail = Detail {
        fields: vec![
            Field { name: "username".into(), kind: FieldKind::Text, value: "hella".into(), conceal: false },
            Field { name: "password".into(), kind: FieldKind::Password, value: "hunter2".into(), conceal: true },
            Field { name: "totp".into(), kind: FieldKind::Totp, value: "JBSWY3DPEHPK3PXP".into(), conceal: true },
        ],
        notes: "2fa enrolled".into(),
    };
    (overview, detail)
}

#[test]
fn create_insert_list_get_roundtrip() {
    let path = temp_path("rt");
    let params = VaultParams { kdf: KdfParams::fast_for_tests() };

    let (mut vault, account_key) = Vault::create(&path, "pw", params).unwrap();
    let (ov, dt) = login();
    let id = vault.insert(Category::Login, &ov, &dt).unwrap();

    assert_eq!(vault.count().unwrap(), 1);

    // listing decrypts overviews only
    let listed = vault.list().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].2.title, "GitHub");
    assert_eq!(listed[0].2.url_host, "github.com");

    // lookup by title, case-insensitively
    let (got_id, cat, got_ov, got_dt) = vault.get("github").unwrap();
    assert_eq!(got_id, id);
    assert_eq!(cat, Category::Login);
    assert_eq!(got_ov.subtitle, "hella");
    assert_eq!(got_dt.notes, "2fa enrolled");
    assert_eq!(vault.field(&id[..8], "PASSWORD").unwrap(), "hunter2");
    assert!(matches!(vault.field("github", "nope"), Err(Error::UnknownField(_))));
    assert!(matches!(vault.get("does-not-exist"), Err(Error::ItemNotFound(_))));

    // totp is 6 digits
    let (code, remaining) = vault.totp("github").unwrap();
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
    assert!(remaining >= 1 && remaining <= 30);

    vault.lock();

    // reopen with the right material
    let reopened = Vault::open(&path, "pw", &account_key).unwrap();
    assert_eq!(reopened.count().unwrap(), 1);
    assert_eq!(reopened.field("github", "password").unwrap(), "hunter2");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn wrong_passphrase_and_wrong_account_key_are_bad_credentials() {
    let path = temp_path("creds");
    let params = VaultParams { kdf: KdfParams::fast_for_tests() };
    let (vault, account_key) = Vault::create(&path, "right", params).unwrap();
    vault.lock();

    assert!(matches!(Vault::open(&path, "wrong", &account_key), Err(Error::BadCredentials)));

    let other = AccountKey::generate();
    assert!(matches!(Vault::open(&path, "right", &other), Err(Error::BadCredentials)));

    // and the good pair still works
    assert!(Vault::open(&path, "right", &account_key).is_ok());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn ciphertext_cannot_be_moved_between_items() {
    let path = temp_path("bind");
    let params = VaultParams { kdf: KdfParams::fast_for_tests() };
    let (mut vault, _ak) = Vault::create(&path, "pw", params).unwrap();

    let (ov, dt) = login();
    let a = vault.insert(Category::Login, &ov, &dt).unwrap();
    let b = vault.insert(Category::Login, &ov, &dt).unwrap();
    assert_ne!(a, b);

    // The store binds every blob to its item id via AAD, so item b's blobs must not decrypt
    // under item a's key. Verified at the SQL level: swap b's overview into a.
    let conn = rusqlite::Connection::open(&path).unwrap();
    let b_blob: Vec<u8> = conn
        .query_row("SELECT overview_enc FROM items WHERE id = ?1", [&b], |r| r.get(0))
        .unwrap();
    conn.execute("UPDATE items SET overview_enc = ?1 WHERE id = ?2", rusqlite::params![b_blob, a])
        .unwrap();
    drop(conn);

    // Item a now fails to list (its overview no longer authenticates) rather than showing b's title.
    let listed = vault.list().unwrap();
    let titles: Vec<String> = listed.iter().map(|(_, _, o)| o.title.clone()).collect();
    assert_eq!(listed.len(), 1, "swapped item must drop out, not silently decrypt: {titles:?}");

    let _ = std::fs::remove_file(&path);
}
