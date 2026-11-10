mod common;

use std::path::Path;
use std::process::Command;

use common::*;
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, SanType};
use rustca_core::edit;
use rustca_core::tls::{self, HttpRequest, LocalOptions, RemoteOptions, RemoteTrust, TlsVersion};
use rustca_core::*;

const PW: &str = "changeit";

fn pem_of(certs: &[&Issued], key: Option<&Issued>) -> String {
    let mut s: String = certs
        .iter()
        .map(|c| pem::encode("CERTIFICATE", &c.der()))
        .collect();
    if let Some(k) = key {
        s.push_str(&pem::encode("PRIVATE KEY", &k.key_der()));
    }
    s
}

fn load_text(name: &str, text: &str) -> Keystore {
    load_bytes(name.into(), text.as_bytes(), &LoadOptions::default()).unwrap()
}

/// 以同一把私鑰重新簽發（模擬續約）。
fn renew(old: &Issued, issuer: &Issued, cn: &str, dns: &[&str]) -> rcgen::Certificate {
    let mut p = CertificateParams::default();
    p.distinguished_name.push(DnType::CommonName, cn);
    p.subject_alt_names = dns
        .iter()
        .map(|d| SanType::DnsName((*d).try_into().unwrap()))
        .collect();
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    p.signed_by(&old.key, &issuer.cert, &issuer.key).unwrap()
}

#[test]
fn full_management_flow() {
    let p = pki();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("managed.jks");

    // 1. 新建並匯入
    let mut ks = edit::new_keystore(&path, StoreFormat::Jks, PW).unwrap();
    let ca = load_text("ca.pem", &pem_of(&[&p.root, &p.inter], None));
    let certs: Vec<CertInfo> = ca.all_certs().into_iter().cloned().collect();
    let added = edit::import_certs(&mut ks, "demo-ca", &certs, false).unwrap();
    assert_eq!(added, vec!["demo-ca", "demo-ca-2"]);
    assert!(
        edit::import_certs(&mut ks, "demo-ca", &certs[..1], false).is_err(),
        "重複別名應失敗"
    );

    let cert_file = load_text("server.crt", &pem_of(&[&p.server, &p.inter], None));
    let key_file = load_text(
        "server.key",
        &pem::encode("PRIVATE KEY", &p.server.key_der()),
    );
    let all: Vec<CertInfo> = cert_file.all_certs().into_iter().cloned().collect();
    let entry = edit::entry_from_cert_and_key("Server", &all, &key_file.entries[0]).unwrap();
    assert_eq!(
        entry.chain[0].subject_cn.as_deref(),
        Some("server.example.com")
    );
    edit::import_key_entry(&mut ks, "Server", &entry, None, false).unwrap();

    // 不相符的私鑰應被拒絕
    let wrong_key = load_text(
        "client.key",
        &pem::encode("PRIVATE KEY", &p.client.key_der()),
    );
    assert!(edit::entry_from_cert_and_key("x", &all[..1], &wrong_key.entries[0]).is_err());

    // 2. 重新命名、刪除
    edit::rename_entry(&mut ks, "demo-ca-2", "demo-inter").unwrap();
    assert!(
        edit::rename_entry(&mut ks, "demo-inter", "SERVER").is_err(),
        "不分大小寫衝突"
    );
    let removed = edit::delete_entry(&mut ks, "demo-inter").unwrap();
    assert_eq!(removed.alias, "demo-inter");

    // 3. 同一別名更新憑證（續約，只給終端憑證，鏈應由憑證庫補齊到根）
    let renewed = renew(
        &p.server,
        &p.inter,
        "server.example.com",
        &["server.example.com", "renewed.example.com"],
    );
    let renewed_ks = load_bytes("r.cer".into(), renewed.der(), &LoadOptions::default()).unwrap();
    let mut new_certs: Vec<CertInfo> = renewed_ks.all_certs().into_iter().cloned().collect();
    new_certs.push(CertInfo::from_der(&p.inter.der()).unwrap());
    let notes = edit::update_certs(&mut ks, "server", &new_certs).unwrap();
    assert!(!notes.is_empty());
    let e = ks.entry("server").unwrap();
    assert!(e.chain[0]
        .subject_alt_names
        .contains(&"DNS:renewed.example.com".to_string()));
    assert_eq!(e.chain.len(), 3, "應補齊根憑證：{notes:?}");
    // 用別人的憑證更新應失敗
    let other = vec![CertInfo::from_der(&p.client.der()).unwrap()];
    assert!(edit::update_certs(&mut ks, "server", &other).is_err());

    // 4. 修改私鑰密碼、儲存、重新開啟
    edit::set_key_password(&mut ks, "server", "keypass-1").unwrap();
    let rep = edit::save(&mut ks, None, None, true).unwrap();
    assert!(rep.backup.is_none(), "新檔不需要備份");
    assert!(rep.warnings.iter().any(|w| w.contains("小寫")));
    let reopened = load_file(&path, &LoadOptions::with_password(PW)).unwrap();
    assert!(
        matches!(reopened.entry("server").unwrap().key, KeyState::Locked(_)),
        "私鑰密碼已不同"
    );
    let mut reopened = load_file(
        &path,
        &LoadOptions {
            password: Some(PW.into()),
            key_password: Some("keypass-1".into()),
        },
    )
    .unwrap();
    assert!(matches!(
        reopened.entry("server").unwrap().key,
        KeyState::Decrypted { .. }
    ));
    assert_eq!(reopened.entries.len(), 2);

    // 5. 修改憑證庫密碼（私鑰保留自己的密碼），再存一次並確認有備份
    edit::set_store_password(&mut reopened, "newstorepass", true).unwrap();
    let rep = edit::save(&mut reopened, None, None, true).unwrap();
    assert!(rep.backup.as_ref().is_some_and(|b| b.exists()));
    assert!(load_file(&path, &LoadOptions::with_password(PW))
        .unwrap_err()
        .is_password_problem());
    let ks2 = load_file(
        &path,
        &LoadOptions {
            password: Some("newstorepass".into()),
            key_password: Some("keypass-1".into()),
        },
    )
    .unwrap();
    assert!(matches!(
        ks2.entry("server").unwrap().key,
        KeyState::Decrypted { .. }
    ));

    // 6. 轉成 JCEKS / PKCS#12，並用轉出的檔案做交握
    for (fmt, name) in [
        (StoreFormat::Jceks, "conv.jceks"),
        (StoreFormat::Pkcs12, "conv.p12"),
    ] {
        let mut k = ks2.clone();
        let out = dir.path().join(name);
        edit::save(&mut k, Some(&out), Some(fmt), false).unwrap();
        let back = load_file(
            &out,
            &LoadOptions {
                password: Some("newstorepass".into()),
                key_password: Some("keypass-1".into()),
            },
        )
        .unwrap();
        assert_eq!(back.format, fmt);
        let id = tls::identity_from_keystore(&back, Some("server")).unwrap();
        let anchors = vec![CertInfo::from_der(&p.root.der()).unwrap()];
        let r = tls::simulate_local(&id, &anchors, None, &[], &LocalOptions::default());
        assert!(r.success, "{name}: {:?}", r.failure);
    }
}

#[test]
fn locked_keys_are_preserved() {
    let p = pki();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("locked.jks");
    let mut ks = edit::new_keystore(&path, StoreFormat::Jks, PW).unwrap();
    let certs = vec![CertInfo::from_der(&p.server.der()).unwrap()];
    let key = load_text("k", &pem::encode("PRIVATE KEY", &p.server.key_der()));
    let e = edit::entry_from_cert_and_key("srv", &certs, &key.entries[0]).unwrap();
    edit::import_key_entry(&mut ks, "srv", &e, Some("secret-key"), false).unwrap();
    edit::save(&mut ks, None, None, false).unwrap();

    // 只用憑證庫密碼開啟 → 私鑰鎖住，但仍可改名並存檔
    let mut locked = load_file(&path, &LoadOptions::with_password(PW)).unwrap();
    assert!(matches!(locked.entries[0].key, KeyState::Locked(_)));
    assert!(edit::set_key_password(&mut locked, "srv", "x").is_err());
    assert!(
        edit::set_store_password(&mut locked, "x", true).is_err(),
        "鎖住的私鑰不能一併改密碼"
    );
    edit::rename_entry(&mut locked, "srv", "renamed").unwrap();
    edit::save(&mut locked, None, None, false).unwrap();
    // 轉成 PKCS#12 需要解密 → 失敗
    assert!(edit::serialize(&locked, StoreFormat::Pkcs12)
        .unwrap_err()
        .is_password_problem());
    // 逐條解鎖後即可轉換
    let mut unlocked = locked.clone();
    assert!(edit::unlock_entry(&mut unlocked, "renamed", "wrong").is_err());
    edit::unlock_entry(&mut unlocked, "renamed", "secret-key").unwrap();
    assert!(matches!(
        unlocked.entries[0].key,
        KeyState::Decrypted { .. }
    ));
    edit::serialize(&unlocked, StoreFormat::Pkcs12).unwrap();

    let back = load_file(
        &path,
        &LoadOptions {
            password: Some(PW.into()),
            key_password: Some("secret-key".into()),
        },
    )
    .unwrap();
    assert_eq!(back.entries[0].alias, "renamed");
    assert!(matches!(back.entries[0].key, KeyState::Decrypted { .. }));

    // 只改憑證庫密碼（不動私鑰）
    let mut k = load_file(&path, &LoadOptions::with_password(PW)).unwrap();
    edit::set_store_password(&mut k, "store-2", false).unwrap();
    edit::save(&mut k, None, None, false).unwrap();
    let back = load_file(
        &path,
        &LoadOptions {
            password: Some("store-2".into()),
            key_password: Some("secret-key".into()),
        },
    )
    .unwrap();
    assert!(matches!(back.entries[0].key, KeyState::Decrypted { .. }));
}

fn keytool(args: &[&str]) -> (bool, String) {
    match Command::new("keytool").args(args).output() {
        Ok(o) => (
            o.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            ),
        ),
        Err(e) => (false, e.to_string()),
    }
}

#[test]
fn keytool_can_read_what_we_write() {
    if Command::new("keytool").arg("-help").output().is_err() {
        eprintln!("找不到 keytool，略過");
        return;
    }
    let p = pki();
    let dir = tempfile::tempdir().unwrap();
    let base = edit::new_keystore(dir.path().join("x"), StoreFormat::Jks, PW).unwrap();
    let mut ks = base;
    let certs = vec![
        CertInfo::from_der(&p.server.der()).unwrap(),
        CertInfo::from_der(&p.inter.der()).unwrap(),
    ];
    let key = load_text("k", &pem::encode("PRIVATE KEY", &p.server.key_der()));
    let e = edit::entry_from_cert_and_key("server", &certs, &key.entries[0]).unwrap();
    edit::import_key_entry(&mut ks, "server", &e, Some("kp-123"), false).unwrap();
    edit::import_certs(
        &mut ks,
        "root",
        &[CertInfo::from_der(&p.root.der()).unwrap()],
        false,
    )
    .unwrap();

    for (fmt, name, st) in [
        (StoreFormat::Jks, "w.jks", "JKS"),
        (StoreFormat::Jceks, "w.jceks", "JCEKS"),
        (StoreFormat::Pkcs12, "w.p12", "PKCS12"),
    ] {
        let mut k = ks.clone();
        let out = dir.path().join(name);
        edit::save(&mut k, Some(&out), Some(fmt), false).unwrap();
        let o = out.to_str().unwrap();
        let (ok, text) = keytool(&["-list", "-keystore", o, "-storetype", st, "-storepass", PW]);
        assert!(ok, "{name}: {text}");
        assert!(
            text.contains("server") && text.contains("root"),
            "{name}: {text}"
        );
        // 讓 Java 實際解密私鑰（轉存到新的 PKCS#12）
        let keypass = if fmt == StoreFormat::Pkcs12 {
            PW
        } else {
            "kp-123"
        };
        let dest = dir.path().join(format!("{name}.out.p12"));
        let (ok, text) = keytool(&[
            "-importkeystore",
            "-noprompt",
            "-srckeystore",
            o,
            "-srcstoretype",
            st,
            "-srcstorepass",
            PW,
            "-srcalias",
            "server",
            "-srckeypass",
            keypass,
            "-destkeystore",
            dest.to_str().unwrap(),
            "-deststoretype",
            "PKCS12",
            "-deststorepass",
            PW,
            "-destkeypass",
            PW,
        ]);
        assert!(ok, "{name} 私鑰無法被 Java 解密：{text}");
    }
    let _ = Path::new("");
}

#[test]
fn target_parsing() {
    let t = tls::parse_target("https://api.example.com:8443/v1/health?x=1").unwrap();
    assert_eq!(
        (t.host.as_str(), t.port, t.path.as_deref()),
        ("api.example.com", 8443, Some("/v1/health?x=1"))
    );
    let t = tls::parse_target("api.example.com/v1").unwrap();
    assert_eq!((t.port, t.path.as_deref()), (443, Some("/v1")));
    let t = tls::parse_target("https://example.com/").unwrap();
    assert_eq!(t.path, None);
    let t = tls::parse_target("example.com?q=1").unwrap();
    assert_eq!(t.path.as_deref(), Some("/?q=1"));
    let t = tls::parse_target("[::1]:9443/a").unwrap();
    assert_eq!(
        (t.host.as_str(), t.port, t.path.as_deref()),
        ("::1", 9443, Some("/a"))
    );
    assert!(tls::parse_target("http://example.com").is_err());
    assert_eq!(
        tls::parse_header("X-Test:  1 ").unwrap(),
        ("X-Test".into(), "1".into())
    );
    assert!(tls::parse_header("bad header").is_err());
}

#[test]
fn http_request_after_handshake() {
    use std::io::{Read, Write};
    use std::sync::Arc;

    let p = pki();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![p.server.der().into(), p.inter.der().into()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(p.server.key_der().into()),
        )
        .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let cfg = Arc::new(cfg);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut conn = rustls::ServerConnection::new(cfg).unwrap();
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        let mut req = Vec::new();
        let mut buf = [0u8; 4096];
        while !req.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = tls.read(&mut buf).unwrap();
            req.extend_from_slice(&buf[..n]);
        }
        let text = String::from_utf8_lossy(&req).to_string();
        // body
        if let Some(i) = text.find("\r\n\r\n") {
            let need = text
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while req.len() - (i + 4) < need {
                let n = tls.read(&mut buf).unwrap();
                req.extend_from_slice(&buf[..n]);
            }
        }
        let body = r#"{"status":"ok"}"#;
        let resp = format!(
            "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
            body.len()
        );
        tls.write_all(resp.as_bytes()).unwrap();
        tls.conn.send_close_notify();
        let _ = tls.flush();
        String::from_utf8_lossy(&req).to_string()
    });

    let r = tls::connect_remote(
        &RemoteOptions {
            address: format!("https://localhost:{port}/api/items?x=1"),
            server_name: None,
            version: TlsVersion::Auto,
            at: None,
            timeout: std::time::Duration::from_secs(5),
            trust: RemoteTrust::Certs(vec![CertInfo::from_der(&p.root.der()).unwrap()]),
            proxy: None,
            http: Some(HttpRequest {
                method: "post".into(),
                path: "/api/items?x=1".into(),
                headers: vec![
                    ("Authorization".into(), "Bearer super-secret-token".into()),
                    ("Content-Type".into(), "application/json".into()),
                ],
                body: br#"{"name":"demo"}"#.to_vec(),
            }),
        },
        None,
    );
    assert!(r.success, "{:?}", r.failure);
    let h = r.http.expect("應有 HTTP 結果");
    assert_eq!(h.status, Some(201), "{h:?}");
    assert_eq!(h.body_preview, r#"{"status":"ok"}"#);
    assert_eq!(h.request_line, "POST /api/items?x=1 HTTP/1.1");
    let auth = h
        .request_headers
        .iter()
        .find(|(k, _)| k == "Authorization")
        .unwrap();
    assert_eq!(auth.1, "Bearer ***", "敏感標頭需遮蔽");
    let raw = server.join().unwrap();
    assert!(
        raw.contains("Bearer super-secret-token"),
        "實際送出的標頭不應被遮蔽"
    );
    assert!(raw.ends_with(r#"{"name":"demo"}"#));
}

#[test]
fn cert_and_key_identity() {
    let p = pki();
    let cert_file = load_text("client.crt", &pem_of(&[&p.inter, &p.client], None)); // 順序故意相反
    let key_file = load_text(
        "client.key",
        &pem::encode("PRIVATE KEY", &p.client.key_der()),
    );
    let id = tls::identity_from_cert_and_key(&cert_file, &key_file).unwrap();
    assert_eq!(
        id.chain[0].subject_cn.as_deref(),
        Some("client-app"),
        "應自動找出與私鑰相符的終端憑證"
    );

    let server_id = {
        let c = load_text("s.crt", &pem_of(&[&p.server, &p.inter], Some(&p.server)));
        tls::identity_from_keystore(&c, None).unwrap()
    };
    let anchors = vec![CertInfo::from_der(&p.root.der()).unwrap()];
    let r = tls::simulate_local(
        &server_id,
        &anchors,
        Some(&id),
        &anchors,
        &LocalOptions {
            require_client_auth: true,
            ..Default::default()
        },
    );
    assert!(r.success, "{:?}", r.failure);
}
