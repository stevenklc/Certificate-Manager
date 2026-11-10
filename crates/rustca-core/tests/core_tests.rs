mod common;

use std::path::PathBuf;

use common::*;
use rustca_core::jks::{self, KeyBlob, WriteEntry};
use rustca_core::tls::{self, LocalOptions, RemoteOptions, RemoteTrust, Side, TlsVersion};
use rustca_core::*;

const PW: &str = "changeit";

fn server_jks(p: &Pki) -> Keystore {
    let leaf = p.server.der();
    let inter = p.inter.der();
    let key = p.server.key_der();
    let data = jks::encode_store(
        StoreFormat::Jks,
        &[WriteEntry::PrivateKey {
            alias: "server",
            created: None,
            key: KeyBlob::Plain {
                pkcs8: &key,
                password: PW,
            },
            chain: vec![&leaf, &inter],
        }],
        PW,
    )
    .unwrap();
    load_bytes(
        PathBuf::from("server.jks"),
        &data,
        &LoadOptions::with_password(PW),
    )
    .unwrap()
}

fn client_jks(p: &Pki) -> Keystore {
    let leaf = p.client.der();
    let inter = p.inter.der();
    let key = p.client.key_der();
    let data = jks::encode_store(
        StoreFormat::Jks,
        &[WriteEntry::PrivateKey {
            alias: "client",
            created: None,
            key: KeyBlob::Plain {
                pkcs8: &key,
                password: PW,
            },
            chain: vec![&leaf, &inter],
        }],
        PW,
    )
    .unwrap();
    load_bytes(
        PathBuf::from("client.jks"),
        &data,
        &LoadOptions::with_password(PW),
    )
    .unwrap()
}

fn trust_jks(certs: &[(&str, Vec<u8>)]) -> Keystore {
    let entries: Vec<_> = certs
        .iter()
        .map(|(a, c)| WriteEntry::TrustedCert {
            alias: a,
            created: None,
            cert: c,
        })
        .collect();
    let data = jks::encode_store(StoreFormat::Jks, &entries, PW).unwrap();
    load_bytes(
        PathBuf::from("trust.jks"),
        &data,
        &LoadOptions::with_password(PW),
    )
    .unwrap()
}

#[test]
fn jks_roundtrip_and_password() {
    let p = pki();
    let ks = server_jks(&p);
    assert_eq!(ks.format, StoreFormat::Jks);
    assert_eq!(ks.integrity, Integrity::Verified);
    assert_eq!(ks.entries.len(), 1);
    let e = &ks.entries[0];
    assert_eq!(e.alias, "server");
    assert_eq!(e.kind, EntryKind::PrivateKey);
    assert_eq!(e.chain.len(), 2);
    assert!(matches!(e.key, KeyState::Decrypted { .. }));
    assert_eq!(e.chain[0].subject_cn.as_deref(), Some("server.example.com"));
    assert!(e.chain[0]
        .subject_alt_names
        .contains(&"DNS:localhost".to_string()));
    assert!(e.chain[0].ext_key_usage.contains(&"serverAuth".to_string()));
    assert!(e.chain[1].is_ca);

    // 不給密碼：可列出，但私鑰鎖住
    let leaf = p.server.der();
    let key = p.server.key_der();
    let data = jks::encode_store(
        StoreFormat::Jks,
        &[WriteEntry::PrivateKey {
            alias: "server",
            created: None,
            key: KeyBlob::Plain {
                pkcs8: &key,
                password: "keypass",
            },
            chain: vec![&leaf],
        }],
        PW,
    )
    .unwrap();
    let ks = load_bytes("a.jks".into(), &data, &LoadOptions::default()).unwrap();
    assert_eq!(ks.integrity, Integrity::NotChecked);
    assert!(matches!(ks.entries[0].key, KeyState::Locked(_)));

    // 錯誤密碼
    let err = load_bytes("a.jks".into(), &data, &LoadOptions::with_password("nope")).unwrap_err();
    assert!(err.is_password_problem());

    // 不同的 key password
    let ks = load_bytes(
        "a.jks".into(),
        &data,
        &LoadOptions {
            password: Some(PW.into()),
            key_password: Some("keypass".into()),
        },
    )
    .unwrap();
    assert!(matches!(ks.entries[0].key, KeyState::Decrypted { .. }));
}

#[test]
fn pem_and_der_loading() {
    let p = pki();
    let text = format!(
        "{}{}{}",
        pem::encode("CERTIFICATE", &p.server.der()),
        pem::encode("CERTIFICATE", &p.inter.der()),
        pem::encode("PRIVATE KEY", &p.server.key_der())
    );
    let ks = load_bytes(
        "server.pem".into(),
        text.as_bytes(),
        &LoadOptions::default(),
    )
    .unwrap();
    assert_eq!(ks.format, StoreFormat::Pem);
    assert_eq!(ks.entries.len(), 1);
    assert_eq!(ks.entries[0].chain.len(), 2);
    tls::identity_from_keystore(&ks, None).unwrap();

    let ks = load_bytes("root.cer".into(), &p.root.der(), &LoadOptions::default()).unwrap();
    assert_eq!(ks.format, StoreFormat::Der);
    assert!(ks.entries[0].chain[0].self_signed);
}

#[test]
fn chain_building() {
    let p = pki();
    let ks = server_jks(&p);
    let trust = trust_jks(&[("root", p.root.der())]);
    let pool: Vec<&CertInfo> = trust.all_certs();
    let chain = build_chain(&ks.entries[0].chain, &pool, now_ts(), 30);
    assert!(chain.is_complete(), "{:?}", chain.problems);
    assert_eq!(chain.links.len(), 3);
    assert!(chain.links.iter().all(|l| l.signature_ok == Some(true)));

    let chain = build_chain(&ks.entries[0].chain, &[], now_ts(), 30);
    assert!(matches!(chain.end, ChainEnd::MissingIssuer { .. }));
}

#[test]
fn validity_status() {
    let p = pki();
    let expired = leaf_with_validity(
        "old",
        &["old.local"],
        true,
        &p.inter,
        Some(((2000, 1, 1), (2001, 1, 1))),
    );
    let c = CertInfo::from_der(&expired.der()).unwrap();
    assert!(matches!(c.status(30), ValidityStatus::Expired { .. }));
    let future = leaf_with_validity(
        "new",
        &["new.local"],
        true,
        &p.inter,
        Some(((2090, 1, 1), (2091, 1, 1))),
    );
    let c = CertInfo::from_der(&future.der()).unwrap();
    assert!(matches!(c.status(30), ValidityStatus::NotYetValid { .. }));
    let c = CertInfo::from_der(&p.server.der()).unwrap();
    let soon = c.status_at(c.not_after - 5 * 86400, 30);
    assert!(matches!(
        soon,
        ValidityStatus::ExpiringSoon { days_left: 5 }
    ));
}

#[test]
fn keyword_search() {
    let p = pki();
    let ks = server_jks(&p);
    let hits = search(&ks, "intermediate");
    assert_eq!(hits.len(), 2); // leaf 的簽發者 + inter 的主體
    let hits = search(&ks, "LOCALHOST");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].matches[0].field, "SAN");
    let serial = ks.entries[0].chain[0].serial.replace(':', "");
    let hits = search(&ks, &serial[..8]);
    assert!(hits
        .iter()
        .any(|h| h.matches.iter().any(|m| m.field == "序號")));
    let hits = search(&ks, "server");
    assert!(hits[0].matches.iter().any(|m| m.field == "別名"));
    assert!(search(&ks, "no-such-thing").is_empty());
}

#[test]
fn local_handshake_ok_and_failures() {
    let p = pki();
    let server = tls::identity_from_keystore(&server_jks(&p), None).unwrap();
    let trust = trust_jks(&[("root", p.root.der())]);
    let client_trust = tls::trust_from_keystores(&[&trust]);

    for v in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let r = tls::simulate_local(
            &server,
            &client_trust,
            None,
            &[],
            &LocalOptions {
                version: v,
                ..Default::default()
            },
        );
        assert!(r.success, "{:?}", r.failure);
        assert_eq!(r.server_chain.len(), 2);
        assert!(!r.transcript.is_empty());
        assert!(r.transcript[0].message.starts_with("ClientHello"));
    }

    // 錯誤主機名稱
    let r = tls::simulate_local(
        &server,
        &client_trust,
        None,
        &[],
        &LocalOptions {
            server_name: Some("wrong.example.com".into()),
            ..Default::default()
        },
    );
    assert!(!r.success);
    let f = r.failure.unwrap();
    assert_eq!(f.side, Side::Client);
    assert!(f.hint.contains("SAN"));

    // 信任庫缺少根憑證
    let wrong = trust_jks(&[("other", p.other_root.der())]);
    let r = tls::simulate_local(
        &server,
        &tls::trust_from_keystores(&[&wrong]),
        None,
        &[],
        &LocalOptions::default(),
    );
    assert!(!r.success);
    assert!(r.failure.unwrap().hint.contains("根 CA"));

    // 模擬未來時間 → 過期（rcgen 預設到期日為 4096 年）
    let r = tls::simulate_local(
        &server,
        &client_trust,
        None,
        &[],
        &LocalOptions {
            at: Some(parse_date("4100-01-01").unwrap()),
            ..Default::default()
        },
    );
    assert!(!r.success);
    assert!(r.failure.unwrap().hint.contains("過期"));
}

#[test]
fn local_mtls() {
    let p = pki();
    let server = tls::identity_from_keystore(&server_jks(&p), None).unwrap();
    let client = tls::identity_from_keystore(&client_jks(&p), None).unwrap();
    let trust = trust_jks(&[("root", p.root.der())]);
    let anchors = tls::trust_from_keystores(&[&trust]);
    let opts = LocalOptions {
        require_client_auth: true,
        ..Default::default()
    };

    let r = tls::simulate_local(&server, &anchors, Some(&client), &anchors, &opts);
    assert!(r.success, "{:?}", r.failure);
    assert!(r.client_auth_requested);
    assert_eq!(r.client_chain.len(), 2);
    assert!(
        r.acceptable_ca_names
            .iter()
            .any(|n| n.contains("Test Root CA")),
        "{:?}",
        r.acceptable_ca_names
    );

    // 沒有 Client 憑證
    let r = tls::simulate_local(&server, &anchors, None, &anchors, &opts);
    assert!(!r.success);
    assert_eq!(r.failure.as_ref().unwrap().side, Side::Server);

    // Server 不信任 Client 的 CA
    let other = trust_jks(&[("other", p.other_root.der())]);
    let r = tls::simulate_local(
        &server,
        &anchors,
        Some(&client),
        &tls::trust_from_keystores(&[&other]),
        &opts,
    );
    assert!(!r.success);
    let f = r.failure.unwrap();
    assert_eq!(f.side, Side::Server);
    assert!(f.hint.contains("Server 信任庫"));

    // Server 憑證拿來當 Client 憑證 → EKU 不符
    let r = tls::simulate_local(&server, &anchors, Some(&server), &anchors, &opts);
    assert!(!r.success);
    assert!(r.failure.unwrap().hint.contains("Extended Key Usage"));
}

#[test]
fn remote_handshake_against_local_server() {
    use std::io::{Read, Write};
    use std::sync::Arc;

    let p = pki();
    let leaf = rustls::pki_types::CertificateDer::from(p.server.der());
    let inter = rustls::pki_types::CertificateDer::from(p.inter.der());
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(p.server.key_der().into());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![leaf, inter], key)
            .unwrap(),
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut sock, _) = listener.accept().unwrap();
            let mut conn = rustls::ServerConnection::new(cfg.clone()).unwrap();
            let _ = conn.complete_io(&mut sock);
            let mut buf = [0u8; 64];
            let _ = sock.read(&mut buf);
            let _ = sock.flush();
        }
    });

    let trust = CertInfo::from_der(&p.root.der()).unwrap();
    let r = tls::connect_remote(
        &RemoteOptions {
            address: format!("127.0.0.1:{port}"),
            server_name: Some("localhost".into()),
            version: TlsVersion::Auto,
            at: None,
            timeout: std::time::Duration::from_secs(5),
            trust: RemoteTrust::Certs(vec![trust]),
            proxy: None,
            http: None,
        },
        None,
    );
    assert!(r.success, "{:?}", r.failure);
    assert_eq!(r.server_chain.len(), 2);
    assert_eq!(r.protocol.as_deref(), Some("TLS 1.3"));

    // 用錯誤信任庫：失敗，但仍取得 Server 憑證鏈
    let other = CertInfo::from_der(&p.other_root.der()).unwrap();
    let r = tls::connect_remote(
        &RemoteOptions {
            address: format!("127.0.0.1:{port}"),
            server_name: Some("localhost".into()),
            version: TlsVersion::Auto,
            at: None,
            timeout: std::time::Duration::from_secs(5),
            trust: RemoteTrust::Certs(vec![other]),
            proxy: None,
            http: None,
        },
        None,
    );
    assert!(!r.success);
    assert_eq!(r.server_chain.len(), 2);
    handle.join().unwrap();
}

#[test]
fn host_port_parsing() {
    assert_eq!(
        tls::split_host_port("example.com").unwrap(),
        ("example.com".into(), 443)
    );
    assert_eq!(
        tls::split_host_port("example.com:8443").unwrap(),
        ("example.com".into(), 8443)
    );
    assert_eq!(
        tls::split_host_port("https://example.com/").unwrap(),
        ("example.com".into(), 443)
    );
    assert_eq!(
        tls::split_host_port("[::1]:9443").unwrap(),
        ("::1".into(), 9443)
    );
}

#[test]
fn proxy_parsing_and_no_proxy() {
    let p = tls::ProxyConfig::parse("http://user:p%40ss@proxy.local:3128").unwrap();
    assert_eq!(p.display(), "http://***@proxy.local:3128");
    assert!(!format!("{p:?}").contains("ss"));
    let p = tls::ProxyConfig::parse("proxy.local").unwrap();
    assert_eq!(p.display(), "http://proxy.local:8080");
    assert!(tls::ProxyConfig::parse("socks5://x:1080").is_err());

    let rules = "localhost,127.0.0.1,.corp.example,*.internal";
    assert!(tls::no_proxy_match("localhost", rules));
    assert!(tls::no_proxy_match("api.corp.example", rules));
    assert!(tls::no_proxy_match("corp.example", rules));
    assert!(tls::no_proxy_match("a.b.internal", rules));
    assert!(!tls::no_proxy_match("www.google.com", rules));
    assert!(!tls::no_proxy_match("evilcorp.example", rules));
}

#[test]
fn remote_via_http_connect_proxy() {
    use std::io::{BufRead, BufReader, Write};
    use std::sync::Arc;

    let p = pki();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![p.server.der().into(), p.inter.der().into()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(p.server.key_der().into()),
            )
            .unwrap(),
    );
    // TLS Server
    let tls_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let tls_port = tls_listener.local_addr().unwrap().port();
    let t1 = std::thread::spawn(move || {
        let (mut sock, _) = tls_listener.accept().unwrap();
        let mut conn = rustls::ServerConnection::new(cfg).unwrap();
        let _ = conn.complete_io(&mut sock);
        let _ = conn.complete_io(&mut sock);
    });
    // 簡易 CONNECT proxy（要求帳密）
    let proxy_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    let t2 = std::thread::spawn(move || {
        let (client, _) = proxy_listener.accept().unwrap();
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut lines = Vec::new();
        loop {
            let mut l = String::new();
            reader.read_line(&mut l).unwrap();
            if l == "\r\n" || l.is_empty() {
                break;
            }
            lines.push(l);
        }
        assert!(lines[0].starts_with(&format!("CONNECT localhost:{tls_port} ")));
        // base64("user:p@ss")
        assert!(
            lines.iter().any(|l| l.contains("Basic dXNlcjpwQHNz")),
            "{lines:?}"
        );
        let mut client_w = client.try_clone().unwrap();
        client_w
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .unwrap();
        let upstream = std::net::TcpStream::connect(("127.0.0.1", tls_port)).unwrap();
        let (mut c_r, mut u_w) = (client.try_clone().unwrap(), upstream.try_clone().unwrap());
        let (mut u_r, mut c_w) = (upstream, client);
        let a = std::thread::spawn(move || {
            let _ = std::io::copy(&mut c_r, &mut u_w);
        });
        let _ = std::io::copy(&mut u_r, &mut c_w);
        let _ = a.join();
    });

    let r = tls::connect_remote(
        &RemoteOptions {
            address: format!("localhost:{tls_port}"),
            server_name: None,
            version: TlsVersion::Auto,
            at: None,
            timeout: std::time::Duration::from_secs(5),
            trust: RemoteTrust::Certs(vec![CertInfo::from_der(&p.root.der()).unwrap()]),
            proxy: Some(format!("http://user:p%40ss@127.0.0.1:{proxy_port}")),
            http: None,
        },
        None,
    );
    assert!(r.success, "{:?}", r.failure);
    assert_eq!(
        r.via_proxy.as_deref(),
        Some(format!("http://***@127.0.0.1:{proxy_port}").as_str())
    );
    t1.join().unwrap();
    drop(t2);
}

#[test]
fn windows_proxy_settings_parsing() {
    assert_eq!(
        tls::parse_proxy_server("proxy.corp:8080").as_deref(),
        Some("http://proxy.corp:8080")
    );
    assert_eq!(
        tls::parse_proxy_server("http=p1:80;https=p2:443;ftp=p3:21").as_deref(),
        Some("http://p2:443")
    );
    assert_eq!(
        tls::parse_proxy_server("ftp=p3:21;http=p1:80").as_deref(),
        Some("http://p1:80")
    );
    assert_eq!(tls::parse_proxy_server(""), None);

    let ov = "*.corp.example;10.*;Fileserver;build*.dev.example;<local>";
    assert!(tls::windows_bypass_match("api.corp.example", ov));
    assert!(tls::windows_bypass_match("10.1.2.3", ov));
    assert!(tls::windows_bypass_match("FILESERVER", ov));
    assert!(tls::windows_bypass_match("build01.dev.example", ov));
    assert!(tls::windows_bypass_match("intranet", ov)); // <local>
    assert!(!tls::windows_bypass_match("www.google.com", ov));
    assert!(!tls::windows_bypass_match("corp.example.evil.com", ov));
}
