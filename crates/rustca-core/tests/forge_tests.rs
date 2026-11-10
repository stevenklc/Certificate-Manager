//! 製作憑證鏈、替換憑證鏈驗證、憑證格式轉換、Java 相容性測試。

use rustca_core::edit::{self, CertFormat, CheckLevel, WriteOptions};
use rustca_core::forge::{self, CertSpec, KeyAlg, Profile, Signer};
use rustca_core::tls::{self, LocalOptions};
use rustca_core::*;

const PW: &str = "changeit";

fn spec(cn: &str, profile: Profile, key: KeyAlg) -> CertSpec {
    let mut s = CertSpec::new(cn, profile);
    s.key = key;
    s.subject.o = "RUST-CA 測試".into();
    s.subject.c = "tw".into();
    s
}

fn make_store(path: &std::path::Path, format: StoreFormat) -> (Keystore, Vec<forge::Issued>) {
    let chain = forge::issue_chain(
        &[
            spec("Test Root", Profile::RootCa, KeyAlg::EcP256),
            spec("Test Intermediate", Profile::IntermediateCa, KeyAlg::EcP256),
            {
                let mut s = spec("svc.example.com", Profile::Server, KeyAlg::Rsa2048);
                s.sans = vec!["svc.example.com".into(), "IP:127.0.0.1".into()];
                s
            },
        ],
        None,
    )
    .unwrap();
    let mut ks = edit::new_keystore(path, format, PW).unwrap();
    edit::import_certs(&mut ks, "root", &[chain[0].cert.clone()], false).unwrap();
    let leaf_chain = vec![
        chain[2].cert.clone(),
        chain[1].cert.clone(),
        chain[0].cert.clone(),
    ];
    edit::add_key_entry(
        &mut ks,
        "server",
        leaf_chain,
        chain[2].key_pkcs8.clone(),
        None,
        false,
    )
    .unwrap();
    (ks, chain)
}

#[test]
fn issue_chain_and_handshake() {
    let dir = tempfile::tempdir().unwrap();
    let (mut ks, chain) = make_store(&dir.path().join("made.jks"), StoreFormat::Jks);
    let root = &chain[0].cert;
    assert!(root.self_signed && root.is_ca);
    assert_eq!(root.subject, "C=TW, O=RUST-CA 測試, CN=Test Root");
    assert!(chain[1].cert.is_ca && !chain[2].cert.is_ca);
    assert_eq!(chain[2].cert.issuer, chain[1].cert.subject);
    assert!(chain[2]
        .cert
        .subject_alt_names
        .iter()
        .any(|s| s.contains("127.0.0.1")));
    assert!(chain[2].cert.public_key.starts_with("RSA"));

    let v = edit::verify_entry(&ks, "server", now_ts()).unwrap();
    assert!(v.ok, "{:?}", v.checks);

    edit::save(&mut ks, None, None, false).unwrap();
    let back = load_file(&ks.path, &LoadOptions::with_password(PW)).unwrap();
    let server = tls::identity_from_keystore(&back, Some("server")).unwrap();
    let r = tls::simulate_local(
        &server,
        &tls::trust_from_keystores(&[&back]),
        None,
        &[],
        &LocalOptions {
            server_name: Some("svc.example.com".into()),
            ..Default::default()
        },
    );
    assert!(r.success, "{:?}", r.failure);
}

#[test]
fn sign_with_existing_ca() {
    let root = forge::issue(
        &spec("Existing Root", Profile::RootCa, KeyAlg::EcP384),
        None,
        None,
    )
    .unwrap();
    let leaf = forge::issue(
        &spec("client-1", Profile::Client, KeyAlg::EcP256),
        Some(Signer {
            cert: &root.cert,
            key_pkcs8: &root.key_pkcs8,
        }),
        None,
    )
    .unwrap();
    assert_eq!(leaf.cert.raw_issuer, root.cert.raw_subject);
    assert_eq!(leaf.cert.authority_key_id, root.cert.subject_key_id);
    assert!(leaf.cert.ext_key_usage.iter().any(|u| u == "clientAuth"));
    // 不是 CA 不能簽發
    assert!(forge::issue(
        &spec("x", Profile::Server, KeyAlg::EcP256),
        Some(Signer {
            cert: &leaf.cert,
            key_pkcs8: &leaf.key_pkcs8
        }),
        None
    )
    .is_err());
}

#[test]
fn replace_chain_is_verified() {
    let dir = tempfile::tempdir().unwrap();
    let (mut ks, chain) = make_store(&dir.path().join("r.p12"), StoreFormat::Pkcs12);
    let inter = Signer {
        cert: &chain[1].cert,
        key_pkcs8: &chain[1].key_pkcs8,
    };
    // 續約：同一把私鑰重新簽發 → 可替換，並自動補上庫內的根憑證
    let renewed = forge::issue(
        &spec("svc.example.com", Profile::Server, KeyAlg::Rsa2048),
        Some(inter),
        Some(chain[2].key_pkcs8.clone()),
    )
    .unwrap();
    let (_, v) = edit::replace_chain(
        &mut ks,
        "server",
        &[renewed.cert.clone(), chain[1].cert.clone()],
    )
    .unwrap();
    assert!(v.ok);
    assert_eq!(
        ks.entry("server").unwrap().chain[0].sha256,
        renewed.cert.sha256
    );

    // 不同私鑰的憑證 → 拒絕，原內容不變
    let other = forge::issue(
        &spec("svc.example.com", Profile::Server, KeyAlg::EcP256),
        Some(inter),
        None,
    )
    .unwrap();
    assert!(edit::replace_chain(&mut ks, "server", std::slice::from_ref(&other.cert)).is_err());
    assert_eq!(
        ks.entry("server").unwrap().chain[0].sha256,
        renewed.cert.sha256
    );

    // 驗證可以抓到錯誤的鏈順序
    let mut bad = ks.clone();
    let e = bad
        .entries
        .iter_mut()
        .find(|e| e.alias == "server")
        .unwrap();
    e.chain.swap(1, 2);
    let v = edit::verify_entry(&bad, "server", now_ts()).unwrap();
    assert!(!v.ok);
    assert!(v.checks.iter().any(|c| c.level == CheckLevel::Error));
}

#[test]
fn cert_format_conversion() {
    let root = forge::issue(
        &spec("Fmt Root", Profile::RootCa, KeyAlg::EcP256),
        None,
        None,
    )
    .unwrap();
    let leaf = forge::issue(
        &spec("fmt.example.com", Profile::Server, KeyAlg::EcP256),
        Some(Signer {
            cert: &root.cert,
            key_pkcs8: &root.key_pkcs8,
        }),
        None,
    )
    .unwrap();
    let certs = [&leaf.cert, &root.cert];
    for f in CertFormat::ALL {
        let data = match edit::encode_certs(&certs, f) {
            Ok(d) => d,
            Err(_) if f == CertFormat::Der => edit::encode_certs(&certs[..1], f).unwrap(),
            Err(e) => panic!("{f:?}: {e}"),
        };
        let ks = load_bytes(
            format!("x.{}", f.extension()).into(),
            &data,
            &LoadOptions::default(),
        )
        .unwrap_or_else(|e| panic!("{f:?}: {e}"));
        let n = if f == CertFormat::Der { 1 } else { 2 };
        assert_eq!(ks.all_certs().len(), n, "{f:?}");
    }
    assert_eq!(CertFormat::parse("cer"), Some(CertFormat::Der));
}

#[test]
fn java_compat_with_local_keytool() {
    let runtimes = javacompat::discover(&[]);
    if runtimes.is_empty() {
        eprintln!("略過：找不到 Java");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    for (format, legacy) in [
        (StoreFormat::Jks, false),
        (StoreFormat::Jceks, false),
        (StoreFormat::Pkcs12, false),
        (StoreFormat::Pkcs12, true),
    ] {
        let (mut ks, _) = make_store(&dir.path().join("j.store"), format);
        // 不同的私鑰密碼也要測得到
        if format != StoreFormat::Pkcs12 {
            edit::set_key_password(&mut ks, "server", "other-key-pw").unwrap();
        }
        let opts = WriteOptions {
            pkcs12_legacy: legacy,
        };
        let rep =
            javacompat::test_keystore(&runtimes, &ks, javacompat::TestSource::Serialize(opts))
                .unwrap();
        assert!(!rep.notes.is_empty());
        for r in &rep.results {
            eprintln!(
                "{format} legacy={legacy}: {} → {} {:?}",
                r.java, r.message, r.keys
            );
            // 環境中的 Java 8 為 8u504，新舊 PKCS#12 都應可讀
            if r.major >= 8 {
                assert!(r.ok, "{format}: {}", r.message);
                assert_eq!(r.keys.len(), 1);
            }
        }
        // 存檔後直接測檔案
        edit::save_with(&mut ks, None, None, false, opts).unwrap();
        let rep = javacompat::test_keystore(&runtimes, &ks, javacompat::TestSource::File(&ks.path))
            .unwrap();
        assert!(rep.ok, "{:?}", rep.results);
        if format == StoreFormat::Pkcs12 {
            let data = std::fs::read(&ks.path).unwrap();
            assert_eq!(javacompat::pkcs12_uses_pbes2(&data), !legacy);
        }
    }
}
