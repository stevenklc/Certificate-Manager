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

#[test]
fn issuance_tree_shows_issuers_and_issued() {
    let dir = tempfile::tempdir().unwrap();
    let (ks, chain) = make_store(&dir.path().join("t.jks"), StoreFormat::Jks);
    // 另一張由中繼 CA 簽發的憑證
    let other = forge::issue(
        &spec("other.example.com", Profile::Server, KeyAlg::EcP256),
        Some(Signer {
            cert: &chain[1].cert,
            key_pkcs8: &chain[1].key_pkcs8,
        }),
        None,
    )
    .unwrap();
    let mut pool: Vec<&CertInfo> = ks.all_certs();
    pool.push(&other.cert);

    // 從終端憑證出發：根 → 中繼 → {svc, other}
    let built = build_chain(&ks.entry("server").unwrap().chain, &pool, now_ts(), 30);
    let tree = issuance_tree(&built, &pool);
    let names: Vec<_> = tree
        .nodes
        .iter()
        .map(|n| (n.depth, n.cert.display_name(), n.is_target, n.on_path))
        .collect();
    assert_eq!(
        names,
        vec![
            (0, "Test Root".to_string(), false, true),
            (1, "Test Intermediate".to_string(), false, true),
            (2, "svc.example.com".to_string(), true, true),
            (2, "other.example.com".to_string(), false, false),
        ]
    );
    assert!(tree.nodes[1..].iter().all(|n| n.signature_ok == Some(true)));
    assert!(tree.missing_issuer.is_none());

    // 從根憑證出發也能看到它簽發的所有憑證
    let built = build_chain(&ks.entry("root").unwrap().chain, &pool, now_ts(), 30);
    let tree = issuance_tree(&built, &pool);
    assert_eq!(tree.nodes.len(), 4);
    assert!(tree.nodes[0].is_target);
}

#[test]
fn check_key_password_variants() {
    let dir = tempfile::tempdir().unwrap();
    // JKS：私鑰密碼與憑證庫不同，存檔後以原始加密資料檢查
    let (mut ks, _) = make_store(&dir.path().join("k.jks"), StoreFormat::Jks);
    edit::set_key_password(&mut ks, "server", "key-secret").unwrap();
    // 尚未存檔：與目前生效的密碼比對
    assert!(edit::check_key_password(&ks, "server", "key-secret").unwrap());
    assert!(!edit::check_key_password(&ks, "server", PW).unwrap());
    edit::save(&mut ks, None, None, false).unwrap();
    // 只給憑證庫密碼開啟 → 私鑰鎖住，仍可驗證並解開
    let mut back = load_file(&ks.path, &LoadOptions::with_password(PW)).unwrap();
    assert!(matches!(
        back.entry("server").unwrap().key,
        KeyState::Locked(_)
    ));
    assert!(!edit::check_key_password(&back, "server", "wrong-pw").unwrap());
    assert!(edit::check_key_password(&back, "server", "key-secret").unwrap());
    edit::unlock_entry(&mut back, "server", "key-secret").unwrap();
    // 信任憑證沒有私鑰密碼
    assert!(edit::check_key_password(&back, "root", PW).is_err());

    // PKCS#12：私鑰密碼等於憑證庫密碼
    let (mut p12, _) = make_store(&dir.path().join("k.p12"), StoreFormat::Pkcs12);
    edit::save(&mut p12, None, None, false).unwrap();
    let back = load_file(&p12.path, &LoadOptions::with_password(PW)).unwrap();
    assert!(edit::check_key_password(&back, "server", PW).unwrap());
    assert!(!edit::check_key_password(&back, "server", "nope").unwrap());
}

#[test]
fn assemble_store_from_cer_and_key_files() {
    let dir = tempfile::tempdir().unwrap();
    let chain = forge::issue_chain(
        &[
            spec("Asm Root", Profile::RootCa, KeyAlg::EcP256),
            spec("Asm Issuing", Profile::IntermediateCa, KeyAlg::EcP256),
            spec("a.example.com", Profile::Server, KeyAlg::Rsa2048),
        ],
        None,
    )
    .unwrap();
    let b = forge::issue(
        &spec("b.example.com", Profile::Server, KeyAlg::EcP256),
        Some(Signer {
            cert: &chain[1].cert,
            key_pkcs8: &chain[1].key_pkcs8,
        }),
        None,
    )
    .unwrap();
    let write = |name: &str, data: String| {
        let p = dir.path().join(name);
        std::fs::write(&p, data).unwrap();
        load_file(&p, &LoadOptions::default()).unwrap()
    };
    let key_pem = |pkcs8: &[u8]| {
        let mut ks = edit::new_keystore("x.p12", StoreFormat::Pkcs12, PW).unwrap();
        edit::add_key_entry(
            &mut ks,
            "k",
            vec![chain[0].cert.clone()],
            pkcs8.to_vec(),
            None,
            true,
        )
        .unwrap();
        edit::private_key_pem(ks.entry("k").unwrap()).unwrap()
    };
    // 檔案順序故意打亂；私鑰與憑證分開
    let sources = vec![
        write("b.key", key_pem(&b.key_pkcs8)),
        write("root.cer", chain[0].cert.to_pem()),
        write("a.crt", chain[2].cert.to_pem()),
        write("inter.cer", chain[1].cert.to_pem()),
        write("a.key", key_pem(&chain[2].key_pkcs8)),
        write("b.crt", b.cert.to_pem()),
        // 重複的憑證只算一次
        write("root-copy.pem", chain[0].cert.to_pem()),
    ];
    let mut plan = edit::plan_assembly(&sources);
    assert!(plan.problems.is_empty(), "{:?}", plan.problems);
    let mut keys: Vec<_> = plan.keys.iter().map(|k| k.alias.as_str()).collect();
    keys.sort();
    assert_eq!(keys, ["a.example.com", "b.example.com"]);
    assert!(plan.keys.iter().all(|k| k.complete && k.chain.len() == 3));
    let mut certs: Vec<_> = plan.certs.iter().map(|c| c.alias.as_str()).collect();
    certs.sort();
    assert_eq!(certs, ["asm-issuing", "asm-root"]);

    // 調整別名、取消中繼 CA 後建立 JKS
    plan.keys[0].alias = "web-1".into();
    plan.certs
        .iter_mut()
        .find(|c| c.alias == "asm-issuing")
        .unwrap()
        .include = false;
    let mut ks = edit::new_keystore(dir.path().join("out.jks"), StoreFormat::Jks, PW).unwrap();
    assert_eq!(edit::apply_assembly(&mut ks, &plan, false).unwrap(), 3);
    edit::save(&mut ks, None, None, false).unwrap();
    let back = load_file(&ks.path, &LoadOptions::with_password(PW)).unwrap();
    assert_eq!(back.entries.len(), 3);
    for k in back.private_key_entries() {
        let v = edit::verify_entry(&back, &k.alias, now_ts()).unwrap();
        assert!(v.ok, "{}: {:?}", k.alias, v.checks);
    }

    // 私鑰找不到憑證 → 列為問題
    let lonely =
        forge::issue(&spec("lonely", Profile::Server, KeyAlg::EcP256), None, None).unwrap();
    let plan = edit::plan_assembly(&[write("lonely.key", key_pem(&lonely.key_pkcs8))]);
    assert!(plan.keys.is_empty());
    assert_eq!(plan.problems.len(), 1);
}

#[test]
fn role_checks() {
    use rustca_core::role::{check_role, name_matches, store_kind, StoreRole};
    let dir = tempfile::tempdir().unwrap();
    let (ks, chain) = make_store(&dir.path().join("role.jks"), StoreFormat::Jks);
    assert_eq!(store_kind(&ks), "Keystore + Truststore");
    let errs = |r: &rustca_core::role::RoleReport| {
        r.sections
            .iter()
            .flat_map(|s| &s.checks)
            .filter(|c| c.level == CheckLevel::Error)
            .map(|c| c.message.clone())
            .collect::<Vec<_>>()
    };

    // Server：主機名稱相符 / 不符
    let r = check_role(&ks, StoreRole::Server, Some("svc.example.com"), now_ts());
    assert!(r.ok, "{:?}", errs(&r));
    let r = check_role(&ks, StoreRole::Server, Some("other.example.com"), now_ts());
    assert!(!r.ok);
    assert!(errs(&r).iter().any(|m| m.contains("other.example.com")));

    // Client：Server 憑證沒有 clientAuth → 錯誤
    let r = check_role(&ks, StoreRole::Client, None, now_ts());
    assert!(errs(&r).iter().any(|m| m.contains("clientAuth")));

    // Truststore：含私鑰只是警告；根 CA 有效 → 沒有錯誤
    let r = check_role(&ks, StoreRole::Truststore, None, now_ts());
    assert!(r.ok && r.warnings > 0);

    // 只有終端憑證的信任庫 → 警告憑證釘選
    let mut ts = edit::new_keystore(dir.path().join("t.jks"), StoreFormat::Jks, PW).unwrap();
    edit::import_certs(&mut ts, "leaf", &[chain[2].cert.clone()], false).unwrap();
    assert_eq!(store_kind(&ts), "Truststore");
    let r = check_role(&ts, StoreRole::Truststore, None, now_ts());
    assert!(r.ok && r.warnings > 0);
    // 信任庫拿去當 Server → 錯誤
    assert!(!check_role(&ts, StoreRole::Server, None, now_ts()).ok);

    assert!(name_matches("*.example.com", "a.example.com"));
    assert!(!name_matches("*.example.com", "a.b.example.com"));
    assert!(!name_matches("*.example.com", "example.com"));
}
