//! 使用真正的 Java keytool 產生的憑證庫驗證解析器。找不到 keytool 時自動略過。

use std::path::Path;
use std::process::Command;

use rustca_core::tls::{self, LocalOptions};
use rustca_core::*;

const PW: &str = "changeit";

fn keytool(args: &[&str]) -> bool {
    Command::new("keytool")
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn have_keytool() -> bool {
    Command::new("keytool").arg("-help").output().is_ok()
}

fn genkey(dir: &Path, file: &str, storetype: &str, alias: &str, keyalg: &str) {
    let path = dir.join(file);
    let ok = keytool(&[
        "-genkeypair",
        "-alias",
        alias,
        "-keyalg",
        keyalg,
        "-keysize",
        if keyalg == "RSA" { "2048" } else { "256" },
        "-dname",
        &format!("CN={alias}.example.com, O=RUST-CA, C=TW"),
        "-ext",
        &format!("SAN=dns:{alias}.example.com,dns:localhost"),
        "-validity",
        "365",
        "-storetype",
        storetype,
        "-keystore",
        path.to_str().unwrap(),
        "-storepass",
        PW,
        "-keypass",
        PW,
    ]);
    assert!(ok, "keytool genkeypair 失敗：{file}");
}

#[test]
fn keytool_jks_jceks_pkcs12() {
    if !have_keytool() {
        eprintln!("找不到 keytool，略過");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();

    genkey(d, "rsa.jks", "JKS", "rsa", "RSA");
    genkey(d, "ec.jceks", "JCEKS", "ec", "EC");
    genkey(d, "rsa.p12", "PKCS12", "p12", "RSA");

    // 匯出憑證並建立 truststore
    assert!(keytool(&[
        "-exportcert",
        "-alias",
        "rsa",
        "-keystore",
        d.join("rsa.jks").to_str().unwrap(),
        "-storepass",
        PW,
        "-file",
        d.join("rsa.cer").to_str().unwrap(),
    ]));
    assert!(keytool(&[
        "-exportcert",
        "-rfc",
        "-alias",
        "ec",
        "-storetype",
        "JCEKS",
        "-keystore",
        d.join("ec.jceks").to_str().unwrap(),
        "-storepass",
        PW,
        "-file",
        d.join("ec.pem").to_str().unwrap(),
    ]));
    assert!(keytool(&[
        "-importcert",
        "-noprompt",
        "-alias",
        "rsa-trust",
        "-file",
        d.join("rsa.cer").to_str().unwrap(),
        "-keystore",
        d.join("trust.jks").to_str().unwrap(),
        "-storepass",
        PW,
        "-storetype",
        "JKS",
    ]));

    let opts = LoadOptions::with_password(PW);

    let jks = load_file(d.join("rsa.jks"), &opts).unwrap();
    assert_eq!(jks.format, StoreFormat::Jks);
    assert_eq!(jks.integrity, Integrity::Verified);
    assert!(
        matches!(jks.entries[0].key, KeyState::Decrypted { .. }),
        "{:?}",
        jks.entries[0].key
    );
    assert_eq!(jks.entries[0].chain[0].public_key, "RSA 2048 bits");

    let jceks = load_file(d.join("ec.jceks"), &opts).unwrap();
    assert_eq!(jceks.format, StoreFormat::Jceks);
    assert!(
        matches!(jceks.entries[0].key, KeyState::Decrypted { .. }),
        "{:?}",
        jceks.entries[0].key
    );
    assert_eq!(jceks.entries[0].chain[0].public_key, "EC P-256");

    let p12 = load_file(d.join("rsa.p12"), &opts).unwrap();
    assert_eq!(p12.format, StoreFormat::Pkcs12);
    assert_eq!(p12.entries[0].kind, EntryKind::PrivateKey);
    assert!(
        load_file(d.join("rsa.p12"), &LoadOptions::with_password("bad"))
            .unwrap_err()
            .is_password_problem()
    );

    let cer = load_file(d.join("rsa.cer"), &LoadOptions::default()).unwrap();
    assert_eq!(cer.format, StoreFormat::Der);
    let pem = load_file(d.join("ec.pem"), &LoadOptions::default()).unwrap();
    assert_eq!(pem.format, StoreFormat::Pem);

    let trust = load_file(d.join("trust.jks"), &opts).unwrap();
    assert_eq!(trust.entries[0].kind, EntryKind::TrustedCert);

    // 用 keytool 產生的憑證庫做交握
    // Java 8 keytool 產生的 ECDSA 憑證帶有非標準 NULL 參數，rustls 會拒絕，工具應給出明確診斷
    {
        let server = tls::identity_from_keystore(&jceks, None).unwrap();
        let anchors: Vec<CertInfo> = vec![server.chain[0].clone()];
        let r = tls::simulate_local(
            &server,
            &anchors,
            None,
            &[],
            &LocalOptions {
                server_name: Some("localhost".into()),
                ..Default::default()
            },
        );
        if !r.success {
            assert!(r.failure.unwrap().hint.contains("NULL"));
        }
    }

    for server_ks in [&jks, &p12] {
        let server = tls::identity_from_keystore(server_ks, None).unwrap();
        let anchors: Vec<CertInfo> = vec![server.chain[0].clone()];
        let r = tls::simulate_local(
            &server,
            &anchors,
            None,
            &[],
            &LocalOptions {
                server_name: Some("localhost".into()),
                ..Default::default()
            },
        );
        assert!(r.success, "{}: {:?}", server_ks.name(), r.failure);
    }
    let server = tls::identity_from_keystore(&jks, None).unwrap();
    let r = tls::simulate_local(
        &server,
        &tls::trust_from_keystores(&[&trust]),
        None,
        &[],
        &LocalOptions::default(),
    );
    assert!(r.success, "{:?}", r.failure);
}
