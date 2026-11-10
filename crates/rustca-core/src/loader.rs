//! 依檔案內容自動判斷格式並載入。

use std::path::{Path, PathBuf};

use crate::cert::CertInfo;
use crate::der;
use crate::error::{Error, Result};
use crate::jks;
use crate::model::{
    Entry, EntryKind, Integrity, KeyFormat, KeyState, Keystore, Secret, StoreFormat,
};
use crate::pem;

const OID_PKCS7_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";

#[derive(Debug, Clone, Default)]
pub struct LoadOptions {
    /// 憑證庫密碼
    pub password: Option<String>,
    /// 私鑰密碼（未提供時使用憑證庫密碼）
    pub key_password: Option<String>,
}

impl LoadOptions {
    pub fn with_password(pw: impl Into<String>) -> Self {
        LoadOptions {
            password: Some(pw.into()),
            key_password: None,
        }
    }
}

/// 載入檔案。
pub fn load_file(path: impl AsRef<Path>, opts: &LoadOptions) -> Result<Keystore> {
    let path = path.as_ref();
    let data = std::fs::read(path)
        .map_err(|e| Error::Other(format!("無法讀取 {}：{e}", path.display())))?;
    load_bytes(path.to_path_buf(), &data, opts)
}

/// 偵測格式（不需密碼）。
pub fn detect_format(data: &[u8]) -> Option<StoreFormat> {
    if let Some(f) = jks::is_jks_or_jceks(data) {
        return Some(f);
    }
    if pem::looks_like_pem(data) {
        return Some(StoreFormat::Pem);
    }
    let (seq, _) = der::expect(data, der::TAG_SEQUENCE).ok()?;
    let (first, _) = der::read_tlv(seq.content).ok()?;
    match first.tag {
        // PFX ::= SEQUENCE { version INTEGER (3), ... }
        der::TAG_INTEGER if first.content == [3] => Some(StoreFormat::Pkcs12),
        // ContentInfo ::= SEQUENCE { contentType OID, ... }
        der::TAG_OID if der::oid_to_string(first.content) == OID_PKCS7_SIGNED_DATA => {
            Some(StoreFormat::Pkcs7)
        }
        // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, ... }
        der::TAG_SEQUENCE => Some(StoreFormat::Der),
        _ => None,
    }
}

/// 從記憶體資料載入。
pub fn load_bytes(path: PathBuf, data: &[u8], opts: &LoadOptions) -> Result<Keystore> {
    let format = detect_format(data).ok_or_else(|| {
        Error::format("無法辨識的檔案格式（支援 JKS、JCEKS、PKCS#12、PEM、DER、PKCS#7）")
    })?;
    let pw = opts.password.as_deref();
    let kpw = opts.key_password.as_deref();

    let (integrity, entries, warnings) = match format {
        StoreFormat::Jks | StoreFormat::Jceks => {
            let p = jks::parse(data, pw, kpw)?;
            (p.integrity, p.entries, p.warnings)
        }
        StoreFormat::Pkcs12 => load_pkcs12(data, pw)?,
        StoreFormat::Pem => load_pem(data)?,
        StoreFormat::Der => {
            let cert = CertInfo::from_der(data)?;
            (
                Integrity::NotApplicable,
                vec![cert_entry("cert", cert)],
                vec![],
            )
        }
        StoreFormat::Pkcs7 => {
            let certs = pkcs7_certs(data)?;
            let entries = certs
                .into_iter()
                .enumerate()
                .map(|(i, c)| cert_entry(&format!("cert{}", i + 1), c))
                .collect();
            (Integrity::NotApplicable, entries, vec![])
        }
    };

    let store_password = match integrity {
        Integrity::Verified => pw.map(Secret::new),
        _ => None,
    };
    Ok(Keystore {
        path,
        format,
        integrity,
        entries,
        warnings,
        store_password,
    })
}

fn cert_entry(alias: &str, cert: CertInfo) -> Entry {
    Entry {
        alias: alias.to_string(),
        kind: EntryKind::TrustedCert,
        created: None,
        chain: vec![cert],
        key: KeyState::None,
        note: None,
        protected: None,
        key_password: None,
    }
}

type Loaded = (Integrity, Vec<Entry>, Vec<String>);

fn load_pkcs12(data: &[u8], password: Option<&str>) -> Result<Loaded> {
    use p12_keystore::{KeyStore, KeyStoreEntry, Pkcs12ImportPolicy};
    let policy = Pkcs12ImportPolicy::Relaxed;
    let ks = match password {
        Some(pw) => KeyStore::from_pkcs12(data, pw, policy).map_err(|e| {
            Error::WrongPassword(format!(
                "無法開啟 PKCS#12（密碼錯誤或加密演算法不支援）：{e}"
            ))
        })?,
        None => KeyStore::from_pkcs12(data, "", policy)
            .map_err(|_| Error::NeedPassword("PKCS#12 檔案需要密碼".into()))?,
    };

    let mut entries = Vec::new();
    let mut warnings = Vec::new();
    for (alias, entry) in ks.entries() {
        match entry {
            KeyStoreEntry::PrivateKeyChain(chain) => {
                let mut certs = Vec::new();
                for c in chain.certs() {
                    match CertInfo::from_der(c.as_der()) {
                        Ok(ci) => certs.push(ci),
                        Err(e) => warnings.push(format!("「{alias}」中的憑證無法解析：{e}")),
                    }
                }
                entries.push(Entry {
                    alias: alias.clone(),
                    kind: EntryKind::PrivateKey,
                    created: None,
                    chain: certs,
                    key: KeyState::Decrypted {
                        format: KeyFormat::Pkcs8,
                        der: chain.key().as_der().to_vec(),
                    },
                    note: None,
                    protected: None,
                    key_password: None,
                });
            }
            KeyStoreEntry::Certificate(c) => match CertInfo::from_der(c.as_der()) {
                Ok(ci) => entries.push(cert_entry(alias, ci)),
                Err(e) => warnings.push(format!("「{alias}」憑證無法解析：{e}")),
            },
            KeyStoreEntry::Secret(s) => entries.push(Entry {
                alias: alias.clone(),
                kind: EntryKind::SecretKey,
                created: None,
                chain: vec![],
                key: KeyState::Locked("秘密金鑰內容不顯示".into()),
                note: Some(format!("{:?}，{} bytes", s.key_type(), s.key().len())),
                protected: None,
                key_password: None,
            }),
        }
    }
    Ok((Integrity::Verified, entries, warnings))
}

fn load_pem(data: &[u8]) -> Result<Loaded> {
    let blocks = pem::parse_all(data)?;
    let mut certs = Vec::new();
    let mut key: Option<KeyState> = None;
    let mut warnings = Vec::new();
    for b in blocks {
        match b.label.as_str() {
            "CERTIFICATE" | "TRUSTED CERTIFICATE" | "X509 CERTIFICATE" => {
                certs.push(CertInfo::from_der(&b.der)?)
            }
            "PKCS7" | "CMS" => certs.extend(pkcs7_certs(&b.der)?),
            "PRIVATE KEY" => {
                key = Some(KeyState::Decrypted {
                    format: KeyFormat::Pkcs8,
                    der: b.der,
                })
            }
            "RSA PRIVATE KEY" => {
                key = Some(KeyState::Decrypted {
                    format: KeyFormat::Pkcs1,
                    der: b.der,
                })
            }
            "EC PRIVATE KEY" => {
                key = Some(KeyState::Decrypted {
                    format: KeyFormat::Sec1,
                    der: b.der,
                })
            }
            "ENCRYPTED PRIVATE KEY" => {
                key = Some(KeyState::Locked(
                    "PEM 加密私鑰暫不支援，請先用 openssl 解密".into(),
                ))
            }
            "EC PARAMETERS" => {}
            other => warnings.push(format!("略過 PEM 區塊：{other}")),
        }
    }
    if certs.is_empty() && key.is_none() {
        return Err(Error::format("PEM 檔案中沒有憑證或私鑰"));
    }

    let entries = match key {
        Some(k) => {
            if certs.is_empty() {
                warnings.push("PEM 只有私鑰、沒有憑證".into());
            }
            vec![Entry {
                alias: "key".into(),
                kind: EntryKind::PrivateKey,
                created: None,
                chain: certs,
                key: k,
                note: Some("PEM 的憑證依檔案順序視為憑證鏈（終端憑證在前）".into()),
                protected: None,
                key_password: None,
            }]
        }
        None => certs
            .into_iter()
            .enumerate()
            .map(|(i, c)| cert_entry(&format!("cert{}", i + 1), c))
            .collect(),
    };
    Ok((Integrity::NotApplicable, entries, warnings))
}

/// 從 PKCS#7 SignedData 取出憑證。
pub fn pkcs7_certs(data: &[u8]) -> Result<Vec<CertInfo>> {
    let (ci, _) = der::expect(data, der::TAG_SEQUENCE)?;
    let (oid, rest) = der::expect(ci.content, der::TAG_OID)?;
    if der::oid_to_string(oid.content) != OID_PKCS7_SIGNED_DATA {
        return Err(Error::Unsupported("只支援 PKCS#7 SignedData".into()));
    }
    let (explicit, _) = der::expect(rest, 0xA0)?;
    let (sd, _) = der::expect(explicit.content, der::TAG_SEQUENCE)?;
    let mut certs = Vec::new();
    for child in der::children(sd.content)? {
        if child.tag == 0xA0 {
            for c in der::children(child.content)? {
                if c.tag == der::TAG_SEQUENCE {
                    certs.push(CertInfo::from_der(c.raw)?);
                }
            }
        }
    }
    Ok(certs)
}
