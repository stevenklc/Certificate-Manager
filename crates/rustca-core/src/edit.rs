//! 憑證庫管理：匯入、刪除、重新命名、更新憑證、修改密碼、儲存。
//!
//! 所有操作都在記憶體中的 [`Keystore`] 上進行，最後呼叫 [`save`] 寫回檔案。

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::cert::CertInfo;
use crate::chain::build_chain;
use crate::der;
use crate::error::{Error, Result};
use crate::jks::{self, KeyBlob, WriteEntry};
use crate::model::{
    Entry, EntryKind, Integrity, KeyFormat, KeyState, Keystore, Secret, StoreFormat,
};

/// 可寫入的格式。
pub const WRITABLE: &[StoreFormat] = &[StoreFormat::Jks, StoreFormat::Jceks, StoreFormat::Pkcs12];

pub fn is_writable(f: StoreFormat) -> bool {
    WRITABLE.contains(&f)
}

/// 建立空的憑證庫（尚未寫入檔案）。
pub fn new_keystore(
    path: impl Into<PathBuf>,
    format: StoreFormat,
    password: &str,
) -> Result<Keystore> {
    if !is_writable(format) {
        return Err(Error::Unsupported(format!("無法建立 {format} 憑證庫")));
    }
    Ok(Keystore {
        path: path.into(),
        format,
        integrity: Integrity::Verified,
        entries: vec![],
        warnings: vec![],
        store_password: Some(Secret::new(password)),
    })
}

fn find(ks: &Keystore, alias: &str) -> Option<usize> {
    ks.entries
        .iter()
        .position(|e| e.alias == alias)
        .or_else(|| {
            ks.entries
                .iter()
                .position(|e| e.alias.eq_ignore_ascii_case(alias))
        })
}

fn find_required(ks: &Keystore, alias: &str) -> Result<usize> {
    find(ks, alias).ok_or_else(|| Error::Other(format!("找不到別名「{alias}」")))
}

fn check_alias(alias: &str) -> Result<()> {
    if alias.trim().is_empty() {
        return Err(Error::Other("別名不可為空白".into()));
    }
    if alias.chars().any(|c| c.is_control()) {
        return Err(Error::Other("別名不可包含控制字元".into()));
    }
    Ok(())
}

/// 檢查別名是否可用；已存在時依 `overwrite` 決定移除舊條目或報錯。
fn claim_alias(ks: &mut Keystore, alias: &str, overwrite: bool) -> Result<Option<usize>> {
    check_alias(alias)?;
    match find(ks, alias) {
        Some(i) if overwrite => Ok(Some(i)),
        Some(_) => Err(Error::Other(format!("別名「{alias}」已存在"))),
        None => Ok(None),
    }
}

fn place(ks: &mut Keystore, slot: Option<usize>, entry: Entry) {
    match slot {
        Some(i) => ks.entries[i] = entry,
        None => ks.entries.push(entry),
    }
}

/// 匯入信任憑證。多張憑證時，別名依序為 alias、alias-2、alias-3…。回傳實際使用的別名。
pub fn import_certs(
    ks: &mut Keystore,
    alias: &str,
    certs: &[CertInfo],
    overwrite: bool,
) -> Result<Vec<String>> {
    if certs.is_empty() {
        return Err(Error::Other("沒有可匯入的憑證".into()));
    }
    let mut added = Vec::new();
    for (i, c) in certs.iter().enumerate() {
        let a = if i == 0 {
            alias.to_string()
        } else {
            format!("{alias}-{}", i + 1)
        };
        let slot = claim_alias(ks, &a, overwrite)?;
        place(
            ks,
            slot,
            Entry {
                alias: a.clone(),
                kind: EntryKind::TrustedCert,
                created: Some(crate::cert::now_ts()),
                chain: vec![c.clone()],
                key: KeyState::None,
                note: None,
                protected: None,
                key_password: None,
            },
        );
        added.push(a);
    }
    Ok(added)
}

/// 匯入金鑰對（私鑰 + 憑證鏈）。來源私鑰必須已解密。
pub fn import_key_entry(
    ks: &mut Keystore,
    alias: &str,
    src: &Entry,
    key_password: Option<&str>,
    overwrite: bool,
) -> Result<()> {
    if src.kind != EntryKind::PrivateKey {
        return Err(Error::Other(format!("來源「{}」不是私鑰條目", src.alias)));
    }
    let KeyState::Decrypted { .. } = &src.key else {
        return Err(Error::NeedPassword(format!(
            "來源「{}」的私鑰尚未解密",
            src.alias
        )));
    };
    if src.chain.is_empty() {
        return Err(Error::Other(
            "來源私鑰沒有對應的憑證，請改用「憑證 + 私鑰」方式匯入".into(),
        ));
    }
    let slot = claim_alias(ks, alias, overwrite)?;
    let mut e = src.clone();
    e.alias = alias.to_string();
    e.created = Some(crate::cert::now_ts());
    e.protected = None;
    e.note = None;
    e.key_password = key_password.map(Secret::new);
    place(ks, slot, e);
    Ok(())
}

/// 由「憑證檔 + 私鑰檔」組成私鑰條目（例如 server.crt + server.key）。
pub fn entry_from_cert_and_key(alias: &str, certs: &[CertInfo], key_src: &Entry) -> Result<Entry> {
    let KeyState::Decrypted { format, der } = &key_src.key else {
        return Err(Error::NeedPassword("私鑰尚未解密".into()));
    };
    let first = certs
        .first()
        .ok_or_else(|| Error::Other("沒有憑證".into()))?;
    // 找出與私鑰相符的終端憑證
    let leaf = certs
        .iter()
        .find(|c| crate::tls::key_matches_cert(*format, der, c) == Some(true))
        .unwrap_or(first);
    if crate::tls::key_matches_cert(*format, der, leaf) == Some(false) {
        return Err(Error::Other("私鑰與憑證的公鑰不相符".into()));
    }
    Ok(Entry {
        alias: alias.to_string(),
        kind: EntryKind::PrivateKey,
        created: Some(crate::cert::now_ts()),
        chain: order_chain(leaf, certs),
        key: key_src.key.clone(),
        note: None,
        protected: None,
        key_password: None,
    })
}

/// 刪除條目，回傳被刪除的條目。
pub fn delete_entry(ks: &mut Keystore, alias: &str) -> Result<Entry> {
    let i = find_required(ks, alias)?;
    Ok(ks.entries.remove(i))
}

/// 重新命名別名。
pub fn rename_entry(ks: &mut Keystore, old: &str, new: &str) -> Result<()> {
    check_alias(new)?;
    let i = find_required(ks, old)?;
    if let Some(j) = find(ks, new) {
        if j != i {
            return Err(Error::Other(format!("別名「{new}」已存在")));
        }
    }
    ks.entries[i].alias = new.to_string();
    Ok(())
}

/// 依簽發關係排序：leaf 在前，接著是它的簽發者…，其餘無法串接的憑證放最後。
fn order_chain(leaf: &CertInfo, certs: &[CertInfo]) -> Vec<CertInfo> {
    let pool: Vec<&CertInfo> = certs.iter().collect();
    let built = build_chain(std::slice::from_ref(leaf), &pool, crate::cert::now_ts(), 0);
    let mut out: Vec<CertInfo> = built.links.into_iter().map(|l| l.cert).collect();
    for c in certs {
        if !out.iter().any(|o| o.sha256 == c.sha256) {
            out.push(c.clone());
        }
    }
    out
}

/// 更新同一別名的憑證：
/// * 信任憑證條目：以新憑證取代（取第一張）
/// * 私鑰條目：以新的憑證鏈取代（例如續約或匯入 CA 回覆），會驗證終端憑證與私鑰相符，
///   並依簽發關係排序；若新鏈不完整，會用憑證庫內的其他憑證補齊。
///
/// 回傳說明訊息。
pub fn update_certs(ks: &mut Keystore, alias: &str, certs: &[CertInfo]) -> Result<Vec<String>> {
    let i = find_required(ks, alias)?;
    if certs.is_empty() {
        return Err(Error::Other("沒有憑證".into()));
    }
    let mut notes = Vec::new();
    match ks.entries[i].kind {
        EntryKind::TrustedCert => {
            if certs.len() > 1 {
                notes.push(format!("檔案含 {} 張憑證，只使用第一張", certs.len()));
            }
            ks.entries[i].chain = vec![certs[0].clone()];
        }
        EntryKind::SecretKey => return Err(Error::Unsupported("秘密金鑰條目沒有憑證".into())),
        EntryKind::PrivateKey => {
            let entry = &ks.entries[i];
            let old_spki = entry.chain.first().map(spki_of);
            // 找出與私鑰相符的終端憑證
            let leaf = match &entry.key {
                KeyState::Decrypted { format, der } => certs
                    .iter()
                    .find(|c| crate::tls::key_matches_cert(*format, der, c) == Some(true))
                    .ok_or_else(|| Error::Other("新憑證中沒有任何一張與此條目的私鑰相符".into()))?,
                _ => {
                    let old = old_spki.flatten().ok_or_else(|| {
                        Error::NeedPassword("私鑰尚未解密，且無既有憑證可比對公鑰".into())
                    })?;
                    certs
                        .iter()
                        .find(|c| spki_of(c).as_ref() == Some(&old))
                        .ok_or_else(|| {
                            Error::Other(
                                "新憑證的公鑰與原本的憑證不同（請先解密私鑰以驗證）".into(),
                            )
                        })?
                }
            };
            let mut pool: Vec<&CertInfo> = certs.iter().collect();
            let others = ks.all_certs();
            pool.extend(others.iter().copied());
            let built = build_chain(std::slice::from_ref(leaf), &pool, crate::cert::now_ts(), 0);
            let chain: Vec<CertInfo> = built.links.into_iter().map(|l| l.cert).collect();
            let from_store = chain
                .iter()
                .filter(|c| !certs.iter().any(|n| n.sha256 == c.sha256))
                .count();
            notes.push(format!(
                "新憑證鏈共 {} 張（終端憑證：{}）",
                chain.len(),
                leaf.display_name()
            ));
            if from_store > 0 {
                notes.push(format!("已用憑證庫中的 CA 補齊 {from_store} 張"));
            }
            ks.entries[i].chain = chain;
        }
    }
    Ok(notes)
}

fn spki_of(c: &CertInfo) -> Option<Vec<u8>> {
    use x509_parser::prelude::{FromDer, X509Certificate};
    let (_, x) = X509Certificate::from_der(&c.der).ok()?;
    Some(x.public_key().raw.to_vec())
}

/// 以指定密碼解開單一條目的私鑰（各條目私鑰密碼不同時使用）。
pub fn unlock_entry(ks: &mut Keystore, alias: &str, password: &str) -> Result<()> {
    let store_pw = ks.store_password.as_ref().map(|s| s.expose().to_string());
    let i = find_required(ks, alias)?;
    let e = &mut ks.entries[i];
    if matches!(e.key, KeyState::Decrypted { .. }) {
        return Ok(());
    }
    let blob = e
        .protected
        .as_ref()
        .ok_or_else(|| Error::Other(format!("「{alias}」沒有可解密的私鑰資料")))?;
    let der = crate::jks::decrypt_key(blob, password)
        .map_err(|_| Error::NeedPassword(format!("「{alias}」的私鑰密碼錯誤")))?;
    e.key = KeyState::Decrypted {
        format: KeyFormat::Pkcs8,
        der,
    };
    e.key_password = (store_pw.as_deref() != Some(password)).then(|| Secret::new(password));
    Ok(())
}

/// 檢查某條目的私鑰密碼（key pass）是否正確，不修改憑證庫。
///
/// JKS / JCEKS 以原始加密資料實際解密；沒有原始資料時（PKCS#12、已改過密碼或新匯入的私鑰）
/// 與目前生效的密碼比對。
pub fn check_key_password(ks: &Keystore, alias: &str, password: &str) -> Result<bool> {
    let e = ks
        .entry(alias)
        .ok_or_else(|| Error::Other(format!("找不到別名「{alias}」")))?;
    if e.kind != EntryKind::PrivateKey {
        return Err(Error::Other(format!(
            "「{alias}」不是私鑰條目，沒有私鑰密碼"
        )));
    }
    if let Some(blob) = &e.protected {
        return Ok(crate::jks::decrypt_key(blob, password).is_ok());
    }
    let current = if ks.format == StoreFormat::Pkcs12 {
        ks.store_password.as_ref()
    } else {
        e.key_password.as_ref().or(ks.store_password.as_ref())
    };
    match current {
        Some(c) if matches!(e.key, KeyState::Decrypted { .. }) => Ok(c.expose() == password),
        _ => Err(Error::NeedPassword(
            "憑證庫未以密碼開啟，無法比對私鑰密碼，請先解鎖".into(),
        )),
    }
}

/// 修改某條目的私鑰密碼（PKCS#12 的私鑰密碼固定等於憑證庫密碼）。
pub fn set_key_password(ks: &mut Keystore, alias: &str, new: &str) -> Result<()> {
    if ks.format == StoreFormat::Pkcs12 {
        return Err(Error::Unsupported(
            "PKCS#12 的私鑰密碼與憑證庫密碼相同，請改用「修改憑證庫密碼」".into(),
        ));
    }
    let i = find_required(ks, alias)?;
    let e = &mut ks.entries[i];
    if e.kind != EntryKind::PrivateKey {
        return Err(Error::Other(format!("「{alias}」不是私鑰條目")));
    }
    if !matches!(e.key, KeyState::Decrypted { .. }) {
        return Err(Error::NeedPassword(format!(
            "「{alias}」的私鑰尚未解密，請先用正確的私鑰密碼開啟"
        )));
    }
    e.key_password = Some(Secret::new(new));
    e.protected = None;
    Ok(())
}

/// 修改憑證庫密碼。
///
/// `also_keys` 為 true 時，私鑰密碼原本與憑證庫相同的條目一併改成新密碼（建議，與一般使用習慣一致）；
/// 為 false 時與 keytool -storepasswd 相同，只改憑證庫密碼，私鑰保留原密碼。
/// PKCS#12 只有一個密碼，一律同時修改。
pub fn set_store_password(ks: &mut Keystore, new: &str, also_keys: bool) -> Result<()> {
    let old = ks
        .store_password
        .clone()
        .ok_or_else(|| Error::NeedPassword("請先用目前的憑證庫密碼開啟".into()))?;
    let also_keys = also_keys || ks.format == StoreFormat::Pkcs12;
    for e in ks
        .entries
        .iter_mut()
        .filter(|e| e.kind == EntryKind::PrivateKey)
    {
        if e.key_password.is_some() && ks.format != StoreFormat::Pkcs12 {
            continue; // 私鑰原本就有自己的密碼，維持不變
        }
        if also_keys {
            if !matches!(e.key, KeyState::Decrypted { .. }) {
                return Err(Error::NeedPassword(format!(
                    "「{}」的私鑰尚未解密，無法一併修改私鑰密碼",
                    e.alias
                )));
            }
            e.key_password = None;
            e.protected = None;
        } else {
            e.key_password = Some(old.clone());
        }
    }
    ks.store_password = Some(Secret::new(new));
    Ok(())
}

/// 把各種格式的私鑰轉成 PKCS#8。
pub fn to_pkcs8(format: KeyFormat, key: &[u8]) -> Result<Vec<u8>> {
    match format {
        KeyFormat::Pkcs8 => Ok(key.to_vec()),
        KeyFormat::Pkcs1 => {
            // PrivateKeyInfo { version 0, rsaEncryption NULL, OCTET STRING(RSAPrivateKey) }
            let mut alg = der::encode(der::TAG_OID, &der::oid_from_string("1.2.840.113549.1.1.1"));
            alg.extend(der::encode(der::TAG_NULL, &[]));
            let mut body = der::encode(der::TAG_INTEGER, &[0]);
            body.extend(der::encode(der::TAG_SEQUENCE, &alg));
            body.extend(der::encode(der::TAG_OCTET_STRING, key));
            Ok(der::encode(der::TAG_SEQUENCE, &body))
        }
        KeyFormat::Sec1 => {
            // 曲線參數取自 ECPrivateKey 的 [0]
            let (ec, _) = der::expect(key, der::TAG_SEQUENCE)?;
            let curve = der::children(ec.content)?
                .into_iter()
                .find(|t| t.tag == 0xA0)
                .ok_or_else(|| Error::Unsupported("SEC1 私鑰缺少曲線參數".into()))?;
            let mut alg = der::encode(der::TAG_OID, &der::oid_from_string("1.2.840.10045.2.1"));
            alg.extend_from_slice(curve.content);
            let mut body = der::encode(der::TAG_INTEGER, &[0]);
            body.extend(der::encode(der::TAG_SEQUENCE, &alg));
            body.extend(der::encode(der::TAG_OCTET_STRING, key));
            Ok(der::encode(der::TAG_SEQUENCE, &body))
        }
    }
}

/// 序列化結果。
pub struct Serialized {
    pub data: Vec<u8>,
    pub warnings: Vec<String>,
}

impl std::fmt::Debug for Serialized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Serialized({} bytes, {:?})",
            self.data.len(),
            self.warnings
        )
    }
}

/// 寫入選項。
#[derive(Debug, Clone, Copy, Default)]
pub struct WriteOptions {
    /// PKCS#12 使用舊式演算法（PBE-SHA1-3DES + HmacSHA1），
    /// 相容 Java 8u301 / 11.0.12 以前的版本；預設為 PBES2-AES256 + HmacSHA256。
    pub pkcs12_legacy: bool,
}

/// 將憑證庫序列化為指定格式。
pub fn serialize(ks: &Keystore, format: StoreFormat) -> Result<Serialized> {
    serialize_with(ks, format, WriteOptions::default())
}

/// 將憑證庫序列化為指定格式（可指定寫入選項）。
pub fn serialize_with(
    ks: &Keystore,
    format: StoreFormat,
    opts: WriteOptions,
) -> Result<Serialized> {
    if !is_writable(format) {
        return Err(Error::Unsupported(format!(
            "無法寫入 {format} 格式（可寫入：JKS、JCEKS、PKCS#12）"
        )));
    }
    let store_pw = ks
        .store_password
        .as_ref()
        .ok_or_else(|| Error::NeedPassword("儲存前需要憑證庫密碼".into()))?
        .expose()
        .to_string();
    if let Some(e) = ks.entries.iter().find(|e| e.kind == EntryKind::SecretKey) {
        return Err(Error::Unsupported(format!(
            "憑證庫含秘密金鑰條目「{}」，本工具無法保留其內容，為避免資料遺失不允許儲存",
            e.alias
        )));
    }
    let mut warnings = Vec::new();

    // JKS / JCEKS 別名不分大小寫（Java 會轉小寫）
    let mut aliases: Vec<String> = ks.entries.iter().map(|e| e.alias.clone()).collect();
    if matches!(format, StoreFormat::Jks | StoreFormat::Jceks) {
        for a in aliases.iter_mut() {
            let lower = a.to_lowercase();
            if *a != lower {
                warnings.push(format!(
                    "別名「{a}」轉為小寫「{lower}」（JKS / JCEKS 不分大小寫）"
                ));
                *a = lower;
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    for a in &aliases {
        if !seen.insert(a.to_lowercase()) {
            return Err(Error::Other(format!("別名「{a}」重複（不分大小寫）")));
        }
    }

    let data = match format {
        StoreFormat::Jks | StoreFormat::Jceks => {
            // 先把需要的 PKCS#8 / 密碼準備好，讓 WriteEntry 可以借用
            let mut pkcs8s: Vec<Option<Vec<u8>>> = Vec::new();
            let mut kpws: Vec<String> = Vec::new();
            for e in &ks.entries {
                pkcs8s.push(match &e.key {
                    KeyState::Decrypted { format, der } => Some(to_pkcs8(*format, der)?),
                    _ => None,
                });
                kpws.push(
                    e.key_password
                        .as_ref()
                        .map(|s| s.expose().to_string())
                        .unwrap_or_else(|| store_pw.clone()),
                );
            }
            let mut wes = Vec::new();
            for (i, e) in ks.entries.iter().enumerate() {
                match e.kind {
                    EntryKind::TrustedCert => {
                        let cert = e
                            .chain
                            .first()
                            .ok_or_else(|| Error::Other(format!("「{}」沒有憑證", e.alias)))?;
                        wes.push(WriteEntry::TrustedCert {
                            alias: &aliases[i],
                            created: e.created,
                            cert: &cert.der,
                        });
                    }
                    EntryKind::PrivateKey => {
                        if e.chain.is_empty() {
                            return Err(Error::Other(format!(
                                "「{}」沒有憑證，JKS 無法儲存只有私鑰的條目",
                                e.alias
                            )));
                        }
                        let key = match (&pkcs8s[i], &e.protected) {
                            (Some(p), _) => KeyBlob::Plain {
                                pkcs8: p,
                                password: &kpws[i],
                            },
                            (None, Some(b)) => KeyBlob::Protected(b),
                            (None, None) => {
                                return Err(Error::NeedPassword(format!(
                                    "「{}」的私鑰尚未解密",
                                    e.alias
                                )))
                            }
                        };
                        wes.push(WriteEntry::PrivateKey {
                            alias: &aliases[i],
                            created: e.created,
                            key,
                            chain: e.chain.iter().map(|c| c.der.as_slice()).collect(),
                        });
                    }
                    EntryKind::SecretKey => unreachable!(),
                }
            }
            jks::encode_store(format, &wes, &store_pw)?
        }
        StoreFormat::Pkcs12 => {
            use p12_keystore::{Certificate, KeyStore, KeyStoreEntry, PrivateKey, PrivateKeyChain};
            let mut p12 = KeyStore::new();
            for (i, e) in ks.entries.iter().enumerate() {
                let err = |m: String| Error::Other(format!("「{}」{m}", e.alias));
                match e.kind {
                    EntryKind::TrustedCert => {
                        let c = e.chain.first().ok_or_else(|| err("沒有憑證".into()))?;
                        let cert = Certificate::from_der(&c.der).map_err(|x| err(x.to_string()))?;
                        p12.add_entry(&aliases[i], KeyStoreEntry::Certificate(cert));
                    }
                    EntryKind::PrivateKey => {
                        let KeyState::Decrypted { format, der } = &e.key else {
                            return Err(Error::NeedPassword(format!(
                                "「{}」的私鑰尚未解密，無法轉存為 PKCS#12",
                                e.alias
                            )));
                        };
                        if e.key_password
                            .as_ref()
                            .is_some_and(|k| k.expose() != store_pw)
                        {
                            warnings.push(format!(
                                "「{}」的私鑰密碼改為與憑證庫密碼相同（PKCS#12 只有一個密碼）",
                                e.alias
                            ));
                        }
                        let key = PrivateKey::from_der(&to_pkcs8(*format, der)?)
                            .map_err(|x| err(x.to_string()))?;
                        let certs = e
                            .chain
                            .iter()
                            .map(|c| Certificate::from_der(&c.der))
                            .collect::<std::result::Result<Vec<_>, _>>()
                            .map_err(|x| err(x.to_string()))?;
                        let local_id = e
                            .chain
                            .first()
                            .map(|c| {
                                use sha1::Digest;
                                sha1::Sha1::digest(&c.der).to_vec()
                            })
                            .unwrap_or_else(|| aliases[i].as_bytes().to_vec());
                        p12.add_entry(
                            &aliases[i],
                            KeyStoreEntry::PrivateKeyChain(PrivateKeyChain::new(
                                local_id, key, certs,
                            )),
                        );
                    }
                    EntryKind::SecretKey => unreachable!(),
                }
            }
            let w = p12.writer(&store_pw);
            let w = if opts.pkcs12_legacy {
                w.encryption_algorithm(
                    p12_keystore::EncryptionAlgorithm::PbeWithShaAnd3KeyTripleDesCbc,
                )
                .mac_algorithm(p12_keystore::MacAlgorithm::HmacSha1)
            } else {
                w
            };
            w.write()
                .map_err(|e| Error::Other(format!("寫入 PKCS#12 失敗：{e}")))?
        }
        _ => unreachable!(),
    };
    Ok(Serialized { data, warnings })
}

/// 儲存結果。
#[derive(Debug)]
pub struct SaveReport {
    pub path: PathBuf,
    pub backup: Option<PathBuf>,
    pub warnings: Vec<String>,
}

/// 寫回檔案。
/// * `path`：None 表示寫回原檔
/// * `format`：None 表示維持原格式（原格式不可寫入時會報錯）
/// * `backup`：覆寫既有檔案前，先複製一份 `檔名.YYYYMMDD-HHMMSS.bak`
pub fn save(
    ks: &mut Keystore,
    path: Option<&Path>,
    format: Option<StoreFormat>,
    backup: bool,
) -> Result<SaveReport> {
    save_with(ks, path, format, backup, WriteOptions::default())
}

/// 同 [`save`]，可指定寫入選項。
pub fn save_with(
    ks: &mut Keystore,
    path: Option<&Path>,
    format: Option<StoreFormat>,
    backup: bool,
    opts: WriteOptions,
) -> Result<SaveReport> {
    let format = format.unwrap_or(ks.format);
    let target = path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| ks.path.clone());
    let ser = serialize_with(ks, format, opts)?;

    let mut backup_path = None;
    if backup && target.exists() {
        let stamp = time::OffsetDateTime::now_utc()
            .format(time::macros::format_description!(
                "[year][month][day]-[hour][minute][second]"
            ))
            .unwrap_or_default();
        // 同一秒內多次儲存時加流水號，避免覆蓋較早的備份
        let base = target.file_name().unwrap_or_default().to_os_string();
        let bp = (1..)
            .map(|i: u32| {
                let mut name = base.clone();
                if i == 1 {
                    name.push(format!(".{stamp}.bak"));
                } else {
                    name.push(format!(".{stamp}-{i}.bak"));
                }
                target.with_file_name(name)
            })
            .find(|p| !p.exists())
            .expect("備份檔名");
        std::fs::copy(&target, &bp).map_err(|e| Error::Other(format!("備份失敗：{e}")))?;
        backup_path = Some(bp);
    }

    // 先寫暫存檔再改名，避免寫到一半造成原檔損毀
    let mut tmp_name = target.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".tmp");
    let tmp = target.with_file_name(tmp_name);
    std::fs::write(&tmp, &ser.data).map_err(|e| Error::Other(format!("寫入失敗：{e}")))?;
    if let Err(e) = std::fs::rename(&tmp, &target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(Error::Other(format!("寫入失敗：{e}")));
    }

    ks.path = target.clone();
    ks.format = format;
    ks.integrity = Integrity::Verified;
    // 儲存後私鑰已以新密碼加密；JKS 別名轉小寫
    if matches!(format, StoreFormat::Jks | StoreFormat::Jceks) {
        for e in ks.entries.iter_mut() {
            e.alias = e.alias.to_lowercase();
        }
    }
    Ok(SaveReport {
        path: target,
        backup: backup_path,
        warnings: ser.warnings,
    })
}

/// 匯出憑證（PEM 或 DER；DER 只能一張）。
pub fn export_certs(certs: &[&CertInfo], pem: bool) -> Result<Vec<u8>> {
    if pem {
        Ok(certs
            .iter()
            .map(|c| c.to_pem())
            .collect::<String>()
            .into_bytes())
    } else {
        match certs {
            [one] => Ok(one.der.clone()),
            _ => Err(Error::Other(
                "DER 格式一次只能匯出一張憑證，請改用 PEM".into(),
            )),
        }
    }
}

// ───────────── 憑證格式轉換 ─────────────

/// 憑證輸出格式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum CertFormat {
    /// PEM（Base64，可多張）
    Pem,
    /// DER / .cer（二進位，僅一張）
    Der,
    /// PKCS#7 / .p7b（二進位，可多張，常用於憑證鏈）
    P7b,
    /// PKCS#7 PEM（-----BEGIN PKCS7-----）
    P7bPem,
}

impl CertFormat {
    pub const ALL: [CertFormat; 4] = [
        CertFormat::Pem,
        CertFormat::Der,
        CertFormat::P7b,
        CertFormat::P7bPem,
    ];

    pub fn label(self) -> &'static str {
        match self {
            CertFormat::Pem => "PEM（.pem / .crt）",
            CertFormat::Der => "DER（.cer / .der，單張）",
            CertFormat::P7b => "PKCS#7（.p7b）",
            CertFormat::P7bPem => "PKCS#7 PEM（.p7b 文字）",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            CertFormat::Pem => "pem",
            CertFormat::Der => "cer",
            CertFormat::P7b | CertFormat::P7bPem => "p7b",
        }
    }

    pub fn parse(s: &str) -> Option<CertFormat> {
        Some(match s.to_ascii_lowercase().as_str() {
            "pem" | "crt" => CertFormat::Pem,
            "der" | "cer" => CertFormat::Der,
            "p7b" | "p7c" | "pkcs7" => CertFormat::P7b,
            "p7b-pem" | "pkcs7-pem" | "p7bpem" => CertFormat::P7bPem,
            _ => return None,
        })
    }

    /// 依副檔名推測（.cer 視為 DER）。
    pub fn from_path(p: &Path) -> Option<CertFormat> {
        CertFormat::parse(p.extension()?.to_str()?)
    }
}

/// PKCS#7 SignedData（degenerate，只含憑證）。
pub fn encode_pkcs7(certs: &[&CertInfo]) -> Vec<u8> {
    let oid = |s: &str| der::encode(der::TAG_OID, &der::oid_from_string(s));
    let cert_set: Vec<u8> = certs.iter().flat_map(|c| c.der.clone()).collect();
    let mut sd = der::encode(der::TAG_INTEGER, &[1]);
    sd.extend(der::encode(der::TAG_SET, &[]));
    sd.extend(der::encode(der::TAG_SEQUENCE, &oid("1.2.840.113549.1.7.1")));
    sd.extend(der::encode(0xa0, &cert_set)); // [0] IMPLICIT certificates
    sd.extend(der::encode(der::TAG_SET, &[])); // signerInfos
    let mut ci = oid("1.2.840.113549.1.7.2");
    ci.extend(der::encode(0xa0, &der::encode(der::TAG_SEQUENCE, &sd)));
    der::encode(der::TAG_SEQUENCE, &ci)
}

/// 將憑證編碼成指定格式。
pub fn encode_certs(certs: &[&CertInfo], format: CertFormat) -> Result<Vec<u8>> {
    if certs.is_empty() {
        return Err(Error::Other("沒有憑證".into()));
    }
    Ok(match format {
        CertFormat::Pem => export_certs(certs, true)?,
        CertFormat::Der => export_certs(certs, false)?,
        CertFormat::P7b => encode_pkcs7(certs),
        CertFormat::P7bPem => crate::pem::encode("PKCS7", &encode_pkcs7(certs)).into_bytes(),
    })
}

/// 私鑰轉成未加密的 PKCS#8 PEM（-----BEGIN PRIVATE KEY-----）。
pub fn private_key_pem(e: &Entry) -> Result<String> {
    match &e.key {
        KeyState::Decrypted { format, der } => {
            Ok(crate::pem::encode("PRIVATE KEY", &to_pkcs8(*format, der)?))
        }
        KeyState::Locked(_) => Err(Error::NeedPassword(format!(
            "「{}」的私鑰尚未解密",
            e.alias
        ))),
        KeyState::None => Err(Error::Other(format!("「{}」沒有私鑰", e.alias))),
    }
}

// ───────────── 新增製作好的憑證 ─────────────

/// 加入由 [`crate::forge`] 製作的私鑰條目（鏈：終端憑證在前）。
pub fn add_key_entry(
    ks: &mut Keystore,
    alias: &str,
    chain: Vec<CertInfo>,
    key_pkcs8: Vec<u8>,
    key_password: Option<&str>,
    overwrite: bool,
) -> Result<()> {
    let src = Entry {
        alias: alias.to_string(),
        kind: EntryKind::PrivateKey,
        created: Some(crate::cert::now_ts()),
        chain,
        key: KeyState::Decrypted {
            format: KeyFormat::Pkcs8,
            der: key_pkcs8,
        },
        note: None,
        protected: None,
        key_password: None,
    };
    import_key_entry(ks, alias, &src, key_password, overwrite)
}

// ───────────── 憑證鏈驗證 ─────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum CheckLevel {
    Ok,
    Warn,
    Error,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Check {
    pub level: CheckLevel,
    pub message: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Verification {
    pub alias: String,
    /// 沒有 Error 等級的項目
    pub ok: bool,
    pub checks: Vec<Check>,
}

impl Verification {
    fn push(&mut self, level: CheckLevel, msg: impl Into<String>) {
        if level == CheckLevel::Error {
            self.ok = false;
        }
        self.checks.push(Check {
            level,
            message: msg.into(),
        });
    }

    pub fn errors(&self) -> Vec<&str> {
        self.checks
            .iter()
            .filter(|c| c.level == CheckLevel::Error)
            .map(|c| c.message.as_str())
            .collect()
    }
}

fn signed_by(child: &CertInfo, issuer: &CertInfo) -> bool {
    use x509_parser::prelude::{FromDer, X509Certificate};
    let (Ok((_, c)), Ok((_, i))) = (
        X509Certificate::from_der(&child.der),
        X509Certificate::from_der(&issuer.der),
    ) else {
        return false;
    };
    c.verify_signature(Some(i.public_key())).is_ok()
}

/// 驗證條目的憑證鏈：私鑰相符、順序與簽章、CA 屬性、有效期限、是否能連到根憑證。
pub fn verify_entry(ks: &Keystore, alias: &str, now: i64) -> Result<Verification> {
    let e = ks
        .entry(alias)
        .ok_or_else(|| Error::Other(format!("找不到別名「{alias}」")))?;
    let mut v = Verification {
        alias: e.alias.clone(),
        ok: true,
        checks: vec![],
    };
    let Some(leaf) = e.chain.first() else {
        v.push(CheckLevel::Error, "條目沒有憑證");
        return Ok(v);
    };
    use CheckLevel::{Error as Bad, Ok as Good, Warn};

    // 私鑰
    if e.kind == EntryKind::PrivateKey {
        match &e.key {
            KeyState::Decrypted { format, der } => {
                match crate::tls::key_matches_cert(*format, der, leaf) {
                    Some(true) => v.push(Good, "私鑰與終端憑證的公鑰相符"),
                    Some(false) => v.push(Bad, "私鑰與終端憑證的公鑰不相符"),
                    None => v.push(Warn, "無法比對私鑰（不支援的金鑰型別）"),
                }
            }
            KeyState::Locked(_) => v.push(Warn, "私鑰尚未解密，略過私鑰比對"),
            KeyState::None => {}
        }
    }

    // 鏈的順序與簽章
    for (i, w) in e.chain.windows(2).enumerate() {
        let (child, parent) = (&w[0], &w[1]);
        if child.raw_issuer != parent.raw_subject {
            v.push(
                Bad,
                format!(
                    "第 {i} 張「{}」的簽發者不是第 {} 張「{}」（順序錯誤或混入無關憑證）",
                    child.display_name(),
                    i + 1,
                    parent.display_name()
                ),
            );
        } else if !signed_by(child, parent) {
            v.push(
                Bad,
                format!(
                    "第 {i} 張「{}」的簽章無法用「{}」的公鑰驗證",
                    child.display_name(),
                    parent.display_name()
                ),
            );
        } else {
            v.push(
                Good,
                format!(
                    "[{i}] {} ← 由 [{}] {} 簽發，簽章正確",
                    child.display_name(),
                    i + 1,
                    parent.display_name()
                ),
            );
        }
        if !parent.is_ca {
            v.push(
                Bad,
                format!(
                    "「{}」不是 CA（BasicConstraints CA=false），不能簽發憑證",
                    parent.display_name()
                ),
            );
        }
    }

    // 有效期限
    for c in &e.chain {
        match c.status_at(now, 30) {
            crate::ValidityStatus::Expired { days_ago } => {
                v.push(Bad, format!("「{}」已過期 {days_ago} 天", c.display_name()))
            }
            crate::ValidityStatus::NotYetValid { days_until } => v.push(
                Bad,
                format!("「{}」尚未生效（{days_until} 天後）", c.display_name()),
            ),
            crate::ValidityStatus::ExpiringSoon { days_left } => v.push(
                Warn,
                format!("「{}」即將到期（剩 {days_left} 天）", c.display_name()),
            ),
            _ => {}
        }
    }

    // 是否連到根
    let last = e.chain.last().unwrap();
    if last.self_signed {
        v.push(
            Good,
            format!("憑證鏈結束於自簽根憑證「{}」", last.display_name()),
        );
    } else {
        let anchor = ks.entries.iter().find(|o| {
            o.alias != e.alias
                && o.chain
                    .first()
                    .is_some_and(|c| c.raw_subject == last.raw_issuer && signed_by(last, c))
        });
        match anchor {
            Some(a) => v.push(
                Good,
                format!(
                    "鏈未含根憑證，但可由憑證庫中的「{}」驗證（{}）",
                    a.alias,
                    a.chain[0].display_name()
                ),
            ),
            None => v.push(
                Warn,
                format!(
                    "鏈未結束於根憑證，憑證庫中也找不到簽發者「{}」；對方信任庫需有此 CA",
                    last.issuer
                ),
            ),
        }
    }
    if e.kind == EntryKind::PrivateKey && leaf.is_ca && e.chain.len() == 1 && leaf.self_signed {
        v.push(Warn, "此私鑰條目是自簽 CA 憑證");
    }
    Ok(v)
}

/// 以新的憑證鏈替換條目，替換後驗證；驗證有錯誤時不套用並回傳錯誤。
pub fn replace_chain(
    ks: &mut Keystore,
    alias: &str,
    certs: &[CertInfo],
) -> Result<(Vec<String>, Verification)> {
    let mut work = ks.clone();
    let notes = update_certs(&mut work, alias, certs)?;
    let v = verify_entry(&work, alias, crate::cert::now_ts())?;
    if !v.ok {
        return Err(Error::Other(format!(
            "替換後的憑證鏈驗證失敗，未套用：{}",
            v.errors().join("；")
        )));
    }
    *ks = work;
    Ok((notes, v))
}

// ───────────── 由多個憑證 / 私鑰檔組成憑證庫 ─────────────

/// 組裝計畫中的私鑰條目。
#[derive(Debug, Clone)]
pub struct PlannedKey {
    pub include: bool,
    pub alias: String,
    /// 終端憑證在前，已依簽發關係排序
    pub chain: Vec<CertInfo>,
    /// 私鑰來源（含已解密的私鑰）
    pub key: Entry,
    /// 「私鑰檔 + 憑證檔」
    pub source: String,
    /// 憑證鏈是否完整連到自簽根憑證
    pub complete: bool,
}

/// 組裝計畫中的信任憑證條目。
#[derive(Debug, Clone)]
pub struct PlannedCert {
    pub include: bool,
    pub alias: String,
    pub cert: CertInfo,
    pub source: String,
}

/// [`plan_assembly`] 的結果，可在套用前調整別名與勾選。
#[derive(Debug, Clone, Default)]
pub struct AssemblyPlan {
    pub keys: Vec<PlannedKey>,
    pub certs: Vec<PlannedCert>,
    /// 無法處理的項目（找不到相符憑證、私鑰未解密…）
    pub problems: Vec<String>,
}

/// 依 CN 產生別名：小寫、空白與特殊字元改成「-」，並避開已使用的名稱。
pub fn suggest_alias(cert: &CertInfo, used: &mut HashSet<String>) -> String {
    let base: String = cert
        .display_name()
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let base = base.trim_matches('-').to_string();
    let base = if base.is_empty() { "cert".into() } else { base };
    let mut alias = base.clone();
    let mut n = 2;
    while !used.insert(alias.clone()) {
        alias = format!("{base}-{n}");
        n += 1;
    }
    alias
}

/// 從多個已載入的檔案（.cer / .crt / .pem / .key / .p7b / .p12 / .jks…）規劃憑證庫內容：
/// * 每把私鑰以公鑰找出相符的憑證，並用所有檔案中的 CA 憑證補齊憑證鏈 → 私鑰條目
/// * 其餘憑證（CA、沒有私鑰的憑證）→ 信任憑證條目；用在鏈中的 CA 也會保留為信任憑證
/// * 重複的憑證 / 私鑰只取一次
pub fn plan_assembly(sources: &[Keystore]) -> AssemblyPlan {
    let mut plan = AssemblyPlan::default();
    let mut used = HashSet::new();

    // 所有憑證（去重），記錄來源檔名
    let mut certs: Vec<(CertInfo, String)> = Vec::new();
    for ks in sources {
        for c in ks.all_certs() {
            if !certs.iter().any(|(x, _)| x.sha256 == c.sha256) {
                certs.push((c.clone(), ks.name()));
            }
        }
    }
    let pool: Vec<&CertInfo> = certs.iter().map(|(c, _)| c).collect();

    // 私鑰
    let mut leaf_shas = HashSet::new();
    let mut seen_keys: Vec<Vec<u8>> = Vec::new();
    for ks in sources {
        for e in ks
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::PrivateKey)
        {
            let KeyState::Decrypted { format, der } = &e.key else {
                plan.problems.push(format!(
                    "{} / {}：私鑰尚未解密（請先輸入密碼開啟）",
                    ks.name(),
                    e.alias
                ));
                continue;
            };
            if seen_keys.contains(der) {
                continue;
            }
            seen_keys.push(der.clone());
            // 條目本身有憑證（.p12 / .jks）就用它，否則從所有憑證中找公鑰相符的
            let leaf = e.chain.first().cloned().or_else(|| {
                pool.iter()
                    .find(|c| crate::tls::key_matches_cert(*format, der, c) == Some(true))
                    .map(|c| (*c).clone())
            });
            let Some(leaf) = leaf else {
                plan.problems.push(format!(
                    "{}：找不到與這把私鑰相符的憑證，請一併選取它的 .cer / .crt",
                    ks.name()
                ));
                continue;
            };
            let built = build_chain(std::slice::from_ref(&leaf), &pool, crate::cert::now_ts(), 0);
            let complete = matches!(built.end, crate::chain::ChainEnd::Root);
            let chain: Vec<CertInfo> = built.links.into_iter().map(|l| l.cert).collect();
            leaf_shas.insert(leaf.sha256.clone());
            let cert_src = certs
                .iter()
                .find(|(c, _)| c.sha256 == leaf.sha256)
                .map(|(_, s)| s.clone())
                .unwrap_or_else(|| ks.name());
            let source = if cert_src == ks.name() {
                ks.name()
            } else {
                format!("{} + {cert_src}", ks.name())
            };
            plan.keys.push(PlannedKey {
                include: true,
                alias: suggest_alias(&leaf, &mut used),
                chain,
                key: e.clone(),
                source,
                complete,
            });
        }
    }

    // 其餘憑證 → 信任憑證
    for (c, src) in &certs {
        if leaf_shas.contains(&c.sha256) {
            continue;
        }
        plan.certs.push(PlannedCert {
            include: true,
            alias: suggest_alias(c, &mut used),
            cert: c.clone(),
            source: src.clone(),
        });
    }
    plan
}

/// 把組裝計畫中勾選的項目加入憑證庫；回傳加入的條目數。
pub fn apply_assembly(ks: &mut Keystore, plan: &AssemblyPlan, overwrite: bool) -> Result<usize> {
    let mut n = 0;
    for k in plan.keys.iter().filter(|k| k.include) {
        let mut src = k.key.clone();
        src.chain = k.chain.clone();
        import_key_entry(ks, k.alias.trim(), &src, None, overwrite)?;
        n += 1;
    }
    for c in plan.certs.iter().filter(|c| c.include) {
        import_certs(ks, c.alias.trim(), std::slice::from_ref(&c.cert), overwrite)?;
        n += 1;
    }
    Ok(n)
}
