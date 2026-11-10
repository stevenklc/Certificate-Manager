//! Java KeyStore（JKS）與 JCEKS 格式解析。
//!
//! 檔案結構：
//! ```text
//! magic(u32) version(u32) count(u32)
//! entry*: tag(u32) alias(UTF) timestamp(u64) ...
//!   tag 1 私鑰：key_len(u32) EncryptedPrivateKeyInfo chain_count(u32) cert*
//!   tag 2 信任憑證：cert
//!   tag 3 秘密金鑰（僅 JCEKS，Java 序列化物件）
//!   cert：[type(UTF), v2 才有] len(u32) DER
//! SHA1(password(UTF-16BE) || "Mighty Aphrodite" || 以上全部資料)
//! ```

use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use md5::Md5;
use sha1::{Digest, Sha1};

use crate::cert::CertInfo;
use crate::der;
use crate::error::{Error, Result};
use crate::model::{Entry, EntryKind, Integrity, KeyFormat, KeyState, Secret, StoreFormat};

pub const JKS_MAGIC: u32 = 0xFEED_FEED;
pub const JCEKS_MAGIC: u32 = 0xCECE_CECE;
const WHITENER: &[u8] = b"Mighty Aphrodite";
const OID_JKS_KEY_PROTECTOR: &str = "1.3.6.1.4.1.42.2.17.1.1";
const OID_PBE_MD5_3DES: &str = "1.3.6.1.4.1.42.2.19.1";

pub struct Parsed {
    pub format: StoreFormat,
    pub integrity: Integrity,
    pub entries: Vec<Entry>,
    pub warnings: Vec<String>,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.data.len())
            .ok_or_else(|| Error::format("JKS 資料不完整（提前結束）"))?;
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn utf(&mut self) -> Result<String> {
        let len = self.u16()? as usize;
        Ok(decode_modified_utf8(self.take(len)?))
    }
}

/// Java DataInput.readUTF 使用 modified UTF-8；對一般字元與 UTF-8 相同。
fn decode_modified_utf8(b: &[u8]) -> String {
    // 0xC0 0x80 代表 NUL
    let fixed: Vec<u8> = {
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == 0xC0 && i + 1 < b.len() && b[i + 1] == 0x80 {
                out.push(0);
                i += 2;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        out
    };
    match String::from_utf8(fixed) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    }
}

fn password_utf16be(password: &str) -> Vec<u8> {
    password
        .encode_utf16()
        .flat_map(|c| c.to_be_bytes())
        .collect()
}

pub fn store_digest(password: &str, data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(password_utf16be(password));
    h.update(WHITENER);
    h.update(data);
    h.finalize().into()
}

pub fn is_jks_or_jceks(data: &[u8]) -> Option<StoreFormat> {
    if data.len() < 4 {
        return None;
    }
    match u32::from_be_bytes(data[..4].try_into().unwrap()) {
        JKS_MAGIC => Some(StoreFormat::Jks),
        JCEKS_MAGIC => Some(StoreFormat::Jceks),
        _ => None,
    }
}

/// 解析 JKS / JCEKS。
///
/// * `password`：憑證庫密碼，None 時略過完整性檢查。
/// * `key_password`：私鑰密碼，None 時使用 `password`。
pub fn parse(data: &[u8], password: Option<&str>, key_password: Option<&str>) -> Result<Parsed> {
    let format = is_jks_or_jceks(data).ok_or_else(|| Error::format("不是 JKS / JCEKS 檔案"))?;
    if data.len() < 12 + 20 {
        return Err(Error::format("JKS 檔案過短"));
    }

    // 完整性檢查（最後 20 bytes）
    let (body, digest) = data.split_at(data.len() - 20);
    let integrity = match password {
        Some(pw) => {
            if store_digest(pw, body) != digest {
                return Err(Error::WrongPassword(
                    "憑證庫完整性檢查失敗（密碼錯誤或檔案損毀）".into(),
                ));
            }
            Integrity::Verified
        }
        None => Integrity::NotChecked,
    };

    let mut r = Reader { data: body, pos: 4 };
    let version = r.u32()?;
    if version != 1 && version != 2 {
        return Err(Error::format(format!("不支援的 JKS 版本：{version}")));
    }
    let count = r.u32()?;
    let key_pw = key_password.or(password);

    let mut entries = Vec::new();
    let mut warnings = Vec::new();

    for _ in 0..count {
        let tag = r.u32()?;
        let alias = r.utf()?;
        let ts = r.u64()? as i64;
        let created = Some(ts / 1000);
        match tag {
            1 => {
                let len = r.u32()? as usize;
                let enc = r.take(len)?;
                let n = r.u32()?;
                let mut chain = Vec::new();
                for _ in 0..n {
                    chain.push(read_cert(&mut r, version)?);
                }
                let key = match key_pw {
                    None => KeyState::Locked("未提供密碼".into()),
                    Some(pw) => match decrypt_key(enc, pw) {
                        Ok(der) => KeyState::Decrypted {
                            format: KeyFormat::Pkcs8,
                            der,
                        },
                        Err(e) => KeyState::Locked(e.to_string()),
                    },
                };
                let key_password = match (&key, key_password) {
                    (KeyState::Decrypted { .. }, Some(k)) if Some(k) != password => {
                        Some(Secret::new(k))
                    }
                    _ => None,
                };
                entries.push(Entry {
                    alias,
                    kind: EntryKind::PrivateKey,
                    created,
                    chain,
                    key,
                    note: None,
                    protected: Some(enc.to_vec()),
                    key_password,
                });
            }
            2 => {
                let cert = read_cert(&mut r, version)?;
                entries.push(Entry {
                    alias,
                    kind: EntryKind::TrustedCert,
                    created,
                    chain: vec![cert],
                    key: KeyState::None,
                    note: None,
                    protected: None,
                    key_password: None,
                });
            }
            3 if format == StoreFormat::Jceks => {
                // Java 序列化的 SealedObject 沒有長度前綴，無法安全跳過，只能停止解析後續條目。
                entries.push(Entry {
                    alias,
                    kind: EntryKind::SecretKey,
                    created,
                    chain: vec![],
                    key: KeyState::Locked("秘密金鑰內容不解析".into()),
                    note: Some("JCEKS 秘密金鑰條目".into()),
                    protected: None,
                    key_password: None,
                });
                if entries.len() < count as usize {
                    warnings.push(format!(
                        "遇到秘密金鑰條目「{}」後無法繼續解析，尚有 {} 個條目未顯示",
                        entries.last().map(|e| e.alias.as_str()).unwrap_or(""),
                        count as usize - entries.len()
                    ));
                }
                break;
            }
            other => return Err(Error::format(format!("未知的 JKS 條目類型：{other}"))),
        }
    }

    if integrity == Integrity::NotChecked {
        warnings.push("未提供密碼：未驗證憑證庫完整性，私鑰也無法解密".into());
    }

    Ok(Parsed {
        format,
        integrity,
        entries,
        warnings,
    })
}

fn read_cert(r: &mut Reader, version: u32) -> Result<CertInfo> {
    if version == 2 {
        let typ = r.utf()?;
        if typ != "X.509" {
            return Err(Error::Unsupported(format!("憑證類型 {typ}")));
        }
    }
    let len = r.u32()? as usize;
    CertInfo::from_der(r.take(len)?)
}

/// 解密 EncryptedPrivateKeyInfo，回傳 PKCS#8 PrivateKeyInfo DER。
pub fn decrypt_key(epki: &[u8], password: &str) -> Result<Vec<u8>> {
    let (seq, _) = der::expect(epki, der::TAG_SEQUENCE)?;
    let (alg, rest) = der::expect(seq.content, der::TAG_SEQUENCE)?;
    let (enc, _) = der::expect(rest, der::TAG_OCTET_STRING)?;
    let (oid, params) = der::expect(alg.content, der::TAG_OID)?;
    match der::oid_to_string(oid.content).as_str() {
        OID_JKS_KEY_PROTECTOR => jks_unprotect(enc.content, password),
        OID_PBE_MD5_3DES => jceks_unprotect(enc.content, params, password),
        other => Err(Error::Unsupported(format!("私鑰加密演算法 {other}"))),
    }
}

/// Sun JKS KeyProtector：SHA1 產生的金鑰流 XOR。
fn jks_unprotect(data: &[u8], password: &str) -> Result<Vec<u8>> {
    if data.len() < 40 {
        return Err(Error::format("加密私鑰資料過短"));
    }
    let pw = password_utf16be(password);
    let salt = &data[..20];
    let check = &data[data.len() - 20..];
    let enc = &data[20..data.len() - 20];
    let plain = jks_xor(&pw, salt, enc);
    let mut h = Sha1::new();
    h.update(&pw);
    h.update(&plain);
    if h.finalize().as_slice() != check {
        return Err(Error::WrongPassword("私鑰密碼錯誤".into()));
    }
    Ok(plain)
}

fn jks_xor(pw: &[u8], salt: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut digest: Vec<u8> = salt.to_vec();
    for chunk in data.chunks(20) {
        let mut h = Sha1::new();
        h.update(pw);
        h.update(&digest);
        digest = h.finalize().to_vec();
        out.extend(chunk.iter().zip(digest.iter()).map(|(a, b)| a ^ b));
    }
    out
}

/// Sun PBEWithMD5AndTripleDES（JCEKS）。
fn jceks_unprotect(data: &[u8], params: &[u8], password: &str) -> Result<Vec<u8>> {
    let (p, _) = der::expect(params, der::TAG_SEQUENCE)?;
    let (salt, rest) = der::expect(p.content, der::TAG_OCTET_STRING)?;
    let (iter, _) = der::expect(rest, der::TAG_INTEGER)?;
    let iterations = iter.content.iter().fold(0u64, |a, b| (a << 8) | *b as u64);
    if salt.content.len() != 8 {
        return Err(Error::format("JCEKS salt 長度不是 8"));
    }
    let mut s = [0u8; 8];
    s.copy_from_slice(salt.content);
    let derived = jceks_derive(password, &s, iterations);
    let dec = cbc::Decryptor::<des::TdesEde3>::new_from_slices(&derived[..24], &derived[24..])
        .map_err(|e| Error::Other(format!("3DES 初始化失敗：{e}")))?;
    let plain = dec
        .decrypt_padded_vec_mut::<Pkcs7>(data)
        .map_err(|_| Error::WrongPassword("私鑰密碼錯誤".into()))?;
    // 驗證結果是 DER SEQUENCE
    match der::expect(&plain, der::TAG_SEQUENCE) {
        Ok((t, rest)) if rest.is_empty() && !t.content.is_empty() => Ok(plain),
        _ => Err(Error::WrongPassword("私鑰密碼錯誤".into())),
    }
}

/// 私鑰資料：明文 PKCS#8（寫入時以指定密碼加密），或沿用既有的加密資料。
pub enum KeyBlob<'a> {
    Plain { pkcs8: &'a [u8], password: &'a str },
    Protected(&'a [u8]),
}

/// 要寫入 JKS / JCEKS 的條目。
pub enum WriteEntry<'a> {
    PrivateKey {
        alias: &'a str,
        created: Option<i64>,
        key: KeyBlob<'a>,
        chain: Vec<&'a [u8]>,
    },
    TrustedCert {
        alias: &'a str,
        created: Option<i64>,
        cert: &'a [u8],
    },
}

/// 加密私鑰資料使用的演算法 OID。
pub fn protected_key_algorithm(epki: &[u8]) -> Option<String> {
    let (seq, _) = der::expect(epki, der::TAG_SEQUENCE).ok()?;
    let (alg, _) = der::expect(seq.content, der::TAG_SEQUENCE).ok()?;
    let (oid, _) = der::expect(alg.content, der::TAG_OID).ok()?;
    Some(der::oid_to_string(oid.content))
}

/// 編碼成 JKS 或 JCEKS（version 2）。
pub fn encode_store(
    format: StoreFormat,
    entries: &[WriteEntry],
    store_password: &str,
) -> Result<Vec<u8>> {
    let magic = match format {
        StoreFormat::Jks => JKS_MAGIC,
        StoreFormat::Jceks => JCEKS_MAGIC,
        other => {
            return Err(Error::Unsupported(format!(
                "jks::encode_store 不支援 {other}"
            )))
        }
    };
    let mut out = Vec::new();
    out.extend(magic.to_be_bytes());
    out.extend(2u32.to_be_bytes());
    out.extend((entries.len() as u32).to_be_bytes());
    let now_ms: u64 = (crate::cert::now_ts() as u64) * 1000;
    let ts = |c: &Option<i64>| c.map(|v| (v.max(0) as u64) * 1000).unwrap_or(now_ms);
    let put_utf = |out: &mut Vec<u8>, s: &str| -> Result<()> {
        let b = s.as_bytes();
        if b.len() > u16::MAX as usize {
            return Err(Error::Other("別名過長".into()));
        }
        out.extend((b.len() as u16).to_be_bytes());
        out.extend(b);
        Ok(())
    };
    let put_cert = |out: &mut Vec<u8>, der: &[u8]| {
        out.extend(5u16.to_be_bytes());
        out.extend(b"X.509");
        out.extend((der.len() as u32).to_be_bytes());
        out.extend(der);
    };
    for e in entries {
        match e {
            WriteEntry::PrivateKey {
                alias,
                created,
                key,
                chain,
            } => {
                out.extend(1u32.to_be_bytes());
                put_utf(&mut out, alias)?;
                out.extend(ts(created).to_be_bytes());
                let epki = match key {
                    KeyBlob::Plain { pkcs8, password } => match format {
                        StoreFormat::Jks => jks_protect(pkcs8, password),
                        _ => jceks_protect(pkcs8, password)?,
                    },
                    KeyBlob::Protected(b) => {
                        let alg = protected_key_algorithm(b).unwrap_or_default();
                        // JKS 只能讀取 JKS KeyProtector；JCEKS 兩種都能讀
                        if format == StoreFormat::Jks && alg != OID_JKS_KEY_PROTECTOR {
                            return Err(Error::NeedPassword(format!(
                                "「{alias}」的私鑰需要先解密才能轉存為 JKS"
                            )));
                        }
                        b.to_vec()
                    }
                };
                out.extend((epki.len() as u32).to_be_bytes());
                out.extend(&epki);
                out.extend((chain.len() as u32).to_be_bytes());
                for c in chain {
                    put_cert(&mut out, c);
                }
            }
            WriteEntry::TrustedCert {
                alias,
                created,
                cert,
            } => {
                out.extend(2u32.to_be_bytes());
                put_utf(&mut out, alias)?;
                out.extend(ts(created).to_be_bytes());
                put_cert(&mut out, cert);
            }
        }
    }
    let d = store_digest(store_password, &out);
    out.extend(d);
    Ok(out)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("無法取得系統亂數");
    b
}

fn jks_protect(plain: &[u8], password: &str) -> Vec<u8> {
    let pw = password_utf16be(password);
    let salt = random_bytes::<20>().to_vec();
    let enc = jks_xor(&pw, &salt, plain);
    let mut h = Sha1::new();
    h.update(&pw);
    h.update(plain);
    let check = h.finalize();
    let mut data = salt;
    data.extend(enc);
    data.extend(check);

    let mut alg = der::encode(der::TAG_OID, &der::oid_from_string(OID_JKS_KEY_PROTECTOR));
    alg.extend(der::encode(der::TAG_NULL, &[]));
    let mut seq = der::encode(der::TAG_SEQUENCE, &alg);
    seq.extend(der::encode(der::TAG_OCTET_STRING, &data));
    der::encode(der::TAG_SEQUENCE, &seq)
}

const JCEKS_ITERATIONS: u32 = 200_000;

fn jceks_derive(password: &str, salt: &[u8; 8], iterations: u64) -> [u8; 32] {
    let mut s = *salt;
    if s[..4] == s[4..] {
        for i in 0..2 {
            s.swap(i, 3 - i);
        }
    }
    let pw: Vec<u8> = password.chars().map(|c| c as u32 as u8).collect();
    let mut derived = [0u8; 32];
    for i in 0..2 {
        let mut to_hash = s[i * 4..i * 4 + 4].to_vec();
        for _ in 0..iterations.max(1) {
            let mut h = Md5::new();
            h.update(&to_hash);
            h.update(&pw);
            to_hash = h.finalize().to_vec();
        }
        derived[i * 16..i * 16 + 16].copy_from_slice(&to_hash);
    }
    derived
}

fn jceks_protect(plain: &[u8], password: &str) -> Result<Vec<u8>> {
    use cbc::cipher::BlockEncryptMut;
    let salt = random_bytes::<8>();
    let derived = jceks_derive(password, &salt, JCEKS_ITERATIONS as u64);
    let enc = cbc::Encryptor::<des::TdesEde3>::new_from_slices(&derived[..24], &derived[24..])
        .map_err(|e| Error::Other(format!("3DES 初始化失敗：{e}")))?
        .encrypt_padded_vec_mut::<Pkcs7>(plain);

    let mut params = der::encode(der::TAG_OCTET_STRING, &salt);
    params.extend(der::encode(
        der::TAG_INTEGER,
        &der::uint_bytes(JCEKS_ITERATIONS as u64),
    ));
    let mut alg = der::encode(der::TAG_OID, &der::oid_from_string(OID_PBE_MD5_3DES));
    alg.extend(der::encode(der::TAG_SEQUENCE, &params));
    let mut seq = der::encode(der::TAG_SEQUENCE, &alg);
    seq.extend(der::encode(der::TAG_OCTET_STRING, &enc));
    Ok(der::encode(der::TAG_SEQUENCE, &seq))
}
