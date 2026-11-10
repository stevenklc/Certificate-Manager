//! Keystore 資料模型。

use std::fmt;
use std::path::PathBuf;

use serde::Serialize;

use crate::cert::CertInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum StoreFormat {
    Jks,
    Jceks,
    Pkcs12,
    Pem,
    Der,
    Pkcs7,
}

impl fmt::Display for StoreFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            StoreFormat::Jks => "JKS",
            StoreFormat::Jceks => "JCEKS",
            StoreFormat::Pkcs12 => "PKCS#12",
            StoreFormat::Pem => "PEM",
            StoreFormat::Der => "DER (X.509)",
            StoreFormat::Pkcs7 => "PKCS#7",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EntryKind {
    /// 私鑰 + 憑證鏈
    PrivateKey,
    /// 受信任憑證
    TrustedCert,
    /// 對稱金鑰（只顯示，不解析內容）
    SecretKey,
}

impl fmt::Display for EntryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            EntryKind::PrivateKey => "私鑰條目",
            EntryKind::TrustedCert => "信任憑證",
            EntryKind::SecretKey => "秘密金鑰",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum KeyFormat {
    Pkcs8,
    Pkcs1,
    Sec1,
}

/// 私鑰狀態。
#[derive(Clone, Default)]
pub enum KeyState {
    #[default]
    None,
    /// 已解密的私鑰
    Decrypted { format: KeyFormat, der: Vec<u8> },
    /// 尚未解密（原因）
    Locked(String),
}

// 刻意不輸出私鑰內容，避免誤印到 log。
impl fmt::Debug for KeyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyState::None => f.write_str("None"),
            KeyState::Decrypted { format, der } => {
                write!(f, "Decrypted({format:?}, {} bytes)", der.len())
            }
            KeyState::Locked(r) => write!(f, "Locked({r})"),
        }
    }
}

impl KeyState {
    pub fn label(&self) -> String {
        match self {
            KeyState::None => "無".into(),
            KeyState::Decrypted { .. } => "已解密".into(),
            KeyState::Locked(r) => format!("未解密：{r}"),
        }
    }
}

impl Serialize for KeyState {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.label())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub alias: String,
    pub kind: EntryKind,
    /// 建立時間（Unix 秒），JKS/JCEKS 才有
    pub created: Option<i64>,
    /// 憑證鏈（信任憑證條目只有一張）
    pub chain: Vec<CertInfo>,
    pub key: KeyState,
    pub note: Option<String>,
}

impl Entry {
    pub fn leaf(&self) -> Option<&CertInfo> {
        self.chain.first()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Integrity {
    /// 已用密碼驗證完整性 / MAC
    Verified,
    /// 未提供密碼，未驗證
    NotChecked,
    /// 格式本身沒有完整性檢查
    NotApplicable,
}

impl fmt::Display for Integrity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Integrity::Verified => "已驗證",
            Integrity::NotChecked => "未驗證（未提供密碼）",
            Integrity::NotApplicable => "不適用",
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Keystore {
    pub path: PathBuf,
    pub format: StoreFormat,
    pub integrity: Integrity,
    pub entries: Vec<Entry>,
    pub warnings: Vec<String>,
}

impl Keystore {
    pub fn name(&self) -> String {
        self.path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.path.display().to_string())
    }

    pub fn entry(&self, alias: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.alias == alias).or_else(|| {
            self.entries
                .iter()
                .find(|e| e.alias.eq_ignore_ascii_case(alias))
        })
    }

    /// 所有憑證（去重）。
    pub fn all_certs(&self) -> Vec<&CertInfo> {
        let mut seen = std::collections::HashSet::new();
        self.entries
            .iter()
            .flat_map(|e| e.chain.iter())
            .filter(|c| seen.insert(c.sha256.clone()))
            .collect()
    }

    /// 作為信任庫時使用的憑證：所有信任憑證條目 + 私鑰條目的終端憑證（與 Java TrustManager 行為一致）。
    pub fn trust_anchors(&self) -> Vec<&CertInfo> {
        let mut seen = std::collections::HashSet::new();
        self.entries
            .iter()
            .filter_map(|e| match e.kind {
                EntryKind::TrustedCert | EntryKind::PrivateKey => e.chain.first(),
                EntryKind::SecretKey => None,
            })
            .filter(|c| seen.insert(c.sha256.clone()))
            .collect()
    }

    pub fn private_key_entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries
            .iter()
            .filter(|e| e.kind == EntryKind::PrivateKey)
    }
}
