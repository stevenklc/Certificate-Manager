//! X.509 憑證資訊擷取與有效期限判斷。

use std::sync::OnceLock;

use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, UtcOffset};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::objects::{oid2sn, oid_registry};
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

use crate::error::{Error, Result};

/// 一張已解析的 X.509 憑證。
#[derive(Debug, Clone, Serialize)]
pub struct CertInfo {
    #[serde(skip)]
    pub der: Vec<u8>,
    pub version: u32,
    pub subject: String,
    pub issuer: String,
    pub subject_cn: Option<String>,
    pub serial: String,
    /// Unix timestamp（秒）
    pub not_before: i64,
    /// Unix timestamp（秒）
    pub not_after: i64,
    pub signature_algorithm: String,
    pub public_key: String,
    pub subject_alt_names: Vec<String>,
    pub is_ca: bool,
    pub path_len: Option<u32>,
    pub key_usage: Vec<String>,
    pub ext_key_usage: Vec<String>,
    pub subject_key_id: Option<String>,
    pub authority_key_id: Option<String>,
    /// 主體與簽發者相同且自簽章驗證成功
    pub self_signed: bool,
    pub sha1: String,
    pub sha256: String,
    #[serde(skip)]
    pub raw_subject: Vec<u8>,
    #[serde(skip)]
    pub raw_issuer: Vec<u8>,
}

/// 有效期限狀態。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ValidityStatus {
    Valid { days_left: i64 },
    ExpiringSoon { days_left: i64 },
    Expired { days_ago: i64 },
    NotYetValid { days_until: i64 },
}

impl ValidityStatus {
    pub fn label(&self) -> String {
        match self {
            ValidityStatus::Valid { days_left } => format!("有效（剩 {days_left} 天）"),
            ValidityStatus::ExpiringSoon { days_left } => format!("即將到期（剩 {days_left} 天）"),
            ValidityStatus::Expired { days_ago } => format!("已過期（{days_ago} 天前）"),
            ValidityStatus::NotYetValid { days_until } => format!("尚未生效（{days_until} 天後）"),
        }
    }

    pub fn is_problem(&self) -> bool {
        !matches!(self, ValidityStatus::Valid { .. })
    }

    pub fn is_bad(&self) -> bool {
        matches!(
            self,
            ValidityStatus::Expired { .. } | ValidityStatus::NotYetValid { .. }
        )
    }
}

const DAY: i64 = 86_400;

impl CertInfo {
    /// 從 DER 解析憑證。
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|e| Error::format(format!("無法解析 X.509 憑證：{e}")))?;
        let reg = oid_registry();

        let subject_cn = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(|s| s.to_string());

        let signature_algorithm = oid2sn(&cert.signature_algorithm.algorithm, reg)
            .map(|s| s.to_string())
            .unwrap_or_else(|_| cert.signature_algorithm.algorithm.to_id_string());

        let spki = cert.public_key();
        let public_key = match spki.parsed() {
            Ok(PublicKey::RSA(rsa)) => format!("RSA {} bits", rsa.key_size()),
            Ok(PublicKey::EC(_)) => {
                let curve = spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|p| p.as_oid().ok())
                    .map(|oid| match oid.to_id_string().as_str() {
                        "1.2.840.10045.3.1.7" => "P-256".to_string(),
                        "1.3.132.0.34" => "P-384".to_string(),
                        "1.3.132.0.35" => "P-521".to_string(),
                        "1.3.132.0.10" => "secp256k1".to_string(),
                        other => other.to_string(),
                    })
                    .unwrap_or_else(|| "未知曲線".into());
                format!("EC {curve}")
            }
            Ok(PublicKey::DSA(_)) => "DSA".to_string(),
            _ => match spki.algorithm.algorithm.to_id_string().as_str() {
                "1.3.101.112" => "Ed25519".to_string(),
                "1.3.101.113" => "Ed448".to_string(),
                other => oid2sn(&spki.algorithm.algorithm, reg)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|_| other.to_string()),
            },
        };

        let mut subject_alt_names = Vec::new();
        let mut is_ca = false;
        let mut path_len = None;
        let mut key_usage = Vec::new();
        let mut ext_key_usage = Vec::new();
        let mut subject_key_id = None;
        let mut authority_key_id = None;

        for ext in cert.extensions() {
            match ext.parsed_extension() {
                ParsedExtension::SubjectAlternativeName(san) => {
                    for name in &san.general_names {
                        subject_alt_names.push(general_name_to_string(name));
                    }
                }
                ParsedExtension::BasicConstraints(bc) => {
                    is_ca = bc.ca;
                    path_len = bc.path_len_constraint;
                }
                ParsedExtension::KeyUsage(ku) => {
                    key_usage = ku
                        .to_string()
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                ParsedExtension::ExtendedKeyUsage(eku) => {
                    if eku.any {
                        ext_key_usage.push("anyExtendedKeyUsage".into());
                    }
                    if eku.server_auth {
                        ext_key_usage.push("serverAuth".into());
                    }
                    if eku.client_auth {
                        ext_key_usage.push("clientAuth".into());
                    }
                    if eku.code_signing {
                        ext_key_usage.push("codeSigning".into());
                    }
                    if eku.email_protection {
                        ext_key_usage.push("emailProtection".into());
                    }
                    if eku.time_stamping {
                        ext_key_usage.push("timeStamping".into());
                    }
                    if eku.ocsp_signing {
                        ext_key_usage.push("OCSPSigning".into());
                    }
                    for o in &eku.other {
                        ext_key_usage.push(o.to_id_string());
                    }
                }
                ParsedExtension::SubjectKeyIdentifier(kid) => {
                    subject_key_id = Some(hex_colon(kid.0));
                }
                ParsedExtension::AuthorityKeyIdentifier(aki) => {
                    authority_key_id = aki.key_identifier.as_ref().map(|k| hex_colon(k.0));
                }
                _ => {}
            }
        }

        let raw_subject = cert.subject().as_raw().to_vec();
        let raw_issuer = cert.issuer().as_raw().to_vec();
        let self_signed = raw_subject == raw_issuer && cert.verify_signature(None).is_ok();

        Ok(CertInfo {
            der: der.to_vec(),
            version: cert.version().0 + 1,
            subject: cert.subject().to_string(),
            issuer: cert.issuer().to_string(),
            subject_cn,
            serial: hex_colon(cert.raw_serial()),
            not_before: cert.validity().not_before.timestamp(),
            not_after: cert.validity().not_after.timestamp(),
            signature_algorithm,
            public_key,
            subject_alt_names,
            is_ca,
            path_len,
            key_usage,
            ext_key_usage,
            subject_key_id,
            authority_key_id,
            self_signed,
            sha1: hex_colon(&Sha1::digest(der)),
            sha256: hex_colon(&Sha256::digest(der)),
            raw_subject,
            raw_issuer,
        })
    }

    /// 憑證在 PKI 中的角色（與它在憑證庫中是哪一種條目無關）。
    pub fn role(&self) -> &'static str {
        match (self.is_ca, self.self_signed) {
            (true, true) => "根 CA",
            (true, false) => "中繼 CA",
            (false, true) => "自簽",
            (false, false) => "終端",
        }
    }

    /// 顯示用名稱：優先使用 CN，否則使用完整主體。
    pub fn display_name(&self) -> String {
        self.subject_cn
            .clone()
            .unwrap_or_else(|| self.subject.clone())
    }

    /// 依指定時間判斷有效狀態。`warn_days` 內到期視為「即將到期」。
    pub fn status_at(&self, now: i64, warn_days: i64) -> ValidityStatus {
        if now < self.not_before {
            ValidityStatus::NotYetValid {
                days_until: ceil_div(self.not_before - now, DAY),
            }
        } else if now > self.not_after {
            ValidityStatus::Expired {
                days_ago: (now - self.not_after) / DAY,
            }
        } else {
            let days_left = (self.not_after - now) / DAY;
            if days_left < warn_days {
                ValidityStatus::ExpiringSoon { days_left }
            } else {
                ValidityStatus::Valid { days_left }
            }
        }
    }

    pub fn status(&self, warn_days: i64) -> ValidityStatus {
        self.status_at(now_ts(), warn_days)
    }

    /// 驗證本憑證是否由 `issuer` 的公鑰簽署。回傳 None 表示演算法不支援、無法判斷。
    pub fn verify_signed_by(&self, issuer: &CertInfo) -> Option<bool> {
        let (_, child) = X509Certificate::from_der(&self.der).ok()?;
        let (_, parent) = X509Certificate::from_der(&issuer.der).ok()?;
        match child.verify_signature(Some(parent.public_key())) {
            Ok(()) => Some(true),
            Err(x509_parser::error::X509Error::SignatureUnsupportedAlgorithm) => None,
            Err(_) => Some(false),
        }
    }

    pub fn to_pem(&self) -> String {
        crate::pem::encode("CERTIFICATE", &self.der)
    }
}

fn ceil_div(a: i64, b: i64) -> i64 {
    (a + b - 1) / b
}

fn general_name_to_string(name: &GeneralName) -> String {
    match name {
        GeneralName::DNSName(s) => format!("DNS:{s}"),
        GeneralName::RFC822Name(s) => format!("email:{s}"),
        GeneralName::URI(s) => format!("URI:{s}"),
        GeneralName::IPAddress(b) => match b.len() {
            4 => format!("IP:{}", std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3])),
            16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(b);
                format!("IP:{}", std::net::Ipv6Addr::from(arr))
            }
            _ => format!("IP:{}", hex::encode(b)),
        },
        GeneralName::DirectoryName(n) => format!("DirName:{n}"),
        GeneralName::RegisteredID(o) => format!("RID:{}", o.to_id_string()),
        other => format!("{other:?}"),
    }
}

/// 以冒號分隔的大寫十六進位字串。
pub fn hex_colon(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// 目前時間（Unix 秒）。
pub fn now_ts() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

static LOCAL_OFFSET: OnceLock<UtcOffset> = OnceLock::new();

/// 在程式啟動時（單執行緒階段）呼叫，以取得本地時區。
pub fn init_local_offset() {
    let _ = LOCAL_OFFSET.set(UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC));
}

/// 以本地時區格式化 Unix timestamp。
pub fn format_ts(ts: i64) -> String {
    let offset = *LOCAL_OFFSET.get_or_init(|| UtcOffset::UTC);
    match OffsetDateTime::from_unix_timestamp(ts) {
        Ok(dt) => {
            let dt = dt.to_offset(offset);
            let (h, m, _) = offset.as_hms();
            let tz = if h == 0 && m == 0 {
                "UTC".to_string()
            } else {
                format!("UTC{:+03}:{:02}", h, m.abs())
            };
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02} {tz}",
                dt.year(),
                dt.month() as u8,
                dt.day(),
                dt.hour(),
                dt.minute(),
                dt.second()
            )
        }
        Err(_) => ts.to_string(),
    }
}

/// 解析日期字串（YYYY-MM-DD 或 RFC3339）為 Unix timestamp，用於「指定時間模擬」。
pub fn parse_date(s: &str) -> Result<i64> {
    let s = s.trim();
    if let Ok(dt) = OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339) {
        return Ok(dt.unix_timestamp());
    }
    let fmt = time::macros::format_description!("[year]-[month]-[day]");
    let date = time::Date::parse(s, &fmt).map_err(|_| {
        Error::Other(format!(
            "無法解析日期「{s}」，請使用 YYYY-MM-DD 或 RFC3339 格式"
        ))
    })?;
    Ok(date.midnight().assume_utc().unix_timestamp())
}
