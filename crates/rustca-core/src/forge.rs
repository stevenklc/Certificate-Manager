//! 製作憑證：產生金鑰、自簽根 CA、中繼 CA、終端憑證（Server / Client），
//! 也可以用憑證庫中既有的 CA（含私鑰）簽發。

use std::net::IpAddr;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, DnValue,
    ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use serde::Serialize;
use time::{Duration, OffsetDateTime};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::cert::CertInfo;
use crate::error::{Error, Result};

/// 金鑰演算法。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum KeyAlg {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcP256,
    EcP384,
}

impl KeyAlg {
    pub const ALL: [KeyAlg; 5] = [
        KeyAlg::Rsa2048,
        KeyAlg::Rsa3072,
        KeyAlg::Rsa4096,
        KeyAlg::EcP256,
        KeyAlg::EcP384,
    ];

    pub fn label(self) -> &'static str {
        match self {
            KeyAlg::Rsa2048 => "RSA 2048",
            KeyAlg::Rsa3072 => "RSA 3072",
            KeyAlg::Rsa4096 => "RSA 4096",
            KeyAlg::EcP256 => "EC P-256",
            KeyAlg::EcP384 => "EC P-384",
        }
    }

    /// 解析 "rsa2048"、"rsa"、"ec256"、"p-384" 等寫法。
    pub fn parse(s: &str) -> Option<KeyAlg> {
        let s: String = s
            .to_ascii_lowercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        Some(match s.as_str() {
            "rsa" | "rsa2048" => KeyAlg::Rsa2048,
            "rsa3072" => KeyAlg::Rsa3072,
            "rsa4096" => KeyAlg::Rsa4096,
            "ec" | "ec256" | "ecp256" | "p256" | "ecdsa" | "prime256v1" | "secp256r1" => {
                KeyAlg::EcP256
            }
            "ec384" | "ecp384" | "p384" | "secp384r1" => KeyAlg::EcP384,
            _ => return None,
        })
    }
}

/// 憑證用途。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Profile {
    RootCa,
    IntermediateCa,
    Server,
    Client,
    ServerClient,
}

impl Profile {
    pub fn label(self) -> &'static str {
        match self {
            Profile::RootCa => "根 CA",
            Profile::IntermediateCa => "中繼 CA",
            Profile::Server => "Server（serverAuth）",
            Profile::Client => "Client（clientAuth）",
            Profile::ServerClient => "Server + Client",
        }
    }

    pub fn is_ca(self) -> bool {
        matches!(self, Profile::RootCa | Profile::IntermediateCa)
    }

    pub fn parse(s: &str) -> Option<Profile> {
        Some(match s.to_ascii_lowercase().as_str() {
            "root" | "rootca" | "root-ca" => Profile::RootCa,
            "ca" | "intermediate" | "inter" | "sub" | "subca" => Profile::IntermediateCa,
            "server" | "tls-server" => Profile::Server,
            "client" | "tls-client" => Profile::Client,
            "both" | "server-client" | "serverclient" => Profile::ServerClient,
            _ => return None,
        })
    }
}

/// 主體資訊。
#[derive(Debug, Clone, Default)]
pub struct Subject {
    pub cn: String,
    pub o: String,
    pub ou: String,
    pub l: String,
    pub st: String,
    pub c: String,
}

impl Subject {
    pub fn cn(cn: impl Into<String>) -> Self {
        Subject {
            cn: cn.into(),
            ..Default::default()
        }
    }

    fn to_dn(&self) -> Result<DistinguishedName> {
        if self.cn.trim().is_empty() {
            return Err(Error::Other("CN（一般名稱）不可空白".into()));
        }
        let mut dn = DistinguishedName::new();
        let c = self.c.trim();
        if !c.is_empty() {
            if c.len() != 2 || !c.chars().all(|x| x.is_ascii_alphabetic()) {
                return Err(Error::Other(format!("國家代碼需為 2 個英文字母：{c}")));
            }
            dn.push(
                DnType::CountryName,
                DnValue::PrintableString(
                    c.to_ascii_uppercase()
                        .try_into()
                        .map_err(|_| Error::Other("國家代碼不合法".into()))?,
                ),
            );
        }
        for (t, v) in [
            (DnType::StateOrProvinceName, &self.st),
            (DnType::LocalityName, &self.l),
            (DnType::OrganizationName, &self.o),
            (DnType::OrganizationalUnitName, &self.ou),
            (DnType::CommonName, &self.cn),
        ] {
            let v = v.trim();
            if !v.is_empty() {
                dn.push(t, DnValue::Utf8String(v.to_string()));
            }
        }
        Ok(dn)
    }
}

/// 一張憑證的規格。
#[derive(Debug, Clone)]
pub struct CertSpec {
    pub subject: Subject,
    pub profile: Profile,
    pub key: KeyAlg,
    pub days: u32,
    /// DNS 名稱、IP、email；可加前綴 "DNS:"、"IP:"、"email:"、"URI:"
    pub sans: Vec<String>,
    /// CA 的 pathLenConstraint
    pub path_len: Option<u8>,
}

impl CertSpec {
    pub fn new(cn: impl Into<String>, profile: Profile) -> Self {
        CertSpec {
            subject: Subject::cn(cn),
            profile,
            key: KeyAlg::Rsa2048,
            days: if profile.is_ca() { 3650 } else { 825 },
            sans: vec![],
            path_len: None,
        }
    }
}

/// 簽發結果。
pub struct Issued {
    pub cert: CertInfo,
    /// PKCS#8 私鑰
    pub key_pkcs8: Vec<u8>,
}

impl std::fmt::Debug for Issued {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Issued({}, key ***)", self.cert.subject)
    }
}

/// 簽發者：既有 CA 憑證與其 PKCS#8 私鑰。
#[derive(Clone, Copy)]
pub struct Signer<'a> {
    pub cert: &'a CertInfo,
    pub key_pkcs8: &'a [u8],
}

/// 產生新私鑰（PKCS#8 DER）。
pub fn generate_key(alg: KeyAlg) -> Result<Vec<u8>> {
    let gen_err = |e: String| Error::Other(format!("產生金鑰失敗：{e}"));
    match alg {
        KeyAlg::EcP256 | KeyAlg::EcP384 => {
            let a = if alg == KeyAlg::EcP256 {
                &rcgen::PKCS_ECDSA_P256_SHA256
            } else {
                &rcgen::PKCS_ECDSA_P384_SHA384
            };
            let kp = KeyPair::generate_for(a).map_err(|e| gen_err(e.to_string()))?;
            Ok(kp.serialize_der())
        }
        KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096 => {
            use rsa::pkcs8::EncodePrivateKey;
            let bits = match alg {
                KeyAlg::Rsa2048 => 2048,
                KeyAlg::Rsa3072 => 3072,
                _ => 4096,
            };
            let key = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, bits)
                .map_err(|e| gen_err(e.to_string()))?;
            let der = key.to_pkcs8_der().map_err(|e| gen_err(e.to_string()))?;
            Ok(der.as_bytes().to_vec())
        }
    }
}

fn key_pair(pkcs8: &[u8]) -> Result<KeyPair> {
    KeyPair::try_from(pkcs8).map_err(|e| {
        Error::Other(format!(
            "無法使用此私鑰簽章（支援 RSA、EC P-256/P-384）：{e}"
        ))
    })
}

fn parse_san(s: &str) -> Result<SanType> {
    let s = s.trim();
    let (kind, v) = match s.split_once(':') {
        Some((k, v))
            if ["dns", "ip", "email", "uri"].contains(&k.to_ascii_lowercase().as_str()) =>
        {
            (k.to_ascii_lowercase(), v.trim())
        }
        _ => (String::new(), s),
    };
    let bad = |_| Error::Other(format!("SAN 格式不合法：{s}"));
    Ok(match kind.as_str() {
        "ip" => SanType::IpAddress(
            v.parse::<IpAddr>()
                .map_err(|_| Error::Other(format!("IP 格式不合法：{v}")))?,
        ),
        "email" => SanType::Rfc822Name(v.try_into().map_err(bad)?),
        "uri" => SanType::URI(v.try_into().map_err(bad)?),
        "dns" => SanType::DnsName(v.try_into().map_err(bad)?),
        _ => {
            if let Ok(ip) = v.parse::<IpAddr>() {
                SanType::IpAddress(ip)
            } else if v.contains('@') {
                SanType::Rfc822Name(v.try_into().map_err(bad)?)
            } else {
                SanType::DnsName(v.try_into().map_err(bad)?)
            }
        }
    })
}

fn looks_like_host(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '*')
        && (s.contains('.') || s == "localhost")
}

/// 依既有 CA 憑證重建簽發者參數（主體 DN 與 SKI 必須與原憑證完全相同）。
fn issuer_params(ca: &CertInfo) -> Result<CertificateParams> {
    let (_, x) = X509Certificate::from_der(&ca.der)
        .map_err(|e| Error::format(format!("無法解析 CA 憑證：{e}")))?;
    let mut dn = DistinguishedName::new();
    for rdn in x.subject().iter() {
        for attr in rdn.iter() {
            let oid: Vec<u64> = attr
                .attr_type()
                .iter()
                .ok_or_else(|| Error::format("CA 主體 OID 不合法"))?
                .collect();
            let t = DnType::from_oid(&oid);
            let data = attr.attr_value().data;
            let text = || {
                std::str::from_utf8(data)
                    .map(str::to_string)
                    .map_err(|_| Error::format("CA 主體字串編碼不合法"))
            };
            use x509_parser::der_parser::asn1_rs::Tag;
            let v = match attr.attr_value().header.tag() {
                Tag::PrintableString => DnValue::PrintableString(
                    text()?
                        .try_into()
                        .map_err(|_| Error::format("CA 主體 PrintableString 不合法"))?,
                ),
                Tag::Ia5String => DnValue::Ia5String(
                    text()?
                        .try_into()
                        .map_err(|_| Error::format("CA 主體 IA5String 不合法"))?,
                ),
                Tag::Utf8String => DnValue::Utf8String(text()?),
                Tag::T61String => DnValue::TeletexString(
                    text()?
                        .try_into()
                        .map_err(|_| Error::format("CA 主體 T61String 不合法"))?,
                ),
                Tag::BmpString => DnValue::BmpString(
                    rcgen::BmpString::from_utf16be(data.to_vec())
                        .map_err(|_| Error::format("CA 主體 BMPString 不合法"))?,
                ),
                _ => return Err(Error::Unsupported("CA 主體含不支援的字串型別".into())),
            };
            dn.push(t, v);
        }
    }
    let mut p = CertificateParams::default();
    // 同型別屬性重複（例如兩個 OU）時 rcgen 無法完整保留，會造成簽發者不符
    if dn.iter().count() != x.subject().iter_attributes().count() {
        return Err(Error::Unsupported(
            "CA 主體含重複的屬性型別（例如多個 OU），無法用此 CA 簽發".into(),
        ));
    }
    p.distinguished_name = dn;
    p.key_identifier_method = match x
        .iter_extensions()
        .find_map(|e| match e.parsed_extension() {
            x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(k) => Some(k.0.to_vec()),
            _ => None,
        }) {
        Some(ski) => KeyIdMethod::PreSpecified(ski),
        None => KeyIdMethod::Sha256,
    };
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    Ok(p)
}

fn random_serial() -> Result<SerialNumber> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|e| Error::Other(format!("亂數產生失敗：{e}")))?;
    b[0] &= 0x7f;
    b[0] |= 0x01;
    Ok(SerialNumber::from(b.to_vec()))
}

/// 簽發一張憑證。`signer` 為 None 時為自簽（只適用根 CA，或測試用的自簽終端憑證）。
/// `key_pkcs8` 為 None 時自動產生新金鑰。
pub fn issue(
    spec: &CertSpec,
    signer: Option<Signer>,
    key_pkcs8: Option<Vec<u8>>,
) -> Result<Issued> {
    if spec.days == 0 {
        return Err(Error::Other("有效天數需大於 0".into()));
    }
    if spec.profile == Profile::IntermediateCa && signer.is_none() {
        return Err(Error::Other("中繼 CA 需要由上一層 CA 簽發".into()));
    }
    let key_der = match key_pkcs8 {
        Some(k) => k,
        None => generate_key(spec.key)?,
    };
    let kp = key_pair(&key_der)?;

    let mut p = CertificateParams::default();
    p.distinguished_name = spec.subject.to_dn()?;
    p.serial_number = Some(random_serial()?);
    let now = OffsetDateTime::now_utc();
    p.not_before = now - Duration::minutes(5);
    let mut not_after = now + Duration::days(spec.days as i64);
    if let Some(s) = &signer {
        // 不超過簽發者的到期日
        if let Ok(limit) = OffsetDateTime::from_unix_timestamp(s.cert.not_after) {
            if not_after > limit {
                not_after = limit;
            }
        }
    }
    p.not_after = not_after;

    let mut sans = Vec::new();
    for s in spec.sans.iter().filter(|s| !s.trim().is_empty()) {
        sans.push(parse_san(s)?);
    }
    let leaf_server = matches!(spec.profile, Profile::Server | Profile::ServerClient);
    if leaf_server && sans.is_empty() && looks_like_host(spec.subject.cn.trim()) {
        // 現代瀏覽器 / Java 只看 SAN，CN 像主機名稱時自動加入
        sans.push(parse_san(spec.subject.cn.trim())?);
    }
    p.subject_alt_names = sans;

    let rsa = matches!(
        spec.key,
        KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096
    ) || kp.algorithm() == &rcgen::PKCS_RSA_SHA256;
    match spec.profile {
        Profile::RootCa | Profile::IntermediateCa => {
            p.is_ca = IsCa::Ca(match spec.path_len {
                Some(n) => BasicConstraints::Constrained(n),
                None => BasicConstraints::Unconstrained,
            });
            p.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::DigitalSignature,
            ];
        }
        _ => {
            p.is_ca = IsCa::ExplicitNoCa;
            p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            if rsa {
                p.key_usages.push(KeyUsagePurpose::KeyEncipherment);
            }
            p.extended_key_usages = match spec.profile {
                Profile::Server => vec![ExtendedKeyUsagePurpose::ServerAuth],
                Profile::Client => vec![ExtendedKeyUsagePurpose::ClientAuth],
                _ => vec![
                    ExtendedKeyUsagePurpose::ServerAuth,
                    ExtendedKeyUsagePurpose::ClientAuth,
                ],
            };
        }
    }

    let cert = match signer {
        None => p
            .self_signed(&kp)
            .map_err(|e| Error::Other(format!("簽發失敗：{e}")))?,
        Some(s) => {
            if !s.cert.is_ca {
                return Err(Error::Other(format!(
                    "「{}」不是 CA 憑證，無法簽發",
                    s.cert.display_name()
                )));
            }
            p.use_authority_key_identifier_extension = true;
            let ikp = key_pair(s.key_pkcs8)?;
            if !crate::tls::key_matches_cert(crate::model::KeyFormat::Pkcs8, s.key_pkcs8, s.cert)
                .unwrap_or(true)
            {
                return Err(Error::Other("簽發者的私鑰與 CA 憑證不相符".into()));
            }
            let issuer = issuer_params(s.cert)?
                .self_signed(&ikp)
                .map_err(|e| Error::Other(format!("簽發失敗：{e}")))?;
            p.signed_by(&kp, &issuer, &ikp)
                .map_err(|e| Error::Other(format!("簽發失敗：{e}")))?
        }
    };
    Ok(Issued {
        cert: CertInfo::from_der(cert.der())?,
        key_pkcs8: key_der,
    })
}

/// 依序簽發一條憑證鏈：`specs[0]` 由 `signer` 簽發（None＝自簽根 CA），
/// 之後每一張由前一張簽發。回傳順序與 `specs` 相同（上層在前）。
pub fn issue_chain(specs: &[CertSpec], signer: Option<Signer>) -> Result<Vec<Issued>> {
    if specs.is_empty() {
        return Err(Error::Other("沒有要簽發的憑證".into()));
    }
    for (i, s) in specs.iter().enumerate() {
        if i + 1 < specs.len() && !s.profile.is_ca() {
            return Err(Error::Other(format!(
                "「{}」不是 CA，不能再簽發下一層憑證",
                s.subject.cn
            )));
        }
    }
    let mut out: Vec<Issued> = Vec::new();
    for (i, s) in specs.iter().enumerate() {
        let issued = if i == 0 {
            issue(s, signer, None)?
        } else {
            let prev = &out[i - 1];
            issue(
                s,
                Some(Signer {
                    cert: &prev.cert,
                    key_pkcs8: &prev.key_pkcs8,
                }),
                None,
            )?
        };
        out.push(issued);
    }
    Ok(out)
}
