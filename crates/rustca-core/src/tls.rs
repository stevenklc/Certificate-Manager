//! TLS 交握模擬：
//! * 本機模擬：同一個行程內建立 Server 與 Client，透過記憶體交換 TLS 位元組。
//! * 遠端連線：以 Client 身分連到真實 Server，記錄對方送出的憑證鏈與 mTLS 要求。

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ResolvesClientCert, WebPkiServerVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    ServerName, UnixTime,
};
use rustls::server::WebPkiClientVerifier;
use rustls::sign::CertifiedKey;
use rustls::time_provider::TimeProvider;
use rustls::{
    AlertDescription, CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct,
    RootCertStore, ServerConfig, ServerConnection, SignatureScheme, SupportedProtocolVersion,
};
use serde::Serialize;
#[allow(unused_imports)]
use x509_parser::prelude::X509Certificate as _;
use x509_parser::prelude::{FromDer, X509Name};

use crate::cert::CertInfo;
use crate::error::{Error, Result};
use crate::model::{KeyFormat, KeyState, Keystore};

// ───────────────────────────── 身分與信任 ─────────────────────────────

/// 一組可用於 TLS 的身分（私鑰 + 憑證鏈）。
pub struct Identity {
    pub label: String,
    pub chain: Vec<CertInfo>,
    key: PrivateKeyDer<'static>,
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        Identity {
            label: self.label.clone(),
            chain: self.chain.clone(),
            key: self.key.clone_key(),
        }
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("label", &self.label)
            .field("chain_len", &self.chain.len())
            .finish()
    }
}

impl Identity {
    fn cert_ders(&self) -> Vec<CertificateDer<'static>> {
        self.chain
            .iter()
            .map(|c| CertificateDer::from(c.der.clone()))
            .collect()
    }
}

/// 從憑證庫取出私鑰條目作為 TLS 身分。`alias` 為 None 時取第一個私鑰條目。
pub fn identity_from_keystore(ks: &Keystore, alias: Option<&str>) -> Result<Identity> {
    let entry = match alias {
        Some(a) => ks
            .entry(a)
            .ok_or_else(|| Error::Other(format!("{} 中找不到別名「{a}」", ks.name())))?,
        None => ks.private_key_entries().next().ok_or_else(|| {
            Error::Other(format!("{} 中沒有私鑰條目，無法作為 TLS 身分", ks.name()))
        })?,
    };
    if entry.chain.is_empty() {
        return Err(Error::Other(format!("「{}」沒有憑證", entry.alias)));
    }
    let key = match &entry.key {
        KeyState::Decrypted { format, der } => private_key_der(*format, der, &entry.chain[0]),
        KeyState::Locked(r) => {
            return Err(Error::NeedPassword(format!(
                "「{}」的私鑰無法使用：{r}",
                entry.alias
            )))
        }
        KeyState::None => {
            return Err(Error::Other(format!(
                "「{}」不是私鑰條目，無法作為 TLS 身分",
                entry.alias
            )))
        }
    };
    Ok(Identity {
        label: format!("{} / {}", ks.name(), entry.alias),
        chain: entry.chain.clone(),
        key,
    })
}

/// Java 8 等工具產生的 EC PKCS#8 私鑰，內層 ECPrivateKey 常省略 publicKey 欄位，
/// 但 ring 要求必須存在。這裡從終端憑證的 SPKI 取出公鑰補上。
/// 不是 EC 金鑰或已含公鑰時回傳 None（維持原樣）。
fn normalize_ec_pkcs8(pkcs8: &[u8], leaf: &CertInfo) -> Option<Vec<u8>> {
    use crate::der::{self, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE};
    const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";

    let (pki, _) = der::expect(pkcs8, TAG_SEQUENCE).ok()?;
    let parts = der::children(pki.content).ok()?;
    if parts.len() < 3 || parts[1].tag != TAG_SEQUENCE || parts[2].tag != TAG_OCTET_STRING {
        return None;
    }
    let alg = der::children(parts[1].content).ok()?;
    if alg.len() < 2
        || alg[0].tag != TAG_OID
        || der::oid_to_string(alg[0].content) != OID_EC_PUBLIC_KEY
    {
        return None;
    }
    let curve = alg[1];
    let (ec, _) = der::expect(parts[2].content, TAG_SEQUENCE).ok()?;
    let fields = der::children(ec.content).ok()?;
    if fields.iter().any(|f| f.tag == 0xA1) || fields.len() < 2 {
        return None;
    }

    let (_, cert) = x509_parser::prelude::X509Certificate::from_der(&leaf.der).ok()?;
    let point = cert.public_key().subject_public_key.data.to_vec();
    let mut bit_string = vec![0u8];
    bit_string.extend(point);

    let mut ec_new = Vec::new();
    ec_new.extend_from_slice(fields[0].raw);
    ec_new.extend_from_slice(fields[1].raw);
    match fields.iter().find(|f| f.tag == 0xA0) {
        Some(params) => ec_new.extend_from_slice(params.raw),
        None => ec_new.extend(der::encode(0xA0, curve.raw)),
    }
    ec_new.extend(der::encode(0xA1, &der::encode(0x03, &bit_string)));
    let ec_new = der::encode(TAG_SEQUENCE, &ec_new);

    let mut pki_new = Vec::new();
    pki_new.extend_from_slice(parts[0].raw);
    pki_new.extend_from_slice(parts[1].raw);
    pki_new.extend(der::encode(TAG_OCTET_STRING, &ec_new));
    for extra in &parts[3..] {
        pki_new.extend_from_slice(extra.raw);
    }
    Some(der::encode(TAG_SEQUENCE, &pki_new))
}

fn private_key_der(format: KeyFormat, der: &[u8], leaf: &CertInfo) -> PrivateKeyDer<'static> {
    match format {
        KeyFormat::Pkcs8 => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            normalize_ec_pkcs8(der, leaf).unwrap_or_else(|| der.to_vec()),
        )),
        KeyFormat::Pkcs1 => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der.to_vec())),
        KeyFormat::Sec1 => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der.to_vec())),
    }
}

/// 檢查私鑰是否與憑證的公鑰相符。None 表示無法判斷（金鑰類型不支援）。
pub fn key_matches_cert(format: KeyFormat, der: &[u8], cert: &CertInfo) -> Option<bool> {
    let key = private_key_der(format, der, cert);
    let signer = provider().key_provider.load_private_key(key).ok()?;
    let spki = signer.public_key()?;
    let (_, x) = x509_parser::prelude::X509Certificate::from_der(&cert.der).ok()?;
    Some(spki.as_ref() == x.public_key().raw)
}

/// 由「憑證檔 + 私鑰檔」組成 TLS 身分（例如 client.cer + client.key）。
pub fn identity_from_cert_and_key(cert_ks: &Keystore, key_ks: &Keystore) -> Result<Identity> {
    let certs: Vec<CertInfo> = cert_ks.all_certs().into_iter().cloned().collect();
    if certs.is_empty() {
        return Err(Error::Other(format!("{} 中沒有憑證", cert_ks.name())));
    }
    let key_entry = key_ks
        .private_key_entries()
        .next()
        .ok_or_else(|| Error::Other(format!("{} 中沒有私鑰", key_ks.name())))?;
    let entry = crate::edit::entry_from_cert_and_key("identity", &certs, key_entry)?;
    let KeyState::Decrypted { format, der } = &entry.key else {
        return Err(Error::NeedPassword("私鑰尚未解密".into()));
    };
    Ok(Identity {
        label: format!("{} + {}", cert_ks.name(), key_ks.name()),
        key: private_key_der(*format, der, &entry.chain[0]),
        chain: entry.chain.clone(),
    })
}

/// 收集多個憑證庫的信任錨點。
pub fn trust_from_keystores(stores: &[&Keystore]) -> Vec<CertInfo> {
    let mut seen = std::collections::HashSet::new();
    stores
        .iter()
        .flat_map(|ks| ks.trust_anchors())
        .filter(|c| seen.insert(c.sha256.clone()))
        .cloned()
        .collect()
}

fn root_store(certs: &[CertInfo], warnings: &mut Vec<String>) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    for c in certs {
        if let Err(e) = roots.add(CertificateDer::from(c.der.clone())) {
            warnings.push(format!("無法加入信任錨點「{}」：{e}", c.display_name()));
        }
    }
    roots
}

// ───────────────────────────── 選項與報告 ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub enum TlsVersion {
    #[default]
    Auto,
    Tls12,
    Tls13,
}

impl TlsVersion {
    fn versions(self) -> Vec<&'static SupportedProtocolVersion> {
        match self {
            TlsVersion::Auto => vec![&rustls::version::TLS13, &rustls::version::TLS12],
            TlsVersion::Tls12 => vec![&rustls::version::TLS12],
            TlsVersion::Tls13 => vec![&rustls::version::TLS13],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Side {
    Client,
    Server,
    Network,
    Config,
}

impl std::fmt::Display for Side {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Side::Client => "Client 端",
            Side::Server => "Server 端",
            Side::Network => "網路",
            Side::Config => "設定",
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Failure {
    /// 偵測到錯誤的一方
    pub side: Side,
    pub message: String,
    /// 中文診斷建議
    pub hint: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TranscriptLine {
    /// "C→S" 或 "S→C"
    pub direction: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct HandshakeReport {
    pub success: bool,
    pub mode: String,
    pub target: String,
    pub server_name: String,
    pub protocol: Option<String>,
    pub cipher_suite: Option<String>,
    pub key_exchange: Option<String>,
    /// Server 送出的憑證鏈
    pub server_chain: Vec<CertInfo>,
    /// Client 送出的憑證鏈
    pub client_chain: Vec<CertInfo>,
    /// Server 是否要求 Client 憑證（mTLS）
    pub client_auth_requested: bool,
    /// Server 在 CertificateRequest 中列出可接受的 CA
    pub acceptable_ca_names: Vec<String>,
    pub trust_anchor_count: usize,
    /// 經由的 proxy（不含帳密）
    pub via_proxy: Option<String>,
    /// HTTP 請求結果（有送出請求時）
    pub http: Option<HttpResponse>,
    pub failure: Option<Failure>,
    pub transcript: Vec<TranscriptLine>,
    pub warnings: Vec<String>,
}

impl HandshakeReport {
    fn new(mode: &str, target: String, server_name: String) -> Self {
        HandshakeReport {
            mode: mode.into(),
            target,
            server_name,
            ..Default::default()
        }
    }

    fn fail(&mut self, side: Side, err: &rustls::Error) {
        self.success = false;
        self.failure = Some(Failure {
            side,
            message: err.to_string(),
            hint: explain(err, side),
        });
    }

    fn fail_msg(&mut self, side: Side, message: String, hint: &str) {
        self.success = false;
        self.failure = Some(Failure {
            side,
            message,
            hint: hint.into(),
        });
    }
}

// ───────────────────────────── 共用元件 ─────────────────────────────

#[derive(Debug)]
struct SimTime(Option<i64>);

impl TimeProvider for SimTime {
    fn current_time(&self) -> Option<UnixTime> {
        match self.0 {
            Some(ts) if ts >= 0 => Some(UnixTime::since_unix_epoch(Duration::from_secs(ts as u64))),
            _ => Some(UnixTime::now()),
        }
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// 記錄 Server 送來的憑證鏈，再交給 WebPKI 驗證（或在 insecure 模式下直接接受）。
#[derive(Debug)]
struct RecordingVerifier {
    inner: Option<Arc<WebPkiServerVerifier>>,
    provider: Arc<CryptoProvider>,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if let Ok(mut s) = self.seen.lock() {
            s.clear();
            s.push(end_entity.to_vec());
            s.extend(intermediates.iter().map(|c| c.to_vec()));
        }
        match &self.inner {
            Some(v) => {
                v.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            }
            None => Ok(ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug, Default)]
struct ClientAuthSeen {
    requested: bool,
    hints: Vec<Vec<u8>>,
    sent: bool,
}

/// 記錄 Server 的 CertificateRequest，並提供 Client 憑證（若有）。
#[derive(Debug)]
struct RecordingResolver {
    key: Option<Arc<CertifiedKey>>,
    seen: Arc<Mutex<ClientAuthSeen>>,
}

impl ResolvesClientCert for RecordingResolver {
    fn resolve(
        &self,
        root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        let chosen = self
            .key
            .as_ref()
            .filter(|k| k.key.choose_scheme(sigschemes).is_some())
            .cloned();
        if let Ok(mut s) = self.seen.lock() {
            s.requested = true;
            s.hints = root_hint_subjects.iter().map(|h| h.to_vec()).collect();
            s.sent = chosen.is_some();
        }
        chosen
    }

    fn has_certs(&self) -> bool {
        self.key.is_some()
    }
}

fn dn_to_string(der: &[u8]) -> String {
    // 依 rustls 版本不同，DistinguishedName 可能含或不含外層 SEQUENCE，兩種都試。
    let wrapped = crate::der::encode(crate::der::TAG_SEQUENCE, der);
    for candidate in [der, &wrapped[..]] {
        if let Ok((rest, name)) = X509Name::from_der(candidate) {
            let s = name.to_string();
            if rest.is_empty() && !s.is_empty() {
                return s;
            }
        }
    }
    hex::encode(der)
}

fn certified_key(
    id: &Identity,
    provider: &CryptoProvider,
) -> std::result::Result<Arc<CertifiedKey>, rustls::Error> {
    Ok(Arc::new(CertifiedKey::from_der(
        id.cert_ders(),
        id.key.clone_key(),
        provider,
    )?))
}

fn default_server_name(server: &Identity) -> String {
    server
        .chain
        .first()
        .and_then(|c| {
            c.subject_alt_names
                .iter()
                .find_map(|s| {
                    s.strip_prefix("DNS:")
                        .map(|d| d.trim_start_matches("*.").to_string())
                })
                .or_else(|| {
                    c.subject_alt_names
                        .iter()
                        .find_map(|s| s.strip_prefix("IP:").map(|d| d.to_string()))
                })
                .or_else(|| c.subject_cn.clone())
        })
        .unwrap_or_else(|| "localhost".into())
}

fn parse_server_name(name: &str) -> std::result::Result<ServerName<'static>, String> {
    ServerName::try_from(name.to_string())
        .map_err(|e| format!("「{name}」不是合法的主機名稱或 IP：{e}"))
}

fn fill_negotiated(report: &mut HandshakeReport, conn: &rustls::CommonState) {
    report.protocol = conn.protocol_version().map(|v| match v {
        rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3".to_string(),
        rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2".to_string(),
        other => format!("{other:?}"),
    });
    report.cipher_suite = conn
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()));
    report.key_exchange = conn
        .negotiated_key_exchange_group()
        .map(|g| format!("{:?}", g.name()));
}

fn parse_chain(ders: &[Vec<u8>], warnings: &mut Vec<String>) -> Vec<CertInfo> {
    ders.iter()
        .filter_map(|d| match CertInfo::from_der(d) {
            Ok(c) => Some(c),
            Err(e) => {
                warnings.push(format!("對方送出的憑證無法解析：{e}"));
                None
            }
        })
        .collect()
}

// ───────────────────────────── TLS 紀錄層解析（交握記錄） ─────────────────────────────

#[derive(Default)]
struct RecordTap {
    buf: Vec<u8>,
    encrypted: bool,
}

fn handshake_name(t: u8) -> &'static str {
    match t {
        1 => "ClientHello",
        2 => "ServerHello",
        4 => "NewSessionTicket",
        8 => "EncryptedExtensions",
        11 => "Certificate",
        12 => "ServerKeyExchange",
        13 => "CertificateRequest",
        14 => "ServerHelloDone",
        15 => "CertificateVerify",
        16 => "ClientKeyExchange",
        20 => "Finished",
        _ => "Handshake",
    }
}

fn alert_name(d: u8) -> String {
    format!("{:?}", AlertDescription::from(d))
}

impl RecordTap {
    fn feed(&mut self, data: &[u8], direction: &'static str, out: &mut Vec<TranscriptLine>) {
        self.buf.extend_from_slice(data);
        loop {
            if self.buf.len() < 5 {
                return;
            }
            let ct = self.buf[0];
            let len = u16::from_be_bytes([self.buf[3], self.buf[4]]) as usize;
            if self.buf.len() < 5 + len {
                return;
            }
            let body: Vec<u8> = self.buf[5..5 + len].to_vec();
            self.buf.drain(..5 + len);
            let msg = match ct {
                20 => {
                    self.encrypted = true;
                    "ChangeCipherSpec".to_string()
                }
                21 if !self.encrypted && body.len() >= 2 => format!(
                    "Alert（{}：{}）",
                    if body[0] == 2 { "fatal" } else { "warning" },
                    alert_name(body[1])
                ),
                21 => "Alert（加密）".to_string(),
                22 if !self.encrypted => {
                    let mut names = Vec::new();
                    let mut p = &body[..];
                    while p.len() >= 4 {
                        let hl = ((p[1] as usize) << 16) | ((p[2] as usize) << 8) | p[3] as usize;
                        names.push(handshake_name(p[0]));
                        if p.len() < 4 + hl {
                            break;
                        }
                        p = &p[4 + hl..];
                    }
                    names.join(" + ")
                }
                22 => "加密的握手訊息（Finished）".to_string(),
                23 => "加密資料（TLS 1.3 握手訊息或應用資料）".to_string(),
                other => format!("未知紀錄類型 {other}"),
            };
            out.push(TranscriptLine {
                direction,
                message: format!("{msg}  [{len} bytes]"),
            });
        }
    }
}

// ───────────────────────────── 本機模擬 ─────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct LocalOptions {
    /// Client 連線用的主機名稱（SNI 與名稱驗證），預設取 Server 憑證 SAN
    pub server_name: Option<String>,
    pub version: TlsVersion,
    /// 模擬時間（Unix 秒），None 表示現在
    pub at: Option<i64>,
    /// Server 是否要求 Client 憑證（mTLS）
    pub require_client_auth: bool,
}

/// 本機模擬交握。
///
/// * `server`：Server 身分（私鑰 + 憑證鏈）
/// * `client_trust`：Client 的信任庫
/// * `client`：Client 身分（mTLS 用，可省略）
/// * `server_trust`：Server 用來驗證 Client 憑證的信任庫（mTLS 用）
pub fn simulate_local(
    server: &Identity,
    client_trust: &[CertInfo],
    client: Option<&Identity>,
    server_trust: &[CertInfo],
    opts: &LocalOptions,
) -> HandshakeReport {
    let name = opts
        .server_name
        .clone()
        .unwrap_or_else(|| default_server_name(server));
    let mut report = HandshakeReport::new("local", server.label.clone(), name.clone());
    report.trust_anchor_count = client_trust.len();
    let provider = provider();
    let time: Arc<dyn TimeProvider> = Arc::new(SimTime(opts.at));
    let versions = opts.version.versions();

    // Server 設定
    let server_cfg = (|| -> std::result::Result<ServerConfig, String> {
        let b = ServerConfig::builder_with_details(provider.clone(), time.clone())
            .with_protocol_versions(&versions)
            .map_err(|e| e.to_string())?;
        let b = if opts.require_client_auth {
            let mut w = Vec::new();
            let roots = root_store(server_trust, &mut w);
            report.warnings.extend(w);
            if roots.is_empty() {
                return Err("啟用 mTLS 但 Server 信任庫沒有任何憑證".into());
            }
            let v = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .map_err(|e| format!("建立 Client 憑證驗證器失敗：{e}"))?;
            b.with_client_cert_verifier(v)
        } else {
            b.with_no_client_auth()
        };
        b.with_single_cert(server.cert_ders(), server.key.clone_key())
            .map_err(|e| format!("Server 私鑰與憑證無法使用：{e}"))
    })();
    let server_cfg = match server_cfg {
        Ok(c) => c,
        Err(e) => {
            report.fail_msg(
                Side::Config,
                e,
                "請確認 Server 條目的私鑰與終端憑證相符，且信任庫內容正確。",
            );
            return report;
        }
    };

    // Client 設定
    let seen_chain = Arc::new(Mutex::new(Vec::new()));
    let seen_auth = Arc::new(Mutex::new(ClientAuthSeen::default()));
    let client_cfg = (|| -> std::result::Result<ClientConfig, String> {
        let mut w = Vec::new();
        let roots = root_store(client_trust, &mut w);
        report.warnings.extend(w);
        if roots.is_empty() {
            return Err("Client 信任庫沒有任何憑證".into());
        }
        let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .map_err(|e| format!("建立 Server 憑證驗證器失敗：{e}"))?;
        let key = match client {
            Some(id) => Some(
                certified_key(id, &provider)
                    .map_err(|e| format!("Client 私鑰與憑證無法使用：{e}"))?,
            ),
            None => None,
        };
        Ok(
            ClientConfig::builder_with_details(provider.clone(), time.clone())
                .with_protocol_versions(&versions)
                .map_err(|e| e.to_string())?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(RecordingVerifier {
                    inner: Some(inner),
                    provider: provider.clone(),
                    seen: seen_chain.clone(),
                }))
                .with_client_cert_resolver(Arc::new(RecordingResolver {
                    key,
                    seen: seen_auth.clone(),
                })),
        )
    })();
    let client_cfg = match client_cfg {
        Ok(c) => c,
        Err(e) => {
            report.fail_msg(
                Side::Config,
                e,
                "請確認 Client 信任庫至少包含一張憑證（通常是根 CA）。",
            );
            return report;
        }
    };

    let sn = match parse_server_name(&name) {
        Ok(s) => s,
        Err(e) => {
            report.fail_msg(Side::Config, e, "請用 --sni 指定合法的主機名稱。");
            return report;
        }
    };
    let mut c = match ClientConnection::new(Arc::new(client_cfg), sn) {
        Ok(c) => c,
        Err(e) => {
            report.fail(Side::Client, &e);
            return report;
        }
    };
    let mut s = match ServerConnection::new(Arc::new(server_cfg)) {
        Ok(s) => s,
        Err(e) => {
            report.fail(Side::Server, &e);
            return report;
        }
    };

    let mut tap_c = RecordTap::default();
    let mut tap_s = RecordTap::default();
    let mut failed = false;

    for _ in 0..64 {
        let mut progressed = false;

        // Client → Server
        let mut buf = Vec::new();
        while c.wants_write() {
            if c.write_tls(&mut buf).is_err() {
                break;
            }
        }
        if !buf.is_empty() {
            progressed = true;
            tap_c.feed(&buf, "C→S", &mut report.transcript);
            if let Err(e) = pump_into_server(&mut s, &buf) {
                report.fail(Side::Server, &e);
                failed = true;
            }
        }

        // Server → Client（失敗時也要送出 alert）
        let mut buf = Vec::new();
        while s.wants_write() {
            if s.write_tls(&mut buf).is_err() {
                break;
            }
        }
        if !buf.is_empty() {
            progressed = true;
            tap_s.feed(&buf, "S→C", &mut report.transcript);
            if let Err(e) = pump_into_client(&mut c, &buf) {
                if !failed {
                    report.fail(Side::Client, &e);
                    failed = true;
                }
            }
        }

        if failed {
            // 把 Client 回應的 alert 也記下來
            let mut buf = Vec::new();
            while c.wants_write() {
                if c.write_tls(&mut buf).is_err() {
                    break;
                }
            }
            tap_c.feed(&buf, "C→S", &mut report.transcript);
            break;
        }
        if !c.is_handshaking() && !s.is_handshaking() && !c.wants_write() && !s.wants_write() {
            report.success = true;
            break;
        }
        if !progressed {
            report.fail_msg(
                Side::Network,
                "交握停滯，雙方都沒有資料要送".into(),
                "這通常是程式錯誤，請回報。",
            );
            break;
        }
    }

    fill_negotiated(&mut report, &c);
    let chain = seen_chain.lock().map(|v| v.clone()).unwrap_or_default();
    let mut w = Vec::new();
    report.server_chain = parse_chain(&chain, &mut w);
    report.warnings.extend(w);
    if let Ok(a) = seen_auth.lock() {
        report.client_auth_requested = a.requested;
        report.acceptable_ca_names = a.hints.iter().map(|h| dn_to_string(h)).collect();
        if a.sent {
            report.client_chain = client.map(|c| c.chain.clone()).unwrap_or_default();
        }
    }
    if opts.require_client_auth && client.is_none() && report.failure.is_none() {
        report
            .warnings
            .push("Server 要求 mTLS 但 Client 沒有提供身分".into());
    }
    report
}

fn pump_into_server(
    s: &mut ServerConnection,
    data: &[u8],
) -> std::result::Result<(), rustls::Error> {
    let mut rd = data;
    while !rd.is_empty() {
        s.read_tls(&mut rd)
            .map_err(|e| rustls::Error::General(e.to_string()))?;
        s.process_new_packets()?;
    }
    Ok(())
}

fn pump_into_client(
    c: &mut ClientConnection,
    data: &[u8],
) -> std::result::Result<(), rustls::Error> {
    let mut rd = data;
    while !rd.is_empty() {
        c.read_tls(&mut rd)
            .map_err(|e| rustls::Error::General(e.to_string()))?;
        c.process_new_packets()?;
    }
    Ok(())
}

// ───────────────────────────── 遠端連線 ─────────────────────────────

#[derive(Debug, Clone)]
pub enum RemoteTrust {
    /// 作業系統憑證庫（Windows 憑證存放區 / Linux CA bundle）
    System,
    /// Mozilla 根憑證（webpki-roots）
    Mozilla,
    /// 指定的信任憑證
    Certs(Vec<CertInfo>),
    /// 不驗證，只觀察對方憑證鏈
    Insecure,
}

#[derive(Debug, Clone)]
pub struct RemoteOptions {
    /// host:port、host（預設 443）或 [IPv6]:port
    pub address: String,
    pub server_name: Option<String>,
    pub version: TlsVersion,
    pub at: Option<i64>,
    pub timeout: Duration,
    pub trust: RemoteTrust,
    /// HTTP CONNECT proxy，例如 http://user:pass@proxy:8080；None 表示直連
    pub proxy: Option<String>,
    /// 交握成功後送出的 HTTP 請求（測試 API 用）；None 表示只做交握
    pub http: Option<HttpRequest>,
}

/// 連線目標：主機、連接埠與（選用的）API 路徑。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    /// 例如 "/api/v1/health?x=1"；沒有路徑時為 None
    pub path: Option<String>,
}

/// 解析連線目標，支援：
/// `host`、`host:port`、`[IPv6]:port`、`https://host[:port]/path?query`
pub fn parse_target(input: &str) -> std::result::Result<Target, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("請輸入主機或網址".into());
    }
    let s = if let Some(r) = s.strip_prefix("https://") {
        r
    } else if s.starts_with("http://") {
        return Err("http:// 不是 TLS 連線，請改用 https://".into());
    } else if s.contains("://") {
        return Err("只支援 https:// 網址".into());
    } else {
        s
    };
    let (authority, path) = match s.find(['/', '?']) {
        Some(i) => (&s[..i], Some(&s[i..])),
        None => (s, None),
    };
    let authority = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or("IPv6 位址缺少 ]")?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| format!("連接埠不合法：{p}"))?,
            None => 443,
        };
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (
                h.to_string(),
                p.parse().map_err(|_| format!("連接埠不合法：{p}"))?,
            ),
            _ => (authority.to_string(), 443),
        }
    };
    if host.is_empty() {
        return Err("缺少主機名稱".into());
    }
    let path = path
        .map(|p| {
            if p.starts_with('?') {
                format!("/{p}")
            } else {
                p.to_string()
            }
        })
        .filter(|p| p != "/");
    Ok(Target { host, port, path })
}

/// 解析 "host:port"（也接受完整網址，路徑會被忽略）。
pub fn split_host_port(addr: &str) -> std::result::Result<(String, u16), String> {
    parse_target(addr).map(|t| (t.host, t.port))
}

/// 交握後要送出的 HTTP 請求。
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    /// 路徑（含 query），例如 "/api/health"
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn get(path: impl Into<String>) -> Self {
        HttpRequest {
            method: "GET".into(),
            path: path.into(),
            headers: vec![],
            body: vec![],
        }
    }
}

/// 解析 "Name: value" 形式的標頭。
pub fn parse_header(line: &str) -> std::result::Result<(String, String), String> {
    let (k, v) = line
        .split_once(':')
        .ok_or_else(|| format!("標頭格式應為「名稱: 值」：{line}"))?;
    let k = k.trim();
    if k.is_empty() || k.contains(char::is_whitespace) {
        return Err(format!("標頭名稱不合法：{line}"));
    }
    Ok((k.to_string(), v.trim().to_string()))
}

impl HandshakeReport {
    /// 以純文字輸出完整結果與過程（供複製、貼到工單或 email）。
    ///
    /// 不含 proxy 帳密；敏感的 HTTP 標頭（Authorization、Cookie…）會遮蔽。
    /// `with_pem` 為 true 時附上憑證鏈的 PEM。
    pub fn to_text(&self, with_pem: bool) -> String {
        use std::fmt::Write as _;
        let now = crate::cert::now_ts();
        let mut s = String::new();
        let mode = if self.mode == "local" {
            "本機模擬"
        } else {
            "遠端連線"
        };
        let _ = writeln!(s, "═══ TLS 交握（{mode}）═══");
        let _ = writeln!(s, "時間：{}", crate::cert::format_ts(now));
        let result = if self.success {
            "✔ 交握成功".to_string()
        } else if let Some(f) = &self.failure {
            format!("✘ 交握失敗（{}偵測到錯誤）", f.side)
        } else {
            "✘ 交握失敗".to_string()
        };
        let _ = writeln!(s, "結果：{result}");
        if let Some(f) = &self.failure {
            let _ = writeln!(s, "錯誤：{}", f.message);
            if !f.hint.is_empty() {
                let _ = writeln!(s, "診斷：");
                for l in f.hint.lines() {
                    let _ = writeln!(s, "  {l}");
                }
            }
        }

        let _ = writeln!(s, "\n── 連線資訊 ──");
        let _ = writeln!(s, "目標：{}", self.target);
        let _ = writeln!(s, "SNI / 驗證名稱：{}", self.server_name);
        if let Some(p) = &self.via_proxy {
            let _ = writeln!(s, "經由 Proxy：{p}");
        }
        let _ = writeln!(s, "信任錨點數：{}", self.trust_anchor_count);
        let dash = |o: &Option<String>| o.clone().unwrap_or_else(|| "-".into());
        let _ = writeln!(s, "協定：{}", dash(&self.protocol));
        let _ = writeln!(s, "加密套件：{}", dash(&self.cipher_suite));
        let _ = writeln!(s, "金鑰交換：{}", dash(&self.key_exchange));
        let _ = writeln!(
            s,
            "Server 要求 Client 憑證：{}",
            if self.client_auth_requested {
                "是（mTLS）"
            } else {
                "否"
            }
        );
        if !self.acceptable_ca_names.is_empty() {
            let _ = writeln!(s, "Server 可接受的 Client CA：");
            for n in &self.acceptable_ca_names {
                let _ = writeln!(s, "  - {n}");
            }
        }
        for w in &self.warnings {
            let _ = writeln!(s, "⚠ {w}");
        }

        if !self.transcript.is_empty() {
            let _ = writeln!(s, "\n── 交握訊息 ──");
            for l in &self.transcript {
                let arrow = if l.direction == "C→S" {
                    "Client ──▶ Server"
                } else {
                    "Client ◀── Server"
                };
                let _ = writeln!(s, "{arrow}  {}", l.message);
            }
        }

        for (title, chain) in [
            ("Server 送出的憑證鏈", &self.server_chain),
            ("Client 送出的憑證鏈", &self.client_chain),
        ] {
            if chain.is_empty() {
                continue;
            }
            let _ = writeln!(s, "\n── {title} ──");
            for (i, c) in chain.iter().enumerate() {
                let _ = writeln!(s, "[{i}] {}  {}", c.display_name(), c.status_at(now, 30).label());
                let _ = writeln!(s, "    主體：{}", c.subject);
                let _ = writeln!(s, "    簽發者：{}", c.issuer);
                let _ = writeln!(
                    s,
                    "    有效期間：{} ～ {}",
                    crate::cert::format_ts(c.not_before),
                    crate::cert::format_ts(c.not_after)
                );
                if !c.subject_alt_names.is_empty() {
                    let _ = writeln!(s, "    SAN：{}", c.subject_alt_names.join(", "));
                }
                let _ = writeln!(s, "    序號：{}", c.serial);
                let _ = writeln!(s, "    簽章演算法：{}", c.signature_algorithm);
                let _ = writeln!(s, "    SHA-256：{}", c.sha256);
            }
            if with_pem {
                let _ = writeln!(s);
                for c in chain.iter() {
                    s.push_str(&c.to_pem());
                    if !s.ends_with('\n') {
                        s.push('\n');
                    }
                }
            }
        }

        if let Some(h) = &self.http {
            let _ = writeln!(s, "\n── HTTP 請求 / 回應 ──");
            let _ = writeln!(s, "> {}", h.request_line);
            for (k, v) in &h.request_headers {
                let _ = writeln!(s, "> {k}: {v}");
            }
            if let Some(e) = &h.error {
                let _ = writeln!(s, "✘ {e}");
            }
            if !h.status_line.is_empty() {
                let _ = writeln!(s, "< {}  ({} ms, {} bytes)", h.status_line, h.elapsed_ms, h.body_bytes);
                for (k, v) in &h.headers {
                    let v = if k.eq_ignore_ascii_case("set-cookie") {
                        "***".to_string()
                    } else {
                        mask_header(k, v)
                    };
                    let _ = writeln!(s, "< {k}: {v}");
                }
                let _ = writeln!(s);
                const MAX_LINES: usize = 40;
                for l in h.body_preview.lines().take(MAX_LINES) {
                    let _ = writeln!(s, "{l}");
                }
                if h.truncated || h.body_preview.lines().count() > MAX_LINES {
                    let _ = writeln!(s, "…（共 {} bytes，僅附部分內容）", h.body_bytes);
                }
            }
        }
        s
    }
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct HttpResponse {
    /// 送出的請求列，例如 "GET /api HTTP/1.1"
    pub request_line: String,
    /// 送出的標頭（敏感值已遮蔽）
    pub request_headers: Vec<(String, String)>,
    pub status: Option<u16>,
    pub status_line: String,
    pub headers: Vec<(String, String)>,
    pub body_preview: String,
    pub body_bytes: usize,
    pub truncated: bool,
    pub elapsed_ms: u128,
    pub error: Option<String>,
}

const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "api-key",
    "apikey",
];

fn mask_header(k: &str, v: &str) -> String {
    let lk = k.to_ascii_lowercase();
    if SENSITIVE_HEADERS.contains(&lk.as_str()) || lk.contains("token") || lk.contains("secret") {
        match v.split_once(' ') {
            Some((scheme, _)) if lk.contains("authorization") => format!("{scheme} ***"),
            _ => "***".into(),
        }
    } else {
        v.to_string()
    }
}

const MAX_BODY: usize = 1024 * 1024;
const PREVIEW: usize = 8 * 1024;

fn do_http(
    conn: &mut ClientConnection,
    sock: &mut TcpStream,
    host: &str,
    port: u16,
    req: &HttpRequest,
) -> HttpResponse {
    let start = std::time::Instant::now();
    let host_hdr = {
        let h = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_string()
        };
        if port == 443 {
            h
        } else {
            format!("{h}:{port}")
        }
    };
    let path = if req.path.is_empty() {
        "/".to_string()
    } else {
        req.path.clone()
    };
    let method = req.method.trim().to_ascii_uppercase();
    let has = |name: &str| {
        req.headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case(name))
    };
    let mut headers: Vec<(String, String)> = Vec::new();
    if !has("host") {
        headers.push(("Host".into(), host_hdr));
    }
    if !has("user-agent") {
        headers.push((
            "User-Agent".into(),
            concat!("rust-ca/", env!("CARGO_PKG_VERSION")).into(),
        ));
    }
    if !has("accept") {
        headers.push(("Accept".into(), "*/*".into()));
    }
    headers.extend(req.headers.iter().cloned());
    if !has("content-length")
        && (!req.body.is_empty() || matches!(method.as_str(), "POST" | "PUT" | "PATCH"))
    {
        headers.push(("Content-Length".into(), req.body.len().to_string()));
    }
    if !has("connection") {
        headers.push(("Connection".into(), "close".into()));
    }

    let request_line = format!("{method} {path} HTTP/1.1");
    let mut resp = HttpResponse {
        request_line: request_line.clone(),
        request_headers: headers
            .iter()
            .map(|(k, v)| (k.clone(), mask_header(k, v)))
            .collect(),
        ..Default::default()
    };
    let mut raw = format!("{request_line}\r\n");
    for (k, v) in &headers {
        raw.push_str(&format!("{k}: {v}\r\n"));
    }
    raw.push_str("\r\n");
    let mut payload = raw.into_bytes();
    payload.extend(&req.body);

    let mut tls = rustls::Stream::new(conn, sock);
    if let Err(e) = tls.write_all(&payload).and_then(|_| tls.flush()) {
        resp.error = Some(format!("送出 HTTP 請求失敗：{e}"));
        return resp;
    }

    // 讀取回應（直到連線關閉、內容長度滿足或達上限）
    let mut data = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    let mut read_err = None;
    loop {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                data.extend_from_slice(&buf[..n]);
                if data.len() > MAX_BODY {
                    resp.truncated = true;
                    break;
                }
                if response_complete(&data, &method) {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                read_err = Some(e);
                break;
            }
        }
    }
    resp.elapsed_ms = start.elapsed().as_millis();

    let Some(hdr_end) = find_subslice(&data, b"\r\n\r\n") else {
        resp.error = Some(match read_err {
            Some(e) => format!("讀取 HTTP 回應失敗：{e}"),
            None if data.is_empty() => "Server 沒有回應任何資料就關閉連線".into(),
            None => "HTTP 回應不完整".into(),
        });
        return resp;
    };
    let head = String::from_utf8_lossy(&data[..hdr_end]).to_string();
    let mut lines = head.split("\r\n");
    resp.status_line = lines.next().unwrap_or_default().to_string();
    resp.status = resp
        .status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok());
    resp.headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();

    let mut body = data[hdr_end + 4..].to_vec();
    let chunked = resp.headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
    });
    if chunked {
        body = decode_chunked(&body);
    }
    resp.body_bytes = body.len();
    let encoded = resp.headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("content-encoding") && !v.eq_ignore_ascii_case("identity")
    });
    resp.body_preview = if encoded {
        format!("（內容經過壓縮編碼，{} bytes）", body.len())
    } else {
        match std::str::from_utf8(&body[..body.len().min(PREVIEW)]) {
            Ok(t) => t.to_string(),
            Err(e) if e.valid_up_to() > 0 && body.len() > PREVIEW => {
                String::from_utf8_lossy(&body[..e.valid_up_to()]).into_owned()
            }
            Err(_) => format!("（二進位資料，{} bytes）", body.len()),
        }
    };
    if body.len() > PREVIEW {
        resp.truncated = true;
    }
    if let (Some(e), None) = (read_err, resp.status) {
        resp.error = Some(format!("讀取 HTTP 回應失敗：{e}"));
    }
    resp
}

fn find_subslice(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

fn response_complete(data: &[u8], method: &str) -> bool {
    let Some(end) = find_subslice(data, b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&data[..end]).to_ascii_lowercase();
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    if method == "HEAD" || status == 204 || status == 304 || (100..200).contains(&status) {
        return true;
    }
    let body = &data[end + 4..];
    for line in head.lines() {
        if let Some(v) = line.strip_prefix("content-length:") {
            if let Ok(n) = v.trim().parse::<usize>() {
                return body.len() >= n;
            }
        }
        if line.starts_with("transfer-encoding:") && line.contains("chunked") {
            return find_subslice(body, b"\r\n0\r\n\r\n").is_some()
                || body.starts_with(b"0\r\n\r\n");
        }
    }
    false
}

fn decode_chunked(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(i) = find_subslice(b, b"\r\n") {
        let size_str = String::from_utf8_lossy(&b[..i]);
        let size =
            usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
        b = &b[i + 2..];
        if size == 0 || b.len() < size {
            out.extend_from_slice(&b[..size.min(b.len())]);
            break;
        }
        out.extend_from_slice(&b[..size]);
        b = &b[(size + 2).min(b.len())..];
    }
    out
}

type ConnectError = (String, &'static str);

fn tcp_connect(
    host: &str,
    port: u16,
    timeout: Duration,
) -> std::result::Result<TcpStream, ConnectError> {
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| {
            (
                format!("無法解析主機 {host}：{e}"),
                "請確認主機名稱與 DNS 設定；企業內網可能需要 --proxy。",
            )
        })?
        .collect();
    let mut errors = Vec::new();
    for a in &addrs {
        match TcpStream::connect_timeout(a, timeout) {
            Ok(s) => return Ok(s),
            Err(e) => errors.push(format!("{a}：{e}")),
        }
    }
    Err((
        format!("TCP 連線失敗：{}", errors.join("；")),
        "請確認主機與連接埠可連線、防火牆設定；企業內網通常需要透過 proxy（--proxy 或 HTTPS_PROXY）。",
    ))
}

/// HTTP CONNECT proxy 設定。
#[derive(Clone)]
pub struct ProxyConfig {
    host: String,
    port: u16,
    /// base64(user:pass)
    auth: Option<String>,
}

impl std::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.display())
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 3 <= b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl ProxyConfig {
    pub fn parse(url: &str) -> std::result::Result<Self, String> {
        use base64::Engine;
        let rest = url.trim();
        let rest = if let Some(r) = rest.strip_prefix("http://") {
            r
        } else if rest.contains("://") {
            return Err("只支援 http:// 形式的 proxy（HTTP CONNECT）".into());
        } else {
            rest
        };
        let rest = rest.trim_end_matches('/');
        let (auth, hostport) = match rest.rsplit_once('@') {
            Some((a, h)) => (Some(a), h),
            None => (None, rest),
        };
        let (host, port) = split_host_port(hostport)?;
        let port = if hostport.contains(':') { port } else { 8080 };
        let auth = auth.map(|a| {
            let (u, p) = a.split_once(':').unwrap_or((a, ""));
            let cred = format!("{}:{}", percent_decode(u), percent_decode(p));
            base64::engine::general_purpose::STANDARD.encode(cred)
        });
        Ok(ProxyConfig { host, port, auth })
    }

    /// 顯示用（不含帳密）。
    pub fn display(&self) -> String {
        format!(
            "http://{}{}:{}",
            if self.auth.is_some() { "***@" } else { "" },
            self.host,
            self.port
        )
    }

    fn connect(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> std::result::Result<TcpStream, ConnectError> {
        let mut sock = tcp_connect(&self.host, self.port, timeout).map_err(|(m, _)| {
            (
                format!("無法連到 proxy {}：{m}", self.display()),
                "請確認 proxy 位址與連接埠。",
            )
        })?;
        let _ = sock.set_read_timeout(Some(timeout));
        let _ = sock.set_write_timeout(Some(timeout));
        let target = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
        if let Some(a) = &self.auth {
            req.push_str(&format!("Proxy-Authorization: Basic {a}\r\n"));
        }
        req.push_str("\r\n");
        sock.write_all(req.as_bytes())
            .map_err(|e| (format!("送出 CONNECT 失敗：{e}"), "請確認 proxy 是否正常。"))?;
        // 逐 byte 讀取回應標頭，避免吃到後面的 TLS 資料
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match sock.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => head.push(byte[0]),
                Err(e) => {
                    return Err((
                        format!("讀取 proxy 回應失敗：{e}"),
                        "proxy 沒有回應，可能逾時。",
                    ))
                }
            }
            if head.len() > 16 * 1024 {
                return Err((
                    "proxy 回應標頭過長".into(),
                    "請確認 proxy 是否為 HTTP proxy。",
                ));
            }
        }
        let text = String::from_utf8_lossy(&head);
        let status_line = text.lines().next().unwrap_or("").to_string();
        let code = status_line.split_whitespace().nth(1).unwrap_or("");
        match code {
            "200" => Ok(sock),
            "407" => Err((
                format!("proxy 需要認證：{status_line}"),
                "請在 proxy URL 中帶入帳密，例如 http://user:pass@proxy:8080（密碼中的特殊字元請用 % 編碼）。",
            )),
            _ => Err((
                format!("proxy 拒絕 CONNECT {target}：{status_line}"),
                "proxy 可能禁止連到此主機或連接埠。",
            )),
        }
    }
}

/// 自動決定 proxy：HTTPS_PROXY 環境變數優先，其次是 Windows 系統 proxy 設定。
/// 回傳 (proxy URL, 來源說明)。
pub fn auto_proxy(target_host: &str) -> Option<(String, &'static str)> {
    if std::env::var("https_proxy")
        .or_else(|_| std::env::var("HTTPS_PROXY"))
        .is_ok_and(|v| !v.trim().is_empty())
    {
        return proxy_from_env(target_host).map(|p| (p, "HTTPS_PROXY 環境變數"));
    }
    windows_system_proxy(target_host).map(|p| (p, "Windows 系統 proxy 設定"))
}

/// 讀取 Windows「網際網路選項」的 proxy 設定（HKCU\...\Internet Settings）。非 Windows 平台回傳 None。
pub fn windows_system_proxy(target_host: &str) -> Option<String> {
    let (enabled, server, overrides) = winreg::read_proxy_settings()?;
    if !enabled {
        return None;
    }
    let proxy = parse_proxy_server(&server)?;
    if windows_bypass_match(target_host, &overrides) {
        return None;
    }
    Some(proxy)
}

/// 解析 ProxyServer：「host:port」或「http=host:port;https=host:port;…」。
pub fn parse_proxy_server(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let pick = if s.contains('=') {
        let map: Vec<(String, String)> = s
            .split(';')
            .filter_map(|p| p.split_once('='))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
            .collect();
        ["https", "http"]
            .iter()
            .find_map(|k| map.iter().find(|(mk, _)| mk == k).map(|(_, v)| v.clone()))?
    } else {
        s.to_string()
    };
    let pick = pick.trim_start_matches("http://").to_string();
    (!pick.is_empty()).then(|| format!("http://{pick}"))
}

/// 判斷主機是否符合 Windows ProxyOverride（以 ; 分隔，支援 * 萬用字元與 <local>）。
pub fn windows_bypass_match(host: &str, overrides: &str) -> bool {
    let h = host.to_ascii_lowercase();
    overrides
        .split(';')
        .map(|r| r.trim().to_ascii_lowercase())
        .filter(|r| !r.is_empty())
        .any(|rule| {
            if rule == "<local>" {
                !h.contains('.') && !h.contains(':')
            } else {
                glob_match(&rule, &h)
            }
        })
}

/// 只支援 * 的萬用字元比對。
fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti, mut star, mut mark) = (0usize, 0usize, None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && p[pi] != '*' && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(windows)]
mod winreg {
    use std::ffi::c_void;

    type Hkey = isize;
    // HKEY_CURRENT_USER = (HKEY)(LONG)0x80000001，在 64 位元下為符號延伸
    const HKCU: Hkey = 0x8000_0001u32 as i32 as isize;
    const RRF_RT_REG_SZ: u32 = 0x0000_0002;
    const RRF_RT_REG_DWORD: u32 = 0x0000_0010;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegGetValueW(
            hkey: Hkey,
            subkey: *const u16,
            value: *const u16,
            flags: u32,
            ty: *mut u32,
            data: *mut c_void,
            len: *mut u32,
        ) -> i32;
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    fn read_dword(name: &str) -> Option<u32> {
        let (k, v) = (wide(KEY), wide(name));
        let mut data = 0u32;
        let mut len = 4u32;
        // SAFETY: 緩衝區大小正確，字串以 NUL 結尾。
        let rc = unsafe {
            RegGetValueW(
                HKCU,
                k.as_ptr(),
                v.as_ptr(),
                RRF_RT_REG_DWORD,
                std::ptr::null_mut(),
                &mut data as *mut u32 as *mut c_void,
                &mut len,
            )
        };
        (rc == 0).then_some(data)
    }

    fn read_sz(name: &str) -> Option<String> {
        let (k, v) = (wide(KEY), wide(name));
        let mut len = 0u32;
        // SAFETY: 第一次呼叫只查詢所需長度。
        let rc = unsafe {
            RegGetValueW(
                HKCU,
                k.as_ptr(),
                v.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut len,
            )
        };
        if rc != 0 || len == 0 {
            return None;
        }
        let mut buf = vec![0u16; (len as usize).div_ceil(2)];
        // SAFETY: buf 大小等於上一步回報的位元組數。
        let rc = unsafe {
            RegGetValueW(
                HKCU,
                k.as_ptr(),
                v.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buf.as_mut_ptr() as *mut c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return None;
        }
        let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..end]))
    }

    pub fn read_proxy_settings() -> Option<(bool, String, String)> {
        let enabled = read_dword("ProxyEnable").unwrap_or(0) != 0;
        let server = read_sz("ProxyServer").unwrap_or_default();
        let overrides = read_sz("ProxyOverride").unwrap_or_default();
        Some((enabled, server, overrides))
    }
}

#[cfg(not(windows))]
mod winreg {
    pub fn read_proxy_settings() -> Option<(bool, String, String)> {
        None
    }
}

/// 依 HTTPS_PROXY / NO_PROXY 環境變數決定要不要使用 proxy。
pub fn proxy_from_env(target_host: &str) -> Option<String> {
    let get = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
    let proxy = get("https_proxy").or_else(|| get("HTTPS_PROXY"))?;
    let no_proxy = get("no_proxy")
        .or_else(|| get("NO_PROXY"))
        .unwrap_or_default();
    if no_proxy_match(target_host, &no_proxy) {
        None
    } else {
        Some(proxy)
    }
}

/// 判斷主機是否符合 NO_PROXY 規則（逗號分隔，支援 .domain、*.domain、*）。
pub fn no_proxy_match(host: &str, no_proxy: &str) -> bool {
    let h = host.to_ascii_lowercase();
    no_proxy
        .split(',')
        .map(|r| r.trim().to_ascii_lowercase())
        .filter(|r| !r.is_empty())
        .any(|rule| {
            if rule == "*" {
                return true;
            }
            let bare = rule.trim_start_matches('*').trim_start_matches('.');
            h == bare || h.ends_with(&format!(".{bare}"))
        })
}

/// 以 Client 身分連到遠端 Server 進行交握。
pub fn connect_remote(opts: &RemoteOptions, client: Option<&Identity>) -> HandshakeReport {
    let (host, port) = match parse_target(&opts.address).map(|t| (t.host, t.port)) {
        Ok(v) => v,
        Err(e) => {
            let mut r = HandshakeReport::new("remote", opts.address.clone(), String::new());
            r.fail_msg(Side::Config, e, "格式：host、host:port 或 [IPv6]:port");
            return r;
        }
    };
    let name = opts.server_name.clone().unwrap_or_else(|| host.clone());
    let mut report = HandshakeReport::new("remote", format!("{host}:{port}"), name.clone());
    let provider = provider();
    let time: Arc<dyn TimeProvider> = Arc::new(SimTime(opts.at));

    // 信任庫
    let mut roots = RootCertStore::empty();
    let insecure = matches!(opts.trust, RemoteTrust::Insecure);
    match &opts.trust {
        RemoteTrust::System => {
            let res = rustls_native_certs::load_native_certs();
            for e in res.errors.iter().take(3) {
                report
                    .warnings
                    .push(format!("讀取系統憑證庫時發生錯誤：{e}"));
            }
            let (added, ignored) = roots.add_parsable_certificates(res.certs);
            if ignored > 0 {
                report
                    .warnings
                    .push(format!("系統憑證庫中有 {ignored} 張憑證無法使用"));
            }
            let _ = added;
        }
        RemoteTrust::Mozilla => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        RemoteTrust::Certs(c) => {
            let mut w = Vec::new();
            roots = root_store(c, &mut w);
            report.warnings.extend(w);
        }
        RemoteTrust::Insecure => report
            .warnings
            .push("insecure 模式：不驗證 Server 憑證，只觀察交握結果".into()),
    }
    report.trust_anchor_count = roots.len();

    let seen_chain = Arc::new(Mutex::new(Vec::new()));
    let seen_auth = Arc::new(Mutex::new(ClientAuthSeen::default()));
    let cfg = (|| -> std::result::Result<ClientConfig, String> {
        let inner = if insecure {
            None
        } else {
            if roots.is_empty() {
                return Err("信任庫沒有任何憑證".into());
            }
            Some(
                WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                    .build()
                    .map_err(|e| format!("建立驗證器失敗：{e}"))?,
            )
        };
        let key = match client {
            Some(id) => Some(
                certified_key(id, &provider)
                    .map_err(|e| format!("Client 私鑰與憑證無法使用：{e}"))?,
            ),
            None => None,
        };
        let mut cfg = ClientConfig::builder_with_details(provider.clone(), time)
            .with_protocol_versions(&opts.version.versions())
            .map_err(|e| e.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(RecordingVerifier {
                inner,
                provider: provider.clone(),
                seen: seen_chain.clone(),
            }))
            .with_client_cert_resolver(Arc::new(RecordingResolver {
                key,
                seen: seen_auth.clone(),
            }));
        if opts.http.is_some() {
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        }
        Ok(cfg)
    })();
    let cfg = match cfg {
        Ok(c) => c,
        Err(e) => {
            report.fail_msg(Side::Config, e, "請確認信任庫與 Client 身分設定。");
            return report;
        }
    };

    let sn = match parse_server_name(&name) {
        Ok(s) => s,
        Err(e) => {
            report.fail_msg(Side::Config, e, "請用 --sni 指定合法的主機名稱。");
            return report;
        }
    };

    // TCP 連線（直連或經由 proxy）
    let sock = match &opts.proxy {
        Some(p) => match ProxyConfig::parse(p) {
            Ok(proxy) => {
                report.via_proxy = Some(proxy.display());
                proxy.connect(&host, port, opts.timeout)
            }
            Err(e) => Err((e, "Proxy 格式：http://[user:pass@]host:port")),
        },
        None => tcp_connect(&host, port, opts.timeout),
    };
    let mut sock = match sock {
        Ok(s) => s,
        Err((msg, hint)) => {
            report.fail_msg(Side::Network, msg, hint);
            return report;
        }
    };
    let _ = sock.set_read_timeout(Some(opts.timeout));
    let _ = sock.set_write_timeout(Some(opts.timeout));

    let mut conn = match ClientConnection::new(Arc::new(cfg), sn) {
        Ok(c) => c,
        Err(e) => {
            report.fail(Side::Client, &e);
            return report;
        }
    };

    let mut tap_c = RecordTap::default();
    let mut tap_s = RecordTap::default();
    let result = (|| -> std::result::Result<(), (Side, rustls::Error)> {
        let mut buf = [0u8; 16 * 1024];
        while conn.is_handshaking() || conn.wants_write() {
            while conn.wants_write() {
                let mut out = Vec::new();
                conn.write_tls(&mut out)
                    .map_err(|e| (Side::Network, rustls::Error::General(e.to_string())))?;
                tap_c.feed(&out, "C→S", &mut report.transcript);
                sock.write_all(&out).map_err(|e| {
                    (
                        Side::Network,
                        rustls::Error::General(format!("寫入失敗：{e}")),
                    )
                })?;
            }
            if !conn.is_handshaking() {
                break;
            }
            let n = sock.read(&mut buf).map_err(|e| {
                (
                    Side::Network,
                    rustls::Error::General(format!("讀取失敗：{e}")),
                )
            })?;
            if n == 0 {
                return Err((
                    Side::Network,
                    rustls::Error::General("Server 關閉了連線（交握未完成）".into()),
                ));
            }
            tap_s.feed(&buf[..n], "S→C", &mut report.transcript);
            let mut rd = &buf[..n];
            while !rd.is_empty() {
                conn.read_tls(&mut rd)
                    .map_err(|e| (Side::Network, rustls::Error::General(e.to_string())))?;
                if let Err(e) = conn.process_new_packets() {
                    // 把 alert 送出去
                    let mut out = Vec::new();
                    let _ = conn.write_tls(&mut out);
                    tap_c.feed(&out, "C→S", &mut report.transcript);
                    let _ = sock.write_all(&out);
                    return Err((Side::Client, e));
                }
            }
        }
        Ok(())
    })();

    match result {
        Ok(()) => {
            report.success = true;
            if let Some(req) = &opts.http {
                report.http = Some(do_http(&mut conn, &mut sock, &host, port, req));
            }
            conn.send_close_notify();
            let mut out = Vec::new();
            let _ = conn.write_tls(&mut out);
            let _ = sock.write_all(&out);
        }
        Err((side, e)) => {
            // TLS 1.3 下 Server 拒絕 Client 憑證時，常表現為收到 alert 或連線被關閉
            report.fail(side, &e);
        }
    }

    fill_negotiated(&mut report, &conn);
    let chain = seen_chain.lock().map(|v| v.clone()).unwrap_or_default();
    let mut w = Vec::new();
    report.server_chain = parse_chain(&chain, &mut w);
    report.warnings.extend(w);
    if report.via_proxy.is_some() {
        if let (Some(f), Some(top)) = (report.failure.as_mut(), report.server_chain.last()) {
            if f.message.contains("UnknownIssuer") {
                f.hint.push_str(&format!(
                    "\n目前經由 proxy 連線：企業 proxy 可能進行 TLS 檢查（SSL inspection），以自家 CA 重新簽發憑證。\n\
                     收到的憑證鏈頂端簽發者：{}\n\
                     若此為企業 CA，請改用系統信任庫（不加 --mozilla / -t），或把該 CA 加入信任庫；也可用 --no-proxy 直連比較。",
                    top.issuer
                ));
            }
        }
    }
    if let Ok(a) = seen_auth.lock() {
        report.client_auth_requested = a.requested;
        report.acceptable_ca_names = a.hints.iter().map(|h| dn_to_string(h)).collect();
        if a.sent {
            report.client_chain = client.map(|c| c.chain.clone()).unwrap_or_default();
        } else if a.requested && report.failure.is_some() {
            if let Some(f) = report.failure.as_mut() {
                f.hint.push_str(if client.is_some() {
                    "\nServer 有要求 Client 憑證，但提供的憑證不符合 Server 支援的簽章演算法。"
                } else {
                    "\nServer 有要求 Client 憑證（mTLS），但未提供 Client 身分；請用 --client 指定含私鑰的憑證庫。"
                });
            }
        }
    }
    report
}

// ───────────────────────────── 錯誤診斷 ─────────────────────────────

/// AlgorithmIdentifier 內容是否為 ecdsa-with-SHAxxx 且帶有 NULL 參數。
fn is_ecdsa_with_null_params(alg_id: &[u8]) -> bool {
    // 06 08 2A 86 48 CE 3D 04 03 xx 05 00
    alg_id.len() == 12
        && alg_id.starts_with(&[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03])
        && alg_id.ends_with(&[0x05, 0x00])
}

/// 將 rustls 錯誤轉為中文診斷建議。`side` 是偵測到錯誤的一方。
pub fn explain(err: &rustls::Error, side: Side) -> String {
    let peer = match side {
        Side::Client => "Server",
        Side::Server => "Client",
        _ => "對方",
    };
    let trust = match side {
        Side::Client => "Client 信任庫",
        Side::Server => "Server 信任庫（驗證 Client 憑證用）",
        _ => "信任庫",
    };
    use rustls::Error as E;
    match err {
        E::InvalidCertificate(ce) => match ce {
            CertificateError::UnknownIssuer => format!(
                "{peer} 的憑證鏈無法連到 {trust}中的任何憑證。\n可能原因：\n  1. {trust}缺少根 CA 或中繼 CA\n  2. {peer} 沒有送出完整的中繼憑證（條目中的鏈不完整）\n  3. 使用了不同 CA 簽發的憑證"
            ),
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                format!("{peer} 憑證鏈中有憑證已過期，請更新憑證。")
            }
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                format!("{peer} 憑證尚未生效，請確認系統時間或憑證的 NotBefore。")
            }
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                "Server 憑證的 SAN 不包含連線使用的主機名稱。\n請確認憑證 SAN（DNS/IP）或用 --sni 指定正確名稱。注意：只看 SAN，不看 CN。".into()
            }
            CertificateError::InvalidPurpose | CertificateError::InvalidPurposeContext { .. } => format!(
                "{peer} 憑證的 Extended Key Usage 不允許此用途（Server 憑證需 serverAuth，Client 憑證需 clientAuth）。"
            ),
            CertificateError::BadSignature => "憑證簽章驗證失敗，憑證鏈中某張憑證的簽發者不正確或憑證遭竄改。".into(),
            CertificateError::Revoked => "憑證已被撤銷。".into(),
            CertificateError::UnsupportedSignatureAlgorithmContext { signature_algorithm_id, .. }
                if is_ecdsa_with_null_params(signature_algorithm_id) =>
            {
                "憑證的 ECDSA 簽章演算法識別碼帶有 NULL 參數（Java 8 keytool 等舊工具產生的非標準編碼，違反 RFC 5758）。\n\
                 rustls / webpki 會嚴格拒絕；Java 與 OpenSSL 通常可接受。\n\
                 建議用 Java 11 以上版本的 keytool 或 openssl 重新簽發憑證。"
                    .into()
            }
            CertificateError::UnsupportedSignatureAlgorithmContext { .. }
            | CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext { .. } => {
                "憑證使用不支援的簽章演算法（例如 SHA-1、MD5 或 DSA），現代 TLS 實作會拒絕。".into()
            }
            CertificateError::BadEncoding => "憑證編碼錯誤。".into(),
            CertificateError::Other(o) => {
                let s = o.to_string();
                if s.contains("CaUsedAsEndEntity") {
                    format!("{peer} 的終端憑證是 CA 憑證（BasicConstraints CA=true），不能直接作為 TLS 憑證。")
                } else {
                    format!("憑證驗證失敗：{s}")
                }
            }
            other => format!("憑證驗證失敗：{other:?}"),
        },
        E::NoCertificatesPresented => match side {
            Side::Server => "Server 要求 Client 憑證（mTLS），但 Client 沒有送出憑證。\n請提供 Client 身分，並確認其憑證鏈由 Server 信任的 CA 簽發。".into(),
            _ => "對方沒有送出憑證。".into(),
        },
        E::AlertReceived(a) => {
            let base = format!("收到 {peer} 的 alert：{a:?}。");
            let extra = match a {
                AlertDescription::BadCertificate | AlertDescription::UnknownCA => {
                    "對方不接受我方送出的憑證（多半是 mTLS 的 Client 憑證不被 Server 信任）。"
                }
                AlertDescription::CertificateRequired => "Server 要求 Client 憑證（mTLS），但沒有送出。",
                AlertDescription::CertificateExpired => "對方認為我方憑證已過期。",
                AlertDescription::HandshakeFailure => {
                    "雙方找不到共同支援的 TLS 版本、加密套件或簽章演算法，或對方拒絕了 Client 憑證。"
                }
                AlertDescription::ProtocolVersion => "對方不支援所選的 TLS 版本。",
                AlertDescription::UnrecognisedName => "對方不認得 SNI 主機名稱。",
                AlertDescription::DecryptError => "簽章或金鑰驗證失敗（私鑰與憑證可能不匹配）。",
                _ => "",
            };
            format!("{base}{extra}")
        }
        E::PeerIncompatible(p) => format!(
            "雙方設定不相容：{p:?}。\n常見原因：TLS 版本不一致（例如對方只支援 TLS 1.0/1.1）、沒有共同的加密套件或簽章演算法。"
        ),
        E::InvalidMessage(m) => format!("收到不合法的 TLS 訊息：{m:?}。對方可能不是 TLS 服務（例如連到 HTTP 埠）。"),
        E::InconsistentKeys(_) => "私鑰與憑證的公鑰不相符。".into(),
        E::General(s) if s.contains("關閉") || s.contains("reset") || s.contains("forcibly") => {
            "連線被對方中斷。若 Server 啟用 mTLS，可能是 Client 憑證被拒絕（TLS 1.3 下 Server 可能在 Client 送完憑證後才中斷）。".into()
        }
        E::General(s)
            if ["timed out", "逾時", "WouldBlock", "Resource temporarily unavailable", "os error 10060", "os error 110)"]
                .iter()
                .any(|k| s.contains(k)) =>
        {
            "連線逾時：對方沒有回應。企業內網常會擋掉直接連外，請改用 proxy（--proxy、HTTPS_PROXY 或 Windows 系統 proxy 設定），或確認防火牆規則。".into()
        }
        _ => String::new(),
    }
}
