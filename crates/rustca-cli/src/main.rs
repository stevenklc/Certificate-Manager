//! RUST-CA 命令列工具：查看 keystore、憑證鏈、搜尋關鍵字、模擬 TLS 交握。

mod console;
mod output;
mod store;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{bail, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use rustca_core::tls::{self, LocalOptions, RemoteOptions, RemoteTrust, TlsVersion};
use rustca_core::{build_chain, now_ts, parse_date, search, CertInfo};

use crate::output::Out;
use crate::store::{PasswordArgs, StoreOpener};

#[derive(Parser)]
#[command(
    name = "rust-ca",
    version,
    about = "查看 JKS / JCEKS / PKCS#12 / PEM / CER 憑證庫、憑證鏈、有效期限，並模擬 TLS 交握",
    after_help = "密碼可用 -p 指定、設定環境變數 RUST_CA_PASSWORD，或在提示時輸入（建議，避免留在 shell 歷史）。"
)]
struct Cli {
    /// 以 JSON 輸出
    #[arg(long, global = true)]
    json: bool,
    /// 不使用顏色
    #[arg(long, global = true)]
    no_color: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 列出憑證庫條目與有效期限
    #[command(alias = "ls")]
    List {
        #[arg(required = true)]
        files: Vec<PathBuf>,
        #[command(flatten)]
        pw: PasswordArgs,
        /// 幾天內到期視為「即將到期」
        #[arg(long, default_value_t = 30)]
        warn_days: i64,
    },
    /// 顯示憑證詳細資訊
    Show {
        file: PathBuf,
        /// 只顯示指定別名
        #[arg(short, long)]
        alias: Option<String>,
        #[command(flatten)]
        pw: PasswordArgs,
        /// 一併輸出 PEM
        #[arg(long)]
        pem: bool,
        #[arg(long, default_value_t = 30)]
        warn_days: i64,
    },
    /// 分析憑證鏈組成（終端 → 中繼 → 根）
    Chain {
        file: PathBuf,
        #[arg(short, long)]
        alias: Option<String>,
        #[command(flatten)]
        pw: PasswordArgs,
        /// 額外的信任庫 / CA 檔案，用來補齊憑證鏈
        #[arg(short, long = "trust")]
        trust: Vec<PathBuf>,
        /// 額外信任庫的密碼
        #[arg(long, env = "RUST_CA_TRUST_PASSWORD", hide_env_values = true)]
        trust_password: Option<String>,
        #[arg(long, default_value_t = 30)]
        warn_days: i64,
    },
    /// 搜尋關鍵字（別名、主體、簽發者、SAN、序號、指紋…）
    #[command(alias = "find")]
    Search {
        keyword: String,
        #[arg(required = true)]
        files: Vec<PathBuf>,
        #[command(flatten)]
        pw: PasswordArgs,
    },
    /// 檢查到期狀況（適合排程：有過期回傳 2、即將到期回傳 1）
    Expiry {
        #[arg(required = true)]
        files: Vec<PathBuf>,
        #[command(flatten)]
        pw: PasswordArgs,
        #[arg(long, default_value_t = 30)]
        days: i64,
        /// 列出全部憑證（預設只列出有問題的）
        #[arg(long)]
        all: bool,
    },
    /// 模擬 TLS 交握
    #[command(subcommand)]
    Handshake(HandshakeCmd),
}

#[derive(Clone, Copy, ValueEnum)]
enum VersionArg {
    Auto,
    #[value(name = "1.2")]
    V12,
    #[value(name = "1.3")]
    V13,
}

impl From<VersionArg> for TlsVersion {
    fn from(v: VersionArg) -> Self {
        match v {
            VersionArg::Auto => TlsVersion::Auto,
            VersionArg::V12 => TlsVersion::Tls12,
            VersionArg::V13 => TlsVersion::Tls13,
        }
    }
}

#[derive(Args)]
struct CommonTls {
    /// 主機名稱（SNI 與憑證名稱驗證）
    #[arg(long)]
    sni: Option<String>,
    /// TLS 版本
    #[arg(long = "tls", value_enum, default_value = "auto")]
    version: VersionArg,
    /// 以指定時間模擬（YYYY-MM-DD 或 RFC3339），可檢查憑證到期後是否還能交握
    #[arg(long)]
    at: Option<String>,
}

#[derive(Subcommand)]
enum HandshakeCmd {
    /// 本機模擬：用兩組憑證庫分別扮演 Server 與 Client
    Local {
        /// Server 憑證庫（需含私鑰）
        #[arg(long)]
        server: PathBuf,
        #[arg(long)]
        server_alias: Option<String>,
        #[arg(long, env = "RUST_CA_SERVER_PASSWORD", hide_env_values = true)]
        server_password: Option<String>,

        /// Client 信任庫（可多個）
        #[arg(long = "client-trust", required = true)]
        client_trust: Vec<PathBuf>,
        #[arg(long, env = "RUST_CA_CLIENT_TRUST_PASSWORD", hide_env_values = true)]
        client_trust_password: Option<String>,

        /// 啟用雙向 TLS（Server 要求 Client 憑證）
        #[arg(long)]
        mtls: bool,
        /// Client 憑證庫（mTLS 用，需含私鑰）
        #[arg(long)]
        client: Option<PathBuf>,
        #[arg(long)]
        client_alias: Option<String>,
        #[arg(long, env = "RUST_CA_CLIENT_PASSWORD", hide_env_values = true)]
        client_password: Option<String>,
        /// Server 信任庫（mTLS 用來驗證 Client 憑證）
        #[arg(long = "server-trust")]
        server_trust: Vec<PathBuf>,
        #[arg(long, env = "RUST_CA_SERVER_TRUST_PASSWORD", hide_env_values = true)]
        server_trust_password: Option<String>,

        #[command(flatten)]
        common: CommonTls,
    },
    /// 連到遠端 Server 測試交握
    Remote {
        /// host[:port]，預設 443
        address: String,
        /// 信任庫檔案（可多個）；未指定時使用作業系統憑證庫
        #[arg(short, long = "trust")]
        trust: Vec<PathBuf>,
        #[arg(long, env = "RUST_CA_TRUST_PASSWORD", hide_env_values = true)]
        trust_password: Option<String>,
        /// 使用 Mozilla 根憑證（webpki-roots）而非系統憑證庫
        #[arg(long, conflicts_with = "trust")]
        mozilla: bool,
        /// 不驗證 Server 憑證，只觀察交握與憑證鏈
        #[arg(long, conflicts_with_all = ["trust", "mozilla"])]
        insecure: bool,
        /// Client 憑證庫（mTLS 用）
        #[arg(long)]
        client: Option<PathBuf>,
        #[arg(long)]
        client_alias: Option<String>,
        #[arg(long, env = "RUST_CA_CLIENT_PASSWORD", hide_env_values = true)]
        client_password: Option<String>,
        /// 逾時秒數
        #[arg(long, default_value_t = 10)]
        timeout: u64,
        /// HTTP CONNECT proxy，例如 http://user:pass@proxy:8080（未指定時依序讀取 HTTPS_PROXY / NO_PROXY、Windows 系統 proxy 設定）
        #[arg(long)]
        proxy: Option<String>,
        /// 不使用任何 proxy（忽略 HTTPS_PROXY 與系統設定）
        #[arg(long, conflicts_with = "proxy")]
        no_proxy: bool,
        #[command(flatten)]
        common: CommonTls,
    },
}

fn main() -> ExitCode {
    console::init();
    rustca_core::init_local_offset();
    let cli = Cli::parse();
    let out = Out::new(cli.json, !cli.no_color);
    match run(cli.cmd, &out) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            out.error(&format!("{e:#}"));
            ExitCode::from(10)
        }
    }
}

fn run(cmd: Cmd, out: &Out) -> Result<u8> {
    match cmd {
        Cmd::List {
            files,
            pw,
            warn_days,
        } => {
            let opener = StoreOpener::new(pw);
            let stores = files
                .iter()
                .map(|f| opener.open(f, false))
                .collect::<Result<Vec<_>>>()?;
            out.list(&stores, warn_days);
            Ok(0)
        }
        Cmd::Show {
            file,
            alias,
            pw,
            pem,
            warn_days,
        } => {
            let ks = StoreOpener::new(pw).open(&file, false)?;
            let entries: Vec<_> = match &alias {
                Some(a) => vec![ks
                    .entry(a)
                    .ok_or_else(|| anyhow::anyhow!("找不到別名「{a}」"))?],
                None => ks.entries.iter().collect(),
            };
            out.show(&ks, &entries, pem, warn_days);
            Ok(0)
        }
        Cmd::Chain {
            file,
            alias,
            pw,
            trust,
            trust_password,
            warn_days,
        } => {
            let opener = StoreOpener::new(pw.clone());
            let ks = opener.open(&file, false)?;
            let trust_opener = StoreOpener::with_password(trust_password.or(pw.password));
            let extra = trust
                .iter()
                .map(|f| trust_opener.open(f, false))
                .collect::<Result<Vec<_>>>()?;
            let mut pool: Vec<&CertInfo> = ks.all_certs();
            for t in &extra {
                pool.extend(t.all_certs());
            }
            let entries: Vec<_> = match &alias {
                Some(a) => vec![ks
                    .entry(a)
                    .ok_or_else(|| anyhow::anyhow!("找不到別名「{a}」"))?],
                None => ks.entries.iter().filter(|e| !e.chain.is_empty()).collect(),
            };
            let now = now_ts();
            let chains: Vec<_> = entries
                .iter()
                .map(|e| (*e, build_chain(&e.chain, &pool, now, warn_days)))
                .collect();
            out.chains(&ks, &chains);
            Ok(if chains.iter().all(|(_, c)| c.is_complete()) {
                0
            } else {
                1
            })
        }
        Cmd::Search { keyword, files, pw } => {
            let opener = StoreOpener::new(pw);
            let mut total = 0;
            let mut results = Vec::new();
            for f in &files {
                let ks = opener.open(f, false)?;
                let hits = search(&ks, &keyword);
                total += hits.len();
                results.push((ks, hits));
            }
            out.search(&keyword, &results);
            Ok(if total > 0 { 0 } else { 1 })
        }
        Cmd::Expiry {
            files,
            pw,
            days,
            all,
        } => {
            let opener = StoreOpener::new(pw);
            let stores = files
                .iter()
                .map(|f| opener.open(f, false))
                .collect::<Result<Vec<_>>>()?;
            Ok(out.expiry(&stores, days, all))
        }
        Cmd::Handshake(h) => handshake(h, out),
    }
}

fn handshake(cmd: HandshakeCmd, out: &Out) -> Result<u8> {
    let at = |c: &CommonTls| -> Result<Option<i64>> {
        c.at.as_deref()
            .map(parse_date)
            .transpose()
            .map_err(Into::into)
    };
    let report = match cmd {
        HandshakeCmd::Local {
            server,
            server_alias,
            server_password,
            client_trust,
            client_trust_password,
            mtls,
            client,
            client_alias,
            client_password,
            server_trust,
            server_trust_password,
            common,
        } => {
            if mtls && client.is_none() {
                out.warn("已啟用 --mtls 但未指定 --client：將模擬 Client 沒有憑證的情況");
            }
            if mtls && server_trust.is_empty() {
                bail!("啟用 --mtls 時必須用 --server-trust 指定 Server 用來驗證 Client 的信任庫");
            }
            let server_ks = StoreOpener::with_password(server_password).open(&server, true)?;
            let server_id = tls::identity_from_keystore(&server_ks, server_alias.as_deref())?;

            let ct = StoreOpener::with_password(client_trust_password);
            let ct_stores = client_trust
                .iter()
                .map(|f| ct.open(f, false))
                .collect::<Result<Vec<_>>>()?;
            let client_anchors = tls::trust_from_keystores(&ct_stores.iter().collect::<Vec<_>>());

            let client_id = match &client {
                Some(f) => {
                    let ks = StoreOpener::with_password(client_password).open(f, true)?;
                    Some(tls::identity_from_keystore(&ks, client_alias.as_deref())?)
                }
                None => None,
            };
            let st = StoreOpener::with_password(server_trust_password);
            let st_stores = server_trust
                .iter()
                .map(|f| st.open(f, false))
                .collect::<Result<Vec<_>>>()?;
            let server_anchors = tls::trust_from_keystores(&st_stores.iter().collect::<Vec<_>>());

            tls::simulate_local(
                &server_id,
                &client_anchors,
                client_id.as_ref(),
                &server_anchors,
                &LocalOptions {
                    server_name: common.sni.clone(),
                    version: common.version.into(),
                    at: at(&common)?,
                    require_client_auth: mtls,
                },
            )
        }
        HandshakeCmd::Remote {
            address,
            trust,
            trust_password,
            mozilla,
            insecure,
            client,
            client_alias,
            client_password,
            timeout,
            proxy,
            no_proxy,
            common,
        } => {
            let proxy = if no_proxy {
                None
            } else if proxy.is_some() {
                proxy
            } else {
                tls::split_host_port(&address)
                    .ok()
                    .and_then(|(h, _)| tls::auto_proxy(&h))
                    .map(|(p, source)| {
                        if !out.json {
                            out.info(&format!("使用 {source}中的 proxy"));
                        }
                        p
                    })
            };
            let trust_mode = if insecure {
                RemoteTrust::Insecure
            } else if mozilla {
                RemoteTrust::Mozilla
            } else if !trust.is_empty() {
                let opener = StoreOpener::with_password(trust_password);
                let stores = trust
                    .iter()
                    .map(|f| opener.open(f, false))
                    .collect::<Result<Vec<_>>>()?;
                RemoteTrust::Certs(tls::trust_from_keystores(
                    &stores.iter().collect::<Vec<_>>(),
                ))
            } else {
                RemoteTrust::System
            };
            let client_id = match &client {
                Some(f) => {
                    let ks = StoreOpener::with_password(client_password).open(f, true)?;
                    Some(tls::identity_from_keystore(&ks, client_alias.as_deref())?)
                }
                None => None,
            };
            if !out.json {
                out.info(&format!("連線至 {address} …"));
            }
            tls::connect_remote(
                &RemoteOptions {
                    address,
                    server_name: common.sni.clone(),
                    version: common.version.into(),
                    at: at(&common)?,
                    timeout: Duration::from_secs(timeout.max(1)),
                    trust: trust_mode,
                    proxy,
                },
                client_id.as_ref(),
            )
        }
    };
    out.handshake(&report);
    Ok(if report.success { 0 } else { 1 })
}
