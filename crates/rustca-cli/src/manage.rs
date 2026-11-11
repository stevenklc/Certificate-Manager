//! `rust-ca manage`：憑證庫管理（匯入 / 刪除 / 改名 / 更新憑證 / 修改密碼 / 轉換 / 匯出）。

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use rustca_core::edit::{self, CertFormat, SaveReport, WriteOptions};
use rustca_core::forge::{self, CertSpec, KeyAlg, Profile, Signer};
use rustca_core::{
    javacompat, load_file, now_ts, CertInfo, EntryKind, KeyState, Keystore, LoadOptions,
    StoreFormat,
};

use crate::output::Out;
use crate::store::PasswordArgs;

#[derive(Clone, Copy, ValueEnum)]
pub enum StoreType {
    Jks,
    Jceks,
    Pkcs12,
}

impl From<StoreType> for StoreFormat {
    fn from(t: StoreType) -> Self {
        match t {
            StoreType::Jks => StoreFormat::Jks,
            StoreType::Jceks => StoreFormat::Jceks,
            StoreType::Pkcs12 => StoreFormat::Pkcs12,
        }
    }
}

#[derive(Args, Clone)]
pub struct SaveArgs {
    /// 另存到其他檔案（預設寫回原檔）
    #[arg(short, long)]
    out: Option<PathBuf>,
    /// 覆寫前不要建立備份檔（預設會建立 檔名.YYYYMMDD-HHMMSS.bak）
    #[arg(long)]
    no_backup: bool,
    /// PKCS#12 使用舊式演算法（3DES + HmacSHA1），相容 Java 8u301 / 11.0.12 以前的版本
    #[arg(long)]
    legacy_p12: bool,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum RoleArg {
    /// Server keystore
    Server,
    /// Client keystore（mTLS）
    Client,
    /// Truststore 信任庫
    Trust,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum CertOut {
    Pem,
    Der,
    P7b,
    P7bPem,
}

impl From<CertOut> for CertFormat {
    fn from(c: CertOut) -> Self {
        match c {
            CertOut::Pem => CertFormat::Pem,
            CertOut::Der => CertFormat::Der,
            CertOut::P7b => CertFormat::P7b,
            CertOut::P7bPem => CertFormat::P7bPem,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub enum LeafProfile {
    Server,
    Client,
    Both,
}

/// 憑證主體共用欄位。
#[derive(Args, Clone)]
pub struct SubjectArgs {
    /// 組織（O）
    #[arg(short = 'O', long)]
    org: Option<String>,
    /// 部門（OU）
    #[arg(long)]
    ou: Option<String>,
    /// 城市（L）
    #[arg(long)]
    locality: Option<String>,
    /// 州 / 省（ST）
    #[arg(long)]
    state: Option<String>,
    /// 國家代碼（C），例如 TW
    #[arg(short = 'C', long)]
    country: Option<String>,
}

impl SubjectArgs {
    fn subject(&self, cn: &str) -> forge::Subject {
        let v = |o: &Option<String>| o.clone().unwrap_or_default();
        forge::Subject {
            cn: cn.to_string(),
            o: v(&self.org),
            ou: v(&self.ou),
            l: v(&self.locality),
            st: v(&self.state),
            c: v(&self.country),
        }
    }
}

fn parse_key_alg(s: &str) -> Result<KeyAlg, String> {
    KeyAlg::parse(s).ok_or_else(|| "可用：rsa2048、rsa3072、rsa4096、ec256、ec384".into())
}

#[derive(Subcommand)]
pub enum ManageCmd {
    /// 匯入信任憑證（.cer / .crt / .pem / .p7b，多張時別名自動加 -2、-3…）
    ImportCert {
        store: PathBuf,
        /// 憑證檔案
        #[arg(short, long)]
        file: PathBuf,
        #[arg(short, long)]
        alias: String,
        /// 別名已存在時覆蓋
        #[arg(long)]
        overwrite: bool,
        /// 憑證庫不存在時建立新的
        #[arg(long)]
        create: bool,
        /// 建立新憑證庫時的格式（預設依副檔名判斷）
        #[arg(long = "type", value_enum)]
        store_type: Option<StoreType>,
        #[command(flatten)]
        pw: PasswordArgs,
        #[command(flatten)]
        save: SaveArgs,
    },
    /// 由多個憑證 / 私鑰檔組成憑證庫：自動配對私鑰與憑證、補齊憑證鏈，其餘憑證成為信任憑證
    #[command(alias = "build")]
    Assemble {
        store: PathBuf,
        /// 來源檔案（.cer / .crt / .pem / .key / .p7b / .p12 / .jks…），可多個或用萬用字元
        #[arg(required = true, num_args = 1..)]
        files: Vec<PathBuf>,
        /// 來源檔密碼（.p12 / .jks / 加密私鑰）
        #[arg(long)]
        from_password: Option<String>,
        /// 只加入私鑰條目，不把 CA 等其餘憑證加為信任憑證
        #[arg(long)]
        keys_only: bool,
        /// 只顯示規劃結果，不寫入
        #[arg(long)]
        dry_run: bool,
        /// 別名已存在時覆蓋
        #[arg(long)]
        overwrite: bool,
        /// 憑證庫不存在時建立新的
        #[arg(long)]
        create: bool,
        /// 建立新憑證庫時的格式（預設依副檔名判斷）
        #[arg(long = "type", value_enum)]
        store_type: Option<StoreType>,
        #[command(flatten)]
        pw: PasswordArgs,
        #[command(flatten)]
        save: SaveArgs,
    },
    /// 匯入金鑰對：來自另一個憑證庫，或「憑證檔 + 私鑰檔」
    ImportKey {
        store: PathBuf,
        /// 新條目的別名
        #[arg(short, long)]
        alias: String,
        /// 來源憑證庫（.p12 / .jks / .pem…）
        #[arg(long, conflicts_with_all = ["cert", "key"])]
        from: Option<PathBuf>,
        /// 來源中的別名（預設第一個私鑰條目）
        #[arg(long)]
        from_alias: Option<String>,
        /// 來源憑證庫密碼
        #[arg(long, env = "RUST_CA_FROM_PASSWORD", hide_env_values = true)]
        from_password: Option<String>,
        /// 憑證檔（與 --key 一起使用）
        #[arg(long, requires = "key")]
        cert: Option<PathBuf>,
        /// 私鑰檔（PEM，與 --cert 一起使用）
        #[arg(long, requires = "cert")]
        key: Option<PathBuf>,
        /// 此條目的私鑰密碼（JKS / JCEKS；預設與憑證庫密碼相同）
        #[arg(long, env = "RUST_CA_NEW_KEY_PASSWORD", hide_env_values = true)]
        new_key_password: Option<String>,
        #[arg(long)]
        overwrite: bool,
        #[arg(long)]
        create: bool,
        #[arg(long = "type", value_enum)]
        store_type: Option<StoreType>,
        #[command(flatten)]
        pw: PasswordArgs,
        #[command(flatten)]
        save: SaveArgs,
    },
    /// 刪除條目
    Delete {
        store: PathBuf,
        #[arg(short, long)]
        alias: String,
        /// 不詢問確認
        #[arg(short, long)]
        yes: bool,
        #[command(flatten)]
        pw: PasswordArgs,
        #[command(flatten)]
        save: SaveArgs,
    },
    /// 修改別名
    Rename {
        store: PathBuf,
        #[arg(short, long)]
        alias: String,
        /// 新別名
        #[arg(short = 'n', long, visible_alias = "new-alias")]
        to: String,
        #[command(flatten)]
        pw: PasswordArgs,
        #[command(flatten)]
        save: SaveArgs,
    },
    /// 替換同一別名的憑證 / 憑證鏈（續約、匯入 CA 回覆、替換信任憑證），替換後自動驗證
    #[command(visible_alias = "replace-chain")]
    UpdateCert {
        store: PathBuf,
        #[arg(short, long)]
        alias: String,
        /// 新憑證檔（可含整條鏈：.pem / .p7b / .cer）
        #[arg(short, long)]
        file: PathBuf,
        /// 驗證失敗仍然套用（不建議）
        #[arg(long)]
        force: bool,
        #[command(flatten)]
        pw: PasswordArgs,
        #[command(flatten)]
        save: SaveArgs,
    },
    /// 修改憑證庫密碼（store pass）
    Passwd {
        store: PathBuf,
        /// 新密碼（未指定時互動輸入）
        #[arg(long, env = "RUST_CA_NEW_PASSWORD", hide_env_values = true)]
        new_password: Option<String>,
        /// 只改憑證庫密碼，私鑰維持原密碼（同 keytool -storepasswd）
        #[arg(long)]
        keep_key_passwords: bool,
        #[command(flatten)]
        pw: PasswordArgs,
        #[command(flatten)]
        save: SaveArgs,
    },
    /// 修改某條目的私鑰密碼（key pass，JKS / JCEKS）
    Keypasswd {
        store: PathBuf,
        #[arg(short, long)]
        alias: String,
        #[arg(long, env = "RUST_CA_NEW_KEY_PASSWORD", hide_env_values = true)]
        new_password: Option<String>,
        #[command(flatten)]
        pw: PasswordArgs,
        #[command(flatten)]
        save: SaveArgs,
    },
    /// 轉換憑證庫格式（JKS / JCEKS / PKCS#12；來源也可以是 PEM 憑證 + 私鑰）
    Convert {
        store: PathBuf,
        /// 輸出檔案
        #[arg(short, long)]
        out: PathBuf,
        /// 輸出格式（預設依輸出副檔名判斷）
        #[arg(long = "type", value_enum)]
        store_type: Option<StoreType>,
        /// 輸出憑證庫的密碼（來源沒有密碼時，例如 PEM，必須指定）
        #[arg(long, env = "RUST_CA_NEW_PASSWORD", hide_env_values = true)]
        new_password: Option<String>,
        /// PKCS#12 使用舊式演算法（相容舊版 Java）
        #[arg(long)]
        legacy_p12: bool,
        #[command(flatten)]
        pw: PasswordArgs,
    },
    /// 轉換憑證檔格式（PEM ⇄ DER ⇄ PKCS#7 .p7b），也可從憑證庫取出憑證 / 私鑰
    ConvertCert {
        /// 來源（任何支援的檔案：.cer / .pem / .p7b / .jks / .p12…）
        input: PathBuf,
        /// 輸出檔案
        #[arg(short, long)]
        out: PathBuf,
        /// 輸出格式（預設依副檔名：.pem/.crt → PEM、.cer/.der → DER、.p7b → PKCS#7）
        #[arg(long, value_enum)]
        to: Option<CertOut>,
        /// 只取某個別名（來源為憑證庫時）
        #[arg(short, long)]
        alias: Option<String>,
        /// 一併輸出私鑰（未加密 PKCS#8 PEM，只能搭配 PEM；請妥善保管）
        #[arg(long)]
        with_key: bool,
        #[command(flatten)]
        pw: PasswordArgs,
    },
    /// 製作憑證鏈：自簽根 CA → 中繼 CA → 終端憑證（或用憑證庫中的 CA 簽發），並存入憑證庫
    #[command(visible_alias = "gen")]
    GenChain {
        store: PathBuf,
        /// 終端憑證的 CN（不指定則只建立 CA）
        #[arg(long)]
        cn: Option<String>,
        /// SAN（可重複）：DNS 名稱、IP，或加前綴 DNS: / IP: / email: / URI:
        #[arg(long = "san")]
        sans: Vec<String>,
        /// 終端憑證用途
        #[arg(long, value_enum, default_value = "server")]
        profile: LeafProfile,
        /// 終端憑證條目的別名（預設為 CN）
        #[arg(short, long)]
        alias: Option<String>,
        /// 用憑證庫中既有的 CA 條目（含私鑰）簽發，不建立新的根 CA
        #[arg(long, conflicts_with_all = ["root_cn", "inter_cn"])]
        issuer: Option<String>,
        /// 新根 CA 的 CN
        #[arg(long, default_value = "RUST-CA Root CA")]
        root_cn: String,
        /// 中繼 CA 的 CN（可重複，依序往下簽）
        #[arg(long = "inter-cn")]
        inter_cn: Vec<String>,
        /// 金鑰演算法
        #[arg(long, default_value = "rsa2048", value_parser = parse_key_alg)]
        key: KeyAlg,
        /// CA 的金鑰演算法（預設同 --key）
        #[arg(long, value_parser = parse_key_alg)]
        ca_key: Option<KeyAlg>,
        /// 終端憑證有效天數
        #[arg(long, default_value_t = 825)]
        days: u32,
        /// CA 有效天數
        #[arg(long, default_value_t = 3650)]
        ca_days: u32,
        /// 保存 CA 私鑰（之後可再用 --issuer 簽發）；未建立終端憑證時一律保存
        #[arg(long)]
        keep_ca_keys: bool,
        #[command(flatten)]
        subject: SubjectArgs,
        /// 此條目的私鑰密碼（JKS / JCEKS；預設與憑證庫密碼相同）
        #[arg(long, env = "RUST_CA_NEW_KEY_PASSWORD", hide_env_values = true)]
        new_key_password: Option<String>,
        #[arg(long)]
        overwrite: bool,
        #[arg(long)]
        create: bool,
        #[arg(long = "type", value_enum)]
        store_type: Option<StoreType>,
        #[command(flatten)]
        pw: PasswordArgs,
        #[command(flatten)]
        save: SaveArgs,
    },
    /// 驗證條目的憑證鏈（私鑰相符、順序、簽章、有效期限、根憑證）
    Verify {
        store: PathBuf,
        /// 別名（不指定則驗證所有私鑰條目）
        #[arg(short, long)]
        alias: Option<String>,
        #[command(flatten)]
        pw: PasswordArgs,
    },
    /// 用途檢查：是否適合作為 Server keystore、Client keystore（mTLS）或 Truststore
    #[command(alias = "role")]
    CheckRole {
        store: PathBuf,
        /// 要檢查的用途（預設依內容判斷：有私鑰為 server，否則 trust）
        #[arg(long = "as", value_enum)]
        role: Option<RoleArg>,
        /// Server 的主機名稱或 IP，檢查憑證是否涵蓋
        #[arg(long)]
        host: Option<String>,
        #[command(flatten)]
        pw: PasswordArgs,
    },
    /// Java 相容性測試：用本機各版本 Java 的 keytool 讀取憑證庫並解開私鑰
    JavaTest {
        store: PathBuf,
        /// 額外的 JDK / JRE 目錄（可重複；也可以是放多個 JDK 的上層目錄）
        #[arg(long = "java")]
        java: Vec<PathBuf>,
        /// 不測原檔，改以舊式 PKCS#12 演算法寫出暫存檔後測試（評估轉換後的相容性）
        #[arg(long)]
        legacy_p12: bool,
        #[command(flatten)]
        pw: PasswordArgs,
    },
    /// 匯出憑證（PEM / DER）
    Export {
        store: PathBuf,
        #[arg(short, long)]
        alias: String,
        #[arg(short, long)]
        out: PathBuf,
        /// 匯出整條憑證鏈（PEM）
        #[arg(long)]
        chain: bool,
        /// 以 DER 格式輸出（僅單張）
        #[arg(long, conflicts_with = "chain")]
        der: bool,
        #[command(flatten)]
        pw: PasswordArgs,
    },
}

fn interactive() -> bool {
    std::io::stdin().is_terminal()
}

fn prompt(msg: &str) -> Result<String> {
    rpassword::prompt_password(msg).context("讀取密碼失敗")
}

/// 取得新密碼：參數 → 互動輸入（輸入兩次確認）。
fn new_password(given: Option<String>, label: &str) -> Result<String> {
    let pw = match given {
        Some(p) => p,
        None if interactive() => {
            let a = prompt(&format!("請輸入新的{label}："))?;
            let b = prompt(&format!("請再輸入一次新的{label}："))?;
            if a != b {
                bail!("兩次輸入的密碼不一致");
            }
            a
        }
        None => bail!("請用 --new-password 或環境變數指定新的{label}"),
    };
    if pw.chars().count() < 6 {
        bail!("{label}至少需要 6 個字元（與 Java keytool 相容）");
    }
    Ok(pw)
}

fn guess_type(path: &Path) -> StoreFormat {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("p12") | Some("pfx") => StoreFormat::Pkcs12,
        Some("jceks") => StoreFormat::Jceks,
        _ => StoreFormat::Jks,
    }
}

/// 開啟要編輯的憑證庫：一定要有憑證庫密碼；`need_keys` 時確保私鑰已解密。
fn open_for_edit(path: &Path, pw: &PasswordArgs, need_keys: bool) -> Result<Keystore> {
    let mut opts = LoadOptions {
        password: pw.password.clone(),
        key_password: pw.key_password.clone(),
    };
    if opts.password.is_none() {
        if !interactive() {
            bail!("編輯憑證庫需要密碼，請用 -p 或 RUST_CA_PASSWORD 指定");
        }
        opts.password = Some(prompt(&format!("請輸入 {} 的密碼：", path.display()))?);
    }
    let mut ks = load_file(path, &opts).with_context(|| format!("無法開啟 {}", path.display()))?;
    if !edit::is_writable(ks.format) {
        bail!(
            "{} 是 {} 格式，無法直接編輯（可用 manage convert 轉成 JKS / PKCS#12）",
            path.display(),
            ks.format
        );
    }
    if ks.store_password.is_none() {
        bail!("無法驗證憑證庫密碼");
    }
    if need_keys {
        // 各條目的私鑰密碼可能不同：逐一詢問仍未解開的條目
        let locked: Vec<String> = ks
            .private_key_entries()
            .filter(|e| matches!(e.key, KeyState::Locked(_)))
            .map(|e| e.alias.clone())
            .collect();
        if !locked.is_empty() && !interactive() {
            bail!(
                "以下條目的私鑰尚未解密：{}，請用 --key-password 指定私鑰密碼（各條目密碼不同時請在互動模式執行）",
                locked.join("、")
            );
        }
        for alias in locked {
            let mut tries = 0;
            loop {
                let p = prompt(&format!("請輸入「{alias}」的私鑰密碼："))?;
                match edit::unlock_entry(&mut ks, &alias, &p) {
                    Ok(()) => break,
                    Err(e) if tries < 2 => {
                        eprintln!("{e}");
                        tries += 1;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
    Ok(ks)
}

/// 開啟或建立憑證庫。
fn open_or_create(
    path: &Path,
    pw: &PasswordArgs,
    create: bool,
    t: Option<StoreType>,
    out: &Out,
) -> Result<Keystore> {
    if path.exists() {
        return open_for_edit(path, pw, false);
    }
    if !create {
        bail!(
            "{} 不存在（加上 --create 可建立新的憑證庫）",
            path.display()
        );
    }
    let format = t.map(Into::into).unwrap_or_else(|| guess_type(path));
    let password = new_password(pw.password.clone(), "憑證庫密碼")?;
    out.info(&format!("建立新的 {format} 憑證庫：{}", path.display()));
    Ok(edit::new_keystore(path, format, &password)?)
}

fn load_any(path: &Path, password: Option<String>) -> Result<Keystore> {
    let opts = LoadOptions {
        password,
        key_password: None,
    };
    match load_file(path, &opts) {
        Ok(k) => Ok(k),
        Err(e) if e.is_password_problem() && opts.password.is_none() && interactive() => {
            let p = prompt(&format!("請輸入 {} 的密碼：", path.display()))?;
            Ok(load_file(path, &LoadOptions::with_password(p))?)
        }
        Err(e) => Err(anyhow::Error::new(e).context(format!("無法開啟 {}", path.display()))),
    }
}

fn certs_of(path: &Path) -> Result<Vec<CertInfo>> {
    let ks = load_any(path, None)?;
    let certs: Vec<CertInfo> = ks.all_certs().into_iter().cloned().collect();
    if certs.is_empty() {
        bail!("{} 中沒有憑證", path.display());
    }
    Ok(certs)
}

fn finish(ks: &mut Keystore, save: &SaveArgs, out: &Out, msg: &str) -> Result<()> {
    // 另存時依輸出副檔名決定格式
    let format = save.out.as_deref().map(guess_type);
    let rep: SaveReport = edit::save_with(
        ks,
        save.out.as_deref(),
        format,
        !save.no_backup,
        WriteOptions {
            pkcs12_legacy: save.legacy_p12,
        },
    )?;
    out.success(msg);
    for w in &rep.warnings {
        out.warn(w);
    }
    out.info(&format!("已儲存：{}", rep.path.display()));
    if let Some(b) = rep.backup {
        out.info(&format!("備份：{}", b.display()));
    }
    Ok(())
}

pub fn run(cmd: ManageCmd, out: &Out) -> Result<u8> {
    match cmd {
        ManageCmd::ImportCert {
            store,
            file,
            alias,
            overwrite,
            create,
            store_type,
            pw,
            save,
        } => {
            let certs = certs_of(&file)?;
            let mut ks = open_or_create(&store, &pw, create, store_type, out)?;
            let added = edit::import_certs(&mut ks, &alias, &certs, overwrite)?;
            for (a, c) in added.iter().zip(certs.iter()) {
                out.info(&format!("  {a} ← {}", c.subject));
            }
            finish(
                &mut ks,
                &save,
                out,
                &format!("已匯入 {} 張信任憑證", added.len()),
            )?;
        }
        ManageCmd::Assemble {
            store,
            files,
            from_password,
            keys_only,
            dry_run,
            overwrite,
            create,
            store_type,
            pw,
            save,
        } => {
            let mut sources = Vec::new();
            for f in &files {
                // 有密碼先用密碼讀，失敗再不帶密碼（.cer / .pem 不需要密碼）
                let ks = match load_any(f, from_password.clone()) {
                    Ok(k) => k,
                    Err(e) if from_password.is_some() => load_any(f, None).map_err(|_| e)?,
                    Err(e) => return Err(e),
                };
                sources.push(ks);
            }
            let mut plan = edit::plan_assembly(&sources);
            if keys_only {
                plan.certs.clear();
            }
            for k in &plan.keys {
                let state = if k.complete {
                    "鏈完整"
                } else {
                    "鏈不完整"
                };
                out.info(&format!(
                    "  🔑 {} ← {}（鏈 {} 張，{state}；{}）",
                    k.alias,
                    k.chain[0].subject,
                    k.chain.len(),
                    k.source
                ));
            }
            for c in &plan.certs {
                out.info(&format!(
                    "  📄 {} ← {}（信任憑證 · {}；{}）",
                    c.alias,
                    c.cert.subject,
                    c.cert.role(),
                    c.source
                ));
            }
            for p in &plan.problems {
                out.warn(p);
            }
            if plan.keys.is_empty() && plan.certs.is_empty() {
                bail!("沒有可加入的憑證");
            }
            if dry_run {
                out.info("（--dry-run：未寫入）");
                return Ok(0);
            }
            let mut ks = open_or_create(&store, &pw, create, store_type, out)?;
            let n = edit::apply_assembly(&mut ks, &plan, overwrite)?;
            finish(&mut ks, &save, out, &format!("已加入 {n} 個條目"))?;
        }
        ManageCmd::ImportKey {
            store,
            alias,
            from,
            from_alias,
            from_password,
            cert,
            key,
            new_key_password,
            overwrite,
            create,
            store_type,
            pw,
            save,
        } => {
            let entry = match (&from, &cert, &key) {
                (Some(src), _, _) => {
                    let ks = load_any(src, from_password)?;
                    let e = match &from_alias {
                        Some(a) => ks
                            .entry(a)
                            .ok_or_else(|| anyhow!("{} 中找不到別名「{a}」", src.display()))?,
                        None => ks
                            .private_key_entries()
                            .next()
                            .ok_or_else(|| anyhow!("{} 中沒有私鑰條目", src.display()))?,
                    };
                    e.clone()
                }
                (None, Some(c), Some(k)) => {
                    let certs = certs_of(c)?;
                    let kks = load_any(k, from_password)?;
                    let ke = kks
                        .private_key_entries()
                        .next()
                        .ok_or_else(|| anyhow!("{} 中沒有私鑰", k.display()))?;
                    edit::entry_from_cert_and_key(&alias, &certs, ke)?
                }
                _ => bail!("請指定 --from <憑證庫>，或 --cert <憑證檔> --key <私鑰檔>"),
            };
            let mut ks = open_or_create(&store, &pw, create, store_type, out)?;
            if let Some(k) = &new_key_password {
                if k.chars().count() < 6 {
                    bail!("私鑰密碼至少需要 6 個字元");
                }
            }
            edit::import_key_entry(
                &mut ks,
                &alias,
                &entry,
                new_key_password.as_deref(),
                overwrite,
            )?;
            let leaf = entry
                .chain
                .first()
                .map(|c| c.subject.clone())
                .unwrap_or_default();
            finish(
                &mut ks,
                &save,
                out,
                &format!(
                    "已匯入金鑰對「{alias}」（{leaf}，鏈 {} 張）",
                    entry.chain.len()
                ),
            )?;
        }
        ManageCmd::Delete {
            store,
            alias,
            yes,
            pw,
            save,
        } => {
            let mut ks = open_for_edit(&store, &pw, false)?;
            let e = ks
                .entry(&alias)
                .ok_or_else(|| anyhow!("找不到別名「{alias}」"))?;
            let desc = format!("{}（{}）", e.alias, e.kind);
            if !yes {
                if !interactive() {
                    bail!("非互動模式刪除需加上 -y");
                }
                eprint!("確定要刪除 {desc}？[y/N] ");
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                if !matches!(line.trim(), "y" | "Y" | "yes") {
                    out.info("已取消");
                    return Ok(1);
                }
            }
            edit::delete_entry(&mut ks, &alias)?;
            finish(&mut ks, &save, out, &format!("已刪除 {desc}"))?;
        }
        ManageCmd::Rename {
            store,
            alias,
            to,
            pw,
            save,
        } => {
            let mut ks = open_for_edit(&store, &pw, false)?;
            edit::rename_entry(&mut ks, &alias, &to)?;
            finish(
                &mut ks,
                &save,
                out,
                &format!("已將「{alias}」改名為「{to}」"),
            )?;
        }
        ManageCmd::UpdateCert {
            store,
            alias,
            file,
            force,
            pw,
            save,
        } => {
            let certs = certs_of(&file)?;
            let mut ks = open_for_edit(&store, &pw, false)?;
            let (notes, v) = if force {
                let notes = edit::update_certs(&mut ks, &alias, &certs)?;
                (notes, edit::verify_entry(&ks, &alias, now_ts())?)
            } else {
                let mut work = ks.clone();
                let notes = edit::update_certs(&mut work, &alias, &certs)?;
                let v = edit::verify_entry(&work, &alias, now_ts())?;
                if !v.ok {
                    for n in &notes {
                        out.info(&format!("  {n}"));
                    }
                    out.verification(&v);
                    bail!("替換後的憑證鏈驗證失敗，未寫入檔案（確定要套用請加 --force）");
                }
                ks = work;
                (notes, v)
            };
            for n in &notes {
                out.info(&format!("  {n}"));
            }
            out.verification(&v);
            finish(&mut ks, &save, out, &format!("已替換「{alias}」的憑證鏈"))?;
        }
        ManageCmd::Passwd {
            store,
            new_password: np,
            keep_key_passwords,
            pw,
            save,
        } => {
            let mut ks = open_for_edit(&store, &pw, !keep_key_passwords)?;
            let np = new_password(np, "憑證庫密碼")?;
            edit::set_store_password(&mut ks, &np, !keep_key_passwords)?;
            let what = if keep_key_passwords {
                "已修改憑證庫密碼（私鑰維持原密碼）"
            } else {
                "已修改憑證庫密碼（原本與憑證庫相同的私鑰密碼一併修改）"
            };
            finish(&mut ks, &save, out, what)?;
        }
        ManageCmd::Keypasswd {
            store,
            alias,
            new_password: np,
            pw,
            save,
        } => {
            let mut ks = open_for_edit(&store, &pw, true)?;
            let np = new_password(np, "私鑰密碼")?;
            edit::set_key_password(&mut ks, &alias, &np)?;
            finish(&mut ks, &save, out, &format!("已修改「{alias}」的私鑰密碼"))?;
        }
        ManageCmd::Convert {
            store,
            out: dest,
            store_type,
            new_password: np,
            legacy_p12,
            pw,
        } => {
            let target: StoreFormat = store_type
                .map(Into::into)
                .unwrap_or_else(|| guess_type(&dest));
            if dest.exists() {
                bail!("{} 已存在，請指定其他檔名", dest.display());
            }
            let src = load_any(&store, pw.password.clone())?;
            let mut ks = if edit::is_writable(src.format) {
                open_for_edit(&store, &pw, target == StoreFormat::Pkcs12)?
            } else {
                // PEM / DER / PKCS#7 沒有密碼：需要指定新憑證庫密碼
                let mut k = src;
                k.store_password = Some(rustca_core::Secret::new(new_password(
                    np.clone(),
                    "憑證庫密碼",
                )?));
                k
            };
            if let Some(np) =
                np.filter(|_| ks.store_password.is_some() && edit::is_writable(ks.format))
            {
                if np.chars().count() < 6 {
                    bail!("憑證庫密碼至少需要 6 個字元");
                }
                edit::set_store_password(&mut ks, &np, true)?;
            }
            let rep = edit::save_with(
                &mut ks,
                Some(&dest),
                Some(target),
                false,
                WriteOptions {
                    pkcs12_legacy: legacy_p12,
                },
            )?;
            out.success(&format!("已轉換為 {target}：{}", rep.path.display()));
            for w in &rep.warnings {
                out.warn(w);
            }
        }
        ManageCmd::Export {
            store,
            alias,
            out: dest,
            chain,
            der,
            pw,
        } => {
            let ks = load_any(&store, pw.password)?;
            let e = ks
                .entry(&alias)
                .ok_or_else(|| anyhow!("找不到別名「{alias}」"))?;
            let certs: Vec<&CertInfo> = if chain {
                e.chain.iter().collect()
            } else {
                e.chain.iter().take(1).collect()
            };
            if certs.is_empty() {
                bail!("「{alias}」沒有憑證");
            }
            let data = edit::export_certs(&certs, !der)?;
            std::fs::write(&dest, data).with_context(|| format!("無法寫入 {}", dest.display()))?;
            out.success(&format!(
                "已匯出 {} 張憑證：{}",
                certs.len(),
                dest.display()
            ));
        }
        ManageCmd::ConvertCert {
            input,
            out: dest,
            to,
            alias,
            with_key,
            pw,
        } => {
            let ks = load_any(&input, pw.password)?;
            let format: CertFormat = match to {
                Some(t) => t.into(),
                None => CertFormat::from_path(&dest).ok_or_else(|| {
                    anyhow!("無法從副檔名判斷輸出格式，請用 --to pem|der|p7b|p7b-pem 指定")
                })?,
            };
            let (certs, key_entry) = match &alias {
                Some(a) => {
                    let e = ks.entry(a).ok_or_else(|| anyhow!("找不到別名「{a}」"))?;
                    (e.chain.iter().collect::<Vec<_>>(), Some(e))
                }
                None => (ks.all_certs(), ks.private_key_entries().next()),
            };
            if certs.is_empty() {
                bail!("{} 中沒有憑證", input.display());
            }
            let certs = if format == CertFormat::Der && certs.len() > 1 {
                out.warn(&format!(
                    "DER 只能存一張，只輸出第一張（共 {} 張；要整條鏈請用 .p7b 或 .pem）",
                    certs.len()
                ));
                certs[..1].to_vec()
            } else {
                certs
            };
            let mut data = edit::encode_certs(&certs, format)?;
            if with_key {
                if format != CertFormat::Pem {
                    bail!("--with-key 只能搭配 PEM 輸出");
                }
                let e = key_entry
                    .filter(|e| e.kind == EntryKind::PrivateKey)
                    .ok_or_else(|| anyhow!("來源沒有私鑰"))?;
                data.extend(edit::private_key_pem(e)?.into_bytes());
            }
            if dest.exists() {
                bail!("{} 已存在，請指定其他檔名", dest.display());
            }
            std::fs::write(&dest, data).with_context(|| format!("無法寫入 {}", dest.display()))?;
            out.success(&format!(
                "已輸出 {} 張憑證{}（{}）：{}",
                certs.len(),
                if with_key { " + 私鑰" } else { "" },
                format.label(),
                dest.display()
            ));
            if with_key {
                out.warn("私鑰未加密，請妥善保管，勿加入版本控制");
            }
        }
        ManageCmd::GenChain {
            store,
            cn,
            sans,
            profile,
            alias,
            issuer,
            root_cn,
            inter_cn,
            key,
            ca_key,
            days,
            ca_days,
            keep_ca_keys,
            subject,
            new_key_password,
            overwrite,
            create,
            store_type,
            pw,
            save,
        } => {
            let mut ks = open_or_create(&store, &pw, create, store_type, out)?;
            if let Some(k) = &new_key_password {
                if k.chars().count() < 6 {
                    bail!("私鑰密碼至少需要 6 個字元");
                }
            }
            let kp = new_key_password.as_deref();
            let ca_key = ca_key.unwrap_or(key);
            let leaf_spec = cn.as_ref().map(|cn| {
                let mut s = CertSpec::new(
                    cn.clone(),
                    match profile {
                        LeafProfile::Server => Profile::Server,
                        LeafProfile::Client => Profile::Client,
                        LeafProfile::Both => Profile::ServerClient,
                    },
                );
                s.subject = subject.subject(cn);
                s.key = key;
                s.days = days;
                s.sans = sans.clone();
                s
            });
            let ca_spec = |cn: &str, p: Profile| {
                let mut s = CertSpec::new(cn, p);
                s.subject = subject.subject(cn);
                s.subject.ou.clear();
                s.key = ca_key;
                s.days = ca_days;
                s
            };
            let slug = |s: &str| -> String {
                s.to_lowercase()
                    .chars()
                    .map(|c| {
                        if c.is_alphanumeric() || c == '-' || c == '.' {
                            c
                        } else {
                            '-'
                        }
                    })
                    .collect::<String>()
                    .trim_matches('-')
                    .to_string()
            };

            if let Some(ia) = issuer {
                // 用既有 CA 簽發
                let leaf_spec = leaf_spec.ok_or_else(|| anyhow!("使用 --issuer 時需要 --cn"))?;
                let ie = ks
                    .entry(&ia)
                    .ok_or_else(|| anyhow!("找不到簽發者「{ia}」"))?
                    .clone();
                let KeyState::Decrypted { format, der } = &ie.key else {
                    bail!("「{ia}」沒有已解密的私鑰（需要 CA 私鑰才能簽發）");
                };
                let ca_cert = ie
                    .chain
                    .first()
                    .ok_or_else(|| anyhow!("「{ia}」沒有憑證"))?;
                let ikey = edit::to_pkcs8(*format, der)?;
                let issued = forge::issue(
                    &leaf_spec,
                    Some(Signer {
                        cert: ca_cert,
                        key_pkcs8: &ikey,
                    }),
                    None,
                )?;
                let mut chain = vec![issued.cert.clone()];
                chain.extend(ie.chain.iter().cloned());
                let a = alias.unwrap_or_else(|| slug(&leaf_spec.subject.cn));
                edit::add_key_entry(&mut ks, &a, chain, issued.key_pkcs8, kp, overwrite)?;
                out.info(&format!(
                    "  {a} ← {}（由 {} 簽發）",
                    issued.cert.subject,
                    ca_cert.display_name()
                ));
                out.verification(&edit::verify_entry(&ks, &a, now_ts())?);
                finish(&mut ks, &save, out, &format!("已簽發「{a}」"))?;
                return Ok(0);
            }

            let mut specs = vec![ca_spec(&root_cn, Profile::RootCa)];
            for i in &inter_cn {
                specs.push(ca_spec(i, Profile::IntermediateCa));
            }
            if let Some(l) = &leaf_spec {
                specs.push(l.clone());
            }
            out.info(&format!(
                "產生 {} 把金鑰並簽發 {} 張憑證…",
                specs.len(),
                specs.len()
            ));
            let issued = forge::issue_chain(&specs, None)?;
            let keep = keep_ca_keys || leaf_spec.is_none();
            let n_ca = specs.len() - leaf_spec.is_some() as usize;
            // CA：依序加入（根在前）
            for (i, it) in issued.iter().take(n_ca).enumerate() {
                let a = slug(&it.cert.display_name());
                // CA 的鏈：自己 + 上層（由下往上）
                let chain: Vec<CertInfo> =
                    issued[..=i].iter().rev().map(|x| x.cert.clone()).collect();
                if keep {
                    edit::add_key_entry(&mut ks, &a, chain, it.key_pkcs8.clone(), kp, overwrite)?;
                    out.info(&format!("  {a} ← {}（含私鑰）", it.cert.subject));
                } else {
                    edit::import_certs(&mut ks, &a, std::slice::from_ref(&it.cert), overwrite)?;
                    out.info(&format!("  {a} ← {}（信任憑證）", it.cert.subject));
                }
            }
            let mut msg = format!("已建立 {} 層 CA", n_ca);
            if let Some(l) = &leaf_spec {
                let a = alias.unwrap_or_else(|| slug(&l.subject.cn));
                let chain: Vec<CertInfo> = issued.iter().rev().map(|x| x.cert.clone()).collect();
                let it = issued.last().unwrap();
                edit::add_key_entry(&mut ks, &a, chain, it.key_pkcs8.clone(), kp, overwrite)?;
                out.info(&format!(
                    "  {a} ← {}（私鑰條目，鏈 {} 張）",
                    it.cert.subject,
                    issued.len()
                ));
                out.verification(&edit::verify_entry(&ks, &a, now_ts())?);
                msg = format!("已製作憑證鏈：{} → {a}", root_cn);
            }
            finish(&mut ks, &save, out, &msg)?;
        }
        ManageCmd::Verify { store, alias, pw } => {
            let ks = load_any(&store, pw.password)?;
            let aliases: Vec<String> = match alias {
                Some(a) => vec![a],
                None => ks.private_key_entries().map(|e| e.alias.clone()).collect(),
            };
            if aliases.is_empty() {
                bail!("沒有私鑰條目，請用 -a 指定別名");
            }
            let mut all_ok = true;
            let mut results = vec![];
            for a in &aliases {
                let v = edit::verify_entry(&ks, a, now_ts())?;
                all_ok &= v.ok;
                results.push(v);
            }
            if out.json {
                out.print_json(&serde_json::to_value(&results).unwrap_or_default());
            } else {
                for v in &results {
                    out.verification(v);
                }
            }
            return Ok(if all_ok { 0 } else { 2 });
        }
        ManageCmd::CheckRole {
            store,
            role,
            host,
            pw,
        } => {
            use rustca_core::role::{check_role, store_kind, StoreRole};
            let ks = load_any(&store, pw.password)?;
            let role = match role {
                Some(RoleArg::Server) => StoreRole::Server,
                Some(RoleArg::Client) => StoreRole::Client,
                Some(RoleArg::Trust) => StoreRole::Truststore,
                None => StoreRole::guess(&ks),
            };
            let rep = check_role(&ks, role, host.as_deref(), now_ts());
            if out.json {
                out.print_json(&serde_json::to_value(&rep).unwrap_or_default());
            } else {
                out.line(
                    None,
                    &format!(
                        "{}（{}）→ 檢查是否適合作為 {}",
                        ks.name(),
                        store_kind(&ks),
                        role.label()
                    ),
                );
                out.role_report(&rep);
            }
            return Ok(if rep.ok { 0 } else { 2 });
        }
        ManageCmd::JavaTest {
            store,
            java,
            legacy_p12,
            pw,
        } => {
            let ks = open_for_edit(&store, &pw, true)?;
            let runtimes = javacompat::discover(&java);
            let opts = WriteOptions {
                pkcs12_legacy: legacy_p12,
            };
            if !out.json {
                out.line(None, &format!("找到 {} 個 Java：", runtimes.len()));
                for r in &runtimes {
                    out.line(None, &format!("  • {} — {}", r.label(), r.home.display()));
                }
            }
            let source = if legacy_p12 {
                javacompat::TestSource::Serialize(opts)
            } else {
                javacompat::TestSource::File(&store)
            };
            let rep = javacompat::test_keystore(&runtimes, &ks, source)?;
            let (results, notes, all_ok) = (rep.results, rep.notes, rep.ok);
            if out.json {
                out.print_json(&serde_json::json!({
                    "store": store,
                    "format": ks.format.to_string(),
                    "ok": all_ok,
                    "results": results,
                    "notes": notes,
                }));
            } else {
                println!();
                for r in &results {
                    let mark = if r.ok { "✔" } else { "✘" };
                    out.line(Some(r.ok), &format!("{mark} {}：{}", r.java, r.message));
                    for (a, ok, m) in &r.keys {
                        let line = format!("    私鑰「{a}」：{m}");
                        out.line(Some(*ok), &line);
                    }
                }
                if !notes.is_empty() {
                    println!();
                    for n in &notes {
                        out.line(None, &format!("ℹ {n}"));
                    }
                }
            }
            return Ok(if all_ok { 0 } else { 2 });
        }
    }
    Ok(0)
}
