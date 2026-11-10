//! Java 相容性測試：找出本機安裝的各版本 JDK / JRE，
//! 用各版本的 keytool 實際讀取憑證庫並解開私鑰，確認不同 Java 版本都能使用。

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Serialize;

use crate::edit::{self, WriteOptions};
use crate::error::{Error, Result};
use crate::model::{EntryKind, KeyState, Keystore, StoreFormat};

/// 一個 Java 執行環境。
#[derive(Debug, Clone, Serialize)]
pub struct JavaRuntime {
    pub home: PathBuf,
    pub keytool: PathBuf,
    /// 例如 "1.8.0_412"、"17.0.11"
    pub version: String,
    /// 主版本，例如 8、11、17
    pub major: u32,
    pub vendor: String,
}

impl JavaRuntime {
    pub fn label(&self) -> String {
        if self.vendor.is_empty() {
            format!("Java {}（{}）", self.major, self.version)
        } else {
            format!("Java {}（{}，{}）", self.major, self.version, self.vendor)
        }
    }
}

fn exe(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

fn command(program: &Path) -> Command {
    #[allow(unused_mut)]
    let mut c = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        c.creation_flags(CREATE_NO_WINDOW);
    }
    c.stdin(Stdio::null());
    c
}

/// canonicalize 但去掉 Windows 的 `\\?\` 前綴，方便閱讀。
fn canonical(p: &Path) -> PathBuf {
    let c = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let s = c.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => c,
    }
}

fn parse_major(v: &str) -> u32 {
    let mut it = v.split(['.', '_', '-', '+']);
    match it.next().and_then(|x| x.parse::<u32>().ok()) {
        Some(1) => it.next().and_then(|x| x.parse().ok()).unwrap_or(1),
        Some(n) => n,
        None => 0,
    }
}

/// 從 JDK / JRE 根目錄建立執行環境資訊；不是 Java 目錄時回傳 None。
pub fn runtime_from_home(home: &Path) -> Option<JavaRuntime> {
    let mut home = home.to_path_buf();
    // 指到 bin 或 keytool 本身時往上找
    if home.is_file() {
        home = home.parent()?.parent()?.to_path_buf();
    } else if home.file_name().is_some_and(|n| n == "bin") {
        home = home.parent()?.to_path_buf();
    }
    // JDK 8 的 jre 子目錄併入 JDK
    if home.file_name().is_some_and(|n| n == "jre") {
        if let Some(p) = home.parent() {
            if p.join("bin").join(exe("keytool")).is_file() {
                home = p.to_path_buf();
            }
        }
    }
    let keytool = home.join("bin").join(exe("keytool"));
    if !keytool.is_file() {
        return None;
    }
    let home = canonical(&home);
    let keytool = home.join("bin").join(exe("keytool"));

    let mut version = String::new();
    let mut vendor = String::new();
    if let Ok(text) = std::fs::read_to_string(home.join("release")) {
        for line in text.lines() {
            let val = |l: &str| {
                l.split_once('=')
                    .map(|(_, v)| v.trim().trim_matches('"').to_string())
            };
            if line.starts_with("JAVA_VERSION=") {
                version = val(line).unwrap_or_default();
            } else if line.starts_with("IMPLEMENTOR=") {
                vendor = val(line).unwrap_or_default();
            }
        }
    }
    if version.is_empty() {
        let java = home.join("bin").join(exe("java"));
        if let Ok(out) = command(&java).arg("-version").output() {
            let text = String::from_utf8_lossy(&out.stderr);
            if let Some(v) = text.split('"').nth(1) {
                version = v.to_string();
            }
        }
    }
    if version.is_empty() {
        version = "未知版本".into();
    }
    Some(JavaRuntime {
        major: parse_major(&version),
        home,
        keytool,
        version,
        vendor,
    })
}

fn children(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect()
        })
        .unwrap_or_default()
}

fn candidate_dirs(extra: &[PathBuf]) -> Vec<PathBuf> {
    let mut c: Vec<PathBuf> = Vec::new();
    // 使用者指定：可以是 JDK 根目錄，或放了多個 JDK 的上層目錄
    for e in extra {
        c.push(e.clone());
        c.extend(children(e));
    }
    if let Some(v) = std::env::var_os("RUST_CA_JAVA_HOMES") {
        for p in std::env::split_paths(&v) {
            c.extend(children(&p));
            c.push(p);
        }
    }
    if let Some(h) = std::env::var_os("JAVA_HOME") {
        c.push(PathBuf::from(h));
    }
    // PATH 上的 keytool
    if let Some(path) = std::env::var_os("PATH") {
        for d in std::env::split_paths(&path) {
            let k = d.join(exe("keytool"));
            if k.is_file() {
                c.push(canonical(&k));
            }
        }
    }
    let home =
        std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from);
    if let Some(h) = &home {
        for sub in [
            ".jdks",
            ".sdkman/candidates/java",
            ".gradle/jdks",
            ".m2/jdks",
        ] {
            c.extend(children(&h.join(sub)));
        }
    }
    if cfg!(windows) {
        let vendors = [
            "Java",
            "Eclipse Adoptium",
            "Eclipse Foundation",
            "AdoptOpenJDK",
            "Microsoft",
            "Zulu",
            "Amazon Corretto",
            "BellSoft",
            "Semeru",
            "OpenJDK",
            "RedHat",
            "Oracle",
        ];
        let mut roots: Vec<PathBuf> = ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]
            .iter()
            .filter_map(std::env::var_os)
            .map(PathBuf::from)
            .collect();
        if let Some(l) = std::env::var_os("LOCALAPPDATA") {
            roots.push(PathBuf::from(l).join("Programs"));
        }
        for r in roots {
            for v in vendors {
                c.extend(children(&r.join(v)));
            }
        }
    } else {
        for d in [
            "/usr/lib/jvm",
            "/usr/java",
            "/opt/java",
            "/opt/jdk",
            "/usr/local/java",
        ] {
            c.extend(children(Path::new(d)));
        }
        for d in children(Path::new("/Library/Java/JavaVirtualMachines")) {
            c.push(d.join("Contents/Home"));
        }
    }
    c
}

/// 找出本機所有 Java 版本（依主版本排序）。`extra` 為使用者額外指定的目錄。
pub fn discover(extra: &[PathBuf]) -> Vec<JavaRuntime> {
    let mut seen = HashSet::new();
    let mut out: Vec<JavaRuntime> = candidate_dirs(extra)
        .into_iter()
        .filter_map(|d| runtime_from_home(&d))
        .filter(|r| seen.insert(r.keytool.clone()))
        .collect();
    // 多個 JDK 常解壓在同一個資料夾：再掃描已找到的 JDK 旁邊兩層
    let mut near: Vec<PathBuf> = Vec::new();
    for r in &out {
        for up in [r.home.parent(), r.home.parent().and_then(Path::parent)]
            .into_iter()
            .flatten()
        {
            let kids = children(up);
            // 避免掃描像 /usr/lib 這種很大的系統目錄
            if kids.len() > 200 {
                continue;
            }
            for c in kids {
                near.extend(children(&c).into_iter().take(50));
                near.push(c);
            }
        }
    }
    near.sort();
    near.dedup();
    for d in near {
        if let Some(r) = runtime_from_home(&d) {
            if seen.insert(r.keytool.clone()) {
                out.push(r);
            }
        }
    }
    out.sort_by(|a, b| a.major.cmp(&b.major).then(a.version.cmp(&b.version)));
    out
}

/// 單一 Java 版本的測試結果。
#[derive(Debug, Clone, Serialize)]
pub struct JavaTestResult {
    pub java: String,
    pub major: u32,
    pub home: PathBuf,
    /// 讀取憑證庫成功
    pub list_ok: bool,
    /// keytool 列出的條目數
    pub listed: usize,
    pub expected: usize,
    /// (別名, 是否成功, 說明)：用私鑰產生 CSR，確認私鑰能被此版本解開
    pub keys: Vec<(String, bool, String)>,
    pub ok: bool,
    pub message: String,
}

fn store_type(f: StoreFormat) -> Option<&'static str> {
    Some(match f {
        StoreFormat::Jks => "JKS",
        StoreFormat::Jceks => "JCEKS",
        StoreFormat::Pkcs12 => "PKCS12",
        _ => return None,
    })
}

fn first_error_line(out: &std::process::Output) -> String {
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    text.lines()
        .map(str::trim)
        .find(|l| l.contains("error") || l.contains("Exception") || l.contains("錯誤"))
        .or_else(|| text.lines().map(str::trim).find(|l| !l.is_empty()))
        .unwrap_or("（沒有輸出）")
        .chars()
        .take(300)
        .collect()
}

fn run_keytool(
    rt: &JavaRuntime,
    args: &[&str],
    envs: &[(&str, &str)],
) -> std::io::Result<std::process::Output> {
    let mut c = command(&rt.keytool);
    // 固定英文輸出，方便解析
    c.args(["-J-Duser.language=en", "-J-Duser.country=US"]);
    c.args(args);
    for (k, v) in envs {
        c.env(k, v);
    }
    c.output()
}

const ENV_STORE: &str = "RUSTCA_KT_STOREPASS";
const ENV_KEY: &str = "RUSTCA_KT_KEYPASS";

/// 測試一個已寫入的憑證庫檔案。
fn test_file(rt: &JavaRuntime, file: &Path, ks: &Keystore, store_pw: &str) -> JavaTestResult {
    let st = store_type(ks.format).unwrap_or("JKS");
    let file_s = file.to_string_lossy().into_owned();
    let expected = ks.entries.len();
    let mut r = JavaTestResult {
        java: rt.label(),
        major: rt.major,
        home: rt.home.clone(),
        list_ok: false,
        listed: 0,
        expected,
        keys: vec![],
        ok: false,
        message: String::new(),
    };
    let list = run_keytool(
        rt,
        &[
            "-list",
            "-keystore",
            &file_s,
            "-storetype",
            st,
            "-storepass:env",
            ENV_STORE,
        ],
        &[(ENV_STORE, store_pw)],
    );
    match list {
        Err(e) => {
            r.message = format!("無法執行 keytool：{e}");
            return r;
        }
        Ok(out) if !out.status.success() => {
            r.message = format!("讀取失敗：{}", first_error_line(&out));
            return r;
        }
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            r.listed = text
                .lines()
                .filter(|l| {
                    l.contains("PrivateKeyEntry")
                        || l.contains("trustedCertEntry")
                        || l.contains("SecretKeyEntry")
                })
                .count();
            r.list_ok = true;
        }
    }

    // 逐一解開私鑰（以 -certreq 產生 CSR，需要私鑰才能簽章）
    for e in ks
        .entries
        .iter()
        .filter(|e| e.kind == EntryKind::PrivateKey)
        .take(20)
    {
        let key_pw = match (&e.key, &e.key_password) {
            (_, Some(k)) => k.expose().to_string(),
            (KeyState::Decrypted { .. }, None) => store_pw.to_string(),
            _ if ks.format == StoreFormat::Pkcs12 => store_pw.to_string(),
            _ => {
                r.keys
                    .push((e.alias.clone(), true, "私鑰密碼未知，略過".into()));
                continue;
            }
        };
        // JKS 別名不分大小寫，keytool 以小寫儲存
        let alias = if ks.format == StoreFormat::Pkcs12 {
            e.alias.clone()
        } else {
            e.alias.to_lowercase()
        };
        let out = run_keytool(
            rt,
            &[
                "-certreq",
                "-alias",
                &alias,
                "-keystore",
                &file_s,
                "-storetype",
                st,
                "-storepass:env",
                ENV_STORE,
                "-keypass:env",
                ENV_KEY,
            ],
            &[(ENV_STORE, store_pw), (ENV_KEY, &key_pw)],
        );
        match out {
            Ok(o)
                if o.status.success()
                    && String::from_utf8_lossy(&o.stdout).contains("CERTIFICATE REQUEST") =>
            {
                r.keys
                    .push((e.alias.clone(), true, "私鑰可解開並簽章".into()))
            }
            Ok(o) => r.keys.push((e.alias.clone(), false, first_error_line(&o))),
            Err(err) => r.keys.push((e.alias.clone(), false, err.to_string())),
        }
    }

    let keys_ok = r.keys.iter().all(|k| k.1);
    r.ok = r.list_ok && r.listed == expected && keys_ok;
    r.message = if r.ok {
        format!("讀取成功（{} 個條目）", r.listed)
    } else if r.listed != expected {
        format!(
            "只讀到 {} / {} 個條目（部分條目此版本不支援）",
            r.listed, expected
        )
    } else {
        "部分私鑰無法解開".into()
    };
    r
}

/// 要測試的內容。
#[derive(Debug, Clone, Copy)]
pub enum TestSource<'a> {
    /// 直接測試磁碟上的檔案
    File(&'a Path),
    /// 以目前記憶體中的內容（含尚未儲存的變更）寫出暫存檔再測試
    Serialize(WriteOptions),
}

/// 測試報告。
#[derive(Debug, Clone, Serialize)]
pub struct JavaTestReport {
    pub results: Vec<JavaTestResult>,
    /// 不需 Java 即可判斷的相容性提示
    pub notes: Vec<String>,
    pub ok: bool,
}

/// PKCS#12 是否使用 PBES2（AES）加密 —— 舊版 Java 無法讀取。
pub fn pkcs12_uses_pbes2(data: &[u8]) -> bool {
    const PBES2: [u8; 11] = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d,
    ];
    data.windows(PBES2.len()).any(|w| w == PBES2)
}

/// 用每個 Java 版本測試憑證庫。
pub fn test_keystore(
    runtimes: &[JavaRuntime],
    ks: &Keystore,
    source: TestSource,
) -> Result<JavaTestReport> {
    if store_type(ks.format).is_none() {
        return Err(Error::Unsupported(format!(
            "{} 不是 Java 憑證庫格式（支援 JKS、JCEKS、PKCS#12）",
            ks.format
        )));
    }
    if runtimes.is_empty() {
        return Err(Error::Other(
            "找不到任何 Java（可設定 JAVA_HOME、RUST_CA_JAVA_HOMES，或手動指定 JDK 目錄）".into(),
        ));
    }
    let store_pw = ks
        .store_password
        .as_ref()
        .map(|s| s.expose().to_string())
        .ok_or_else(|| Error::NeedPassword("需要憑證庫密碼".into()))?;
    let (results, data) = match source {
        TestSource::File(path) => {
            let data = std::fs::read(path)
                .map_err(|e| Error::Other(format!("無法讀取 {}：{e}", path.display())))?;
            let r: Vec<JavaTestResult> = runtimes
                .iter()
                .map(|rt| test_file(rt, path, ks, &store_pw))
                .collect();
            (r, data)
        }
        TestSource::Serialize(opts) => {
            let ser = edit::serialize_with(ks, ks.format, opts)?;
            let mut rnd = [0u8; 8];
            let _ = getrandom::getrandom(&mut rnd);
            let ext = match ks.format {
                StoreFormat::Pkcs12 => "p12",
                StoreFormat::Jceks => "jceks",
                _ => "jks",
            };
            let tmp =
                std::env::temp_dir().join(format!("rustca-javatest-{}.{ext}", hex::encode(rnd)));
            std::fs::write(&tmp, &ser.data)
                .map_err(|e| Error::Other(format!("無法寫入暫存檔：{e}")))?;
            let r: Vec<JavaTestResult> = runtimes
                .iter()
                .map(|rt| test_file(rt, &tmp, ks, &store_pw))
                .collect();
            let _ = std::fs::remove_file(&tmp);
            (r, ser.data)
        }
    };
    let modern = ks.format == StoreFormat::Pkcs12 && pkcs12_uses_pbes2(&data);
    let notes = static_notes(ks, modern);
    let ok = results.iter().all(|r: &JavaTestResult| r.ok);
    Ok(JavaTestReport { results, notes, ok })
}

/// 不需要 Java 就能判斷的相容性提示。
/// `pkcs12_pbes2`：PKCS#12 是否使用 PBES2（見 [`pkcs12_uses_pbes2`]）。
pub fn static_notes(ks: &Keystore, pkcs12_pbes2: bool) -> Vec<String> {
    let mut notes = Vec::new();
    match ks.format {
        StoreFormat::Pkcs12 if pkcs12_pbes2 => notes.push(
            "PKCS#12 預設使用 PBES2-AES256 + HmacSHA256，需 Java 8u301+、11.0.12+ 或 12 以上；\
             要給更舊的 Java 使用請改存為「舊版相容 PKCS#12」（CLI：--legacy-p12）"
                .into(),
        ),
        StoreFormat::Pkcs12 => {
            notes.push("PKCS#12 使用舊式演算法（3DES / RC2 + HmacSHA1），舊版 Java 也能讀取".into())
        }
        StoreFormat::Jks => notes.push(
            "JKS 為 Java 專屬格式，所有 Java 版本都能讀；Java 9 以後 keytool 會建議改用 PKCS#12"
                .into(),
        ),
        StoreFormat::Jceks => notes.push("JCEKS 為 Java 專屬格式，所有 Java 版本都能讀".into()),
        _ => {}
    }
    for e in &ks.entries {
        for c in &e.chain {
            let alg = c.signature_algorithm.to_ascii_lowercase();
            let pk = c.public_key.to_ascii_lowercase();
            if pk.contains("ed25519") || pk.contains("ed448") {
                notes.push(format!("「{}」使用 EdDSA 金鑰，需 Java 15 以上", e.alias));
            }
            if alg.contains("md5") || alg.contains("md2") {
                notes.push(format!(
                    "「{}」的憑證「{}」使用 MD5 簽章，新版 Java 會拒絕",
                    e.alias,
                    c.display_name()
                ));
            } else if alg.contains("sha1") && !c.self_signed {
                notes.push(format!(
                    "「{}」的憑證「{}」使用 SHA-1 簽章，新版 Java 的 TLS 會拒絕",
                    e.alias,
                    c.display_name()
                ));
            }
            if let Some(bits) = pk
                .strip_prefix("rsa ")
                .and_then(|r| r.split_whitespace().next())
                .and_then(|b| b.parse::<u32>().ok())
            {
                if bits < 2048 {
                    notes.push(format!(
                        "「{}」的憑證「{}」RSA 金鑰只有 {bits} bits，新版 Java 可能拒絕（建議 ≥ 2048）",
                        e.alias,
                        c.display_name()
                    ));
                }
            }
        }
    }
    notes.dedup();
    notes
}
