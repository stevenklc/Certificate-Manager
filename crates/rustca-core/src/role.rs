//! 用途檢查：確認憑證庫適合作為 Server keystore、Client keystore（mTLS）或 Truststore。

use serde::Serialize;

use crate::cert::CertInfo;
use crate::edit::{verify_entry, Check, CheckLevel};
use crate::model::{EntryKind, Keystore};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum StoreRole {
    /// Server 端的 keystore（含私鑰與憑證鏈）
    Server,
    /// Client 端的 keystore（mTLS 用）
    Client,
    /// 信任庫（只放信任的 CA）
    Truststore,
}

impl StoreRole {
    pub const ALL: [StoreRole; 3] = [StoreRole::Server, StoreRole::Client, StoreRole::Truststore];

    pub fn label(self) -> &'static str {
        match self {
            StoreRole::Server => "Server keystore",
            StoreRole::Client => "Client keystore（mTLS）",
            StoreRole::Truststore => "Truststore 信任庫",
        }
    }

    /// 依內容猜測用途：有私鑰視為 Server，否則為 Truststore。
    pub fn guess(ks: &Keystore) -> StoreRole {
        if ks.private_key_entries().next().is_some() {
            StoreRole::Server
        } else {
            StoreRole::Truststore
        }
    }
}

/// 憑證庫的內容種類（顯示用）。
pub fn store_kind(ks: &Keystore) -> &'static str {
    let keys = ks.private_key_entries().count();
    let trusted = ks
        .entries
        .iter()
        .filter(|e| e.kind == EntryKind::TrustedCert)
        .count();
    match (keys > 0, trusted > 0) {
        (true, false) => "Keystore",
        (false, true) => "Truststore",
        (true, true) => "Keystore + Truststore",
        (false, false) => "空的",
    }
}

/// 一個區段（整體或某個條目）的檢查結果。
#[derive(Debug, Clone, Serialize)]
pub struct RoleSection {
    pub title: String,
    pub checks: Vec<Check>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RoleReport {
    pub role: StoreRole,
    pub sections: Vec<RoleSection>,
    /// 沒有任何 Error
    pub ok: bool,
    pub errors: usize,
    pub warnings: usize,
}

struct Builder {
    sections: Vec<RoleSection>,
}

impl Builder {
    fn section(&mut self, title: impl Into<String>) {
        self.sections.push(RoleSection {
            title: title.into(),
            checks: vec![],
        });
    }
    fn push(&mut self, level: CheckLevel, msg: impl Into<String>) {
        if let Some(s) = self.sections.last_mut() {
            s.checks.push(Check {
                level,
                message: msg.into(),
            });
        }
    }
    fn finish(self, role: StoreRole) -> RoleReport {
        let count = |l: CheckLevel| {
            self.sections
                .iter()
                .flat_map(|s| &s.checks)
                .filter(|c| c.level == l)
                .count()
        };
        let errors = count(CheckLevel::Error);
        let warnings = count(CheckLevel::Warn);
        RoleReport {
            role,
            ok: errors == 0,
            errors,
            warnings,
            sections: self.sections,
        }
    }
}

use CheckLevel::{Error as Bad, Ok as Good, Warn};

/// 檢查憑證庫是否適合指定用途。`host` 只用於 Server：檢查憑證是否涵蓋此主機名稱 / IP。
pub fn check_role(ks: &Keystore, role: StoreRole, host: Option<&str>, now: i64) -> RoleReport {
    let mut b = Builder { sections: vec![] };
    match role {
        StoreRole::Server | StoreRole::Client => check_keystore(&mut b, ks, role, host, now),
        StoreRole::Truststore => check_truststore(&mut b, ks, now),
    }
    b.finish(role)
}

fn check_keystore(b: &mut Builder, ks: &Keystore, role: StoreRole, host: Option<&str>, now: i64) {
    let keys: Vec<_> = ks.private_key_entries().collect();
    let trusted = ks
        .entries
        .iter()
        .filter(|e| e.kind == EntryKind::TrustedCert)
        .count();
    b.section("整體");
    if keys.is_empty() {
        b.push(
            Bad,
            match role {
                StoreRole::Server => "沒有私鑰條目：Server 必須有私鑰 + 憑證鏈才能提供 TLS 服務",
                _ => "沒有私鑰條目：mTLS 的 Client 必須有私鑰 + 憑證才能送出 Client 憑證",
            },
        );
        if trusted > 0 {
            b.push(
                Warn,
                format!("只有 {trusted} 張信任憑證，看起來是 Truststore，可改選「Truststore」檢查"),
            );
        }
        return;
    }
    b.push(Good, format!("有 {} 個私鑰條目", keys.len()));
    if keys.len() > 1 {
        b.push(
            Warn,
            "有多個私鑰條目：Tomcat / Spring Boot 等請以 keyAlias 指定要用哪一個，否則會取第一個",
        );
    }
    if trusted > 0 {
        b.push(
            Good,
            format!("另有 {trusted} 張信任憑證（keystore 與 truststore 共用同一個檔案也可以）"),
        );
    }

    let any_covers = host.filter(|h| !h.trim().is_empty()).is_some_and(|h| {
        keys.iter()
            .any(|e| e.chain.first().is_some_and(|c| covers_host(c, h)))
    });
    let (need_eku, eku_name) = match role {
        StoreRole::Server => ("serverAuth", "Server 驗證（serverAuth）"),
        _ => ("clientAuth", "Client 驗證（clientAuth）"),
    };
    for e in keys {
        b.section(format!("🔑 {}", e.alias));
        let Some(leaf) = e.chain.first() else {
            b.push(Bad, "沒有憑證");
            continue;
        };
        // 憑證鏈：私鑰相符、順序、簽章、期限、根
        if let Ok(v) = verify_entry(ks, &e.alias, now) {
            for c in v.checks {
                b.push(c.level, c.message);
            }
        }
        if leaf.is_ca {
            b.push(
                Bad,
                "終端憑證是 CA 憑證（CA=true），不應直接拿來當 TLS 身分",
            );
        }
        // 延伸金鑰用途
        let eku = &leaf.ext_key_usage;
        if eku.is_empty() {
            b.push(Good, "沒有延伸金鑰用途（EKU）限制，可用於任何用途");
        } else if eku
            .iter()
            .any(|u| u == need_eku || u == "anyExtendedKeyUsage")
        {
            b.push(Good, format!("延伸金鑰用途包含{eku_name}"));
        } else {
            b.push(
                Bad,
                format!(
                    "延伸金鑰用途為「{}」，不含{eku_name}，對方會拒絕",
                    eku.join("、")
                ),
            );
        }
        // 金鑰用途
        let ku = leaf.key_usage.join(", ").to_lowercase();
        if !ku.is_empty() {
            let rsa = leaf.public_key.starts_with("RSA");
            let ok = ku.contains("digital signature") || (rsa && ku.contains("key encipherment"));
            if ok {
                b.push(Good, format!("金鑰用途：{}", leaf.key_usage.join(", ")));
            } else {
                b.push(
                    Bad,
                    format!(
                        "金鑰用途「{}」不含 Digital Signature{}，無法用於 TLS",
                        leaf.key_usage.join(", "),
                        if rsa { " / Key Encipherment" } else { "" }
                    ),
                );
            }
        }
        weak_crypto(b, leaf);
        if role == StoreRole::Server {
            server_names(b, leaf, host, any_covers);
        }
    }
}

/// 憑證是否涵蓋主機名稱（有 SAN 只看 SAN，沒有才看 CN）。
pub fn covers_host(leaf: &CertInfo, host: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let names: Vec<&str> = leaf
        .subject_alt_names
        .iter()
        .filter_map(|s| s.strip_prefix("DNS:").or_else(|| s.strip_prefix("IP:")))
        .collect();
    if names.is_empty() {
        leaf.subject_cn
            .as_deref()
            .is_some_and(|cn| name_matches(cn, &host))
    } else {
        names.iter().any(|n| name_matches(n, &host))
    }
}

fn server_names(b: &mut Builder, leaf: &CertInfo, host: Option<&str>, any_covers: bool) {
    let names: Vec<&str> = leaf
        .subject_alt_names
        .iter()
        .filter_map(|s| s.strip_prefix("DNS:").or_else(|| s.strip_prefix("IP:")))
        .collect();
    if names.is_empty() {
        b.push(
            Warn,
            "沒有 SAN（主體別名）：瀏覽器與多數新版 Client 只看 SAN，不再使用 CN 比對主機名稱",
        );
    } else {
        b.push(Good, format!("SAN：{}", names.join("、")));
    }
    let Some(host) = host.map(str::trim).filter(|h| !h.is_empty()) else {
        return;
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if covers_host(leaf, &host) {
        b.push(Good, format!("憑證涵蓋主機名稱「{host}」"));
    } else if any_covers {
        // 另有條目涵蓋：Server 以 keyAlias 指定那個條目即可
        b.push(
            Warn,
            format!("此條目不涵蓋主機名稱「{host}」（另有條目涵蓋，請以 keyAlias 指定該條目）"),
        );
    } else {
        b.push(
            Bad,
            format!("憑證不涵蓋主機名稱「{host}」，Client 會出現主機名稱不符的錯誤"),
        );
    }
}

/// 主機名稱比對（支援最左邊一層的萬用字元 *.example.com）。
pub fn name_matches(pattern: &str, host: &str) -> bool {
    let p = pattern.trim_end_matches('.').to_ascii_lowercase();
    if p == host {
        return true;
    }
    match p.strip_prefix("*.") {
        Some(rest) => host
            .split_once('.')
            .is_some_and(|(first, tail)| !first.is_empty() && tail == rest),
        None => false,
    }
}

fn weak_crypto(b: &mut Builder, c: &CertInfo) {
    let alg = c.signature_algorithm.to_ascii_lowercase();
    if alg.contains("md5") || alg.contains("md2") {
        b.push(
            Bad,
            format!("「{}」使用 MD5 簽章，已不安全", c.display_name()),
        );
    } else if alg.contains("sha1") && !c.self_signed {
        b.push(
            Bad,
            format!(
                "「{}」使用 SHA-1 簽章，新版 Java 與瀏覽器會拒絕",
                c.display_name()
            ),
        );
    }
    if let Some(bits) = rsa_bits(c) {
        if bits < 2048 {
            b.push(
                Bad,
                format!(
                    "「{}」的 RSA 金鑰只有 {bits} bits（需 ≥ 2048）",
                    c.display_name()
                ),
            );
        }
    }
}

fn rsa_bits(c: &CertInfo) -> Option<u32> {
    c.public_key
        .strip_prefix("RSA ")?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn check_truststore(b: &mut Builder, ks: &Keystore, now: i64) {
    let trusted: Vec<_> = ks
        .entries
        .iter()
        .filter(|e| e.kind == EntryKind::TrustedCert)
        .collect();
    let keys = ks.private_key_entries().count();
    b.section("整體");
    if trusted.is_empty() {
        b.push(Bad, "沒有信任憑證條目，無法用來驗證對方");
        if keys > 0 {
            b.push(
                Warn,
                "只有私鑰條目，看起來是 keystore，可改選「Server」或「Client」檢查",
            );
        }
        return;
    }
    let roots = trusted
        .iter()
        .filter(|e| e.chain.first().is_some_and(|c| c.self_signed && c.is_ca))
        .count();
    b.push(
        Good,
        format!("有 {} 張信任憑證，其中 {roots} 張為根 CA", trusted.len()),
    );
    if keys > 0 {
        b.push(
            Warn,
            format!("含有 {keys} 個私鑰條目：信任庫通常只放 CA 憑證，私鑰建議放在另外的 keystore"),
        );
    }
    let mut expired = 0;
    let mut leafs = 0;
    let mut bad_rows = Vec::new();
    for e in &trusted {
        let Some(c) = e.chain.first() else { continue };
        let mut row = Vec::new();
        match c.status_at(now, 30) {
            crate::ValidityStatus::Expired { days_ago } => {
                expired += 1;
                row.push((
                    Warn,
                    format!("已過期 {days_ago} 天，由它簽發的憑證會驗證失敗"),
                ));
            }
            crate::ValidityStatus::NotYetValid { days_until } => {
                row.push((Warn, format!("尚未生效（{days_until} 天後）")))
            }
            crate::ValidityStatus::ExpiringSoon { days_left } => {
                row.push((Warn, format!("即將到期（剩 {days_left} 天）")))
            }
            _ => {}
        }
        if !c.is_ca {
            leafs += 1;
            if c.self_signed {
                row.push((
                    Warn,
                    "自簽的非 CA 憑證：只能用來信任這一張憑證本身".to_string(),
                ));
            } else {
                row.push((
                    Warn,
                    "終端憑證（非 CA）：等於只信任這一張，對方續約換憑證後就要重新匯入；建議改放它的 CA".to_string(),
                ));
            }
        }
        let alg = c.signature_algorithm.to_ascii_lowercase();
        if alg.contains("md5") || alg.contains("md2") {
            row.push((Warn, "使用 MD5 簽章".to_string()));
        }
        if let Some(bits) = rsa_bits(c) {
            if bits < 2048 {
                row.push((
                    Warn,
                    format!("RSA 金鑰只有 {bits} bits，新版 Java 可能停用"),
                ));
            }
        }
        if !row.is_empty() {
            bad_rows.push((e.alias.clone(), c.display_name(), row));
        }
    }
    if expired == 0 && leafs == 0 && bad_rows.is_empty() {
        b.push(Good, "所有信任憑證都是有效的 CA 憑證");
    } else {
        if expired > 0 {
            b.push(Warn, format!("{expired} 張信任憑證已過期，建議移除或更新"));
        }
        if leafs > 0 {
            b.push(Warn, format!("{leafs} 張信任憑證不是 CA（憑證釘選）"));
        }
    }
    for (alias, name, row) in bad_rows {
        b.section(format!("📄 {alias}（{name}）"));
        for (l, m) in row {
            b.push(l, m);
        }
    }
}
