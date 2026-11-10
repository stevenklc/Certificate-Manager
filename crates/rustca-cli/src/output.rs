//! 輸出格式（表格 / 樹狀 / JSON）。

use std::io::IsTerminal;

use comfy_table::{presets::UTF8_FULL_CONDENSED, Cell, Color, ContentArrangement, Table};
use rustca_core::chain::LinkSource;
use rustca_core::tls::HandshakeReport;
use rustca_core::{
    format_ts, now_ts, BuiltChain, CertInfo, ChainEnd, Entry, Keystore, SearchHit, ValidityStatus,
};
use serde_json::{json, Value};

pub struct Out {
    pub json: bool,
    color: bool,
}

const RED: &str = "31";
const GREEN: &str = "32";
const YELLOW: &str = "33";
const CYAN: &str = "36";
const DIM: &str = "2";
const BOLD: &str = "1";

impl Out {
    pub fn new(json: bool, color: bool) -> Self {
        let color =
            color && std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal();
        Out { json, color }
    }

    fn paint(&self, s: &str, code: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    fn table(&self) -> Table {
        let mut t = Table::new();
        t.load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic);
        if !self.color {
            t.force_no_tty();
        }
        t
    }

    pub fn print_json(&self, v: &Value) {
        println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
    }

    pub fn error(&self, msg: &str) {
        eprintln!("{} {msg}", self.paint("錯誤：", RED));
    }

    pub fn success(&self, msg: &str) {
        println!("{}", self.paint(&format!("✔ {msg}"), GREEN));
    }

    /// 一行結果（stdout）：Some(true) 綠、Some(false) 紅、None 一般。
    pub fn line(&self, ok: Option<bool>, msg: &str) {
        match ok {
            Some(true) => println!("{}", self.paint(msg, GREEN)),
            Some(false) => println!("{}", self.paint(msg, RED)),
            None => println!("{msg}"),
        }
    }

    /// 憑證鏈驗證結果。
    pub fn verification(&self, v: &rustca_core::edit::Verification) {
        use rustca_core::edit::CheckLevel;
        println!("{}", self.paint(&format!("── 驗證「{}」──", v.alias), CYAN));
        for c in &v.checks {
            match c.level {
                CheckLevel::Ok => println!("  {}", self.paint(&format!("✔ {}", c.message), GREEN)),
                CheckLevel::Warn => {
                    println!("  {}", self.paint(&format!("⚠ {}", c.message), YELLOW))
                }
                CheckLevel::Error => println!("  {}", self.paint(&format!("✘ {}", c.message), RED)),
            }
        }
        if v.ok {
            println!("{}", self.paint("驗證通過", GREEN));
        } else {
            println!("{}", self.paint("驗證失敗", RED));
        }
    }

    pub fn warn(&self, msg: &str) {
        eprintln!("{} {msg}", self.paint("注意：", YELLOW));
    }

    pub fn info(&self, msg: &str) {
        eprintln!("{}", self.paint(msg, DIM));
    }

    fn status_cell(&self, s: ValidityStatus) -> Cell {
        let c = Cell::new(s.label());
        match s {
            ValidityStatus::Valid { .. } => c.fg(Color::Green),
            ValidityStatus::ExpiringSoon { .. } => c.fg(Color::Yellow),
            _ => c.fg(Color::Red),
        }
    }

    fn status_text(&self, s: ValidityStatus) -> String {
        let code = match s {
            ValidityStatus::Valid { .. } => GREEN,
            ValidityStatus::ExpiringSoon { .. } => YELLOW,
            _ => RED,
        };
        self.paint(&s.label(), code)
    }

    fn store_header(&self, ks: &Keystore) {
        println!(
            "{}  格式：{}  完整性：{}  條目數：{}",
            self.paint(&format!("■ {}", ks.path.display()), BOLD),
            ks.format,
            ks.integrity,
            ks.entries.len()
        );
        for w in &ks.warnings {
            println!("  {}", self.paint(&format!("⚠ {w}"), YELLOW));
        }
    }

    // ───────────── list ─────────────

    pub fn list(&self, stores: &[Keystore], warn_days: i64) {
        let now = now_ts();
        if self.json {
            let v: Vec<Value> = stores
                .iter()
                .map(|ks| store_json(ks, now, warn_days))
                .collect();
            self.print_json(&json!(v));
            return;
        }
        for ks in stores {
            self.store_header(ks);
            let mut t = self.table();
            t.set_header(vec![
                "#",
                "別名",
                "類型",
                "主體 CN",
                "簽發者",
                "到期日",
                "狀態",
                "私鑰",
            ]);
            for (i, e) in ks.entries.iter().enumerate() {
                match e.leaf() {
                    Some(c) => {
                        let issuer = if c.self_signed {
                            "（自簽）".to_string()
                        } else {
                            short_dn(&c.issuer)
                        };
                        t.add_row(vec![
                            Cell::new(i + 1),
                            Cell::new(&e.alias),
                            Cell::new(format!("{}{}", e.kind, chain_suffix(e))),
                            Cell::new(c.display_name()),
                            Cell::new(issuer),
                            Cell::new(format_ts(c.not_after)),
                            self.status_cell(c.status_at(now, warn_days)),
                            Cell::new(key_label(e)),
                        ]);
                    }
                    None => {
                        t.add_row(vec![
                            Cell::new(i + 1),
                            Cell::new(&e.alias),
                            Cell::new(e.kind.to_string()),
                            Cell::new(e.note.clone().unwrap_or_default()),
                            Cell::new(""),
                            Cell::new(""),
                            Cell::new(""),
                            Cell::new(key_label(e)),
                        ]);
                    }
                }
            }
            println!("{t}\n");
        }
    }

    // ───────────── show ─────────────

    pub fn show(&self, ks: &Keystore, entries: &[&Entry], pem: bool, warn_days: i64) {
        let now = now_ts();
        if self.json {
            let v: Vec<Value> = entries
                .iter()
                .map(|e| entry_json(e, now, warn_days))
                .collect();
            self.print_json(&json!({ "file": ks.path, "format": ks.format, "entries": v }));
            return;
        }
        self.store_header(ks);
        for e in entries {
            println!();
            println!(
                "{} {}（{}，私鑰：{}）",
                self.paint("▶ 別名：", CYAN),
                self.paint(&e.alias, BOLD),
                e.kind,
                e.key.label()
            );
            if let Some(ts) = e.created {
                println!("  建立時間：{}", format_ts(ts));
            }
            if let Some(n) = &e.note {
                println!("  備註：{n}");
            }
            for (i, c) in e.chain.iter().enumerate() {
                println!(
                    "\n  {} 憑證 [{i}] {}",
                    self.paint("─", DIM),
                    self.paint(&c.display_name(), BOLD)
                );
                let mut t = self.table();
                let rows: Vec<(&str, String)> = cert_rows(c);
                for (k, v) in rows {
                    t.add_row(vec![Cell::new(k), Cell::new(v)]);
                }
                t.add_row(vec![
                    Cell::new("狀態"),
                    self.status_cell(c.status_at(now, warn_days)),
                ]);
                println!("{t}");
                if pem {
                    print!("{}", c.to_pem());
                }
            }
        }
    }

    // ───────────── chain ─────────────

    pub fn chains(&self, ks: &Keystore, chains: &[(&Entry, BuiltChain)]) {
        if self.json {
            let v: Vec<Value> = chains
                .iter()
                .map(|(e, c)| json!({ "alias": e.alias, "complete": c.is_complete(), "chain": c }))
                .collect();
            self.print_json(&json!({ "file": ks.path, "chains": v }));
            return;
        }
        self.store_header(ks);
        for (e, chain) in chains {
            println!(
                "\n{} {}",
                self.paint("▶ 別名：", CYAN),
                self.paint(&e.alias, BOLD)
            );
            for (i, l) in chain.links.iter().enumerate() {
                let indent = "   ".repeat(i);
                let branch = if i == 0 { "" } else { "└─ " };
                let role = if l.cert.self_signed {
                    "根憑證（自簽）"
                } else if i == 0 {
                    "終端憑證"
                } else {
                    "中繼憑證"
                };
                let src = match l.source {
                    LinkSource::Entry => "",
                    LinkSource::Pool => "［從信任庫補齊］",
                };
                let sig = match l.signature_ok {
                    Some(true) => self.paint("簽章 ✔", GREEN),
                    Some(false) => self.paint("簽章 ✘", RED),
                    None => self.paint("簽章 ?", YELLOW),
                };
                println!(
                    "  {indent}{branch}[{i}] {}  {}  {}{}",
                    self.paint(&l.cert.display_name(), BOLD),
                    self.paint(role, DIM),
                    sig,
                    self.paint(src, CYAN)
                );
                println!(
                    "  {indent}{}    主體：{}",
                    if i == 0 { "" } else { "   " },
                    l.cert.subject
                );
                println!(
                    "  {indent}{}    有效：{} ～ {}  {}",
                    if i == 0 { "" } else { "   " },
                    format_ts(l.cert.not_before),
                    format_ts(l.cert.not_after),
                    self.status_text(l.validity)
                );
            }
            match &chain.end {
                ChainEnd::Root if chain.problems.is_empty() => {
                    println!("  {}", self.paint("✔ 憑證鏈完整，結束於自簽根憑證", GREEN))
                }
                ChainEnd::Root => {
                    println!("  {}", self.paint("⚠ 結束於根憑證，但有問題：", YELLOW))
                }
                ChainEnd::MissingIssuer { .. } => println!(
                    "  {}",
                    self.paint("✘ 憑證鏈不完整（可用 -t 指定 CA 檔案補齊）：", RED)
                ),
                ChainEnd::Loop => println!("  {}", self.paint("✘ 憑證鏈異常：", RED)),
            }
            for p in &chain.problems {
                println!("    - {p}");
            }
        }
    }

    // ───────────── search ─────────────

    pub fn search(&self, keyword: &str, results: &[(Keystore, Vec<SearchHit>)]) {
        if self.json {
            let v: Vec<Value> = results
                .iter()
                .map(|(ks, hits)| json!({ "file": ks.path, "hits": hits }))
                .collect();
            self.print_json(&json!({ "keyword": keyword, "results": v }));
            return;
        }
        let total: usize = results.iter().map(|(_, h)| h.len()).sum();
        println!("搜尋「{}」：共 {} 筆", self.paint(keyword, BOLD), total);
        for (ks, hits) in results {
            if hits.is_empty() {
                continue;
            }
            println!(
                "\n{}（{} 筆）",
                self.paint(&format!("■ {}", ks.path.display()), BOLD),
                hits.len()
            );
            let mut t = self.table();
            t.set_header(vec!["別名", "憑證", "符合欄位", "內容"]);
            for h in hits {
                let cert = match (h.cert_index, &h.cert_name) {
                    (Some(i), Some(n)) => format!("[{i}] {n}"),
                    _ => String::new(),
                };
                let fields = h
                    .matches
                    .iter()
                    .map(|m| m.field)
                    .collect::<Vec<_>>()
                    .join("\n");
                let values = h
                    .matches
                    .iter()
                    .map(|m| highlight(&m.value, keyword, self.color))
                    .collect::<Vec<_>>()
                    .join("\n");
                t.add_row(vec![
                    Cell::new(&h.alias),
                    Cell::new(cert),
                    Cell::new(fields),
                    Cell::new(values),
                ]);
            }
            println!("{t}");
        }
    }

    // ───────────── expiry ─────────────

    pub fn expiry(&self, stores: &[Keystore], days: i64, all: bool) -> u8 {
        let now = now_ts();
        let mut rows = Vec::new();
        let mut worst = 0u8;
        for ks in stores {
            for e in &ks.entries {
                for (i, c) in e.chain.iter().enumerate() {
                    let s = c.status_at(now, days);
                    let level = match s {
                        ValidityStatus::Valid { .. } => 0,
                        ValidityStatus::ExpiringSoon { .. } => 1,
                        _ => 2,
                    };
                    worst = worst.max(level);
                    if all || level > 0 {
                        rows.push((ks, e, i, c, s));
                    }
                }
            }
        }
        rows.sort_by_key(|r| r.3.not_after);
        if self.json {
            let v: Vec<Value> = rows
                .iter()
                .map(|(ks, e, i, c, s)| {
                    json!({ "file": ks.path, "alias": e.alias, "index": i, "subject": c.subject,
                            "not_after": c.not_after, "not_after_text": format_ts(c.not_after), "status": s })
                })
                .collect();
            self.print_json(&json!({ "days": days, "items": v, "exit_code": worst }));
            return worst;
        }
        if rows.is_empty() {
            println!(
                "{}",
                self.paint(&format!("✔ 所有憑證在 {days} 天內都不會到期"), GREEN)
            );
            return 0;
        }
        let mut t = self.table();
        t.set_header(vec!["檔案", "別名", "憑證", "到期日", "狀態"]);
        for (ks, e, i, c, s) in rows {
            t.add_row(vec![
                Cell::new(ks.name()),
                Cell::new(&e.alias),
                Cell::new(format!("[{i}] {}", c.display_name())),
                Cell::new(format_ts(c.not_after)),
                self.status_cell(s),
            ]);
        }
        println!("{t}");
        worst
    }

    // ───────────── handshake ─────────────

    pub fn handshake(&self, r: &HandshakeReport) {
        if self.json {
            self.print_json(&serde_json::to_value(r).unwrap_or_default());
            return;
        }
        let mode = if r.mode == "local" {
            "本機模擬"
        } else {
            "遠端連線"
        };
        println!(
            "{}",
            self.paint(&format!("═══ TLS 交握（{mode}）═══"), BOLD)
        );
        println!("  目標：{}", r.target);
        println!("  SNI / 驗證名稱：{}", r.server_name);
        if let Some(p) = &r.via_proxy {
            println!("  經由 Proxy：{p}");
        }
        println!("  信任錨點數：{}", r.trust_anchor_count);
        if let Some(p) = &r.protocol {
            println!("  協定：{p}");
        }
        if let Some(c) = &r.cipher_suite {
            println!("  加密套件：{c}");
        }
        if let Some(k) = &r.key_exchange {
            println!("  金鑰交換：{k}");
        }
        println!(
            "  Server 要求 Client 憑證：{}",
            if r.client_auth_requested {
                "是（mTLS）"
            } else {
                "否"
            }
        );
        if !r.acceptable_ca_names.is_empty() {
            println!("  Server 可接受的 Client CA：");
            for n in &r.acceptable_ca_names {
                println!("    - {n}");
            }
        }

        if !r.transcript.is_empty() {
            println!("\n{}", self.paint("── 交握訊息 ──", CYAN));
            for l in &r.transcript {
                let arrow = if l.direction == "C→S" {
                    self.paint("Client ──▶ Server", DIM)
                } else {
                    self.paint("Client ◀── Server", DIM)
                };
                let msg = if l.message.starts_with("Alert") {
                    self.paint(&l.message, RED)
                } else {
                    l.message.clone()
                };
                println!("  {arrow}  {msg}");
            }
        }

        self.cert_list("Server 送出的憑證鏈", &r.server_chain);
        if !r.client_chain.is_empty() {
            self.cert_list("Client 送出的憑證鏈", &r.client_chain);
        }
        for w in &r.warnings {
            println!("{}", self.paint(&format!("⚠ {w}"), YELLOW));
        }

        if let Some(h) = &r.http {
            println!("\n{}", self.paint("── HTTP 請求 ──", CYAN));
            println!("  {}", self.paint(&format!("> {}", h.request_line), BOLD));
            for (k, v) in &h.request_headers {
                println!("  {}", self.paint(&format!("> {k}: {v}"), DIM));
            }
            if let Some(e) = &h.error {
                println!("  {}", self.paint(&format!("✘ {e}"), RED));
            }
            if !h.status_line.is_empty() {
                let code = match h.status {
                    Some(c) if c < 300 => GREEN,
                    Some(c) if c < 400 => CYAN,
                    Some(c) if c < 500 => YELLOW,
                    _ => RED,
                };
                println!(
                    "  {}  {}",
                    self.paint(&format!("< {}", h.status_line), code),
                    self.paint(&format!("({} ms)", h.elapsed_ms), DIM)
                );
                for (k, v) in &h.headers {
                    println!("  {}", self.paint(&format!("< {k}: {v}"), DIM));
                }
                println!();
                for line in h.body_preview.lines().take(40) {
                    println!("  {line}");
                }
                let shown = h.body_preview.lines().count();
                if h.truncated || shown > 40 {
                    println!(
                        "  {}",
                        self.paint(&format!("…（共 {} bytes，僅顯示部分）", h.body_bytes), DIM)
                    );
                }
            }
        }

        println!();
        if r.success {
            println!("{}", self.paint("✔ 交握成功", GREEN));
        } else if let Some(f) = &r.failure {
            println!(
                "{}",
                self.paint(&format!("✘ 交握失敗（{}偵測到錯誤）", f.side), RED)
            );
            println!("  錯誤：{}", f.message);
            if !f.hint.is_empty() {
                println!("  {}", self.paint("診斷：", YELLOW));
                for line in f.hint.lines() {
                    println!("    {line}");
                }
            }
        } else {
            println!("{}", self.paint("✘ 交握失敗", RED));
        }
    }

    fn cert_list(&self, title: &str, chain: &[CertInfo]) {
        if chain.is_empty() {
            return;
        }
        let now = now_ts();
        println!("\n{}", self.paint(&format!("── {title} ──"), CYAN));
        for (i, c) in chain.iter().enumerate() {
            println!(
                "  [{i}] {}  {}",
                self.paint(&c.display_name(), BOLD),
                self.status_text(c.status_at(now, 30))
            );
            println!("      主體：{}", c.subject);
            println!("      簽發者：{}", c.issuer);
            if !c.subject_alt_names.is_empty() {
                println!("      SAN：{}", c.subject_alt_names.join(", "));
            }
        }
    }
}

fn chain_suffix(e: &Entry) -> String {
    if e.chain.len() > 1 {
        format!("（鏈 {}）", e.chain.len())
    } else {
        String::new()
    }
}

fn key_label(e: &Entry) -> String {
    match &e.key {
        rustca_core::KeyState::None => "-".into(),
        rustca_core::KeyState::Decrypted { .. } => "✔".into(),
        rustca_core::KeyState::Locked(_) => "🔒".into(),
    }
}

/// 從 DN 取出 CN，取不到則回傳原字串。
fn short_dn(dn: &str) -> String {
    dn.split(',')
        .map(|p| p.trim())
        .find_map(|p| p.strip_prefix("CN="))
        .map(|s| s.to_string())
        .unwrap_or_else(|| dn.to_string())
}

fn highlight(value: &str, keyword: &str, color: bool) -> String {
    if !color || keyword.is_empty() {
        return value.to_string();
    }
    let lower = value.to_lowercase();
    let kw = keyword.to_lowercase();
    match lower.find(&kw) {
        // 只在大小寫轉換不改變長度時標示，避免切到多位元組字元中間
        Some(pos)
            if lower.len() == value.len()
                && value.is_char_boundary(pos)
                && value.is_char_boundary(pos + kw.len()) =>
        {
            format!(
                "{}\x1b[1;33m{}\x1b[0m{}",
                &value[..pos],
                &value[pos..pos + kw.len()],
                &value[pos + kw.len()..]
            )
        }
        _ => value.to_string(),
    }
}

fn cert_rows(c: &CertInfo) -> Vec<(&'static str, String)> {
    let mut rows = vec![
        ("主體", c.subject.clone()),
        ("簽發者", c.issuer.clone()),
        ("序號", c.serial.clone()),
        ("版本", format!("v{}", c.version)),
        ("生效日", format_ts(c.not_before)),
        ("到期日", format_ts(c.not_after)),
        ("簽章演算法", c.signature_algorithm.clone()),
        ("公鑰", c.public_key.clone()),
    ];
    if !c.subject_alt_names.is_empty() {
        rows.push(("SAN", c.subject_alt_names.join("\n")));
    }
    rows.push((
        "CA",
        if c.is_ca {
            match c.path_len {
                Some(n) => format!("是（pathLen={n}）"),
                None => "是".into(),
            }
        } else {
            "否".into()
        },
    ));
    if !c.key_usage.is_empty() {
        rows.push(("金鑰用途", c.key_usage.join(", ")));
    }
    if !c.ext_key_usage.is_empty() {
        rows.push(("延伸金鑰用途", c.ext_key_usage.join(", ")));
    }
    if let Some(k) = &c.subject_key_id {
        rows.push(("SKI", k.clone()));
    }
    if let Some(k) = &c.authority_key_id {
        rows.push(("AKI", k.clone()));
    }
    rows.push((
        "自簽",
        if c.self_signed {
            "是".into()
        } else {
            "否".into()
        },
    ));
    rows.push(("SHA-1", c.sha1.clone()));
    rows.push(("SHA-256", c.sha256.clone()));
    rows
}

fn cert_json(c: &CertInfo, now: i64, warn_days: i64) -> Value {
    let mut v = serde_json::to_value(c).unwrap_or_default();
    if let Value::Object(m) = &mut v {
        m.insert(
            "validity".into(),
            serde_json::to_value(c.status_at(now, warn_days)).unwrap_or_default(),
        );
        m.insert("not_before_text".into(), json!(format_ts(c.not_before)));
        m.insert("not_after_text".into(), json!(format_ts(c.not_after)));
    }
    v
}

fn entry_json(e: &Entry, now: i64, warn_days: i64) -> Value {
    json!({
        "alias": e.alias,
        "kind": e.kind,
        "created": e.created,
        "key": e.key.label(),
        "note": e.note,
        "chain": e.chain.iter().map(|c| cert_json(c, now, warn_days)).collect::<Vec<_>>(),
    })
}

fn store_json(ks: &Keystore, now: i64, warn_days: i64) -> Value {
    json!({
        "file": ks.path,
        "format": ks.format,
        "integrity": ks.integrity,
        "warnings": ks.warnings,
        "entries": ks.entries.iter().map(|e| entry_json(e, now, warn_days)).collect::<Vec<_>>(),
    })
}
