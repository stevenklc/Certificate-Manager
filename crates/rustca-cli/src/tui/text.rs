//! TUI 文字頁內容：條目詳細資料、說明、到期清單。

use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use rustca_core::chain::{ChainEnd, LinkSource};
use rustca_core::{build_chain, format_ts, now_ts, CertInfo, Entry, Keystore, ValidityStatus};

use super::app::App;

pub fn status_color(s: ValidityStatus) -> Color {
    match s {
        ValidityStatus::Valid { .. } => Color::Green,
        ValidityStatus::ExpiringSoon { .. } => Color::Yellow,
        _ => Color::Red,
    }
}

/// 以終端機顯示寬度補空白（中文字佔兩格）。
pub fn pad(s: &str, w: usize) -> String {
    let cur = Span::raw(s).width();
    format!("{s}{}", " ".repeat(w.saturating_sub(cur)))
}

/// 只取日期部分（表格用）。
pub fn short_date(ts: i64) -> String {
    format_ts(ts).chars().take(10).collect()
}

fn heading(s: impl Into<String>) -> Line<'static> {
    Line::from(Span::styled(
        format!("── {} ──", s.into()),
        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    ))
}

fn kv(k: &str, v: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  {k}："), Style::new().fg(Color::DarkGray)),
        Span::raw(v.into()),
    ])
}

pub fn entry_detail(
    ks: &Keystore,
    e: &Entry,
    pool: &[&CertInfo],
    now: i64,
    warn: i64,
    pem: bool,
) -> Vec<Line<'static>> {
    let mut out = vec![];
    out.push(Line::from(vec![
        Span::styled(e.alias.clone(), Style::new().bold()),
        Span::raw(format!("    {}    檔案：{}", e.kind, ks.path.display())),
    ]));
    if let Some(t) = e.created {
        out.push(kv("建立時間", format_ts(t)));
    }
    if e.kind == rustca_core::EntryKind::PrivateKey {
        out.push(kv("私鑰", e.key.label()));
    }
    if let Some(n) = &e.note {
        out.push(kv("備註", n.clone()));
    }

    if !e.chain.is_empty() {
        out.push(Line::raw(""));
        out.push(heading("憑證鏈分析（終端 → 根）"));
        let chain = build_chain(&e.chain, pool, now, warn);
        for (i, l) in chain.links.iter().enumerate() {
            let src = match l.source {
                LinkSource::Entry => "條目內",
                LinkSource::Pool => "由其他憑證補齊",
            };
            let sig = match l.signature_ok {
                Some(true) => Span::styled("簽章 OK", Style::new().fg(Color::Green)),
                Some(false) => Span::styled("簽章不符", Style::new().fg(Color::Red)),
                None => Span::raw("簽章未驗證"),
            };
            out.push(Line::from(vec![
                Span::raw(format!("  {}[{i}] ", "  ".repeat(i))),
                Span::styled(l.cert.display_name(), Style::new().bold()),
                Span::raw(format!("  {}  ", l.cert.role())),
                Span::styled(l.validity.label(), Style::new().fg(status_color(l.validity))),
                Span::raw("  "),
                sig,
                Span::styled(format!("  （{src}）"), Style::new().fg(Color::DarkGray)),
            ]));
        }
        match &chain.end {
            ChainEnd::Root => out.push(Line::styled(
                "  ✔ 結束於自簽根憑證",
                Style::new().fg(Color::Green),
            )),
            ChainEnd::MissingIssuer { issuer } => out.push(Line::styled(
                format!("  ✘ 找不到簽發者：{issuer}（可開啟對應的信任庫來補齊）"),
                Style::new().fg(Color::Red),
            )),
            ChainEnd::Loop => out.push(Line::styled(
                "  ✘ 憑證鏈出現循環或過長",
                Style::new().fg(Color::Red),
            )),
        }
        for p in &chain.problems {
            out.push(Line::styled(format!("  ⚠ {p}"), Style::new().fg(Color::Yellow)));
        }
    }

    for (i, c) in e.chain.iter().enumerate() {
        out.push(Line::raw(""));
        out.push(heading(format!("[{i}] {}", c.display_name())));
        out.extend(cert_lines(c, now, warn));
        if pem {
            out.push(Line::raw(""));
            for l in c.to_pem().lines() {
                out.push(Line::raw(l.to_string()));
            }
        }
    }
    if !pem && !e.chain.is_empty() {
        out.push(Line::raw(""));
        out.push(Line::styled(
            "（按 p 顯示 PEM）",
            Style::new().fg(Color::DarkGray),
        ));
    }
    out
}

pub fn cert_lines(c: &CertInfo, now: i64, warn: i64) -> Vec<Line<'static>> {
    let st = c.status_at(now, warn);
    let mut v = vec![
        kv("類型", c.role()),
        kv("主體", c.subject.clone()),
        kv("簽發者", c.issuer.clone()),
        kv("序號", c.serial.clone()),
        Line::from(vec![
            Span::styled("  有效期間：", Style::new().fg(Color::DarkGray)),
            Span::raw(format!("{} ～ {}  ", format_ts(c.not_before), format_ts(c.not_after))),
            Span::styled(st.label(), Style::new().fg(status_color(st))),
        ]),
        kv("簽章演算法", c.signature_algorithm.clone()),
        kv("公鑰", c.public_key.clone()),
    ];
    if !c.subject_alt_names.is_empty() {
        v.push(kv("SAN", c.subject_alt_names.join(", ")));
    }
    let ca = if c.is_ca {
        match c.path_len {
            Some(n) => format!("是（路徑長度上限 {n}）"),
            None => "是".into(),
        }
    } else {
        "否".into()
    };
    v.push(kv("CA", ca));
    if !c.key_usage.is_empty() {
        v.push(kv("Key Usage", c.key_usage.join(", ")));
    }
    if !c.ext_key_usage.is_empty() {
        v.push(kv("Extended Key Usage", c.ext_key_usage.join(", ")));
    }
    if let Some(s) = &c.subject_key_id {
        v.push(kv("Subject Key ID", s.clone()));
    }
    if let Some(s) = &c.authority_key_id {
        v.push(kv("Authority Key ID", s.clone()));
    }
    v.push(kv("SHA-1", c.sha1.clone()));
    v.push(kv("SHA-256", c.sha256.clone()));
    v
}

pub fn expiry_lines(app: &App) -> Vec<Line<'static>> {
    let now = now_ts();
    let mut v = vec![Line::raw(format!(
        "到期檢查：{}（{}）",
        if app.expiry.all {
            "全部憑證".to_string()
        } else {
            format!("{} 天內到期、已過期或尚未生效", app.expiry.days)
        },
        format_ts(now)
    ))];
    for r in &app.expiry.rows {
        let ks = &app.stores[r.store];
        let c = ks.entries[r.entry]
            .chain
            .iter()
            .find(|c| c.display_name() == r.name);
        let st = c
            .map(|c| c.status_at(now, app.warn_days).label())
            .unwrap_or_default();
        v.push(Line::raw(format!(
            "{}  {}  {} / {}  {}",
            short_date(r.not_after),
            st,
            ks.name(),
            r.alias,
            r.name
        )));
    }
    v
}

/// 去掉樣式，轉成純文字（存檔用）。
pub fn plain(lines: &[Line]) -> String {
    let mut s = lines
        .iter()
        .map(|l| l.spans.iter().map(|sp| sp.content.as_ref()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n");
    s.push('\n');
    s
}

pub fn help() -> Vec<Line<'static>> {
    let key = |k: &str, d: &str| {
        Line::from(vec![
            Span::styled(format!("  {}", pad(k, 14)), Style::new().fg(Color::Yellow)),
            Span::raw(d.to_string()),
        ])
    };
    vec![
        heading(if cfg!(target_os = "linux") {
            format!("{} - Terminal UI", crate::APP_TITLE)
        } else {
            format!("{}：終端機介面", crate::APP_TITLE)
        }),
        Line::raw("  透過 SSH 即可使用，不需要圖形環境。啟動：rust-ca tui <檔案或目錄…> [-p 密碼]"),
        Line::raw("  開檔時會依序嘗試：-p / RUST_CA_PASSWORD、已輸入過的密碼、changeit；都不對才詢問。"),
        Line::raw(""),
        heading("主畫面"),
        key("↑↓ j k", "移動選取"),
        key("PgUp PgDn", "翻頁；g / G 跳到最前 / 最後"),
        key("Tab ← →", "切換左側檔案清單與右側條目清單"),
        key("Enter", "條目詳細資料（憑證鏈分析、全部欄位）"),
        key("/", "篩選目前檔案（別名、主體、簽發者、SAN、序號、指紋）；Esc 清除"),
        key("s", "搜尋全部已開啟的檔案"),
        key("e", "到期檢查（全部檔案）"),
        key("h", "TLS 交握測試（連線遠端 Server）"),
        key("o", "開啟檔案或目錄（Tab 補齊路徑）"),
        key("r", "重新載入目前檔案"),
        key("P", "輸入密碼重新開啟目前檔案（解開私鑰、驗證完整性）"),
        key("x", "關閉目前檔案"),
        key("t", "切換排序：檔案順序 / 到期日"),
        key("?", "說明"),
        key("q  Ctrl+C", "離開"),
        Line::raw(""),
        heading("詳細資料頁"),
        key("↑↓ PgUp PgDn", "捲動"),
        key("n / N", "下一個 / 上一個條目"),
        key("p", "顯示 / 隱藏 PEM"),
        key("w", "存成文字檔"),
        key("Esc  q", "返回"),
        Line::raw(""),
        heading("搜尋、到期檢查"),
        key("Enter", "跳到該條目"),
        key("s", "（搜尋）重新輸入關鍵字"),
        key("d / a", "（到期）修改天數 / 切換顯示全部"),
        key("w", "（到期）存成文字檔"),
        Line::raw(""),
        heading("TLS 交握"),
        key("↑↓ Tab", "選擇欄位"),
        key("Enter", "編輯文字欄位 / 切換選項 / 開始交握"),
        key("← → 空白", "切換選項（信任庫、Client 身分、TLS 版本）"),
        key("r", "開始交握"),
        key("PgUp PgDn", "捲動結果"),
        key("w / W", "結果存成文字檔 / 另附憑證 PEM"),
        Line::raw("  Proxy 留空會自動偵測（HTTPS_PROXY / NO_PROXY）；填 none 表示直連。"),
        Line::raw("  經由 proxy 且收到的憑證鏈連不到公開根憑證時，會提醒「這不是 Server 的真實憑證鏈」。"),
        Line::raw(""),
        heading("輸入框"),
        key("Enter / Esc", "確定 / 取消"),
        key("Ctrl+U", "清空"),
        key("Tab", "（路徑）補齊"),
        Line::raw(""),
        Line::raw("  提示：介面沒有攔截滑鼠，可直接用終端機（例如 MobaXterm）選取文字複製。"),
    ]
}
