//! TUI 畫面繪製。

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Cell, HighlightSpacing, List, ListItem, ListState, Paragraph, Row, Table, Wrap,
};
use ratatui::Frame;
use rustca_core::role::store_kind;
use rustca_core::{now_ts, EntryKind, Integrity, KeyState};

use super::app::*;
use super::text::{pad, short_date, status_color};

const HL: Style = Style::new().bg(Color::Blue).fg(Color::White);
const DIM: Style = Style::new().fg(Color::DarkGray);

pub fn draw(f: &mut Frame, app: &mut App) {
    let [body, status, keys] = Layout::vertical([
        Constraint::Min(3),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(f.area());

    match app.view {
        View::Main => draw_main(f, app, body),
        View::Detail | View::Help => draw_page(f, app, body),
        View::Search => draw_search(f, app, body),
        View::Expiry => draw_expiry(f, app, body),
        View::Handshake => draw_handshake(f, app, body),
    }
    draw_status(f, app, status);
    draw_keys(f, app, keys);
}

fn block(title: impl Into<String>, focused: bool) -> Block<'static> {
    let b = Block::bordered().title(Span::styled(
        format!(" {} ", title.into()),
        Style::new().add_modifier(Modifier::BOLD),
    ));
    if focused {
        b.border_style(Style::new().fg(Color::Cyan))
    } else {
        b.border_style(DIM)
    }
}

// ───────────── 主畫面 ─────────────

fn store_line(s: &rustca_core::Keystore) -> Line<'static> {
    let kind = match store_kind(s) {
        "Keystore" => "金鑰",
        "Truststore" => "信任",
        "Keystore + Truststore" => "金鑰+信任",
        _ => "空",
    };
    Line::from(vec![
        Span::raw(s.name()),
        Span::styled(format!(" {kind} {}", s.entries.len()), DIM),
    ])
}

fn label(k: &str) -> Span<'static> {
    Span::styled(pad(k, 9), DIM)
}

fn draw_main(f: &mut Frame, app: &mut App, area: Rect) {
    let [top, detail] = Layout::vertical([Constraint::Min(5), Constraint::Length(8)]).areas(area);
    let left_w = app
        .stores
        .iter()
        .map(|s| store_line(s).width() as u16 + 5)
        .max()
        .unwrap_or(20)
        .clamp(22, 44);
    let [left, right] =
        Layout::horizontal([Constraint::Length(left_w), Constraint::Min(20)]).areas(top);

    // 左：已開啟的檔案
    let items: Vec<ListItem> = app
        .stores
        .iter()
        .map(|s| ListItem::new(store_line(s)))
        .collect();
    let mut ls = ListState::default();
    if !app.stores.is_empty() {
        ls.select(Some(app.store_sel));
    }
    let list = List::new(items)
        .block(block(format!("檔案 {}", app.stores.len()), app.focus == Focus::Stores))
        .highlight_style(HL)
        .highlight_symbol("> ");
    f.render_stateful_widget(list, left, &mut ls);

    // 右：條目
    let now = now_ts();
    let warn = app.warn_days;
    let Some(ks) = app.stores.get(app.store_sel) else {
        let p = Paragraph::new(vec![
            Line::raw(""),
            Line::raw("  尚未開啟任何檔案。"),
            Line::raw("  按 o 開啟檔案或目錄，或以 rust-ca tui <檔案或目錄…> 啟動。"),
            Line::raw("  按 ? 查看說明。"),
        ])
        .block(block("條目", app.focus == Focus::Entries));
        f.render_widget(p, right);
        f.render_widget(Paragraph::new("").block(block("詳細", false)), detail);
        return;
    };
    let rows: Vec<Row> = app
        .visible
        .iter()
        .map(|&i| {
            let e = &ks.entries[i];
            let leaf = e.leaf();
            let kind = match e.kind {
                EntryKind::PrivateKey => "私鑰",
                EntryKind::TrustedCert => "信任",
                EntryKind::SecretKey => "秘密金鑰",
            };
            let kind = match leaf {
                Some(c) => format!("{kind}·{}", c.role()),
                None => kind.to_string(),
            };
            let key = match &e.key {
                KeyState::None => "",
                KeyState::Decrypted { .. } => "可用",
                KeyState::Locked(_) => "鎖定",
            };
            let (date, st) = match leaf {
                Some(c) => {
                    let st = c.status_at(now, warn);
                    (
                        short_date(c.not_after),
                        Cell::from(st.label()).style(Style::new().fg(status_color(st))),
                    )
                }
                None => (String::new(), Cell::from("")),
            };
            let chain = if e.chain.len() > 1 {
                format!(" (鏈{})", e.chain.len())
            } else {
                String::new()
            };
            Row::new(vec![
                Cell::from(e.alias.clone()),
                Cell::from(kind),
                Cell::from(format!(
                    "{}{chain}",
                    leaf.map(|c| c.display_name()).unwrap_or_default()
                )),
                Cell::from(date),
                st,
                Cell::from(key),
            ])
        })
        .collect();
    let mut title = format!("{}  {}  {} 筆", ks.name(), ks.format, ks.entries.len());
    if ks.integrity == Integrity::NotChecked {
        title.push_str("  未驗證完整性");
    }
    if !app.filter.is_empty() {
        title.push_str(&format!("  篩選「{}」：{} 筆", app.filter, app.visible.len()));
    }
    if app.sort_expiry {
        title.push_str("  依到期日");
    }
    let table = Table::new(
        rows,
        [
            Constraint::Fill(3),
            Constraint::Length(13),
            Constraint::Fill(4),
            Constraint::Length(10),
            Constraint::Length(20),
            Constraint::Length(4),
        ],
    )
    .header(
        Row::new(["別名", "類型", "主體 CN", "到期日", "狀態", "私鑰"])
            .style(Style::new().fg(Color::Yellow).bold()),
    )
    .block(block(title, app.focus == Focus::Entries))
    .row_highlight_style(HL)
    .highlight_symbol("> ")
    .highlight_spacing(HighlightSpacing::Always);
    f.render_stateful_widget(table, right, &mut app.entries);
    if app.visible.is_empty() && !ks.entries.is_empty() {
        let inner = right.inner(ratatui::layout::Margin::new(2, 2));
        f.render_widget(
            Paragraph::new(format!(
                "沒有符合「{}」的條目。按 Esc 清除篩選，或按 s 搜尋全部檔案。",
                app.filter
            ))
            .style(Style::new().fg(Color::Yellow)),
            inner,
        );
    }

    // 下：選取條目的摘要
    let mut lines = vec![];
    if let Some(e) = app.selected_entry().and_then(|i| ks.entries.get(i)) {
        if let Some(c) = e.leaf() {
            let st = c.status_at(now, warn);
            lines.push(Line::from(vec![
                label("主體"),
                Span::raw(c.subject.clone()),
            ]));
            lines.push(Line::from(vec![
                label("簽發者"),
                Span::raw(c.issuer.clone()),
            ]));
            lines.push(Line::from(vec![
                label("有效期間"),
                Span::raw(format!(
                    "{} ～ {}  ",
                    rustca_core::format_ts(c.not_before),
                    rustca_core::format_ts(c.not_after)
                )),
                Span::styled(st.label(), Style::new().fg(status_color(st))),
            ]));
            if !c.subject_alt_names.is_empty() {
                lines.push(Line::from(vec![
                    label("SAN"),
                    Span::raw(c.subject_alt_names.join(", ")),
                ]));
            }
            lines.push(Line::from(vec![
                label("SHA-256"),
                Span::raw(c.sha256.clone()),
            ]));
            if e.chain.len() > 1 {
                let names: Vec<String> = e.chain.iter().map(|c| c.display_name()).collect();
                lines.push(Line::from(vec![
                    label("憑證鏈"),
                    Span::raw(names.join(" → ")),
                ]));
            }
        } else {
            lines.push(Line::raw(format!("{}（{}）", e.alias, e.kind)));
        }
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block("摘要（Enter 看完整資料）", false)),
        detail,
    );
}

// ───────────── 文字頁 ─────────────

fn draw_page(f: &mut Frame, app: &App, area: Rect) {
    let total = app.page.lines.len();
    let title = format!(
        "{}  {}/{}",
        app.page.title,
        (app.page.scroll as usize + 1).min(total),
        total
    );
    f.render_widget(
        Paragraph::new(app.page.lines.clone())
            .wrap(Wrap { trim: false })
            .scroll((app.page.scroll, 0))
            .block(block(title, true)),
        area,
    );
}

// ───────────── 搜尋 ─────────────

fn draw_search(f: &mut Frame, app: &mut App, area: Rect) {
    let rows: Vec<Row> = app
        .search
        .hits
        .iter()
        .map(|h| {
            Row::new(vec![
                Cell::from(app.stores.get(h.store).map(|s| s.name()).unwrap_or_default()),
                Cell::from(h.alias.clone()),
                Cell::from(h.cert.clone()),
                Cell::from(h.fields.clone()),
            ])
        })
        .collect();
    let title = format!(
        "搜尋「{}」：{} 個檔案中共 {} 筆",
        app.search.query,
        app.stores.len(),
        app.search.hits.len()
    );
    let table = Table::new(
        rows,
        [
            Constraint::Fill(2),
            Constraint::Fill(2),
            Constraint::Fill(2),
            Constraint::Fill(5),
        ],
    )
    .header(Row::new(["檔案", "別名", "憑證", "符合欄位"]).style(Style::new().fg(Color::Yellow).bold()))
    .block(block(title, true))
    .row_highlight_style(HL)
    .highlight_symbol("> ")
    .highlight_spacing(HighlightSpacing::Always);
    f.render_stateful_widget(table, area, &mut app.search.table);
}

// ───────────── 到期 ─────────────

fn draw_expiry(f: &mut Frame, app: &mut App, area: Rect) {
    let now = now_ts();
    let rows: Vec<Row> = app
        .expiry
        .rows
        .iter()
        .map(|r| {
            let ks = &app.stores[r.store];
            let st = ks.entries[r.entry]
                .chain
                .iter()
                .find(|c| c.display_name() == r.name)
                .map(|c| c.status_at(now, app.warn_days));
            let st_cell = match st {
                Some(s) => Cell::from(s.label()).style(Style::new().fg(status_color(s))),
                None => Cell::from(""),
            };
            Row::new(vec![
                Cell::from(short_date(r.not_after)),
                st_cell,
                Cell::from(ks.name()),
                Cell::from(r.alias.clone()),
                Cell::from(r.name.clone()),
            ])
        })
        .collect();
    let title = if app.expiry.all {
        format!("到期檢查：全部憑證 {} 張", app.expiry.rows.len())
    } else {
        format!(
            "到期檢查：{} 天內到期、已過期或尚未生效 {} 張",
            app.expiry.days,
            app.expiry.rows.len()
        )
    };
    if app.expiry.rows.is_empty() {
        f.render_widget(
            Paragraph::new(format!(
                "\n  ✔ 所有已開啟檔案中的憑證，{} 天內都不會到期。按 a 顯示全部，d 修改天數。",
                app.expiry.days
            ))
            .style(Style::new().fg(Color::Green))
            .block(block(title, true)),
            area,
        );
        return;
    }
    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(20),
            Constraint::Fill(2),
            Constraint::Fill(2),
            Constraint::Fill(3),
        ],
    )
    .header(
        Row::new(["到期日", "狀態", "檔案", "別名", "憑證"])
            .style(Style::new().fg(Color::Yellow).bold()),
    )
    .block(block(title, true))
    .row_highlight_style(HL)
    .highlight_symbol("> ")
    .highlight_spacing(HighlightSpacing::Always);
    f.render_stateful_widget(table, area, &mut app.expiry.table);
}

// ───────────── 交握 ─────────────

fn draw_handshake(f: &mut Frame, app: &App, area: Rect) {
    let form_h = HS_FIELDS.len() as u16 + 3;
    let [form, result] =
        Layout::vertical([Constraint::Length(form_h), Constraint::Min(3)]).areas(area);

    let trust_opts = app.trust_options();
    let client_opts = app.client_options();
    let (proxy_val, proxy_src) = app.effective_proxy();
    let proxy_show = proxy_val
        .as_deref()
        .map(|p| {
            rustca_core::tls::ProxyConfig::parse(p)
                .map(|c| c.display())
                .unwrap_or_else(|_| p.to_string())
        })
        .unwrap_or_else(|| "（無）".into());
    let mut lines = vec![];
    for (i, name) in HS_FIELDS.iter().enumerate() {
        let sel = app.hs.field == i;
        let value: Vec<Span> = match i {
            HS_TARGET => vec![if app.hs.address.is_empty() {
                Span::styled("（Enter 輸入，例如 www.example.com 或 https://host/api）", DIM)
            } else {
                Span::raw(app.hs.address.clone())
            }],
            HS_TRUST => vec![
                Span::raw(format!(
                    "< {} >",
                    trust_opts.get(app.hs.trust).cloned().unwrap_or_default()
                )),
                Span::styled("  ← → 切換", DIM),
            ],
            HS_CLIENT => {
                let v = match client_opts.get(app.hs.client.wrapping_sub(1)) {
                    Some(&s) if app.hs.client > 0 => app.stores[s].name(),
                    _ => "無（Server 要求 mTLS 時才需要）".into(),
                };
                vec![Span::raw(format!("< {v} >"))]
            }
            HS_PROXY => vec![
                Span::raw(if app.hs.proxy.is_empty() {
                    String::new()
                } else {
                    proxy_show.clone()
                }),
                Span::styled(
                    if app.hs.proxy.is_empty() {
                        match proxy_val {
                            Some(_) => format!("{proxy_src}  {proxy_show}"),
                            None => proxy_src.clone(),
                        }
                    } else {
                        String::new()
                    },
                    DIM,
                ),
            ],
            HS_SNI => vec![if app.hs.sni.is_empty() {
                Span::styled("（自動）", DIM)
            } else {
                Span::raw(app.hs.sni.clone())
            }],
            HS_VERSION => vec![Span::raw(format!(
                "< {} >",
                ["自動", "TLS 1.2", "TLS 1.3"][app.hs.version]
            ))],
            HS_TIMEOUT => vec![Span::raw(app.hs.timeout.clone())],
            HS_AT => vec![if app.hs.at.is_empty() {
                Span::styled("（現在）", DIM)
            } else {
                Span::raw(app.hs.at.clone())
            }],
            _ => {
                let running = app.hs.running.is_some();
                vec![Span::styled(
                    if running {
                        let spin = ["|", "/", "-", "\\"][(app.tick % 4) as usize];
                        let secs = app.hs.running.as_ref().map(|r| r.1.elapsed().as_secs()).unwrap_or(0);
                        format!("[ 連線中 {spin} {secs}s ]")
                    } else {
                        "[ 開始交握 ]".into()
                    },
                    Style::new().fg(Color::Green).bold(),
                )]
            }
        };
        let mut spans = vec![Span::styled(
            format!("{} {}", if sel { ">" } else { " " }, pad(name, 12)),
            if sel {
                Style::new().fg(Color::Cyan).bold()
            } else {
                Style::new().fg(Color::Yellow)
            },
        )];
        spans.extend(value);
        let mut line = Line::from(spans);
        if sel {
            line = line.style(Style::new().bg(Color::Rgb(30, 40, 60)));
        }
        lines.push(line);
    }
    f.render_widget(
        Paragraph::new(lines).block(block("TLS 交握（連線遠端 Server）", true)),
        form,
    );

    let Some(r) = &app.hs.report else {
        f.render_widget(
            Paragraph::new(vec![
                Line::raw(""),
                Line::raw("  填好目標後按 r 或選「開始交握」按 Enter。"),
                Line::raw("  信任庫可選作業系統憑證庫、Mozilla 根憑證，或已開啟的檔案（例如 cacerts）。"),
            ])
            .style(DIM)
            .block(block("結果", false)),
            result,
        );
        return;
    };
    let txt = r.to_text(false);
    let lines: Vec<Line> = txt
        .lines()
        .map(|l| {
            let t = l.trim_start();
            let style = if t.starts_with('✔') {
                Style::new().fg(Color::Green).bold()
            } else if t.starts_with('✘') || t.starts_with("結果：✘") || t.starts_with("錯誤：") {
                Style::new().fg(Color::Red).bold()
            } else if t.starts_with('⚠') {
                Style::new().fg(Color::Yellow).bold()
            } else if t.starts_with("──") || t.starts_with('═') {
                Style::new().fg(Color::Cyan).bold()
            } else if t.starts_with("結果：✔") {
                Style::new().fg(Color::Green).bold()
            } else {
                Style::new()
            };
            Line::styled(l.to_string(), style)
        })
        .collect();
    let title = if r.success {
        "結果：交握成功"
    } else {
        "結果：交握失敗"
    };
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((app.hs.scroll, 0))
            .block(block(format!("{title}  （PgUp/PgDn 捲動，w 存檔）"), false)),
        result,
    );
}

// ───────────── 狀態列、按鍵提示 ─────────────

fn draw_status(f: &mut Frame, app: &App, area: Rect) {
    if let Some(inp) = &app.input {
        let shown = if inp.masked {
            "*".repeat(inp.value.chars().count())
        } else {
            inp.value.clone()
        };
        let prompt = format!("{}：", inp.prompt);
        // 太長時只顯示結尾（游標所在處）
        let room = (area.width as usize).saturating_sub(Span::raw(&prompt).width() + 2);
        let shown = if Span::raw(&shown).width() > room {
            let mut tail = String::new();
            for c in shown.chars().rev() {
                if Span::raw(&tail).width() + 2 >= room {
                    break;
                }
                tail.insert(0, c);
            }
            format!("…{tail}")
        } else {
            shown
        };
        let line = Line::from(vec![
            Span::styled(prompt, Style::new().fg(Color::Cyan).bold()),
            Span::raw(shown),
            Span::styled(" ", Style::new().bg(Color::White)),
        ]);
        f.render_widget(Paragraph::new(line), area);
        return;
    }
    if let Some(s) = &app.status {
        if s.at.elapsed().as_secs() < 8 || s.err {
            let style = if s.err {
                Style::new().fg(Color::Red)
            } else {
                Style::new().fg(Color::Green)
            };
            f.render_widget(Paragraph::new(Span::styled(s.msg.clone(), style)), area);
        }
    }
}

fn draw_keys(f: &mut Frame, app: &App, area: Rect) {
    let keys: &[(&str, &str)] = if app.input.is_some() {
        &[("Enter", "確定"), ("Esc", "取消"), ("Ctrl+U", "清空"), ("Tab", "補齊路徑")]
    } else {
        match app.view {
            View::Main => &[
                ("Enter", "詳細"),
                ("/", "篩選"),
                ("s", "搜尋"),
                ("e", "到期"),
                ("h", "交握"),
                ("o", "開檔"),
                ("t", "排序"),
                ("Tab", "切換"),
                ("?", "說明"),
                ("q", "離開"),
            ],
            View::Detail => &[
                ("↑↓", "捲動"),
                ("n/N", "下/上一筆"),
                ("p", "PEM"),
                ("w", "存檔"),
                ("Esc", "返回"),
            ],
            View::Help => &[("↑↓", "捲動"), ("Esc", "返回")],
            View::Search => &[("Enter", "跳到條目"), ("s", "重新搜尋"), ("Esc", "返回")],
            View::Expiry => &[
                ("Enter", "跳到條目"),
                ("d", "天數"),
                ("a", "全部"),
                ("w", "存檔"),
                ("Esc", "返回"),
            ],
            View::Handshake => &[
                ("↑↓", "欄位"),
                ("Enter", "編輯/執行"),
                ("←→", "切換"),
                ("r", "交握"),
                ("w/W", "存檔/含PEM"),
                ("Esc", "返回"),
            ],
        }
    };
    let mut spans = vec![];
    for (k, d) in keys {
        spans.push(Span::styled(format!(" {k} "), Style::new().fg(Color::Black).bg(Color::Cyan)));
        spans.push(Span::raw(format!(" {d}  ")));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}
