//! 主視窗：憑證庫瀏覽、搜尋、憑證鏈。

use std::path::PathBuf;

use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};
use rustca_core::chain::LinkSource;
use rustca_core::{
    build_chain, format_ts, load_file, now_ts, BuiltChain, CertInfo, ChainEnd, KeyState, Keystore,
    LoadOptions, Matcher,
};

use crate::handshake::HandshakeState;
use crate::widgets::{cert_grid, short_dn, status_text, BLUE, GREEN, RED, YELLOW};

#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Browse,
    Handshake,
}

/// 等待輸入密碼的開檔請求。
struct PendingOpen {
    path: PathBuf,
    /// Some(i) 表示重新載入（解鎖）第 i 個已開啟的憑證庫
    replace: Option<usize>,
    password: String,
    key_password: String,
    error: Option<String>,
}

pub struct App {
    stores: Vec<Keystore>,
    /// None 表示「全部檔案」
    selected_store: Option<usize>,
    selected_entry: Option<(usize, usize)>,
    selected_link: usize,
    search: String,
    warn_days: i64,
    tab: Tab,
    pending: Option<PendingOpen>,
    queue: Vec<PathBuf>,
    message: Option<(String, bool)>,
    hs: HandshakeState,
    chain_cache: Option<((usize, usize), BuiltChain)>,
    devshot: Option<crate::devshot::DevShot>,
}

impl App {
    pub fn new(files: Vec<PathBuf>) -> Self {
        App {
            stores: Vec::new(),
            selected_store: None,
            selected_entry: None,
            selected_link: 0,
            search: String::new(),
            warn_days: 30,
            tab: Tab::Browse,
            pending: None,
            queue: files,
            message: None,
            hs: HandshakeState::default(),
            chain_cache: None,
            devshot: crate::devshot::DevShot::from_env(),
        }
    }

    fn info(&mut self, msg: impl Into<String>) {
        self.message = Some((msg.into(), false));
    }

    fn error(&mut self, msg: impl Into<String>) {
        self.message = Some((msg.into(), true));
    }

    /// 嘗試開檔；需要密碼時跳出輸入框。
    fn open_path(&mut self, path: PathBuf, opts: LoadOptions, replace: Option<usize>) {
        match load_file(&path, &opts) {
            Ok(ks) => {
                let locked = ks
                    .private_key_entries()
                    .any(|e| matches!(e.key, KeyState::Locked(_)));
                let name = ks.name();
                let idx = match replace {
                    Some(i) if i < self.stores.len() => {
                        self.stores[i] = ks;
                        i
                    }
                    _ => {
                        // 同一個檔案重複開啟時取代舊的
                        if let Some(i) = self.stores.iter().position(|s| s.path == path) {
                            self.stores[i] = ks;
                            i
                        } else {
                            self.stores.push(ks);
                            self.stores.len() - 1
                        }
                    }
                };
                self.selected_store = Some(idx);
                self.selected_entry = None;
                self.chain_cache = None;
                self.hs.on_stores_changed(self.stores.len());
                if locked {
                    self.info(format!("已開啟 {name}（私鑰未解密，可按「解鎖」輸入密碼）"));
                } else {
                    self.info(format!("已開啟 {name}"));
                }
            }
            Err(e) if e.is_password_problem() => {
                let had_password = opts.password.is_some();
                self.pending = Some(PendingOpen {
                    path,
                    replace,
                    password: String::new(),
                    key_password: String::new(),
                    error: had_password.then(|| e.to_string()),
                });
            }
            Err(e) => self.error(format!("無法開啟 {}：{e}", path.display())),
        }
    }

    fn handle_queue(&mut self) {
        if self.pending.is_some() {
            return;
        }
        if let Some(p) = (!self.queue.is_empty()).then(|| self.queue.remove(0)) {
            // 若有設定 RUST_CA_PASSWORD 先試試看，失敗再詢問
            let opts = LoadOptions {
                password: std::env::var("RUST_CA_PASSWORD")
                    .ok()
                    .filter(|v| !v.is_empty()),
                key_password: None,
            };
            self.open_path(p, opts, None);
        }
    }

    fn close_store(&mut self, i: usize) {
        self.stores.remove(i);
        self.selected_store = None;
        self.selected_entry = None;
        self.chain_cache = None;
        self.hs.on_stores_changed(self.stores.len());
    }

    fn pool(&self) -> Vec<&CertInfo> {
        let mut seen = std::collections::HashSet::new();
        self.stores
            .iter()
            .flat_map(|s| s.all_certs())
            .filter(|c| seen.insert(c.sha256.clone()))
            .collect()
    }

    // ───────────── UI ─────────────

    fn top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("📂 開啟檔案…").clicked() {
                    if let Some(files) = rfd::FileDialog::new()
                        .add_filter(
                            "憑證庫 / 憑證",
                            &[
                                "jks", "jceks", "keystore", "p12", "pfx", "pem", "crt", "cer",
                                "der", "p7b", "key",
                            ],
                        )
                        .add_filter("所有檔案", &["*"])
                        .pick_files()
                    {
                        self.queue.extend(files);
                    }
                }
                ui.separator();
                ui.selectable_value(&mut self.tab, Tab::Browse, "📚 憑證庫");
                ui.selectable_value(&mut self.tab, Tab::Handshake, "🔑 交握模擬");
                ui.separator();
                if self.tab == Tab::Browse {
                    ui.label("🔍");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.search)
                            .hint_text("搜尋別名、主體、簽發者、SAN、序號、指紋…")
                            .desired_width(320.0),
                    );
                    if !self.search.is_empty() && ui.small_button("✖").clicked() {
                        self.search.clear();
                    }
                    ui.separator();
                    ui.label("到期提醒");
                    ui.add(
                        egui::DragValue::new(&mut self.warn_days)
                            .range(1..=3650)
                            .suffix(" 天"),
                    );
                }
            });
            ui.add_space(4.0);
        });
    }

    fn status_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| match &self.message {
                Some((m, true)) => {
                    ui.colored_label(RED, format!("✘ {m}"));
                }
                Some((m, false)) => {
                    ui.label(m);
                }
                None => {
                    ui.weak("將 JKS / JCEKS / PKCS#12 / PEM / CER 檔案拖曳到視窗即可開啟");
                }
            });
        });
    }

    fn store_panel(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("stores")
            .resizable(true)
            .default_width(230.0)
            .show(ctx, |ui| {
                ui.heading("已開啟的檔案");
                ui.separator();
                if self.stores.is_empty() {
                    ui.weak("尚未開啟任何檔案");
                    return;
                }
                if ui
                    .selectable_label(
                        self.selected_store.is_none(),
                        RichText::new("📚 全部檔案").strong(),
                    )
                    .clicked()
                {
                    self.selected_store = None;
                }
                let mut close = None;
                let mut unlock = None;
                egui::ScrollArea::vertical()
                    .id_salt("store_list")
                    .show(ui, |ui| {
                        for (i, ks) in self.stores.iter().enumerate() {
                            let now = now_ts();
                            let bad = ks
                                .entries
                                .iter()
                                .flat_map(|e| e.chain.iter())
                                .filter(|c| c.status_at(now, self.warn_days).is_problem())
                                .count();
                            let locked = ks
                                .private_key_entries()
                                .any(|e| matches!(e.key, KeyState::Locked(_)));
                            ui.group(|ui| {
                                ui.set_width(ui.available_width());
                                let sel = self.selected_store == Some(i);
                                if ui
                                    .selectable_label(
                                        sel,
                                        RichText::new(format!("📄 {}", ks.name())).strong(),
                                    )
                                    .on_hover_text(ks.path.display().to_string())
                                    .clicked()
                                {
                                    self.selected_store = Some(i);
                                }
                                ui.horizontal_wrapped(|ui| {
                                    ui.weak(format!("{} · {} 個條目", ks.format, ks.entries.len()));
                                    if bad > 0 {
                                        ui.colored_label(YELLOW, format!("⚠ {bad} 張需注意"));
                                    }
                                });
                                ui.horizontal(|ui| {
                                    if locked
                                        && ui
                                            .small_button("🔓 解鎖")
                                            .on_hover_text("輸入密碼以解密私鑰")
                                            .clicked()
                                    {
                                        unlock = Some(i);
                                    }
                                    if ui.small_button("✖ 關閉").clicked() {
                                        close = Some(i);
                                    }
                                });
                                for w in &ks.warnings {
                                    ui.colored_label(YELLOW, format!("⚠ {w}"));
                                }
                            });
                        }
                    });
                if let Some(i) = unlock {
                    self.pending = Some(PendingOpen {
                        path: self.stores[i].path.clone(),
                        replace: Some(i),
                        password: String::new(),
                        key_password: String::new(),
                        error: None,
                    });
                }
                if let Some(i) = close {
                    self.close_store(i);
                }
            });
    }

    fn entry_table(&mut self, ui: &mut egui::Ui) {
        let matcher = Matcher::new(&self.search);
        let now = now_ts();
        struct Row {
            store: usize,
            entry: usize,
            file: String,
            alias: String,
            kind: String,
            cn: String,
            issuer: String,
            not_after: String,
            status: Option<rustca_core::ValidityStatus>,
            key: &'static str,
            matched: String,
        }
        let mut rows = Vec::new();
        for (si, ks) in self.stores.iter().enumerate() {
            if self.selected_store.is_some_and(|s| s != si) {
                continue;
            }
            for (ei, e) in ks.entries.iter().enumerate() {
                let matched = if matcher.is_empty() {
                    String::new()
                } else {
                    let hits = matcher.entry(ei, e);
                    if hits.is_empty() {
                        continue;
                    }
                    let mut fields: Vec<&str> = hits
                        .iter()
                        .flat_map(|h| h.matches.iter().map(|m| m.field))
                        .collect();
                    fields.dedup();
                    fields.join("、")
                };
                let leaf = e.leaf();
                rows.push(Row {
                    store: si,
                    entry: ei,
                    file: ks.name(),
                    alias: e.alias.clone(),
                    kind: if e.chain.len() > 1 {
                        format!("{}（鏈 {}）", e.kind, e.chain.len())
                    } else {
                        e.kind.to_string()
                    },
                    cn: leaf
                        .map(|c| c.display_name())
                        .or_else(|| e.note.clone())
                        .unwrap_or_default(),
                    issuer: leaf
                        .map(|c| {
                            if c.self_signed {
                                "（自簽）".into()
                            } else {
                                short_dn(&c.issuer)
                            }
                        })
                        .unwrap_or_default(),
                    not_after: leaf
                        .map(|c| format_ts(c.not_after).chars().take(10).collect())
                        .unwrap_or_default(),
                    status: leaf.map(|c| c.status_at(now, self.warn_days)),
                    key: match e.key {
                        KeyState::None => "",
                        KeyState::Decrypted { .. } => "🔑",
                        KeyState::Locked(_) => "🔒",
                    },
                    matched,
                });
            }
        }

        let show_file = self.selected_store.is_none();
        let show_match = !matcher.is_empty();
        ui.horizontal(|ui| {
            ui.strong(format!("{} 個條目", rows.len()));
            if show_match {
                ui.weak(format!("（符合「{}」）", self.search.trim()));
            }
        });

        let mut clicked = None;
        let selected = self.selected_entry;
        let mut table = TableBuilder::new(ui)
            .id_salt("entries")
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .max_scroll_height(f32::INFINITY);
        if show_file {
            table = table.column(Column::initial(110.0).clip(true));
        }
        table = table
            .column(Column::initial(100.0).clip(true))
            .column(Column::initial(115.0).clip(true))
            .column(Column::initial(180.0).clip(true))
            .column(Column::initial(150.0).clip(true))
            .column(Column::initial(90.0))
            .column(Column::initial(130.0).clip(true))
            .column(Column::exact(36.0));
        if show_match {
            table = table.column(Column::remainder());
        }
        table
            .header(22.0, |mut h| {
                if show_file {
                    h.col(|ui| {
                        ui.strong("檔案");
                    });
                }
                for t in [
                    "別名",
                    "類型",
                    "主體 CN",
                    "簽發者",
                    "到期日",
                    "狀態",
                    "私鑰",
                ] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
                if show_match {
                    h.col(|ui| {
                        ui.strong("符合欄位");
                    });
                }
            })
            .body(|body| {
                body.rows(22.0, rows.len(), |mut row| {
                    let r = &rows[row.index()];
                    row.set_selected(selected == Some((r.store, r.entry)));
                    if show_file {
                        row.col(|ui| {
                            ui.label(&r.file);
                        });
                    }
                    row.col(|ui| {
                        ui.label(&r.alias);
                    });
                    row.col(|ui| {
                        ui.label(&r.kind);
                    });
                    row.col(|ui| {
                        ui.label(&r.cn);
                    });
                    row.col(|ui| {
                        ui.label(&r.issuer);
                    });
                    row.col(|ui| {
                        ui.label(&r.not_after);
                    });
                    row.col(|ui| {
                        if let Some(s) = r.status {
                            ui.label(status_text(s));
                        }
                    });
                    row.col(|ui| {
                        ui.label(r.key);
                    });
                    if show_match {
                        row.col(|ui| {
                            ui.colored_label(BLUE, &r.matched);
                        });
                    }
                    if row.response().clicked() {
                        clicked = Some((r.store, r.entry));
                    }
                });
            });
        if let Some(c) = clicked {
            if self.selected_entry != Some(c) {
                self.selected_entry = Some(c);
                self.selected_link = 0;
            }
        }
    }

    fn detail_panel(&mut self, ctx: &egui::Context) {
        let Some((si, ei)) = self.selected_entry else {
            return;
        };
        let Some(entry) = self.stores.get(si).and_then(|s| s.entries.get(ei)) else {
            self.selected_entry = None;
            return;
        };
        if entry.chain.is_empty() {
            egui::TopBottomPanel::bottom("detail").show(ctx, |ui| {
                ui.heading(format!("{}（{}）", entry.alias, entry.kind));
                if let Some(n) = &entry.note {
                    ui.label(n);
                }
            });
            return;
        }

        // 憑證鏈（所有開啟的檔案都作為補齊來源）
        let need = !matches!(&self.chain_cache, Some((k, _)) if *k == (si, ei));
        if need {
            let built = build_chain(&entry.chain, &self.pool(), now_ts(), self.warn_days);
            self.chain_cache = Some(((si, ei), built));
        }
        let Some((_, chain)) = &self.chain_cache else {
            return;
        };
        let entry = &self.stores[si].entries[ei];
        let mut select_link = None;
        let mut copy = None;

        egui::TopBottomPanel::bottom("detail")
            .resizable(true)
            .default_height(380.0)
            .min_height(160.0)
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.heading(&entry.alias);
                    ui.weak(format!("{} · 私鑰：{}", entry.kind, entry.key.label()));
                    if let Some(ts) = entry.created {
                        ui.weak(format!("· 建立於 {}", format_ts(ts)));
                    }
                });
                ui.separator();
                ui.columns(2, |cols| {
                    // 左：憑證鏈
                    egui::ScrollArea::vertical()
                        .id_salt("chain")
                        .show(&mut cols[0], |ui| {
                            ui.strong("憑證鏈");
                            for (i, l) in chain.links.iter().enumerate() {
                                ui.horizontal(|ui| {
                                    ui.add_space(i as f32 * 18.0);
                                    if i > 0 {
                                        ui.weak("└─");
                                    }
                                    let role = if l.cert.self_signed {
                                        "根"
                                    } else if i == 0 {
                                        "終端"
                                    } else {
                                        "中繼"
                                    };
                                    let text = RichText::new(format!(
                                        "[{i}] {} · {role}",
                                        l.cert.display_name()
                                    ));
                                    if ui.selectable_label(self.selected_link == i, text).clicked()
                                    {
                                        select_link = Some(i);
                                    }
                                    match l.signature_ok {
                                        Some(true) => ui.colored_label(GREEN, "✔"),
                                        Some(false) => ui.colored_label(RED, "✘ 簽章"),
                                        None => ui.colored_label(YELLOW, "?"),
                                    }
                                    .on_hover_text("簽章驗證結果");
                                    if l.source == LinkSource::Pool {
                                        ui.colored_label(BLUE, "補齊").on_hover_text(
                                            "此憑證不在條目本身儲存的鏈中，是從已開啟的檔案補齊的",
                                        );
                                    }
                                    ui.label(status_text(l.validity));
                                });
                            }
                            ui.add_space(6.0);
                            match &chain.end {
                                ChainEnd::Root if chain.problems.is_empty() => {
                                    ui.colored_label(GREEN, "✔ 憑證鏈完整，結束於自簽根憑證");
                                }
                                ChainEnd::Root => {
                                    ui.colored_label(YELLOW, "⚠ 結束於根憑證，但有問題：");
                                }
                                ChainEnd::MissingIssuer { .. } => {
                                    ui.colored_label(
                                        RED,
                                        "✘ 憑證鏈不完整（可開啟含 CA 的檔案來補齊）",
                                    );
                                }
                                ChainEnd::Loop => {
                                    ui.colored_label(RED, "✘ 憑證鏈異常");
                                }
                            }
                            for p in &chain.problems {
                                ui.label(format!("  • {p}"));
                            }
                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                if ui.button("📋 複製此憑證 PEM").clicked() {
                                    copy = Some(false);
                                }
                                if ui.button("📋 複製整條鏈 PEM").clicked() {
                                    copy = Some(true);
                                }
                            });
                        });
                    // 右：憑證內容
                    let idx = self.selected_link.min(chain.links.len().saturating_sub(1));
                    if let Some(l) = chain.links.get(idx) {
                        egui::ScrollArea::vertical()
                            .id_salt("cert")
                            .show(&mut cols[1], |ui| {
                                ui.strong(format!("憑證 [{idx}] {}", l.cert.display_name()));
                                cert_grid(ui, "cert_grid", &l.cert, l.validity);
                            });
                    }
                });
            });

        if let Some(i) = select_link {
            self.selected_link = i;
        }
        if let Some(all) = copy {
            let text = if all {
                chain
                    .links
                    .iter()
                    .map(|l| l.cert.to_pem())
                    .collect::<String>()
            } else {
                chain
                    .links
                    .get(self.selected_link)
                    .map(|l| l.cert.to_pem())
                    .unwrap_or_default()
            };
            ctx.copy_text(text);
            self.info("已複製 PEM 到剪貼簿");
        }
    }

    fn password_dialog(&mut self, ctx: &egui::Context) {
        let Some(p) = self.pending.as_mut() else {
            return;
        };
        let mut submit = false;
        let mut cancel = false;
        egui::Window::new("🔐 需要密碼")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(format!("檔案：{}", p.path.display()));
                ui.add_space(4.0);
                egui::Grid::new("pw").num_columns(2).show(ui, |ui| {
                    ui.label("憑證庫密碼");
                    let r = ui.add(
                        egui::TextEdit::singleline(&mut p.password)
                            .password(true)
                            .desired_width(220.0),
                    );
                    if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        submit = true;
                    }
                    r.request_focus();
                    ui.end_row();
                    ui.label("私鑰密碼");
                    ui.add(
                        egui::TextEdit::singleline(&mut p.key_password)
                            .password(true)
                            .hint_text("與憑證庫相同可留空")
                            .desired_width(220.0),
                    );
                    ui.end_row();
                });
                if let Some(e) = &p.error {
                    ui.colored_label(RED, e);
                }
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if ui.button("開啟").clicked() {
                        submit = true;
                    }
                    if ui.button("取消").clicked() {
                        cancel = true;
                    }
                });
            });
        if cancel {
            self.pending = None;
        } else if submit {
            let p = self.pending.take().unwrap();
            let opts = LoadOptions {
                password: Some(p.password.clone()),
                key_password: (!p.key_password.is_empty()).then(|| p.key_password.clone()),
            };
            self.open_path(p.path, opts, p.replace);
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 拖放檔案
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|f| f.path.clone())
                .collect()
        });
        self.queue.extend(dropped);
        self.handle_queue();
        if let Some(mut shot) = self.devshot.take() {
            if !self.stores.is_empty() && self.queue.is_empty() {
                if shot.tab == "handshake" {
                    if self.tab != Tab::Handshake {
                        self.tab = Tab::Handshake;
                        self.hs.demo(&self.stores);
                    }
                } else if self.selected_entry.is_none() {
                    self.selected_store = Some(0);
                    let first = self.stores[0]
                        .entries
                        .iter()
                        .position(|e| e.kind == rustca_core::EntryKind::PrivateKey)
                        .unwrap_or(0);
                    self.selected_entry = Some((0, first));
                    if !shot.tab.is_empty() {
                        self.search = shot.tab.clone();
                        self.selected_store = None;
                    }
                }
            }
            if !shot.tick(ctx) {
                self.devshot = Some(shot);
            }
        }

        self.top_bar(ctx);
        self.status_bar(ctx);
        match self.tab {
            Tab::Browse => {
                self.store_panel(ctx);
                self.detail_panel(ctx);
                egui::CentralPanel::default().show(ctx, |ui| {
                    if self.stores.is_empty() {
                        ui.centered_and_justified(|ui| {
                            ui.label(
                                RichText::new(
                                    "📂 開啟或拖曳 JKS / JCEKS / PKCS#12 / PEM / CER 檔案",
                                )
                                .size(20.0)
                                .color(Color32::GRAY),
                            );
                        });
                    } else {
                        self.entry_table(ui);
                    }
                });
            }
            Tab::Handshake => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    self.hs.ui(ui, &self.stores);
                });
            }
        }
        self.password_dialog(ctx);

        // 讓交握執行緒結束時能更新畫面
        if self.hs.is_running() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}
