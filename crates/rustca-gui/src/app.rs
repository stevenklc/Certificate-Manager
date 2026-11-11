//! 主視窗：憑證庫瀏覽、搜尋、憑證鏈。

use std::path::PathBuf;

use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};
use rustca_core::chain::LinkSource;
use rustca_core::{
    build_chain, edit, format_ts, issuance_forest, issuance_tree, load_file, now_ts, BuiltChain,
    CertInfo, ChainEnd, EntryKind, IssuanceTree, KeyState, Keystore, LoadOptions, Matcher,
    StoreFormat,
};

use crate::handshake::HandshakeState;
use crate::manage::{self, Dialog, Effect, GenChain, Kind};
use crate::tools::{verify_window, JavaTest, RoleCheck};
use crate::widgets::{cert_grid, pick_cert_files, short_dn, status_text, BLUE, GREEN, RED, YELLOW};
use rustca_core::edit::{CertFormat, Verification};

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
    chain_cache: Option<((usize, usize), BuiltChain, IssuanceTree)>,
    /// 詳細面板左側顯示簽發關係圖（否則顯示憑證鏈）
    show_tree: bool,
    tree_selected: usize,
    /// 下一個 frame 要捲動到清單中的這個條目
    scroll_to: Option<(usize, usize)>,
    /// 清單排序：(欄位, 是否升冪)；None＝原始順序
    sort: Option<(SortCol, bool)>,
    /// 下方面板的中心條目：(中心, 當時清單選取的條目)。
    /// 從憑證鏈 / 關係圖跳到其他條目時保留原本的鏈；清單選取改變後自動失效。
    view_anchor: Option<((usize, usize), (usize, usize))>,
    devshot: Option<crate::devshot::DevShot>,
    /// 與 stores 一一對應：是否有未儲存的變更
    dirty: Vec<bool>,
    dialog: Option<Dialog>,
    allow_close: bool,
    verify_view: Option<Verification>,
    java_test: Option<JavaTest>,
    role_check: Option<RoleCheck>,
    graph_view: Option<GraphView>,
    help: Option<crate::help::Help>,
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
            show_tree: false,
            tree_selected: 0,
            scroll_to: None,
            sort: None,
            view_anchor: None,
            devshot: crate::devshot::DevShot::from_env(),
            dirty: Vec::new(),
            dialog: None,
            allow_close: false,
            verify_view: None,
            java_test: None,
            role_check: None,
            graph_view: None,
            help: None,
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
                        // 同一個檔案重複開啟時取代舊的（有未儲存變更時保留舊的）
                        if let Some(i) = self.stores.iter().position(|s| s.path == path) {
                            if self.dirty[i] {
                                self.selected_store = Some(i);
                                self.error(format!("{name} 已開啟且有未儲存的變更"));
                                return;
                            }
                            self.stores[i] = ks;
                            i
                        } else {
                            self.stores.push(ks);
                            self.dirty.push(false);
                            self.stores.len() - 1
                        }
                    }
                };
                self.dirty[idx] = false;
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

    fn add_store(&mut self, ks: Keystore) {
        self.stores.push(ks);
        self.dirty.push(false);
        self.selected_store = Some(self.stores.len() - 1);
        self.selected_entry = None;
        self.chain_cache = None;
        self.hs.on_stores_changed(self.stores.len());
    }

    fn close_store(&mut self, i: usize) {
        self.stores.remove(i);
        self.dirty.remove(i);
        self.selected_store = None;
        self.selected_entry = None;
        self.chain_cache = None;
        self.hs.on_stores_changed(self.stores.len());
    }

    /// 大畫面簽發關係圖視窗。
    fn graph_window(&mut self, ctx: &egui::Context) {
        let Some(mut g) = self.graph_view.take() else {
            return;
        };
        if g.store >= self.stores.len() {
            return;
        }
        // 目前條目（需在範圍內）
        let center = self.selected_entry.filter(|(s, e)| {
            (g.all_files || *s == g.store) && self.stores[*s].entries.get(*e).is_some()
        });
        let key = (
            g.whole || center.is_none(),
            g.all_files,
            center,
            self.stores.len(),
            self.stores[g.store].entries.len(),
        );
        if g.key != Some(key) || g.dirty {
            let pool: Vec<&CertInfo> = if g.all_files {
                self.pool()
            } else {
                let mut seen = std::collections::HashSet::new();
                self.stores[g.store]
                    .all_certs()
                    .into_iter()
                    .filter(|c| seen.insert(c.sha256.clone()))
                    .collect()
            };
            let target = center.and_then(|(s, e)| self.stores[s].entries[e].leaf());
            g.tree = match center {
                Some((s, e)) if !g.whole => {
                    let built = build_chain(
                        &self.stores[s].entries[e].chain,
                        &pool,
                        now_ts(),
                        self.warn_days,
                    );
                    issuance_tree(&built, &pool)
                }
                _ => issuance_forest(&pool, target.map(|c| c.sha256.as_str())),
            };
            g.selected = g.tree.nodes.iter().position(|n| n.is_target).unwrap_or(0);
            g.scroll = Some(g.selected);
            g.key = Some(key);
            g.dirty = false;
        }

        let screen = ctx.screen_rect();
        let size = egui::vec2(screen.width() * 0.94, screen.height() * 0.88);
        let locations = self.locations();
        let mut open = true;
        let mut close = false;
        let mut goto = None;
        let mut menu_act = None;
        let stores = &self.stores;
        let title = if g.all_files {
            "所有已開啟的檔案".to_string()
        } else {
            stores[g.store].name()
        };
        egui::Window::new(format!("🌳 簽發關係圖：{title}"))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .fixed_size(size)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label("顯示：");
                    ui.add_enabled_ui(center.is_some(), |ui| {
                        ui.radio_value(&mut g.whole, false, "目前條目的簽發關係")
                            .on_disabled_hover_text("請先在清單中選取一個條目");
                    });
                    ui.radio_value(&mut g.whole, true, "全部憑證");
                    ui.separator();
                    ui.checkbox(&mut g.all_files, "包含所有已開啟的檔案");
                    if ui.button("🔄 重新整理").clicked() {
                        g.dirty = true;
                    }
                    ui.separator();
                    let tops = g.tree.nodes.iter().filter(|n| n.parent.is_none()).count();
                    ui.weak(format!("{} 張憑證、{tops} 棵樹", g.tree.nodes.len()));
                });
                if let Some(m) = &g.tree.missing_issuer {
                    ui.colored_label(RED, format!("✘ 最上層憑證的簽發者不在範圍內：{m}"));
                }
                if g.tree.truncated {
                    ui.colored_label(YELLOW, "⚠ 憑證太多，只顯示一部分");
                }
                egui::TopBottomPanel::bottom("big_tree_bottom")
                    .show_separator_line(true)
                    .show_inside(ui, |ui| {
                        ui.add_space(4.0);
                        ui.horizontal_wrapped(|ui| {
                            if ui.button("關閉").clicked() {
                                close = true;
                            }
                            ui.weak("點一下看內容 · 點兩下跳到所在條目 · 右鍵管理 · 線條：綠＝簽章正確、紅＝失敗、灰＝無法判斷");
                        });
                    });
                // 右：選取憑證的內容
                egui::SidePanel::right("big_tree_cert_panel")
                    .resizable(true)
                    .default_width(size.x * 0.36)
                    .min_width(260.0)
                    .max_width(size.x * 0.6)
                    .show_inside(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .id_salt("big_tree_cert")
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                let Some(n) = g.tree.nodes.get(g.selected) else {
                                    ui.weak("點選左側的憑證查看內容");
                                    return;
                                };
                                ui.horizontal_wrapped(|ui| {
                                    ui.strong(n.cert.display_name());
                                    if let Some(loc) = self.find_cert(&n.cert.sha256, g.store) {
                                        if ui
                                            .button("➡ 前往此條目")
                                            .on_hover_text("在主畫面清單中選取這張憑證所在的條目")
                                            .clicked()
                                        {
                                            goto = Some(loc);
                                        }
                                    }
                                });
                                if let Some(v) = locations.get(&n.cert.sha256) {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(format!("位置：{}", v.join("、"))).weak(),
                                        )
                                        .wrap(),
                                    );
                                }
                                cert_grid(
                                    ui,
                                    "big_tree_grid",
                                    &n.cert,
                                    n.cert.status_at(now_ts(), self.warn_days),
                                );
                            });
                    });
                // 左：關係圖
                egui::CentralPanel::default().show_inside(ui, |ui| {
                    egui::ScrollArea::both()
                        .id_salt("big_tree")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            let prefer = center.map_or(g.store, |(s, _)| s);
                            let find = |sha: &str| self.find_cert(sha, prefer);
                            let tree = &g.tree;
                            let r = crate::graph::tree_ui(
                                ui,
                                tree,
                                g.selected,
                                &locations,
                                self.warn_days,
                                g.scroll.take(),
                                &mut |ui, i| {
                                    let loc = find(&tree.nodes[i].cert.sha256);
                                    entry_menu(ui, stores, loc, &mut menu_act);
                                },
                            );
                            if let Some(i) = r.clicked {
                                g.selected = i;
                            }
                            if let Some(i) = r.double_clicked {
                                goto = find(&tree.nodes[i].cert.sha256);
                            }
                        });
                });
                if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                    close = true;
                }
            });
        if let Some(loc) = goto {
            self.jump_to(loc);
        }
        if let Some((s, e, a)) = menu_act {
            self.entry_act(s, e, a);
        }
        if open && !close {
            self.graph_view = Some(g);
        }
    }

    /// 每張憑證（sha256）出現在哪些「檔案 / 別名」。
    fn locations(&self) -> crate::graph::Locations {
        let mut m = crate::graph::Locations::new();
        for ks in &self.stores {
            for e in &ks.entries {
                for (i, c) in e.chain.iter().enumerate() {
                    let label = if i == 0 {
                        format!("{} / {}", ks.name(), e.alias)
                    } else {
                        format!("{} / {}（鏈第 {i} 層）", ks.name(), e.alias)
                    };
                    m.entry(c.sha256.clone()).or_default().push(label);
                }
            }
        }
        m
    }

    /// 找出以這張憑證為終端憑證的條目，優先找 `prefer` 檔案。
    fn find_cert(&self, sha256: &str, prefer: usize) -> Option<(usize, usize)> {
        let hit = |si: usize| {
            self.stores.get(si).and_then(|ks| {
                ks.entries
                    .iter()
                    .position(|e| e.leaf().is_some_and(|c| c.sha256 == sha256))
                    .map(|ei| (si, ei))
            })
        };
        hit(prefer).or_else(|| (0..self.stores.len()).find_map(hit))
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
                    self.queue.extend(pick_cert_files());
                }
                if ui.button("🆕 新增憑證庫…").clicked() {
                    self.dialog = Some(
                        Kind::NewStore {
                            path: None,
                            format: StoreFormat::Jks,
                            pw: String::new(),
                            pw2: String::new(),
                            asm: Default::default(),
                        }
                        .into(),
                    );
                }
                if ui
                    .button("🔁 轉換憑證格式…")
                    .on_hover_text(
                        "PEM ⇄ DER（.cer）⇄ PKCS#7（.p7b），也可從 .p12 / .jks 取出憑證與私鑰",
                    )
                    .clicked()
                {
                    self.dialog = Some(
                        Kind::ConvertCert {
                            file: None,
                            file_pw: String::new(),
                            format: CertFormat::Pem,
                            with_key: false,
                        }
                        .into(),
                    );
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
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .button(RichText::new("❓ 說明").strong())
                        .on_hover_text(
                            "名詞解釋（Client / Server / Truststore / clientAuth…）與功能介紹",
                        )
                        .clicked()
                    {
                        self.help = Some(crate::help::Help::default());
                    }
                });
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
                                .any(|e| matches!(e.key, KeyState::Locked(_)))
                                || (edit::is_writable(ks.format) && ks.store_password.is_none());
                            let dirty = self.dirty.get(i).copied().unwrap_or(false);
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
                                    if self.selected_entry.is_some_and(|(s, _)| s != i) {
                                        self.selected_entry = None;
                                    }
                                }
                                ui.horizontal_wrapped(|ui| {
                                    ui.weak(format!("{} · {} 個條目", ks.format, ks.entries.len()));
                                    let kind = rustca_core::role::store_kind(ks);
                                    let keys = ks.private_key_entries().count();
                                    let trusted = ks
                                        .entries
                                        .iter()
                                        .filter(|e| e.kind == EntryKind::TrustedCert)
                                        .count();
                                    let (icon, color) = match kind {
                                        "Keystore" => ("🔑", GREEN),
                                        "Truststore" => ("🛡", BLUE),
                                        "空的" => ("○", Color32::GRAY),
                                        _ => ("🔑🛡", YELLOW),
                                    };
                                    ui.colored_label(color, format!("{icon} {kind}")).on_hover_text(
                                        format!(
                                            "{keys} 個私鑰條目、{trusted} 張信任憑證\n\
                                             Keystore：含私鑰，當作自己的身分（Server / mTLS Client）\n\
                                             Truststore：只有信任憑證，用來驗證對方\n\
                                             可用「☑ 用途檢查」確認是否適合"
                                        ),
                                    );
                                    if bad > 0 {
                                        ui.colored_label(YELLOW, format!("⚠ {bad} 張需注意"));
                                    }
                                    if dirty {
                                        ui.colored_label(YELLOW, "● 未儲存");
                                    }
                                });
                                ui.horizontal(|ui| {
                                    if locked
                                        && !dirty
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
                    if self.dirty.get(i).copied().unwrap_or(false) {
                        self.dialog = Some(Kind::ConfirmClose { store: Some(i) }.into());
                    } else {
                        self.close_store(i);
                    }
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
            not_after_ts: i64,
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
                    kind: {
                        let mut k = e.kind.to_string();
                        if let Some(c) = leaf {
                            k = format!("{k} · {}", c.role());
                        }
                        if e.chain.len() > 1 {
                            k = format!("{k}（鏈 {}）", e.chain.len());
                        }
                        k
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
                    not_after_ts: leaf.map_or(i64::MAX, |c| c.not_after),
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

        if let Some((col, asc)) = self.sort {
            use std::cmp::Ordering;
            let text = |a: &str, b: &str| a.to_lowercase().cmp(&b.to_lowercase());
            // 狀態：已過期 → 即將到期 → 尚未生效 → 有效，同狀態再依到期日
            let rank = |r: &Row| match r.status {
                Some(rustca_core::ValidityStatus::Expired { .. }) => 0,
                Some(rustca_core::ValidityStatus::ExpiringSoon { .. }) => 1,
                Some(rustca_core::ValidityStatus::NotYetValid { .. }) => 2,
                Some(rustca_core::ValidityStatus::Valid { .. }) => 3,
                None => 4,
            };
            rows.sort_by(|a, b| {
                let o: Ordering = match col {
                    SortCol::File => text(&a.file, &b.file),
                    SortCol::Alias => text(&a.alias, &b.alias),
                    SortCol::Kind => text(&a.kind, &b.kind),
                    SortCol::Cn => text(&a.cn, &b.cn),
                    SortCol::Issuer => text(&a.issuer, &b.issuer),
                    SortCol::NotAfter => a.not_after_ts.cmp(&b.not_after_ts),
                    SortCol::Status => (rank(a), a.not_after_ts).cmp(&(rank(b), b.not_after_ts)),
                    SortCol::Key => a.key.cmp(b.key).reverse(),
                    SortCol::Matched => text(&a.matched, &b.matched),
                };
                if asc {
                    o
                } else {
                    o.reverse()
                }
            });
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
        let mut menu_act = None;
        let selected = self.selected_entry;
        let stores = &self.stores;
        let scroll_row = self
            .scroll_to
            .take()
            .and_then(|t| rows.iter().position(|r| (r.store, r.entry) == t));
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
            .column(Column::initial(170.0).clip(true))
            .column(Column::initial(180.0).clip(true))
            .column(Column::initial(150.0).clip(true))
            .column(Column::initial(90.0))
            .column(Column::initial(130.0).clip(true))
            .column(Column::exact(36.0));
        if show_match {
            table = table.column(Column::remainder());
        }
        if let Some(i) = scroll_row {
            table = table.scroll_to_row(i, Some(egui::Align::Center));
        }
        let sort = self.sort;
        let mut sort_click = None;
        let mut header = |h: &mut egui_extras::TableRow, t: &str, col: SortCol| {
            h.col(|ui| {
                let arrow = match sort {
                    Some((c, true)) if c == col => " ▲",
                    Some((c, false)) if c == col => " ▼",
                    _ => "",
                };
                if ui
                    .add(
                        egui::Button::new(RichText::new(format!("{t}{arrow}")).strong())
                            .frame(false),
                    )
                    .on_hover_text("點選排序：升冪 ▲ → 降冪 ▼ → 原始順序")
                    .clicked()
                {
                    sort_click = Some(col);
                }
            });
        };
        table
            .header(22.0, |mut h| {
                if show_file {
                    header(&mut h, "檔案", SortCol::File);
                }
                for (t, col) in [
                    ("別名", SortCol::Alias),
                    ("類型", SortCol::Kind),
                    ("主體 CN", SortCol::Cn),
                    ("簽發者", SortCol::Issuer),
                    ("到期日", SortCol::NotAfter),
                    ("狀態", SortCol::Status),
                    ("私鑰", SortCol::Key),
                ] {
                    header(&mut h, t, col);
                }
                if show_match {
                    header(&mut h, "符合欄位", SortCol::Matched);
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
                    let resp = row.response();
                    if resp.clicked() || resp.secondary_clicked() {
                        clicked = Some((r.store, r.entry));
                    }
                    resp.context_menu(|ui| {
                        if let Some(e) = stores.get(r.store).and_then(|s| s.entries.get(r.entry)) {
                            ui.weak(format!("條目「{}」", e.alias));
                            ui.separator();
                            if let Some(a) = entry_actions(ui, &stores[r.store], e, true) {
                                menu_act = Some((r.store, r.entry, a));
                            }
                        }
                    });
                });
            });
        if let Some(col) = sort_click {
            self.sort = match self.sort {
                Some((c, true)) if c == col => Some((col, false)),
                Some((c, false)) if c == col => None,
                _ => Some((col, true)),
            };
            // 排序後讓選取的條目保持在畫面中
            self.scroll_to = self.selected_entry;
        }
        if let Some(c) = clicked {
            self.view_anchor = None;
            if self.selected_entry != Some(c) {
                self.selected_entry = Some(c);
                self.selected_link = 0;
                self.tree_selected = usize::MAX;
            }
        }
        if let Some((si, ei, a)) = menu_act {
            self.entry_act(si, ei, a);
        }
    }

    /// 跳到某個條目：在清單中選取並捲動過去。
    fn jump_to(&mut self, (s, e): (usize, usize)) {
        if self.selected_store.is_some() {
            self.selected_store = Some(s);
        }
        self.selected_entry = Some((s, e));
        self.selected_link = 0;
        self.tree_selected = usize::MAX;
        self.scroll_to = Some((s, e));
    }

    fn detail_panel(&mut self, ctx: &egui::Context) {
        let Some(sel) = self.selected_entry else {
            return;
        };
        let (si, ei) = match self.view_anchor {
            Some((a, s))
                if s == sel && self.stores.get(a.0).is_some_and(|k| a.1 < k.entries.len()) =>
            {
                a
            }
            _ => sel,
        };
        let sel_alias = (sel != (si, ei))
            .then(|| {
                self.stores
                    .get(sel.0)?
                    .entries
                    .get(sel.1)
                    .map(|e| e.alias.clone())
            })
            .flatten();
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
        let need = !matches!(&self.chain_cache, Some((k, _, _)) if *k == (si, ei));
        if need {
            let pool = self.pool();
            let built = build_chain(&entry.chain, &pool, now_ts(), self.warn_days);
            let tree = issuance_tree(&built, &pool);
            self.chain_cache = Some(((si, ei), built, tree));
        }
        let Some((_, chain, tree)) = &self.chain_cache else {
            return;
        };
        if self.tree_selected >= tree.nodes.len() {
            self.tree_selected = tree.nodes.iter().position(|n| n.is_target).unwrap_or(0);
        }
        let locations = if self.show_tree {
            self.locations()
        } else {
            Default::default()
        };
        let mut show_tree = self.show_tree;
        let mut tree_click = None;
        let mut goto = None;
        let mut menu_act = None;
        let mut recenter = false;
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
                if let Some(a) = &sel_alias {
                    ui.horizontal_wrapped(|ui| {
                        ui.colored_label(
                            BLUE,
                            format!("清單中選取的是「{a}」（已在下方標示），這裡仍以「{}」為中心顯示", entry.alias),
                        );
                        if ui.small_button(format!("改以「{a}」為中心")).clicked() {
                            recenter = true;
                        }
                    });
                }
                ui.separator();
                ui.columns(2, |cols| {
                    // 左：憑證鏈
                    cols[0].horizontal(|ui| {
                        ui.selectable_value(&mut show_tree, false, RichText::new("🔗 憑證鏈").strong());
                        ui.selectable_value(
                            &mut show_tree,
                            true,
                            RichText::new("🌳 簽發關係圖").strong(),
                        )
                        .on_hover_text("在所有已開啟的檔案中，找出誰簽發了這張憑證、它又簽發了哪些憑證");
                    });
                    if self.show_tree {
                        egui::ScrollArea::both()
                            .id_salt("tree")
                            .auto_shrink([false, false])
                            .show(&mut cols[0], |ui| {
                                let stores = &self.stores;
                                let find = |sha: &str| {
                                    if stores[si].entries[ei]
                                        .leaf()
                                        .is_some_and(|c| c.sha256 == sha)
                                    {
                                        Some((si, ei))
                                    } else {
                                        self.find_cert(sha, si)
                                    }
                                };
                                let r = crate::graph::tree_ui(
                                    ui,
                                    tree,
                                    self.tree_selected,
                                    &locations,
                                    self.warn_days,
                                    None,
                                    &mut |ui, i| {
                                        let loc = find(&tree.nodes[i].cert.sha256);
                                        entry_menu(ui, stores, loc, &mut menu_act);
                                    },
                                );
                                tree_click = r.clicked;
                                if let Some(i) = r.double_clicked {
                                    goto = find(&tree.nodes[i].cert.sha256)
                                        .filter(|x| Some(*x) != self.selected_entry);
                                }
                                ui.add_space(4.0);
                                if let Some(m) = &tree.missing_issuer {
                                    ui.colored_label(
                                        RED,
                                        format!("✘ 最上層憑證的簽發者不在已開啟的檔案中：{m}"),
                                    );
                                }
                                if tree.truncated {
                                    ui.colored_label(YELLOW, "⚠ 憑證太多，只顯示前 400 張");
                                }
                                let target = tree.nodes.iter().position(|n| n.is_target);
                                let issued = target.map_or(0, |t| {
                                    tree.nodes.iter().filter(|n| n.parent == Some(t)).count()
                                });
                                if target.is_some_and(|t| tree.nodes[t].cert.is_ca) && issued == 0 {
                                    ui.weak("已開啟的檔案中沒有由這張 CA 簽發的憑證；可開啟其他憑證庫一起比對");
                                }
                                ui.weak("線條：綠＝簽章驗證通過、紅＝失敗、灰＝無法判斷；藍框＝目前憑證到根的路徑");
                            });
                    } else {
                    egui::ScrollArea::vertical()
                        .id_salt("chain")
                        .show(&mut cols[0], |ui| {
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
                                    // 這張憑證所在的條目（i == 0 就是目前條目）
                                    let loc = if i == 0 {
                                        Some((si, ei))
                                    } else {
                                        self.find_cert(&l.cert.sha256, si)
                                    };
                                    let r = ui.selectable_label(self.selected_link == i, text);
                                    let r = if loc.is_some_and(|x| Some(x) != self.selected_entry) {
                                        r.on_hover_text("點選跳到這張憑證的條目；右鍵可管理")
                                    } else {
                                        r
                                    };
                                    if r.clicked() {
                                        match loc {
                                            Some(x) if Some(x) != self.selected_entry => {
                                                goto = Some(x)
                                            }
                                            _ => select_link = Some(i),
                                        }
                                    }
                                    r.context_menu(|ui| {
                                        entry_menu(ui, &self.stores, loc, &mut menu_act);
                                    });
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
                    }
                    // 右：憑證內容
                    if self.show_tree {
                        if let Some(n) = tree.nodes.get(self.tree_selected) {
                            egui::ScrollArea::vertical()
                                .id_salt("cert")
                                .show(&mut cols[1], |ui| {
                                    ui.horizontal_wrapped(|ui| {
                                        ui.strong(n.cert.display_name());
                                        let target = self.stores[si].entries[ei]
                                            .leaf()
                                            .is_some_and(|c| c.sha256 == n.cert.sha256);
                                        if !target {
                                            if let Some(loc) = self.find_cert(&n.cert.sha256, si) {
                                                if ui
                                                    .button("➡ 前往此條目")
                                                    .on_hover_text("在清單中選取這張憑證所在的條目")
                                                    .clicked()
                                                {
                                                    goto = Some(loc);
                                                }
                                            }
                                        }
                                    });
                                    if let Some(v) = locations.get(&n.cert.sha256) {
                                        ui.weak(format!("位置：{}", v.join("、")));
                                    }
                                    cert_grid(
                                        ui,
                                        "tree_cert_grid",
                                        &n.cert,
                                        n.cert.status_at(now_ts(), self.warn_days),
                                    );
                                });
                        }
                    } else {
                    let idx = self.selected_link.min(chain.links.len().saturating_sub(1));
                    if let Some(l) = chain.links.get(idx) {
                        egui::ScrollArea::vertical()
                            .id_salt("cert")
                            .show(&mut cols[1], |ui| {
                                ui.strong(format!("憑證 [{idx}] {}", l.cert.display_name()));
                                cert_grid(ui, "cert_grid", &l.cert, l.validity);
                            });
                    }
                    }
                });
            });

        self.show_tree = show_tree;
        if let Some(i) = tree_click {
            self.tree_selected = i;
        }
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
        if recenter {
            self.view_anchor = None;
            self.selected_link = 0;
            self.tree_selected = usize::MAX;
        }
        if let Some(loc) = goto {
            // 保留目前的中心，只在清單中選取並標示該憑證
            self.jump_to(loc);
            self.view_anchor = (loc != (si, ei)).then_some(((si, ei), loc));
            let sha = self.stores[loc.0].entries[loc.1]
                .leaf()
                .map(|c| c.sha256.clone());
            if let (Some(sha), Some((_, chain, tree))) = (sha, &self.chain_cache) {
                if let Some(i) = chain.links.iter().position(|l| l.cert.sha256 == sha) {
                    self.selected_link = i;
                }
                if let Some(n) = tree.nodes.iter().position(|n| n.cert.sha256 == sha) {
                    self.tree_selected = n;
                }
            }
        }
        if let Some((s, e, a)) = menu_act {
            self.entry_act(s, e, a);
        }
    }

    /// 目前操作的憑證庫：選取條目所在的檔案，否則為左側選取的檔案。
    fn target_store(&self) -> Option<usize> {
        // 左側有選檔案時以它為準；「全部檔案」時才看選取條目所在的檔案
        self.selected_store
            .or(self.selected_entry.map(|(s, _)| s))
            .filter(|i| *i < self.stores.len())
    }

    /// 執行條目動作（工具列與右鍵選單共用）。
    fn entry_act(&mut self, si: usize, ei: usize, act: EntryAct) {
        let Some(e) = self.stores.get(si).and_then(|s| s.entries.get(ei)) else {
            return;
        };
        let alias = e.alias.clone();
        let kind = match act {
            EntryAct::Rename => Kind::Rename {
                store: si,
                old: alias.clone(),
                new: alias,
            },
            EntryAct::UpdateCert => Kind::UpdateCert {
                store: si,
                alias,
                file: None,
                file_pw: String::new(),
            },
            EntryAct::KeyPass => Kind::KeyPass {
                store: si,
                alias,
                current: String::new(),
                new: String::new(),
                new2: String::new(),
            },
            EntryAct::CheckKeyPass => Kind::CheckKeyPass {
                store: si,
                alias,
                pw: String::new(),
            },
            EntryAct::Delete => Kind::Delete { store: si, alias },
            EntryAct::VerifyChain => {
                match edit::verify_entry(&self.stores[si], &alias, now_ts()) {
                    Ok(v) => self.verify_view = Some(v),
                    Err(e) => self.error(e.to_string()),
                }
                return;
            }
            EntryAct::Export => {
                match manage::export_entry(e, true) {
                    Ok(Some(m)) => self.info(m),
                    Ok(None) => {}
                    Err(m) => self.error(m),
                }
                return;
            }
        };
        self.dialog = Some(kind.into());
    }

    fn manage_bar(&mut self, ui: &mut egui::Ui) {
        let Some(si) = self.target_store() else {
            ui.weak("選擇左側的檔案即可管理（匯入、刪除、改名、修改密碼、另存新檔）");
            return;
        };
        let ks = &self.stores[si];
        let writable = edit::is_writable(ks.format);
        let can_edit = writable && ks.store_password.is_some();
        let dirty = self.dirty[si];
        let entry = self
            .selected_entry
            .filter(|(s, _)| *s == si)
            .and_then(|(_, e)| ks.entries.get(e));
        let mut open: Option<Kind> = None;
        let mut save = false;
        let mut java = false;
        let mut role = false;
        let mut graph = false;
        ui.horizontal_wrapped(|ui| {
            ui.strong(format!("🛠 {}", ks.name()));
            if !writable {
                ui.colored_label(
                    YELLOW,
                    format!("{} 為唯讀格式，可「另存新檔」轉成 JKS / PKCS#12", ks.format),
                );
            } else if !can_edit {
                ui.colored_label(YELLOW, "未以密碼開啟，請先按左側「解鎖」");
            }
            ui.separator();
            if ui
                .add_enabled(can_edit, egui::Button::new("➕ 匯入憑證"))
                .clicked()
            {
                open = Some(Kind::ImportCert {
                    store: si,
                    file: None,
                    file_pw: String::new(),
                    alias: String::new(),
                    overwrite: false,
                });
            }
            if ui
                .add_enabled(can_edit, egui::Button::new("➕ 匯入金鑰對"))
                .clicked()
            {
                open = Some(Kind::ImportKey {
                    store: si,
                    pair: false,
                    src: None,
                    src_pw: String::new(),
                    src_alias: String::new(),
                    cert: None,
                    key: None,
                    alias: String::new(),
                    key_pw: String::new(),
                    key_pw2: String::new(),
                    overwrite: false,
                });
            }
            if ui
                .add_enabled(can_edit, egui::Button::new("📥 批次匯入…"))
                .on_hover_text("一次選取多個 .cer / .key / .p12…，自動配對私鑰與憑證並補齊憑證鏈")
                .clicked()
            {
                open = Some(Kind::Assemble {
                    store: si,
                    asm: Default::default(),
                    overwrite: false,
                });
            }
            if ui
                .add_enabled(can_edit, egui::Button::new("🔐 改憑證庫密碼"))
                .clicked()
            {
                open = Some(Kind::StorePass {
                    store: si,
                    new: String::new(),
                    new2: String::new(),
                    also_keys: true,
                });
            }
            if ui
                .add_enabled(can_edit && dirty, egui::Button::new("💾 儲存"))
                .on_hover_text("寫回原檔（會先建立 .bak 備份）")
                .clicked()
            {
                save = true;
            }
            if ui.button("💾 另存新檔 / 轉換…").clicked() {
                let format = if writable {
                    ks.format
                } else {
                    StoreFormat::Jks
                };
                open = Some(Kind::SaveAs {
                    store: si,
                    path: None,
                    format,
                    pw: String::new(),
                    pw2: String::new(),
                    legacy: false,
                });
            }
            ui.separator();
            if ui
                .add_enabled(can_edit, egui::Button::new("🏭 製作憑證鏈…"))
                .on_hover_text("建立根 CA / 中繼 CA / Server、Client 憑證，或用庫中的 CA 簽發")
                .clicked()
            {
                open = Some(Kind::GenChain(Box::new(GenChain::new(si))));
            }
            let java_ok = writable && ks.store_password.is_some();
            if ui
                .add_enabled(java_ok, egui::Button::new("☕ Java 相容性測試"))
                .on_hover_text("用本機各版本 Java 的 keytool 讀取此憑證庫並解開私鑰")
                .clicked()
            {
                java = true;
            }
            if ui
                .add_enabled(!ks.entries.is_empty(), egui::Button::new("🌳 簽發關係圖"))
                .on_hover_text("以大畫面檢視誰簽發了誰（目前條目，或整個憑證庫）")
                .clicked()
            {
                graph = true;
            }
            if ui
                .button("☑ 用途檢查")
                .on_hover_text(
                    "檢查是否適合當 Server keystore、Client keystore（mTLS）或 Truststore",
                )
                .clicked()
            {
                role = true;
            }
        });
        let mut act = None;
        if let Some(e) = entry {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(format!("條目「{}」：", e.alias)).strong());
                act = entry_actions(ui, ks, e, false);
            });
        }
        if let Some(k) = open {
            self.dialog = Some(k.into());
        }
        if save {
            match manage::save_in_place(&mut self.stores[si]) {
                Ok(m) => {
                    self.dirty[si] = false;
                    self.chain_cache = None;
                    self.info(m);
                }
                Err(e) => self.error(e),
            }
        }
        if graph {
            self.graph_view = Some(GraphView::new(si, self.selected_entry.is_none()));
        }
        if role {
            self.role_check = Some(RoleCheck::new(self.stores[si].clone()));
        }
        if java {
            let mut t = JavaTest::new(self.stores[si].clone(), self.dirty[si]);
            t.start(ui.ctx());
            self.java_test = Some(t);
        }
        if let (Some(a), Some((_, ei))) = (act, self.selected_entry) {
            self.entry_act(si, ei, a);
        }
    }

    fn manage_dialog(&mut self, ctx: &egui::Context) {
        let Some(d) = self.dialog.as_mut() else {
            return;
        };
        match manage::show(d, ctx, &self.stores) {
            Some(false) => self.dialog = None,
            Some(true) => match manage::apply(&d.kind, &mut self.stores) {
                Ok(effect) => {
                    self.dialog = None;
                    self.chain_cache = None;
                    match effect {
                        Effect::Modified(i, m) => {
                            self.dirty[i] = true;
                            if let Some((s, e)) = self.selected_entry {
                                if s == i && e >= self.stores[i].entries.len() {
                                    self.selected_entry = None;
                                }
                            }
                            self.info(format!("{m}（尚未儲存）"));
                        }
                        Effect::Verified(i, m, v) => {
                            self.dirty[i] = true;
                            self.info(format!("{m}（尚未儲存）"));
                            self.verify_view = Some(v);
                        }
                        Effect::Done(m) => self.info(m),
                        Effect::Saved(i, m) => {
                            self.dirty[i] = false;
                            self.info(m);
                        }
                        Effect::Created(ks, m) => {
                            self.add_store(*ks);
                            self.info(m);
                        }
                        Effect::Close(Some(i)) => self.close_store(i),
                        Effect::Close(None) => {
                            self.allow_close = true;
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    }
                }
                Err(e) => d.error = Some(e),
            },
            None => {}
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
            .max_width(crate::tools::max_window_width(ctx))
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                crate::widgets::trunc_label(ui, format!("檔案：{}", p.path.display()), 460.0);
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
        self.queue.append(&mut self.hs.open_requests);
        self.handle_queue();
        // 有未儲存變更時，關閉視窗前先確認
        if ctx.input(|i| i.viewport().close_requested())
            && !self.allow_close
            && self.dirty.iter().any(|d| *d)
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.dialog = Some(Kind::ConfirmClose { store: None }.into());
        }
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
                    match shot.tab.as_str() {
                        "help" => {
                            self.help = Some(crate::help::Help::default());
                        }
                        "graph" => {
                            self.graph_view = Some(GraphView::new(0, true));
                        }
                        "role" => {
                            self.role_check = Some(RoleCheck::new(self.stores[0].clone()));
                        }
                        "asm" => {
                            // RUST_CA_ASM_DIR 中的所有檔案作為「新增憑證庫」的內容
                            let mut asm = manage::Assembly::default();
                            if let Some(d) = std::env::var_os("RUST_CA_ASM_DIR") {
                                if let Ok(rd) = std::fs::read_dir(d) {
                                    asm.files = rd.flatten().map(|e| e.path()).collect();
                                    asm.files.sort();
                                }
                            }
                            asm.reload();
                            self.dialog = Some(
                                Kind::NewStore {
                                    path: Some("servers.jks".into()),
                                    format: StoreFormat::Jks,
                                    pw: String::new(),
                                    pw2: String::new(),
                                    asm: Box::new(asm),
                                }
                                .into(),
                            );
                        }
                        "sort" => {
                            self.selected_store = None;
                            self.sort = Some((SortCol::NotAfter, false));
                        }
                        "anchor" => {
                            // 模擬：以終端憑證為中心，從鏈中點到根憑證
                            let ks = &self.stores[0];
                            let leaf = ks.entries.iter().position(|e| e.chain.len() > 2);
                            let root = ks
                                .entries
                                .iter()
                                .position(|e| e.leaf().is_some_and(|c| c.self_signed));
                            if let (Some(l), Some(r)) = (leaf, root) {
                                self.selected_store = None;
                                self.selected_entry = Some((0, r));
                                self.view_anchor = Some(((0, l), (0, r)));
                                self.selected_link = 2;
                            }
                        }
                        "tree" => {
                            self.selected_store = None;
                            self.show_tree = true;
                        }
                        "gen" => {
                            let mut g = GenChain::new(0);
                            g.leaf_cn = "api.example.com".into();
                            g.sans = "api.example.com, 10.0.0.5".into();
                            self.dialog = Some(Kind::GenChain(Box::new(g)).into());
                        }
                        "java" => {
                            let mut t = JavaTest::new(self.stores[0].clone(), false);
                            t.start(ctx);
                            self.java_test = Some(t);
                        }
                        "convert" => {
                            self.dialog = Some(
                                Kind::ConvertCert {
                                    file: Some(self.stores[0].path.clone()),
                                    file_pw: String::new(),
                                    format: CertFormat::P7b,
                                    with_key: false,
                                }
                                .into(),
                            );
                        }
                        "" => {}
                        t => {
                            self.search = t.to_string();
                            self.selected_store = None;
                        }
                    }
                }
            }
            shot.hold = self.java_test.as_ref().is_some_and(|t| t.is_running());
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
                        self.manage_bar(ui);
                        ui.separator();
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
        self.manage_dialog(ctx);
        if let Some(v) = &self.verify_view {
            if !verify_window(ctx, v) {
                self.verify_view = None;
            }
        }
        self.graph_window(ctx);
        if let Some(h) = self.help.as_mut() {
            if !h.ui(ctx) {
                self.help = None;
            }
        }
        if let Some(r) = self.role_check.as_mut() {
            if !r.ui(ctx) {
                self.role_check = None;
            }
        }
        if let Some(t) = self.java_test.as_mut() {
            if !t.ui(ctx) {
                self.java_test = None;
            } else if t.is_running() {
                ctx.request_repaint_after(std::time::Duration::from_millis(200));
            }
        }

        // 讓交握執行緒結束時能更新畫面
        if self.hs.is_running() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}

/// 單一條目可執行的動作。
#[derive(Clone, Copy, PartialEq, Eq)]
enum EntryAct {
    Rename,
    UpdateCert,
    KeyPass,
    CheckKeyPass,
    VerifyChain,
    Export,
    Delete,
}

/// 條目動作按鈕；`menu` 為 true 時用於右鍵選單（點選後關閉選單）。
fn entry_actions(
    ui: &mut egui::Ui,
    ks: &Keystore,
    e: &rustca_core::Entry,
    menu: bool,
) -> Option<EntryAct> {
    let can_edit = edit::is_writable(ks.format) && ks.store_password.is_some();
    let is_key = e.kind == EntryKind::PrivateKey;
    let has_chain = !e.chain.is_empty();
    let edit_hint = if !edit::is_writable(ks.format) {
        "此格式為唯讀，請先「另存新檔」轉成 JKS / PKCS#12"
    } else {
        "憑證庫未以密碼開啟，請先按左側「解鎖」"
    };
    let key_off = if !is_key {
        "只有私鑰條目有私鑰密碼"
    } else if ks.format == StoreFormat::Pkcs12 {
        "PKCS#12 的私鑰密碼等於憑證庫密碼，請用「改憑證庫密碼」"
    } else {
        edit_hint
    };
    // (動作, 可用, 文字, 可用時提示, 停用時提示)
    let items: [(EntryAct, bool, RichText, &str, &str); 7] = [
        (EntryAct::Rename, can_edit, "✏ 改名".into(), "", edit_hint),
        (
            EntryAct::UpdateCert,
            can_edit && e.kind != EntryKind::SecretKey,
            "🔄 替換憑證鏈".into(),
            "同一別名替換憑證 / 憑證鏈（續約、匯入 CA 回覆），替換後自動驗證",
            edit_hint,
        ),
        (
            EntryAct::KeyPass,
            can_edit && is_key && ks.format != StoreFormat::Pkcs12,
            "🔑 改私鑰密碼".into(),
            "",
            key_off,
        ),
        (
            EntryAct::CheckKeyPass,
            is_key,
            "🔍 驗證私鑰密碼".into(),
            "輸入密碼，檢查是否為這把私鑰的 key pass",
            "只有私鑰條目有私鑰密碼",
        ),
        (
            EntryAct::VerifyChain,
            has_chain,
            "✅ 驗證憑證鏈".into(),
            "檢查私鑰相符、順序、簽章、有效期限與根憑證",
            "",
        ),
        (EntryAct::Export, has_chain, "📤 匯出憑證鏈…".into(), "", ""),
        (
            EntryAct::Delete,
            can_edit,
            RichText::new("🗑 刪除").color(RED),
            "",
            edit_hint,
        ),
    ];
    let mut act = None;
    for (a, enabled, label, on, off) in items {
        let mut r = ui.add_enabled(enabled, egui::Button::new(label));
        if enabled && !on.is_empty() {
            r = r.on_hover_text(on);
        } else if !enabled && !off.is_empty() {
            r = r.on_disabled_hover_text(off);
        }
        if r.clicked() {
            act = Some(a);
            if menu {
                ui.close_menu();
            }
        }
    }
    act
}

/// 右鍵選單：顯示某個條目可用的動作；`loc` 為 None 表示這張憑證不是獨立條目。
fn entry_menu(
    ui: &mut egui::Ui,
    stores: &[Keystore],
    loc: Option<(usize, usize)>,
    out: &mut Option<(usize, usize, EntryAct)>,
) {
    match loc.and_then(|(s, e)| Some((s, e, stores.get(s)?, stores.get(s)?.entries.get(e)?))) {
        Some((s, e, ks, entry)) => {
            ui.weak(format!("{} / {}", ks.name(), entry.alias));
            ui.separator();
            if let Some(a) = entry_actions(ui, ks, entry, true) {
                *out = Some((s, e, a));
            }
        }
        None => {
            ui.weak("這張憑證只存在於憑證鏈中，不是獨立的條目");
        }
    }
}

/// 條目清單可排序的欄位。
#[derive(Clone, Copy, PartialEq, Eq)]
enum SortCol {
    File,
    Alias,
    Kind,
    Cn,
    Issuer,
    NotAfter,
    Status,
    Key,
    Matched,
}

/// 關係圖快取鍵：(全部, 所有檔案, 中心條目, 檔案數, 條目數)
type GraphKey = (bool, bool, Option<(usize, usize)>, usize, usize);

/// 大畫面簽發關係圖的狀態。
struct GraphView {
    store: usize,
    /// true＝全部憑證；false＝以目前條目為中心
    whole: bool,
    all_files: bool,
    selected: usize,
    tree: IssuanceTree,
    key: Option<GraphKey>,
    dirty: bool,
    /// 下一個 frame 要捲動到的節點
    scroll: Option<usize>,
}

impl GraphView {
    fn new(store: usize, whole: bool) -> Self {
        GraphView {
            store,
            whole,
            all_files: false,
            selected: 0,
            tree: IssuanceTree {
                nodes: vec![],
                missing_issuer: None,
                truncated: false,
            },
            key: None,
            dirty: true,
            scroll: None,
        }
    }
}
