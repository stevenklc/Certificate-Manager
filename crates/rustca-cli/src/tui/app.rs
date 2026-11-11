//! TUI 狀態與按鍵處理。

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::text::Line;
use ratatui::widgets::TableState;
use ratatui::DefaultTerminal;
use rustca_core::tls::{self, HandshakeReport, RemoteOptions, RemoteTrust, TlsVersion};
use rustca_core::{
    load_file, now_ts, parse_date, search, EntryKind, Integrity, Keystore, LoadOptions,
};

use super::text;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Stores,
    Entries,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum View {
    Main,
    Detail,
    Search,
    Expiry,
    Handshake,
    Help,
}

pub enum InputKind {
    /// 篩選目前憑證庫（輸入時即時套用）
    Filter,
    Open,
    Password(PathBuf),
    Search,
    ExpiryDays,
    /// 存檔：內容為要寫入的文字
    Save(String),
    /// 交握表單的文字欄位
    HsField(usize),
}

pub struct Input {
    pub kind: InputKind,
    pub prompt: String,
    pub value: String,
    pub masked: bool,
}

pub struct Status {
    pub msg: String,
    pub err: bool,
    pub at: Instant,
}

/// 可捲動的文字頁（詳細資料、說明）。
#[derive(Default)]
pub struct TextPage {
    pub title: String,
    pub lines: Vec<Line<'static>>,
    pub scroll: u16,
}

pub struct SearchHitRow {
    pub store: usize,
    pub entry: usize,
    pub alias: String,
    pub cert: String,
    pub fields: String,
}

#[derive(Default)]
pub struct SearchState {
    pub query: String,
    pub hits: Vec<SearchHitRow>,
    pub table: TableState,
}

pub struct ExpiryRow {
    pub store: usize,
    pub entry: usize,
    pub alias: String,
    pub name: String,
    pub not_after: i64,
}

pub struct ExpiryState {
    pub days: i64,
    pub all: bool,
    pub rows: Vec<ExpiryRow>,
    pub table: TableState,
}

/// 交握表單欄位
pub const HS_FIELDS: &[&str] = &[
    "目標",
    "信任庫",
    "Client 身分",
    "Proxy",
    "SNI",
    "TLS 版本",
    "逾時（秒）",
    "模擬時間",
    "",
];
pub const HS_TARGET: usize = 0;
pub const HS_TRUST: usize = 1;
pub const HS_CLIENT: usize = 2;
pub const HS_PROXY: usize = 3;
pub const HS_SNI: usize = 4;
pub const HS_VERSION: usize = 5;
pub const HS_TIMEOUT: usize = 6;
pub const HS_AT: usize = 7;
pub const HS_RUN: usize = 8;

pub struct HsState {
    pub address: String,
    /// 0 系統、1 Mozilla、2 不驗證、3.. 已開啟的憑證庫
    pub trust: usize,
    /// 0 無、其他為 client_options() 的索引 + 1
    pub client: usize,
    pub proxy: String,
    pub sni: String,
    pub version: usize,
    pub timeout: String,
    pub at: String,
    pub field: usize,
    pub running: Option<(Receiver<HandshakeReport>, Instant)>,
    pub report: Option<HandshakeReport>,
    pub scroll: u16,
}

pub struct App {
    pub stores: Vec<Keystore>,
    pub store_sel: usize,
    pub focus: Focus,
    pub entries: TableState,
    pub filter: String,
    /// 目前憑證庫篩選、排序後要顯示的條目索引
    pub visible: Vec<usize>,
    pub sort_expiry: bool,
    pub view: View,
    pub input: Option<Input>,
    pub status: Option<Status>,
    pub page: TextPage,
    /// 詳細頁目前顯示的 (憑證庫, 條目) 與是否附 PEM
    pub detail: Option<(usize, usize, bool)>,
    pub search: SearchState,
    pub expiry: ExpiryState,
    pub hs: HsState,
    pub queue: VecDeque<PathBuf>,
    passwords: Vec<String>,
    pub warn_days: i64,
    pub tick: u64,
    quit: bool,
}

impl App {
    pub fn new(password: Option<String>, warn_days: i64) -> Self {
        App {
            stores: vec![],
            store_sel: 0,
            focus: Focus::Entries,
            entries: TableState::default(),
            filter: String::new(),
            visible: vec![],
            sort_expiry: false,
            view: View::Main,
            input: None,
            status: None,
            page: TextPage::default(),
            detail: None,
            search: SearchState::default(),
            expiry: ExpiryState {
                days: warn_days,
                all: false,
                rows: vec![],
                table: TableState::default(),
            },
            hs: HsState {
                address: String::new(),
                trust: 0,
                client: 0,
                proxy: String::new(),
                sni: String::new(),
                version: 0,
                timeout: "10".into(),
                at: String::new(),
                field: 0,
                running: None,
                report: None,
                scroll: 0,
            },
            queue: VecDeque::new(),
            passwords: password.into_iter().collect(),
            warn_days,
            tick: 0,
            quit: false,
        }
    }

    pub fn info(&mut self, msg: impl Into<String>) {
        self.status = Some(Status {
            msg: msg.into(),
            err: false,
            at: Instant::now(),
        });
    }

    pub fn error(&mut self, msg: impl Into<String>) {
        self.status = Some(Status {
            msg: msg.into(),
            err: true,
            at: Instant::now(),
        });
    }

    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        self.process_queue();
        while !self.quit {
            self.poll_handshake();
            terminal.draw(|f| super::ui::draw(f, self))?;
            if event::poll(Duration::from_millis(200))? {
                match event::read()? {
                    // Windows 會同時送出按下與放開事件，只處理按下
                    Event::Key(k) if k.kind != KeyEventKind::Release => self.on_key(k),
                    _ => {}
                }
            }
            self.tick = self.tick.wrapping_add(1);
        }
        Ok(())
    }

    // ───────────── 開啟檔案 ─────────────

    /// 依序開啟佇列中的檔案；需要密碼時跳出輸入框並暫停。
    pub fn process_queue(&mut self) {
        while let Some(path) = self.queue.pop_front() {
            match self.try_open(&path) {
                Ok(ks) => self.add_store(ks),
                Err(e) if e.is_password_problem() => {
                    self.ask_password(path, false);
                    return;
                }
                Err(e) => self.error(format!("無法開啟 {}：{e}", path.display())),
            }
        }
    }

    /// 依序嘗試：使用者給過的密碼 → changeit（Java 預設）→ 不帶密碼（只讀憑證、不驗證完整性）。
    fn try_open(&self, path: &PathBuf) -> rustca_core::Result<Keystore> {
        let mut cands: Vec<Option<String>> = self.passwords.iter().cloned().map(Some).collect();
        if !self.passwords.iter().any(|p| p == "changeit") {
            cands.push(Some("changeit".into()));
        }
        cands.push(None);
        let mut last = None;
        for pw in cands {
            match load_file(
                path,
                &LoadOptions {
                    password: pw,
                    key_password: None,
                },
            ) {
                Ok(ks) => return Ok(ks),
                Err(e) if e.is_password_problem() => last = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap_or_else(|| rustca_core::Error::NeedPassword(path.display().to_string())))
    }

    fn ask_password(&mut self, path: PathBuf, retry: bool) {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        self.input = Some(Input {
            prompt: if retry {
                format!("密碼錯誤，請重新輸入 {name} 的密碼（Esc 略過）")
            } else {
                format!("{name} 的密碼（Esc 略過）")
            },
            kind: InputKind::Password(path),
            value: String::new(),
            masked: true,
        });
    }

    fn open_with_password(&mut self, path: PathBuf, pw: String) {
        match load_file(
            &path,
            &LoadOptions {
                password: Some(pw.clone()),
                key_password: None,
            },
        ) {
            Ok(ks) => {
                if !self.passwords.contains(&pw) {
                    self.passwords.push(pw);
                }
                self.add_store(ks);
                self.process_queue();
            }
            Err(e) if e.is_password_problem() => {
                let _ = e;
                self.ask_password(path, true);
            }
            Err(e) => {
                self.error(format!("無法開啟 {}：{e}", path.display()));
                self.process_queue();
            }
        }
    }

    fn add_store(&mut self, ks: Keystore) {
        let mut msg = format!("已開啟 {}（{}，{} 筆）", ks.name(), ks.format, ks.entries.len());
        if ks.integrity == Integrity::NotChecked {
            msg.push_str("；未驗證完整性（未提供正確密碼），私鑰無法使用，可按 P 輸入密碼");
        }
        // 同一個檔案重新開啟時取代原本的
        if let Some(i) = self.stores.iter().position(|s| s.path == ks.path) {
            self.stores[i] = ks;
            self.store_sel = i;
        } else {
            self.stores.push(ks);
            self.store_sel = self.stores.len() - 1;
        }
        self.filter.clear();
        self.refresh_visible();
        self.entries.select(if self.visible.is_empty() { None } else { Some(0) });
        self.info(msg);
    }

    // ───────────── 清單 ─────────────

    pub fn current(&self) -> Option<&Keystore> {
        self.stores.get(self.store_sel)
    }

    pub fn refresh_visible(&mut self) {
        let Some(ks) = self.stores.get(self.store_sel) else {
            self.visible.clear();
            return;
        };
        let mut v: Vec<usize> = if self.filter.trim().is_empty() {
            (0..ks.entries.len()).collect()
        } else {
            let mut idx: Vec<usize> = search(ks, &self.filter)
                .into_iter()
                .map(|h| h.entry_index)
                .collect();
            idx.dedup();
            idx
        };
        if self.sort_expiry {
            v.sort_by_key(|&i| {
                ks.entries[i]
                    .leaf()
                    .map(|c| c.not_after)
                    .unwrap_or(i64::MAX)
            });
        }
        self.visible = v;
        let sel = self.entries.selected().unwrap_or(0);
        self.entries.select(if self.visible.is_empty() {
            None
        } else {
            Some(sel.min(self.visible.len() - 1))
        });
    }

    pub fn selected_entry(&self) -> Option<usize> {
        self.entries.selected().and_then(|i| self.visible.get(i).copied())
    }

    fn select_store(&mut self, i: usize) {
        if i < self.stores.len() && i != self.store_sel {
            self.store_sel = i;
            self.filter.clear();
            self.entries.select(Some(0));
            self.refresh_visible();
        }
    }

    fn jump_to(&mut self, store: usize, entry: usize) {
        if store >= self.stores.len() {
            return;
        }
        self.store_sel = store;
        self.filter.clear();
        self.refresh_visible();
        let pos = self.visible.iter().position(|&e| e == entry);
        self.entries.select(pos.or(Some(0)));
        self.focus = Focus::Entries;
        self.view = View::Main;
    }

    // ───────────── 按鍵 ─────────────

    fn on_key(&mut self, k: KeyEvent) {
        if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        if self.input.is_some() {
            self.on_input_key(k);
            return;
        }
        match self.view {
            View::Main => self.on_main_key(k),
            View::Detail | View::Help => self.on_page_key(k),
            View::Search => self.on_search_key(k),
            View::Expiry => self.on_expiry_key(k),
            View::Handshake => self.on_hs_key(k),
        }
    }

    fn start_input(&mut self, kind: InputKind, prompt: impl Into<String>, value: String) {
        self.input = Some(Input {
            kind,
            prompt: prompt.into(),
            value,
            masked: false,
        });
    }

    fn on_input_key(&mut self, k: KeyEvent) {
        let Some(input) = self.input.as_mut() else {
            return;
        };
        match k.code {
            KeyCode::Esc => {
                let input = self.input.take().expect("input");
                match input.kind {
                    InputKind::Filter => {
                        self.filter.clear();
                        self.refresh_visible();
                    }
                    InputKind::Password(p) => {
                        self.info(format!("已略過 {}", p.display()));
                        self.process_queue();
                    }
                    _ => {}
                }
            }
            KeyCode::Enter => {
                let input = self.input.take().expect("input");
                self.submit_input(input);
            }
            KeyCode::Backspace => {
                input.value.pop();
                if matches!(input.kind, InputKind::Filter) {
                    self.filter = input.value.clone();
                    self.refresh_visible();
                }
            }
            KeyCode::Tab if matches!(input.kind, InputKind::Open | InputKind::Save(_)) => {
                input.value = complete_path(&input.value);
            }
            KeyCode::Char(c) => {
                if k.modifiers.contains(KeyModifiers::CONTROL) {
                    if c == 'u' {
                        input.value.clear();
                    }
                } else {
                    input.value.push(c);
                }
                if matches!(input.kind, InputKind::Filter) {
                    self.filter = input.value.clone();
                    self.refresh_visible();
                }
            }
            _ => {}
        }
    }

    fn submit_input(&mut self, input: Input) {
        let v = input.value.trim().to_string();
        match input.kind {
            InputKind::Filter => {
                self.filter = v;
                self.refresh_visible();
            }
            InputKind::Open => {
                if v.is_empty() {
                    return;
                }
                let p = PathBuf::from(expand_home(&v));
                if p.is_dir() {
                    let mut found = super::expand_dir(&p);
                    found.sort();
                    if found.is_empty() {
                        self.error(format!("目錄 {} 中沒有憑證庫檔案", p.display()));
                    }
                    self.queue.extend(found);
                } else {
                    self.queue.push_back(p);
                }
                self.process_queue();
            }
            InputKind::Password(p) => self.open_with_password(p, input.value),
            InputKind::Search => {
                self.search.query = v;
                self.run_search();
                self.view = View::Search;
            }
            InputKind::ExpiryDays => match v.parse::<i64>() {
                Ok(d) if d >= 0 => {
                    self.expiry.days = d;
                    self.refresh_expiry();
                }
                _ => self.error("請輸入 0 以上的天數"),
            },
            InputKind::Save(content) => {
                if v.is_empty() {
                    return;
                }
                let path = expand_home(&v);
                match std::fs::write(&path, content) {
                    Ok(()) => self.info(format!("已儲存：{path}")),
                    Err(e) => self.error(format!("寫入 {path} 失敗：{e}")),
                }
            }
            InputKind::HsField(f) => {
                let target = match f {
                    HS_TARGET => &mut self.hs.address,
                    HS_PROXY => &mut self.hs.proxy,
                    HS_SNI => &mut self.hs.sni,
                    HS_TIMEOUT => &mut self.hs.timeout,
                    HS_AT => &mut self.hs.at,
                    _ => return,
                };
                *target = v;
                // 填完目標直接跳到開始交握
                if f == HS_TARGET && !self.hs.address.is_empty() {
                    self.hs.field = HS_RUN;
                }
            }
        }
    }

    fn on_main_key(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Esc => {
                if !self.filter.is_empty() {
                    self.filter.clear();
                    self.refresh_visible();
                }
            }
            KeyCode::Tab | KeyCode::BackTab => {
                self.focus = match self.focus {
                    Focus::Stores => Focus::Entries,
                    Focus::Entries => Focus::Stores,
                }
            }
            KeyCode::Left => self.focus = Focus::Stores,
            KeyCode::Right => self.focus = Focus::Entries,
            KeyCode::Up | KeyCode::Char('k') => self.move_sel(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_sel(1),
            KeyCode::PageUp => self.move_sel(-10),
            KeyCode::PageDown => self.move_sel(10),
            KeyCode::Home | KeyCode::Char('g') => self.move_sel(i32::MIN / 2),
            KeyCode::End | KeyCode::Char('G') => self.move_sel(i32::MAX / 2),
            KeyCode::Enter => match self.focus {
                Focus::Stores => self.focus = Focus::Entries,
                Focus::Entries => self.open_detail(),
            },
            KeyCode::Char('/') => {
                if self.current().is_some() {
                    let v = self.filter.clone();
                    self.start_input(InputKind::Filter, "篩選", v);
                }
            }
            KeyCode::Char('s') => {
                let v = self.search.query.clone();
                self.start_input(InputKind::Search, "搜尋全部檔案", v);
            }
            KeyCode::Char('e') => {
                self.refresh_expiry();
                self.view = View::Expiry;
            }
            KeyCode::Char('h') => self.enter_handshake(),
            KeyCode::Char('o') => {
                let cwd = std::env::current_dir()
                    .map(|p| format!("{}/", p.display()))
                    .unwrap_or_default();
                self.start_input(InputKind::Open, "開啟檔案或目錄（Tab 補齊）", cwd);
            }
            KeyCode::Char('r') => self.reload_current(),
            KeyCode::Char('P') => {
                if let Some(ks) = self.current() {
                    let p = ks.path.clone();
                    self.ask_password(p, false);
                }
            }
            KeyCode::Char('x') => {
                if self.store_sel < self.stores.len() {
                    let ks = self.stores.remove(self.store_sel);
                    self.store_sel = self.store_sel.min(self.stores.len().saturating_sub(1));
                    self.hs.trust = 0;
                    self.hs.client = 0;
                    self.filter.clear();
                    self.refresh_visible();
                    self.info(format!("已關閉 {}", ks.name()));
                }
            }
            KeyCode::Char('t') => {
                self.sort_expiry = !self.sort_expiry;
                self.refresh_visible();
                self.info(if self.sort_expiry {
                    "依到期日排序"
                } else {
                    "依檔案順序排列"
                });
            }
            KeyCode::Char('?') => self.open_help(),
            _ => {}
        }
    }

    fn move_sel(&mut self, d: i32) {
        match self.focus {
            Focus::Stores => {
                if self.stores.is_empty() {
                    return;
                }
                let n = self.stores.len() as i64;
                let i = (self.store_sel as i64 + d as i64).clamp(0, n - 1) as usize;
                self.select_store(i);
            }
            Focus::Entries => move_table(&mut self.entries, self.visible.len(), d),
        }
    }

    fn reload_current(&mut self) {
        let Some(ks) = self.current() else {
            return;
        };
        let path = ks.path.clone();
        let pw = ks.store_password.as_ref().map(|s| s.expose().to_string());
        let sel = self.entries.selected();
        match load_file(
            &path,
            &LoadOptions {
                password: pw,
                key_password: None,
            },
        ) {
            Ok(ks) => {
                self.stores[self.store_sel] = ks;
                self.refresh_visible();
                self.entries.select(sel);
                self.refresh_visible();
                self.info(format!("已重新載入 {}", path.display()));
            }
            Err(e) => self.error(format!("重新載入失敗：{e}")),
        }
    }

    // ───────────── 文字頁（詳細、說明） ─────────────

    fn open_detail(&mut self) {
        if let Some(e) = self.selected_entry() {
            self.detail = Some((self.store_sel, e, false));
            self.rebuild_detail();
            self.page.scroll = 0;
            self.view = View::Detail;
        }
    }

    fn rebuild_detail(&mut self) {
        let Some((s, e, pem)) = self.detail else {
            return;
        };
        let Some(ks) = self.stores.get(s) else {
            return;
        };
        let Some(entry) = ks.entries.get(e) else {
            return;
        };
        let pool: Vec<_> = self.stores.iter().flat_map(|k| k.all_certs()).collect();
        self.page.title = format!("{} / {}", ks.name(), entry.alias);
        self.page.lines = text::entry_detail(ks, entry, &pool, now_ts(), self.warn_days, pem);
    }

    fn open_help(&mut self) {
        self.detail = None;
        self.page.title = "說明".into();
        self.page.lines = text::help();
        self.page.scroll = 0;
        self.view = View::Help;
    }

    fn on_page_key(&mut self, k: KeyEvent) {
        let max = self.page.lines.len().saturating_sub(1) as u16;
        match k.code {
            KeyCode::Esc | KeyCode::Char('q') => self.view = View::Main,
            KeyCode::Up | KeyCode::Char('k') => self.page.scroll = self.page.scroll.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => self.page.scroll = (self.page.scroll + 1).min(max),
            KeyCode::PageUp => self.page.scroll = self.page.scroll.saturating_sub(15),
            KeyCode::PageDown | KeyCode::Char(' ') => {
                self.page.scroll = (self.page.scroll + 15).min(max)
            }
            KeyCode::Home | KeyCode::Char('g') => self.page.scroll = 0,
            KeyCode::End | KeyCode::Char('G') => self.page.scroll = max,
            KeyCode::Char('p') if self.view == View::Detail => {
                if let Some(d) = self.detail.as_mut() {
                    d.2 = !d.2;
                }
                self.rebuild_detail();
            }
            KeyCode::Char('n') | KeyCode::Char('N') if self.view == View::Detail => {
                let d = if k.code == KeyCode::Char('n') { 1 } else { -1 };
                move_table(&mut self.entries, self.visible.len(), d);
                if let (Some(e), Some(det)) = (self.selected_entry(), self.detail.as_mut()) {
                    det.1 = e;
                }
                self.rebuild_detail();
                self.page.scroll = 0;
            }
            KeyCode::Char('w') => {
                let content = text::plain(&self.page.lines);
                let name = format!("{}.txt", sanitize(&self.page.title));
                self.start_input(InputKind::Save(content), "存成文字檔（Tab 補齊）", name);
            }
            _ => {}
        }
    }

    // ───────────── 搜尋 ─────────────

    fn run_search(&mut self) {
        self.search.hits.clear();
        let q = self.search.query.clone();
        for (si, ks) in self.stores.iter().enumerate() {
            for h in search(ks, &q) {
                self.search.hits.push(SearchHitRow {
                    store: si,
                    entry: h.entry_index,
                    alias: h.alias,
                    cert: h.cert_name.unwrap_or_default(),
                    fields: h
                        .matches
                        .iter()
                        .map(|m| format!("{}：{}", m.field, m.value))
                        .collect::<Vec<_>>()
                        .join("  "),
                });
            }
        }
        self.search.table.select(if self.search.hits.is_empty() {
            None
        } else {
            Some(0)
        });
    }

    fn on_search_key(&mut self, k: KeyEvent) {
        let n = self.search.hits.len();
        match k.code {
            KeyCode::Esc | KeyCode::Char('q') => self.view = View::Main,
            KeyCode::Up | KeyCode::Char('k') => move_table(&mut self.search.table, n, -1),
            KeyCode::Down | KeyCode::Char('j') => move_table(&mut self.search.table, n, 1),
            KeyCode::PageUp => move_table(&mut self.search.table, n, -10),
            KeyCode::PageDown => move_table(&mut self.search.table, n, 10),
            KeyCode::Char('s') | KeyCode::Char('/') => {
                let v = self.search.query.clone();
                self.start_input(InputKind::Search, "搜尋全部檔案", v);
            }
            KeyCode::Enter => {
                if let Some(h) = self.search.table.selected().and_then(|i| self.search.hits.get(i)) {
                    let (s, e) = (h.store, h.entry);
                    self.jump_to(s, e);
                }
            }
            _ => {}
        }
    }

    // ───────────── 到期檢查 ─────────────

    fn refresh_expiry(&mut self) {
        let now = now_ts();
        let limit = now + self.expiry.days * 86400;
        let mut rows = vec![];
        for (si, ks) in self.stores.iter().enumerate() {
            for (ei, e) in ks.entries.iter().enumerate() {
                for c in &e.chain {
                    if self.expiry.all || c.not_after <= limit || now < c.not_before {
                        rows.push(ExpiryRow {
                            store: si,
                            entry: ei,
                            alias: e.alias.clone(),
                            name: c.display_name(),
                            not_after: c.not_after,
                        });
                    }
                }
            }
        }
        rows.sort_by_key(|r| r.not_after);
        self.expiry.rows = rows;
        let n = self.expiry.rows.len();
        self.expiry.table.select(if n == 0 { None } else { Some(0) });
    }

    fn on_expiry_key(&mut self, k: KeyEvent) {
        let n = self.expiry.rows.len();
        match k.code {
            KeyCode::Esc | KeyCode::Char('q') => self.view = View::Main,
            KeyCode::Up | KeyCode::Char('k') => move_table(&mut self.expiry.table, n, -1),
            KeyCode::Down | KeyCode::Char('j') => move_table(&mut self.expiry.table, n, 1),
            KeyCode::PageUp => move_table(&mut self.expiry.table, n, -10),
            KeyCode::PageDown => move_table(&mut self.expiry.table, n, 10),
            KeyCode::Char('a') => {
                self.expiry.all = !self.expiry.all;
                self.refresh_expiry();
            }
            KeyCode::Char('d') => {
                let v = self.expiry.days.to_string();
                self.start_input(InputKind::ExpiryDays, "幾天內到期", v);
            }
            KeyCode::Char('w') => {
                let content = text::plain(&text::expiry_lines(self));
                self.start_input(InputKind::Save(content), "存成文字檔", "expiry.txt".into());
            }
            KeyCode::Enter => {
                if let Some(r) = self.expiry.table.selected().and_then(|i| self.expiry.rows.get(i)) {
                    let (s, e) = (r.store, r.entry);
                    self.jump_to(s, e);
                }
            }
            _ => {}
        }
    }

    // ───────────── 交握 ─────────────

    /// 可選的信任庫：系統、Mozilla、不驗證，以及已開啟的檔案。
    pub fn trust_options(&self) -> Vec<String> {
        let mut v = vec![
            "作業系統憑證庫".to_string(),
            "Mozilla 根憑證".to_string(),
            "不驗證（只看憑證鏈）".to_string(),
        ];
        v.extend(self.stores.iter().map(|s| s.name()));
        v
    }

    /// 可作為 Client 身分的憑證庫（含私鑰）。
    pub fn client_options(&self) -> Vec<usize> {
        self.stores
            .iter()
            .enumerate()
            .filter(|(_, s)| s.private_key_entries().next().is_some())
            .map(|(i, _)| i)
            .collect()
    }

    fn enter_handshake(&mut self) {
        // 目前選的是純信任庫時，預設拿它來驗證
        if self.hs.trust == 0 {
            if let Some(ks) = self.current() {
                let trust_only = ks.private_key_entries().next().is_none()
                    && ks.entries.iter().any(|e| e.kind == EntryKind::TrustedCert);
                if trust_only {
                    self.hs.trust = 3 + self.store_sel;
                }
            }
        }
        self.view = View::Handshake;
        if self.hs.address.is_empty() {
            self.hs.field = HS_TARGET;
        }
    }

    fn cycle_hs(&mut self, d: i32) {
        let cyc = |v: usize, n: usize| ((v as i64 + d as i64).rem_euclid(n as i64)) as usize;
        match self.hs.field {
            HS_TRUST => self.hs.trust = cyc(self.hs.trust, self.trust_options().len()),
            HS_CLIENT => self.hs.client = cyc(self.hs.client, self.client_options().len() + 1),
            HS_VERSION => self.hs.version = cyc(self.hs.version, 3),
            _ => {}
        }
    }

    fn on_hs_key(&mut self, k: KeyEvent) {
        let n = HS_FIELDS.len();
        let max_scroll = self
            .hs
            .report
            .as_ref()
            .map(|r| r.to_text(false).lines().count().saturating_sub(1) as u16)
            .unwrap_or(0);
        match k.code {
            KeyCode::Esc | KeyCode::Char('q') => self.view = View::Main,
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                self.hs.field = (self.hs.field + n - 1) % n
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                self.hs.field = (self.hs.field + 1) % n
            }
            KeyCode::Left => self.cycle_hs(-1),
            KeyCode::Right | KeyCode::Char(' ') => self.cycle_hs(1),
            KeyCode::PageUp => self.hs.scroll = self.hs.scroll.saturating_sub(10),
            KeyCode::PageDown => self.hs.scroll = (self.hs.scroll + 10).min(max_scroll),
            KeyCode::Char('r') => self.start_handshake(),
            KeyCode::Char('w') | KeyCode::Char('W') => {
                if let Some(r) = &self.hs.report {
                    let content = r.to_text(k.code == KeyCode::Char('W'));
                    let host = tls::parse_target(&self.hs.address)
                        .map(|t| t.host)
                        .unwrap_or_else(|_| "handshake".into());
                    let name = format!("handshake-{}.txt", sanitize(&host));
                    self.start_input(InputKind::Save(content), "存成文字檔（Tab 補齊）", name);
                }
            }
            KeyCode::Enter => match self.hs.field {
                HS_RUN => self.start_handshake(),
                HS_TRUST | HS_CLIENT | HS_VERSION => self.cycle_hs(1),
                f => {
                    let cur = match f {
                        HS_TARGET => self.hs.address.clone(),
                        HS_PROXY => self.hs.proxy.clone(),
                        HS_SNI => self.hs.sni.clone(),
                        HS_TIMEOUT => self.hs.timeout.clone(),
                        HS_AT => self.hs.at.clone(),
                        _ => String::new(),
                    };
                    let prompt = match f {
                        HS_TARGET => "目標（host[:port] 或 https://host/path）",
                        HS_PROXY => "Proxy（http://[user:pass@]host:port；留空＝自動偵測，none＝不使用）",
                        HS_SNI => "SNI / 主機名稱（留空＝自動）",
                        HS_TIMEOUT => "逾時秒數",
                        HS_AT => "模擬時間 YYYY-MM-DD（留空＝現在）",
                        _ => "",
                    };
                    self.start_input(InputKind::HsField(f), prompt, cur);
                }
            },
            _ => {}
        }
    }

    /// Proxy 欄位實際會使用的值與來源說明（顯示用，不含帳密）。
    pub fn effective_proxy(&self) -> (Option<String>, String) {
        let p = self.hs.proxy.trim();
        if p.eq_ignore_ascii_case("none") || p == "-" {
            return (None, "不使用 proxy".into());
        }
        if !p.is_empty() {
            return (Some(p.to_string()), "手動指定".into());
        }
        let host = tls::parse_target(&self.hs.address).map(|t| t.host).ok();
        match host.as_deref().and_then(tls::auto_proxy) {
            Some((url, src)) => (Some(url), format!("自動：{src}")),
            None => (None, "自動：無（直連）".into()),
        }
    }

    fn start_handshake(&mut self) {
        if self.hs.running.is_some() {
            return;
        }
        let address = self.hs.address.trim().to_string();
        if address.is_empty() {
            self.hs.field = HS_TARGET;
            self.error("請先填寫目標");
            return;
        }
        let target = match tls::parse_target(&address) {
            Ok(t) => t,
            Err(e) => return self.error(e),
        };
        let trust = match self.hs.trust {
            0 => RemoteTrust::System,
            1 => RemoteTrust::Mozilla,
            2 => RemoteTrust::Insecure,
            n => match self.stores.get(n - 3) {
                Some(ks) => RemoteTrust::Certs(tls::trust_from_keystores(&[ks])),
                None => RemoteTrust::System,
            },
        };
        let client = match self.client_options().get(self.hs.client.wrapping_sub(1)) {
            Some(&i) if self.hs.client > 0 => {
                match tls::identity_from_keystore(&self.stores[i], None) {
                    Ok(id) => Some(id),
                    Err(e) => {
                        return self.error(format!(
                            "{} 無法作為 Client 身分：{e}（私鑰未解密時請按 P 輸入密碼）",
                            self.stores[i].name()
                        ))
                    }
                }
            }
            _ => None,
        };
        let at = if self.hs.at.trim().is_empty() {
            None
        } else {
            match parse_date(self.hs.at.trim()) {
                Ok(t) => Some(t),
                Err(e) => return self.error(format!("模擬時間格式錯誤：{e}")),
            }
        };
        let timeout = self.hs.timeout.trim().parse::<u64>().unwrap_or(10).max(1);
        let version = match self.hs.version {
            1 => TlsVersion::Tls12,
            2 => TlsVersion::Tls13,
            _ => TlsVersion::Auto,
        };
        let sni = Some(self.hs.sni.trim().to_string()).filter(|s| !s.is_empty());
        let http = target.path.map(|path| tls::HttpRequest {
            method: "GET".into(),
            path,
            headers: vec![],
            body: vec![],
        });
        let opts = RemoteOptions {
            address,
            server_name: sni,
            version,
            at,
            timeout: Duration::from_secs(timeout),
            trust,
            proxy: self.effective_proxy().0,
            http,
        };
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let r = tls::connect_remote(&opts, client.as_ref());
            let _ = tx.send(r);
        });
        self.hs.running = Some((rx, Instant::now()));
        self.hs.report = None;
        self.hs.scroll = 0;
    }

    fn poll_handshake(&mut self) {
        let Some((rx, _)) = &self.hs.running else {
            return;
        };
        match rx.try_recv() {
            Ok(r) => {
                self.hs.running = None;
                let ok = r.success;
                self.hs.report = Some(r);
                self.hs.scroll = 0;
                if ok {
                    self.info("交握成功");
                } else {
                    self.error("交握失敗，詳見下方結果");
                }
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                self.hs.running = None;
                self.error("交握執行緒異常結束");
            }
        }
    }
}

fn move_table(t: &mut TableState, n: usize, d: i32) {
    if n == 0 {
        t.select(None);
        return;
    }
    let cur = t.selected().unwrap_or(0) as i64;
    let next = (cur + d as i64).clamp(0, n as i64 - 1);
    t.select(Some(next as usize));
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || "-_.".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn expand_home(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return format!("{}/{rest}", PathBuf::from(home).display());
        }
    }
    p.to_string()
}

/// 路徑 Tab 補齊：補到所有候選的共同前綴；唯一候選是目錄時加上分隔符號。
fn complete_path(input: &str) -> String {
    let expanded = expand_home(input);
    let sep_pos = expanded.rfind(['/', '\\']);
    let (dir, prefix) = match sep_pos {
        Some(i) => (&expanded[..=i], &expanded[i + 1..]),
        None => ("", expanded.as_str()),
    };
    let read_dir = if dir.is_empty() { "." } else { dir };
    let Ok(rd) = std::fs::read_dir(read_dir) else {
        return input.to_string();
    };
    let mut names: Vec<(String, bool)> = rd
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.starts_with(prefix)
                .then(|| (n, e.path().is_dir()))
        })
        .collect();
    if names.is_empty() {
        return input.to_string();
    }
    names.sort();
    let mut common = names[0].0.clone();
    for (n, _) in &names[1..] {
        while !n.starts_with(&common) {
            common.pop();
        }
    }
    let mut out = format!("{dir}{common}");
    if names.len() == 1 && names[0].1 {
        out.push(std::path::MAIN_SEPARATOR);
    }
    out
}
