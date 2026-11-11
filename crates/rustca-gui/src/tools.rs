//! 結果視窗：憑證鏈驗證、Java 相容性測試。

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use eframe::egui::{self, RichText};
use rustca_core::edit::{CheckLevel, Verification, WriteOptions};
use rustca_core::javacompat::{self, JavaRuntime, JavaTestReport, TestSource};
use rustca_core::role::{check_role, RoleReport, StoreRole};
use rustca_core::{Keystore, StoreFormat};

use crate::widgets::{GREEN, RED, YELLOW};

/// 視窗可用的最大高度：保留空間給標題列與底部按鈕，避免視窗超出畫面而關不掉。
pub fn max_window_height(ctx: &egui::Context) -> f32 {
    (ctx.screen_rect().height() - 60.0).max(200.0)
}

/// 視窗可用的最大寬度。
pub fn max_window_width(ctx: &egui::Context) -> f32 {
    (ctx.screen_rect().width() - 40.0).max(240.0)
}

/// 底部的「關閉」按鈕（也接受 Esc）；回傳 true 表示要關閉。
pub fn close_button(ui: &mut egui::Ui) -> bool {
    ui.separator();
    ui.horizontal(|ui| ui.button("關閉").clicked()).inner
        || ui.input(|i| i.key_pressed(egui::Key::Escape))
}

/// 顯示驗證結果；回傳 false 表示使用者關閉視窗。
pub fn verify_window(ctx: &egui::Context, v: &Verification) -> bool {
    let mut open = true;
    let mut close = false;
    let max_h = max_window_height(ctx);
    egui::Window::new(format!("✅ 憑證鏈驗證：{}", v.alias))
        .open(&mut open)
        .collapsible(false)
        .resizable(true)
        .default_width(560.0)
        .max_height(max_h)
        .max_width(max_window_width(ctx))
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .max_height(max_h - 90.0)
                .show(ui, |ui| verification_ui(ui, v));
            close = close_button(ui);
        });
    open && !close
}

pub fn verification_ui(ui: &mut egui::Ui, v: &Verification) {
    for c in &v.checks {
        let (icon, color) = match c.level {
            CheckLevel::Ok => ("✔", GREEN),
            CheckLevel::Warn => ("⚠", YELLOW),
            CheckLevel::Error => ("✘", RED),
        };
        ui.add(
            egui::Label::new(RichText::new(format!("{icon} {}", c.message)).color(color)).wrap(),
        );
    }
    ui.add_space(4.0);
    if v.ok {
        ui.label(RichText::new("驗證通過").color(GREEN).strong());
    } else {
        ui.label(RichText::new("驗證失敗").color(RED).strong());
    }
}

type Outcome = Result<(Vec<JavaRuntime>, JavaTestReport), String>;

/// Java 相容性測試視窗。
pub struct JavaTest {
    ks: Keystore,
    /// 沒有未儲存變更時直接測原檔
    file: Option<PathBuf>,
    extra: Vec<PathBuf>,
    legacy: bool,
    running: Option<Arc<Mutex<Option<Outcome>>>>,
    result: Option<Outcome>,
}

impl JavaTest {
    pub fn new(ks: Keystore, dirty: bool) -> Self {
        let file = (!dirty && ks.path.is_file()).then(|| ks.path.clone());
        JavaTest {
            ks,
            file,
            extra: vec![],
            legacy: false,
            running: None,
            result: None,
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.is_some()
    }

    pub fn start(&mut self, ctx: &egui::Context) {
        let shared: Arc<Mutex<Option<Outcome>>> = Arc::new(Mutex::new(None));
        let out = shared.clone();
        let ks = self.ks.clone();
        let extra = self.extra.clone();
        let opts = WriteOptions {
            pkcs12_legacy: self.legacy,
        };
        // 勾選「舊版相容」時一律重新寫出；否則有原檔就測原檔
        let file = if self.legacy { None } else { self.file.clone() };
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let runtimes = javacompat::discover(&extra);
            let source = match &file {
                Some(f) => TestSource::File(f),
                None => TestSource::Serialize(opts),
            };
            let r = javacompat::test_keystore(&runtimes, &ks, source)
                .map(|rep| (runtimes, rep))
                .map_err(|e| e.to_string());
            if let Ok(mut g) = out.lock() {
                *g = Some(r);
            }
            ctx.request_repaint();
        });
        self.running = Some(shared);
        self.result = None;
    }

    fn poll(&mut self) {
        let done = self
            .running
            .as_ref()
            .and_then(|r| r.lock().ok().and_then(|mut g| g.take()));
        if let Some(r) = done {
            self.result = Some(r);
            self.running = None;
        }
    }

    /// 回傳 false 表示使用者關閉視窗。
    pub fn ui(&mut self, ctx: &egui::Context) -> bool {
        self.poll();
        let mut open = true;
        let mut close = false;
        let mut rerun = false;
        let max_h = max_window_height(ctx);
        egui::Window::new(format!("☕ Java 相容性測試：{}", self.ks.name()))
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_width(680.0)
            .default_height(480.0)
            .max_height(max_h)
            .max_width(max_window_width(ctx))
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(match &self.file {
                    Some(f) if !self.legacy => format!("測試檔案：{}", f.display()),
                    _ => "測試目前內容（含尚未儲存的變更，寫出暫存檔後測試）".into(),
                });
                ui.weak("以每個 Java 版本的 keytool 執行 -list 讀取所有條目，並以 -certreq 確認各私鑰都能解開");
                ui.horizontal_wrapped(|ui| {
                    if ui.button("📂 加入 JDK 目錄…").clicked() {
                        if let Some(d) = rfd::FileDialog::new().pick_folder() {
                            self.extra.push(d);
                            rerun = true;
                        }
                    }
                    if self.ks.format == StoreFormat::Pkcs12
                        && ui
                            .checkbox(&mut self.legacy, "以舊版相容 PKCS#12 寫出後測試")
                            .changed()
                    {
                        rerun = true;
                    }
                    if ui
                        .add_enabled(self.running.is_none(), egui::Button::new("🔄 重新測試"))
                        .clicked()
                    {
                        rerun = true;
                    }
                });
                for d in &self.extra {
                    ui.weak(format!("額外目錄：{}", d.display()));
                }
                ui.separator();
                if self.running.is_some() {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("搜尋 Java 並測試中…");
                    });
                    close = close_button(ui);
                    return;
                }
                // 結果與提示全部放進捲動區，底部的「關閉」永遠看得到
                egui::ScrollArea::vertical()
                    .max_height((max_h - 190.0).max(120.0))
                    .auto_shrink([false, true])
                    .show(ui, |ui| match &self.result {
                    None => {}
                    Some(Err(e)) => {
                        ui.colored_label(RED, format!("✘ {e}"));
                        ui.weak("可設定 JAVA_HOME / RUST_CA_JAVA_HOMES 環境變數，或按「加入 JDK 目錄」");
                    }
                    Some(Ok((runtimes, rep))) => {
                        ui.label(format!("找到 {} 個 Java 版本", runtimes.len()));
                        {
                            egui::Grid::new("java_results")
                                .num_columns(3)
                                .striped(true)
                                .spacing([12.0, 6.0])
                                .show(ui, |ui| {
                                    ui.strong("Java");
                                    ui.strong("結果");
                                    ui.strong("私鑰");
                                    ui.end_row();
                                    for r in &rep.results {
                                        ui.label(&r.java).on_hover_text(r.home.display().to_string());
                                        if r.ok {
                                            ui.colored_label(GREEN, format!("✔ {}", r.message));
                                        } else {
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(format!("✘ {}", r.message)).color(RED),
                                                )
                                                .wrap(),
                                            );
                                        }
                                        ui.vertical(|ui| {
                                            for (a, ok, m) in &r.keys {
                                                let c = if *ok { GREEN } else { RED };
                                                ui.add(
                                                    egui::Label::new(
                                                        RichText::new(format!("{a}：{m}")).color(c),
                                                    )
                                                    .wrap(),
                                                );
                                            }
                                        });
                                        ui.end_row();
                                    }
                                });
                        }
                        ui.add_space(4.0);
                        if rep.ok {
                            ui.label(RichText::new("✔ 所有 Java 版本都能使用").color(GREEN).strong());
                        } else {
                            ui.label(RichText::new("✘ 部分 Java 版本無法使用").color(RED).strong());
                        }
                        if !rep.notes.is_empty() {
                            ui.add_space(4.0);
                            egui::CollapsingHeader::new(format!("ℹ 注意事項（{} 項）", rep.notes.len()))
                                .default_open(rep.notes.len() <= 5)
                                .show(ui, |ui| {
                                    for n in &rep.notes {
                                        ui.add(egui::Label::new(format!("ℹ {n}")).wrap());
                                    }
                                });
                        }
                    }
                });
                close = close_button(ui);
            });
        if rerun && self.running.is_none() {
            self.start(ctx);
        }
        open && !close
    }
}

/// 用途檢查視窗：Server keystore / Client keystore / Truststore。
pub struct RoleCheck {
    ks: Keystore,
    role: StoreRole,
    host: String,
    report: Option<RoleReport>,
}

impl RoleCheck {
    pub fn new(ks: Keystore) -> Self {
        let role = StoreRole::guess(&ks);
        let mut r = RoleCheck {
            ks,
            role,
            host: String::new(),
            report: None,
        };
        r.run();
        r
    }

    fn run(&mut self) {
        let host = (self.role == StoreRole::Server).then_some(self.host.as_str());
        self.report = Some(check_role(&self.ks, self.role, host, rustca_core::now_ts()));
    }

    /// 回傳 false 表示使用者關閉視窗。
    pub fn ui(&mut self, ctx: &egui::Context) -> bool {
        let mut open = true;
        let mut close = false;
        let mut rerun = false;
        let max_h = max_window_height(ctx);
        egui::Window::new(format!("☑ 用途檢查：{}", self.ks.name()))
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_width(640.0)
            .max_height(max_h)
            .max_width(max_window_width(ctx))
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label("要當作：");
                    for r in StoreRole::ALL {
                        if ui.radio_value(&mut self.role, r, r.label()).changed() {
                            rerun = true;
                        }
                    }
                });
                if self.role == StoreRole::Server {
                    ui.horizontal(|ui| {
                        ui.label("主機名稱（選填）");
                        let r = ui.add(
                            egui::TextEdit::singleline(&mut self.host)
                                .hint_text("例如 api.example.com，檢查憑證是否涵蓋")
                                .desired_width(280.0),
                        );
                        if r.changed() {
                            rerun = true;
                        }
                    });
                }
                ui.weak(match self.role {
                    StoreRole::Server => "Server 提供 TLS 服務時用的 keystore：需有私鑰、完整憑證鏈、serverAuth 用途，SAN 要涵蓋主機名稱",
                    StoreRole::Client => "mTLS 時 Client 送出憑證用的 keystore：需有私鑰、完整憑證鏈、clientAuth 用途",
                    StoreRole::Truststore => "用來驗證對方憑證的信任庫：應放對方的 CA（根 / 中繼），不需要私鑰",
                });
                ui.separator();
                if let Some(rep) = &self.report {
                    let (text, color) = if !rep.ok {
                        (format!("✘ 不適合作為 {}（{} 個錯誤、{} 個警告）", rep.role.label(), rep.errors, rep.warnings), RED)
                    } else if rep.warnings > 0 {
                        (format!("⚠ 可以作為 {}，但有 {} 個警告", rep.role.label(), rep.warnings), YELLOW)
                    } else {
                        (format!("✔ 適合作為 {}", rep.role.label()), GREEN)
                    };
                    ui.label(RichText::new(text).color(color).strong());
                    ui.add_space(4.0);
                    egui::ScrollArea::vertical()
                        .max_height((max_h - 230.0).max(120.0))
                        .auto_shrink([false, true])
                        .show(ui, |ui| {
                            for (i, s) in rep.sections.iter().enumerate() {
                                let bad = s.checks.iter().any(|c| c.level == CheckLevel::Error);
                                let warn = s.checks.iter().any(|c| c.level == CheckLevel::Warn);
                                let icon = if bad { "✘" } else if warn { "⚠" } else { "✔" };
                                egui::CollapsingHeader::new(format!("{icon} {}", s.title))
                                    .id_salt(("role_sec", i))
                                    // 有問題的區段預設展開；區段很多時正常的收合
                                    .default_open(bad || warn || rep.sections.len() <= 4)
                                    .show(ui, |ui| {
                                        for c in &s.checks {
                                            let (icon, color) = match c.level {
                                                CheckLevel::Ok => ("✔", GREEN),
                                                CheckLevel::Warn => ("⚠", YELLOW),
                                                CheckLevel::Error => ("✘", RED),
                                            };
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(format!("{icon} {}", c.message))
                                                        .color(color),
                                                )
                                                .wrap(),
                                            );
                                        }
                                    });
                            }
                        });
                }
                close = close_button(ui);
            });
        if rerun {
            self.run();
        }
        open && !close
    }
}
