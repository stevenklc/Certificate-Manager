//! 交握模擬分頁。

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eframe::egui::{self, RichText};
use rustca_core::tls::{
    self, HandshakeReport, LocalOptions, RemoteOptions, RemoteTrust, TlsVersion,
};
use rustca_core::{now_ts, parse_date, CertInfo, Keystore};

use crate::widgets::{pick_cert_files, status_text, BLUE, GREEN, RED, YELLOW};

const METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

/// TLS 身分選擇：憑證庫中的私鑰條目，或「憑證檔 + 私鑰檔」。
#[derive(Default)]
struct IdPicker {
    pair: bool,
    store: Option<usize>,
    alias: Option<String>,
    cert: Option<usize>,
    key: Option<usize>,
}

impl IdPicker {
    fn fix(&mut self, n: usize) {
        for s in [&mut self.store, &mut self.cert, &mut self.key] {
            if s.is_some_and(|i| i >= n) {
                *s = None;
            }
        }
    }

    fn is_set(&self) -> bool {
        if self.pair {
            self.cert.is_some() || self.key.is_some()
        } else {
            self.store.is_some()
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, id: &str, stores: &[Keystore], opens: &mut Vec<PathBuf>) {
        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                ui.radio_value(&mut self.pair, false, "憑證庫（含私鑰）");
                ui.radio_value(&mut self.pair, true, "憑證檔 + 私鑰檔");
                if ui
                    .small_button("📂 加入檔案…")
                    .on_hover_text("開啟 .jks / .p12 / .cer / .pem / .key 檔案")
                    .clicked()
                {
                    opens.extend(pick_cert_files());
                }
            });
            ui.horizontal(|ui| {
                if self.pair {
                    ui.label("憑證");
                    file_combo(ui, &format!("{id}_cert"), &mut self.cert, stores, |s| {
                        let n = s.all_certs().len();
                        (n > 0).then(|| format!("{}（{n} 張憑證）", s.name()))
                    });
                    ui.label("私鑰");
                    file_combo(ui, &format!("{id}_key"), &mut self.key, stores, |s| {
                        s.private_key_entries().next().map(|_| s.name())
                    });
                } else {
                    store_combo(ui, id, &mut self.store, &mut self.alias, stores);
                }
            });
        });
    }

    fn resolve(&self, stores: &[Keystore], what: &str) -> Result<Option<tls::Identity>, String> {
        if !self.pair {
            return identity(self.store, &self.alias, stores, what);
        }
        match (
            self.cert.and_then(|i| stores.get(i)),
            self.key.and_then(|i| stores.get(i)),
        ) {
            (None, None) => Ok(None),
            (Some(c), Some(k)) => tls::identity_from_cert_and_key(c, k)
                .map(Some)
                .map_err(|e| format!("{what}：{e}")),
            _ => Err(format!("{what}：請同時選擇憑證檔與私鑰檔")),
        }
    }
}

fn file_combo(
    ui: &mut egui::Ui,
    id: &str,
    sel: &mut Option<usize>,
    stores: &[Keystore],
    label: impl Fn(&Keystore) -> Option<String>,
) {
    let text = sel
        .and_then(|i| stores.get(i))
        .map(|s| s.name())
        .unwrap_or_else(|| "（請選擇）".into());
    egui::ComboBox::from_id_salt(id)
        .selected_text(text)
        .width(200.0)
        .show_ui(ui, |ui| {
            ui.selectable_value(sel, None, "（無）");
            for (i, s) in stores.iter().enumerate() {
                if let Some(l) = label(s) {
                    ui.selectable_value(sel, Some(i), l);
                }
            }
        });
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Mode {
    Local,
    Remote,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum TrustMode {
    System,
    Mozilla,
    Stores,
    Insecure,
}

type Shared = Arc<Mutex<Option<HandshakeReport>>>;

pub struct HandshakeState {
    mode: Mode,
    // 本機
    server: IdPicker,
    client_trust: Vec<bool>,
    mtls: bool,
    client: IdPicker,
    server_trust: Vec<bool>,
    // 遠端
    address: String,
    trust_mode: TrustMode,
    remote_trust: Vec<bool>,
    remote_client: IdPicker,
    http: bool,
    method: String,
    http_path: String,
    headers: String,
    body: String,
    proxy: String,
    use_env_proxy: bool,
    timeout: u64,
    // 共用
    sni: String,
    version: TlsVersion,
    at: String,
    running: Option<Shared>,
    result: Option<HandshakeReport>,
    error: Option<String>,
    /// 上次按下複製的時間（顯示「已複製」提示用）
    copied_at: Option<f64>,
    /// 使用者在此分頁要求開啟的檔案，由 App 取走
    pub open_requests: Vec<PathBuf>,
}

impl Default for HandshakeState {
    fn default() -> Self {
        HandshakeState {
            mode: Mode::Local,
            server: IdPicker::default(),
            client_trust: vec![],
            mtls: false,
            client: IdPicker::default(),
            server_trust: vec![],
            address: String::new(),
            trust_mode: TrustMode::System,
            remote_trust: vec![],
            remote_client: IdPicker::default(),
            http: false,
            method: "GET".into(),
            http_path: String::new(),
            headers: String::new(),
            body: String::new(),
            proxy: String::new(),
            use_env_proxy: true,
            timeout: 10,
            sni: String::new(),
            version: TlsVersion::Auto,
            at: String::new(),
            running: None,
            result: None,
            error: None,
            copied_at: None,
            open_requests: vec![],
        }
    }
}

fn store_combo(
    ui: &mut egui::Ui,
    id: &str,
    sel: &mut Option<usize>,
    alias: &mut Option<String>,
    stores: &[Keystore],
) {
    let text = sel
        .and_then(|i| stores.get(i))
        .map(|s| s.name())
        .unwrap_or_else(|| "（請選擇）".into());
    let before = *sel;
    egui::ComboBox::from_id_salt(id)
        .selected_text(text)
        .width(220.0)
        .show_ui(ui, |ui| {
            ui.selectable_value(sel, None, "（無）");
            for (i, s) in stores.iter().enumerate() {
                let n = s.private_key_entries().count();
                if n > 0 {
                    ui.selectable_value(sel, Some(i), format!("{}（{n} 個私鑰）", s.name()));
                } else {
                    // 沒有私鑰的憑證庫（如 cacerts）只能當信任庫，不能當 TLS 身分
                    ui.add_enabled(false, egui::Button::new(format!("{}（無私鑰）", s.name())))
                        .on_disabled_hover_text(
                            "沒有私鑰，不能作為身分；要用它驗證對方請勾選在「信任庫」",
                        );
                }
            }
        });
    if *sel != before {
        *alias = None;
    }
    if let Some(ks) = sel.and_then(|i| stores.get(i)) {
        let keys: Vec<String> = ks.private_key_entries().map(|e| e.alias.clone()).collect();
        if keys.is_empty() {
            ui.colored_label(
                YELLOW,
                "⚠ 沒有私鑰，不能作為身分（信任用的憑證庫請勾選在「信任庫」）",
            );
            return;
        }
        if alias.is_none() {
            *alias = keys.first().cloned();
        }
        egui::ComboBox::from_id_salt(format!("{id}_alias"))
            .selected_text(alias.clone().unwrap_or_else(|| "（沒有私鑰條目）".into()))
            .width(160.0)
            .show_ui(ui, |ui| {
                for k in keys {
                    ui.selectable_value(alias, Some(k.clone()), k);
                }
            });
    }
}

fn trust_checks(
    ui: &mut egui::Ui,
    sel: &mut Vec<bool>,
    stores: &[Keystore],
    opens: &mut Vec<PathBuf>,
) {
    sel.resize(stores.len(), false);
    ui.horizontal_wrapped(|ui| {
        if ui
            .small_button("📂 加入檔案…")
            .on_hover_text("可選 .cer / .crt / .pem / .p7b / .jks / .p12")
            .clicked()
        {
            opens.extend(pick_cert_files());
        }
        if stores.is_empty() {
            ui.weak("尚未開啟任何檔案");
        }
        for (i, s) in stores.iter().enumerate() {
            ui.checkbox(&mut sel[i], s.name())
                .on_hover_text(format!("{} 張信任錨點", s.trust_anchors().len()));
        }
    });
}

fn selected_anchors(sel: &[bool], stores: &[Keystore]) -> Vec<CertInfo> {
    let chosen: Vec<&Keystore> = stores
        .iter()
        .zip(sel.iter())
        .filter(|(_, s)| **s)
        .map(|(k, _)| k)
        .collect();
    tls::trust_from_keystores(&chosen)
}

fn identity(
    sel: Option<usize>,
    alias: &Option<String>,
    stores: &[Keystore],
    what: &str,
) -> Result<Option<tls::Identity>, String> {
    match sel.and_then(|i| stores.get(i)) {
        None => Ok(None),
        Some(ks) if ks.private_key_entries().next().is_none() => Err(format!(
            "{what} 身分：{} 沒有私鑰，不能作為 TLS 身分。\
             Client 一般不需要私鑰，只有 Server 要求 Client 憑證（mTLS）時才要；\
             若要用它驗證對方的憑證，請把它勾選在「信任庫」，身分欄位選「（無）」",
            ks.name()
        )),
        Some(ks) => tls::identity_from_keystore(ks, alias.as_deref())
            .map(Some)
            .map_err(|e| format!("{what}：{e}")),
    }
}

impl HandshakeState {
    pub fn on_stores_changed(&mut self, n: usize) {
        for s in [&mut self.server, &mut self.client, &mut self.remote_client] {
            s.fix(n);
        }
        self.client_trust.resize(n, false);
        self.server_trust.resize(n, false);
        self.remote_trust.resize(n, false);
    }

    /// 開發截圖用：以第一個檔案為 Server、其餘全部作為信任庫並執行本機模擬。
    pub fn demo(&mut self, stores: &[Keystore]) {
        self.on_stores_changed(stores.len());
        self.server.store = Some(0);
        for (i, t) in self.client_trust.iter_mut().enumerate() {
            *t = i > 0;
        }
        if let Ok(r) = self.run_local(stores) {
            self.result = Some(r);
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.is_some()
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

    fn at(&self) -> Result<Option<i64>, String> {
        let t = self.at.trim();
        if t.is_empty() {
            Ok(None)
        } else {
            parse_date(t).map(Some).map_err(|e| e.to_string())
        }
    }

    fn run_local(&mut self, stores: &[Keystore]) -> Result<HandshakeReport, String> {
        let server = self
            .server
            .resolve(stores, "Server")?
            .ok_or("請選擇 Server 身分（憑證庫或憑證 + 私鑰）")?;
        let client = if self.mtls {
            self.client.resolve(stores, "Client")?
        } else {
            None
        };
        let client_anchors = selected_anchors(&self.client_trust, stores);
        if client_anchors.is_empty() {
            return Err("請勾選至少一個 Client 信任庫".into());
        }
        let server_anchors = selected_anchors(&self.server_trust, stores);
        if self.mtls && server_anchors.is_empty() {
            return Err("啟用 mTLS 時請勾選 Server 信任庫".into());
        }
        Ok(tls::simulate_local(
            &server,
            &client_anchors,
            client.as_ref(),
            &server_anchors,
            &LocalOptions {
                server_name: (!self.sni.trim().is_empty()).then(|| self.sni.trim().to_string()),
                version: self.version,
                at: self.at()?,
                require_client_auth: self.mtls,
            },
        ))
    }

    fn start_remote(&mut self, stores: &[Keystore], ctx: &egui::Context) -> Result<(), String> {
        let address = self.address.trim().to_string();
        if address.is_empty() {
            return Err("請輸入網域（www.example.com:443）或 API 網址（https://host/api）".into());
        }
        let target = tls::parse_target(&address)?;
        let http = if self.http || target.path.is_some() {
            let path = match self.http_path.trim() {
                "" => target.path.clone().unwrap_or_else(|| "/".into()),
                p if p.starts_with('/') => p.to_string(),
                p => format!("/{p}"),
            };
            let headers = self
                .headers
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(tls::parse_header)
                .collect::<Result<Vec<_>, _>>()?;
            let method = match self.method.trim() {
                "" => "GET".to_string(),
                m => m.to_ascii_uppercase(),
            };
            Some(tls::HttpRequest {
                method,
                path,
                headers,
                body: self.body.as_bytes().to_vec(),
            })
        } else {
            None
        };
        let trust = match self.trust_mode {
            TrustMode::System => RemoteTrust::System,
            TrustMode::Mozilla => RemoteTrust::Mozilla,
            TrustMode::Insecure => RemoteTrust::Insecure,
            TrustMode::Stores => {
                let a = selected_anchors(&self.remote_trust, stores);
                if a.is_empty() {
                    return Err("請勾選至少一個信任庫".into());
                }
                RemoteTrust::Certs(a)
            }
        };
        let client = self.remote_client.resolve(stores, "Client")?;
        let proxy = if !self.proxy.trim().is_empty() {
            Some(self.proxy.trim().to_string())
        } else if self.use_env_proxy {
            tls::auto_proxy(&target.host).map(|(p, _)| p)
        } else {
            None
        };
        let opts = RemoteOptions {
            address,
            server_name: (!self.sni.trim().is_empty()).then(|| self.sni.trim().to_string()),
            version: self.version,
            at: self.at()?,
            timeout: Duration::from_secs(self.timeout.max(1)),
            trust,
            proxy,
            http,
        };
        let shared: Shared = Arc::new(Mutex::new(None));
        let out = shared.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let r = tls::connect_remote(&opts, client.as_ref());
            if let Ok(mut g) = out.lock() {
                *g = Some(r);
            }
            ctx.request_repaint();
        });
        self.running = Some(shared);
        self.result = None;
        Ok(())
    }

    fn http_ui(&mut self, ui: &mut egui::Ui) {
        let url_path = tls::parse_target(&self.address).ok().and_then(|t| t.path);
        ui.vertical(|ui| {
            ui.checkbox(&mut self.http, "交握成功後送出 HTTP 請求（測試 API）");
            if !self.http && url_path.is_some() {
                ui.weak("網址含路徑，會自動送出請求");
            }
            if !(self.http || url_path.is_some()) {
                return;
            }
            ui.horizontal(|ui| {
                egui::ComboBox::from_id_salt("http_method")
                    .selected_text(self.method.clone())
                    .width(90.0)
                    .show_ui(ui, |ui| {
                        for m in METHODS {
                            ui.selectable_value(&mut self.method, m.to_string(), *m);
                        }
                    });
                ui.add(
                    egui::TextEdit::singleline(&mut self.http_path)
                        .hint_text(url_path.as_deref().unwrap_or("/"))
                        .desired_width(330.0),
                )
                .on_hover_text("路徑（含 query）；留空＝使用網址中的路徑");
            });
            ui.label("標頭（每行一個）");
            ui.add(
                egui::TextEdit::multiline(&mut self.headers)
                    .hint_text("Authorization: Bearer xxx\nContent-Type: application/json")
                    .code_editor()
                    .desired_rows(3)
                    .desired_width(430.0),
            );
            ui.label("內容（Body）");
            ui.add(
                egui::TextEdit::multiline(&mut self.body)
                    .hint_text("{\"key\": \"value\"}")
                    .code_editor()
                    .desired_rows(4)
                    .desired_width(430.0),
            );
        });
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, stores: &[Keystore]) {
        self.poll();
        ui.horizontal(|ui| {
            ui.selectable_value(
                &mut self.mode,
                Mode::Local,
                RichText::new("💻 本機模擬（Server 與 Client）").strong(),
            );
            ui.selectable_value(
                &mut self.mode,
                Mode::Remote,
                RichText::new("🌐 連線遠端 Server").strong(),
            );
        });
        ui.separator();

        egui::ScrollArea::vertical()
            .id_salt("hs_scroll")
            .show(ui, |ui| {
                egui::Grid::new("hs_form")
                    .num_columns(2)
                    .spacing([12.0, 8.0])
                    .show(ui, |ui| {
                        match self.mode {
                            Mode::Local => {
                                ui.label(RichText::new("Server 身分").strong());
                                self.server.ui(ui, "srv", stores, &mut self.open_requests);
                                ui.end_row();
                                ui.label(RichText::new("Client 信任庫").strong())
                                    .on_hover_text("Client 用來驗證 Server 憑證的 CA，例如 cacerts");
                                ui.vertical(|ui| {
                                    trust_checks(
                                        ui,
                                        &mut self.client_trust,
                                        stores,
                                        &mut self.open_requests,
                                    )
                                });
                                ui.end_row();
                                ui.label(RichText::new("雙向 TLS").strong());
                                ui.checkbox(&mut self.mtls, "Server 要求 Client 憑證（mTLS）");
                                ui.end_row();
                                if self.mtls {
                                    ui.label(RichText::new("Client 身分").strong());
                                    ui.vertical(|ui| {
                                        self.client.ui(ui, "cli", stores, &mut self.open_requests);
                                        if !self.client.is_set() {
                                            ui.weak("不選＝模擬 Client 沒有憑證");
                                        }
                                    });
                                    ui.end_row();
                                    ui.label(RichText::new("Server 信任庫").strong());
                                    ui.vertical(|ui| {
                                        trust_checks(
                                            ui,
                                            &mut self.server_trust,
                                            stores,
                                            &mut self.open_requests,
                                        )
                                    });
                                    ui.end_row();
                                }
                            }
                            Mode::Remote => {
                                ui.label(RichText::new("目標").strong());
                                ui.vertical(|ui| {
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.address)
                                            .hint_text(
                                                "網域 www.example.com[:443] 或 API 網址 https://host/api/…",
                                            )
                                            .desired_width(420.0),
                                    );
                                    if let Err(e) = (!self.address.trim().is_empty())
                                        .then(|| tls::parse_target(&self.address))
                                        .transpose()
                                    {
                                        ui.colored_label(RED, e);
                                    }
                                });
                                ui.end_row();
                                ui.label(RichText::new("HTTP 請求").strong());
                                self.http_ui(ui);
                                ui.end_row();
                                ui.label(RichText::new("信任庫").strong());
                                ui.vertical(|ui| {
                                    ui.horizontal(|ui| {
                                        ui.radio_value(
                                            &mut self.trust_mode,
                                            TrustMode::System,
                                            "系統憑證庫",
                                        );
                                        ui.radio_value(
                                            &mut self.trust_mode,
                                            TrustMode::Mozilla,
                                            "Mozilla 根憑證",
                                        );
                                        ui.radio_value(
                                            &mut self.trust_mode,
                                            TrustMode::Stores,
                                            "指定檔案",
                                        );
                                        ui.radio_value(
                                            &mut self.trust_mode,
                                            TrustMode::Insecure,
                                            "不驗證（只看憑證鏈）",
                                        );
                                    });
                                    if self.trust_mode == TrustMode::Stores {
                                        trust_checks(
                                            ui,
                                            &mut self.remote_trust,
                                            stores,
                                            &mut self.open_requests,
                                        );
                                    }
                                });
                                ui.end_row();
                                ui.label(RichText::new("Client 身分（選填）").strong());
                                ui.vertical(|ui| {
                                    self.remote_client.ui(
                                        ui,
                                        "rcli",
                                        stores,
                                        &mut self.open_requests,
                                    );
                                    ui.weak("只有 Server 要求 Client 憑證（mTLS）時才需要，需含私鑰；一般 HTTPS 請留「（無）」。cacerts 之類的請選在上方「信任庫 → 指定檔案」");
                                });
                                ui.end_row();
                                ui.label(RichText::new("Proxy").strong());
                                ui.horizontal(|ui| {
                                    let hide = self.proxy.contains('@');
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.proxy)
                                            .hint_text("http://user:pass@proxy:8080")
                                            .password(hide)
                                            .desired_width(260.0),
                                    );
                                    ui.checkbox(
                                        &mut self.use_env_proxy,
                                        "未填時使用系統 proxy 設定",
                                    );
                                });
                                ui.end_row();
                                ui.label(RichText::new("逾時").strong());
                                ui.add(
                                    egui::DragValue::new(&mut self.timeout)
                                        .range(1..=120)
                                        .suffix(" 秒"),
                                );
                                ui.end_row();
                            }
                        }
                        ui.label(RichText::new("SNI / 主機名稱").strong());
                        ui.add(
                            egui::TextEdit::singleline(&mut self.sni)
                                .hint_text("留空＝自動")
                                .desired_width(260.0),
                        );
                        ui.end_row();
                        ui.label(RichText::new("TLS 版本").strong());
                        ui.horizontal(|ui| {
                            ui.radio_value(&mut self.version, TlsVersion::Auto, "自動");
                            ui.radio_value(&mut self.version, TlsVersion::Tls12, "TLS 1.2");
                            ui.radio_value(&mut self.version, TlsVersion::Tls13, "TLS 1.3");
                        });
                        ui.end_row();
                        ui.label(RichText::new("模擬時間").strong());
                        ui.add(
                            egui::TextEdit::singleline(&mut self.at)
                                .hint_text("YYYY-MM-DD，留空＝現在")
                                .desired_width(160.0),
                        );
                        ui.end_row();
                    });

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let running = self.running.is_some();
                    if ui
                        .add_enabled(
                            !running,
                            egui::Button::new(RichText::new("▶ 開始交握").strong().size(16.0)),
                        )
                        .clicked()
                    {
                        self.error = None;
                        let res = match self.mode {
                            Mode::Local => self.run_local(stores).map(|r| self.result = Some(r)),
                            Mode::Remote => self.start_remote(stores, ui.ctx()),
                        };
                        if let Err(e) = res {
                            self.error = Some(e);
                            self.result = None;
                        }
                    }
                    if running {
                        ui.spinner();
                        ui.label("連線中…");
                    }
                });
                if let Some(e) = &self.error {
                    ui.colored_label(RED, format!("✘ {e}"));
                }
                ui.separator();
                if let Some(r) = &self.result {
                    copy_bar(ui, r, &mut self.copied_at);
                    report_ui(ui, r);
                }
            });
    }
}

/// 結果上方的複製列：把結果與過程以純文字複製到剪貼簿。
fn copy_bar(ui: &mut egui::Ui, r: &HandshakeReport, copied_at: &mut Option<f64>) {
    let now = ui.input(|i| i.time);
    ui.horizontal(|ui| {
        if ui
            .button("📋 複製結果與過程")
            .on_hover_text("連線資訊、交握訊息、憑證鏈（含有效期間與 SHA-256）、HTTP 回應，純文字格式")
            .clicked()
        {
            ui.ctx().copy_text(r.to_text(false));
            *copied_at = Some(now);
        }
        let has_chain = !r.server_chain.is_empty() || !r.client_chain.is_empty();
        if ui
            .add_enabled(has_chain, egui::Button::new("📋 複製（含憑證 PEM）"))
            .on_hover_text("同上，另附憑證鏈的 PEM，可直接存成 .pem 匯入或用 openssl 檢查")
            .clicked()
        {
            ui.ctx().copy_text(r.to_text(true));
            *copied_at = Some(now);
        }
        if let Some(t) = *copied_at {
            if now - t < 2.5 {
                ui.colored_label(GREEN, "✔ 已複製到剪貼簿");
                ui.ctx().request_repaint_after(std::time::Duration::from_millis(500));
            } else {
                *copied_at = None;
            }
        }
    });
    ui.add_space(4.0);
}

fn report_ui(ui: &mut egui::Ui, r: &HandshakeReport) {
    if r.success {
        ui.label(RichText::new("✔ 交握成功").color(GREEN).size(20.0).strong());
    } else {
        ui.label(RichText::new("✘ 交握失敗").color(RED).size(20.0).strong());
        if let Some(f) = &r.failure {
            egui::Frame::group(ui.style())
                .stroke(egui::Stroke::new(1.0_f32, RED))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(format!("{}偵測到錯誤", f.side)).strong());
                    ui.add(
                        egui::Label::new(format!("錯誤：{}", f.message))
                            .wrap()
                            .selectable(true),
                    );
                    if !f.hint.is_empty() {
                        ui.add_space(4.0);
                        ui.label(RichText::new("診斷").color(YELLOW).strong());
                        ui.add(egui::Label::new(&f.hint).wrap().selectable(true));
                    }
                });
        }
    }
    ui.add_space(6.0);
    egui::Grid::new("hs_summary")
        .num_columns(2)
        .striped(true)
        .show(ui, |ui| {
            let mut row = |k: &str, v: String| {
                ui.label(RichText::new(k).strong());
                ui.label(v);
                ui.end_row();
            };
            row("目標", r.target.clone());
            row("SNI / 驗證名稱", r.server_name.clone());
            if let Some(p) = &r.via_proxy {
                row("經由 Proxy", p.clone());
            }
            row("信任錨點數", r.trust_anchor_count.to_string());
            row("協定", r.protocol.clone().unwrap_or("-".into()));
            row("加密套件", r.cipher_suite.clone().unwrap_or("-".into()));
            row("金鑰交換", r.key_exchange.clone().unwrap_or("-".into()));
            row(
                "Server 要求 Client 憑證",
                if r.client_auth_requested {
                    "是（mTLS）".into()
                } else {
                    "否".into()
                },
            );
            if !r.acceptable_ca_names.is_empty() {
                row("可接受的 Client CA", r.acceptable_ca_names.join("\n"));
            }
        });
    for w in &r.warnings {
        ui.colored_label(YELLOW, format!("⚠ {w}"));
    }
    if let Some(h) = &r.http {
        http_ui(ui, h);
    }

    ui.add_space(6.0);
    egui::CollapsingHeader::new(RichText::new("交握訊息").strong())
        .default_open(true)
        .show(ui, |ui| {
            for l in &r.transcript {
                ui.horizontal(|ui| {
                    if l.direction == "C→S" {
                        ui.monospace("Client ──▶ Server");
                    } else {
                        ui.monospace("Client ◀── Server");
                    }
                    if l.message.starts_with("Alert") {
                        ui.colored_label(RED, &l.message);
                    } else {
                        ui.label(&l.message);
                    }
                });
            }
        });
    chain_ui(ui, "Server 送出的憑證鏈", "srv_chain", &r.server_chain);
    if !r.client_chain.is_empty() {
        chain_ui(ui, "Client 送出的憑證鏈", "cli_chain", &r.client_chain);
    }
}

fn chain_ui(ui: &mut egui::Ui, title: &str, id: &str, chain: &[CertInfo]) {
    if chain.is_empty() {
        return;
    }
    let now = now_ts();
    egui::CollapsingHeader::new(RichText::new(title).strong())
        .id_salt(id)
        .default_open(true)
        .show(ui, |ui| {
            for (i, c) in chain.iter().enumerate() {
                egui::CollapsingHeader::new(format!("[{i}] {}", c.display_name()))
                    .id_salt(format!("{id}_{i}"))
                    .show(ui, |ui| {
                        crate::widgets::cert_grid(
                            ui,
                            &format!("{id}_grid_{i}"),
                            c,
                            c.status_at(now, 30),
                        );
                    });
                ui.horizontal(|ui| {
                    ui.add_space(16.0);
                    ui.label(status_text(c.status_at(now, 30)));
                    ui.colored_label(BLUE, format!("簽發者：{}", c.issuer));
                });
            }
        });
}

fn http_ui(ui: &mut egui::Ui, h: &tls::HttpResponse) {
    ui.add_space(6.0);
    egui::CollapsingHeader::new(RichText::new("HTTP 請求 / 回應").strong())
        .id_salt("http_resp")
        .default_open(true)
        .show(ui, |ui| {
            ui.monospace(format!("> {}", h.request_line));
            for (k, v) in &h.request_headers {
                ui.weak(format!("> {k}: {v}"));
            }
            if let Some(e) = &h.error {
                ui.colored_label(RED, format!("✘ {e}"));
            }
            if h.status_line.is_empty() {
                return;
            }
            let color = match h.status {
                Some(c) if c < 300 => GREEN,
                Some(c) if c < 400 => BLUE,
                Some(c) if c < 500 => YELLOW,
                _ => RED,
            };
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("< {}", h.status_line))
                        .color(color)
                        .strong(),
                );
                ui.weak(format!("{} ms · {} bytes", h.elapsed_ms, h.body_bytes));
            });
            egui::CollapsingHeader::new("回應標頭")
                .id_salt("http_resp_headers")
                .show(ui, |ui| {
                    for (k, v) in &h.headers {
                        ui.add(
                            egui::Label::new(format!("{k}: {v}"))
                                .wrap()
                                .selectable(true),
                        );
                    }
                });
            let mut body = h.body_preview.clone();
            egui::ScrollArea::vertical()
                .id_salt("http_body")
                .max_height(260.0)
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut body)
                            .code_editor()
                            .interactive(true)
                            .desired_width(f32::INFINITY),
                    );
                });
            if h.truncated {
                ui.weak(format!("…僅顯示部分內容（共 {} bytes）", h.body_bytes));
            }
        });
}
