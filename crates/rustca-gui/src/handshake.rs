//! 交握模擬分頁。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use eframe::egui::{self, RichText};
use rustca_core::tls::{
    self, HandshakeReport, LocalOptions, RemoteOptions, RemoteTrust, TlsVersion,
};
use rustca_core::{now_ts, parse_date, CertInfo, Keystore};

use crate::widgets::{status_text, BLUE, GREEN, RED, YELLOW};

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
    server: Option<usize>,
    server_alias: Option<String>,
    client_trust: Vec<bool>,
    mtls: bool,
    client: Option<usize>,
    client_alias: Option<String>,
    server_trust: Vec<bool>,
    // 遠端
    address: String,
    trust_mode: TrustMode,
    remote_trust: Vec<bool>,
    remote_client: Option<usize>,
    remote_client_alias: Option<String>,
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
}

impl Default for HandshakeState {
    fn default() -> Self {
        HandshakeState {
            mode: Mode::Local,
            server: None,
            server_alias: None,
            client_trust: vec![],
            mtls: false,
            client: None,
            client_alias: None,
            server_trust: vec![],
            address: String::new(),
            trust_mode: TrustMode::System,
            remote_trust: vec![],
            remote_client: None,
            remote_client_alias: None,
            proxy: String::new(),
            use_env_proxy: true,
            timeout: 10,
            sni: String::new(),
            version: TlsVersion::Auto,
            at: String::new(),
            running: None,
            result: None,
            error: None,
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
                ui.selectable_value(sel, Some(i), format!("{}（{} 個私鑰）", s.name(), n));
            }
        });
    if *sel != before {
        *alias = None;
    }
    if let Some(ks) = sel.and_then(|i| stores.get(i)) {
        let keys: Vec<String> = ks.private_key_entries().map(|e| e.alias.clone()).collect();
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

fn trust_checks(ui: &mut egui::Ui, sel: &mut Vec<bool>, stores: &[Keystore]) {
    sel.resize(stores.len(), false);
    if stores.is_empty() {
        ui.weak("請先在「憑證庫」分頁開啟檔案");
    }
    ui.horizontal_wrapped(|ui| {
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
        Some(ks) => tls::identity_from_keystore(ks, alias.as_deref())
            .map(Some)
            .map_err(|e| format!("{what}：{e}")),
    }
}

impl HandshakeState {
    pub fn on_stores_changed(&mut self, n: usize) {
        for s in [&mut self.server, &mut self.client, &mut self.remote_client] {
            if s.is_some_and(|i| i >= n) {
                *s = None;
            }
        }
        self.client_trust.resize(n, false);
        self.server_trust.resize(n, false);
        self.remote_trust.resize(n, false);
    }

    /// 開發截圖用：以第一個檔案為 Server、其餘全部作為信任庫並執行本機模擬。
    pub fn demo(&mut self, stores: &[Keystore]) {
        self.on_stores_changed(stores.len());
        self.server = Some(0);
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
        let server = identity(self.server, &self.server_alias, stores, "Server")?
            .ok_or("請選擇 Server 憑證庫（需含私鑰）")?;
        let client = if self.mtls {
            identity(self.client, &self.client_alias, stores, "Client")?
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
            return Err("請輸入主機，例如 www.example.com:443".into());
        }
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
        let client = identity(
            self.remote_client,
            &self.remote_client_alias,
            stores,
            "Client",
        )?;
        let proxy = if !self.proxy.trim().is_empty() {
            Some(self.proxy.trim().to_string())
        } else if self.use_env_proxy {
            tls::split_host_port(&address)
                .ok()
                .and_then(|(h, _)| tls::proxy_from_env(&h))
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
                                ui.horizontal(|ui| {
                                    store_combo(
                                        ui,
                                        "srv",
                                        &mut self.server,
                                        &mut self.server_alias,
                                        stores,
                                    )
                                });
                                ui.end_row();
                                ui.label(RichText::new("Client 信任庫").strong());
                                ui.vertical(|ui| trust_checks(ui, &mut self.client_trust, stores));
                                ui.end_row();
                                ui.label(RichText::new("雙向 TLS").strong());
                                ui.checkbox(&mut self.mtls, "Server 要求 Client 憑證（mTLS）");
                                ui.end_row();
                                if self.mtls {
                                    ui.label(RichText::new("Client 身分").strong());
                                    ui.horizontal(|ui| {
                                        store_combo(
                                            ui,
                                            "cli",
                                            &mut self.client,
                                            &mut self.client_alias,
                                            stores,
                                        );
                                        if self.client.is_none() {
                                            ui.weak("不選＝模擬 Client 沒有憑證");
                                        }
                                    });
                                    ui.end_row();
                                    ui.label(RichText::new("Server 信任庫").strong());
                                    ui.vertical(|ui| {
                                        trust_checks(ui, &mut self.server_trust, stores)
                                    });
                                    ui.end_row();
                                }
                            }
                            Mode::Remote => {
                                ui.label(RichText::new("主機").strong());
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.address)
                                        .hint_text("host:port，預設 443")
                                        .desired_width(320.0),
                                );
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
                                        trust_checks(ui, &mut self.remote_trust, stores);
                                    }
                                });
                                ui.end_row();
                                ui.label(RichText::new("Client 身分").strong());
                                ui.horizontal(|ui| {
                                    store_combo(
                                        ui,
                                        "rcli",
                                        &mut self.remote_client,
                                        &mut self.remote_client_alias,
                                        stores,
                                    );
                                    ui.weak("（mTLS 時使用）");
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
                                    ui.checkbox(&mut self.use_env_proxy, "未填時使用 HTTPS_PROXY");
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
                    report_ui(ui, r);
                }
            });
    }
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
