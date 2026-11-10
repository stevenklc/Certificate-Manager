//! 共用小元件。

use std::path::PathBuf;

use eframe::egui::{self, Color32, RichText};
use rustca_core::{format_ts, CertInfo, ValidityStatus};

pub const GREEN: Color32 = Color32::from_rgb(0x2e, 0xa0, 0x43);
pub const YELLOW: Color32 = Color32::from_rgb(0xd2, 0x99, 0x22);
pub const RED: Color32 = Color32::from_rgb(0xd7, 0x3a, 0x49);
pub const BLUE: Color32 = Color32::from_rgb(0x2f, 0x81, 0xf7);

pub fn status_color(s: ValidityStatus) -> Color32 {
    match s {
        ValidityStatus::Valid { .. } => GREEN,
        ValidityStatus::ExpiringSoon { .. } => YELLOW,
        _ => RED,
    }
}

pub fn status_text(s: ValidityStatus) -> RichText {
    RichText::new(s.label()).color(status_color(s))
}

/// 憑證詳細資訊表格。
pub fn cert_grid(ui: &mut egui::Ui, id: &str, c: &CertInfo, status: ValidityStatus) {
    egui::Grid::new(id)
        .num_columns(2)
        .striped(true)
        .spacing([16.0, 4.0])
        .show(ui, |ui| {
            let row = |ui: &mut egui::Ui, k: &str, v: String| {
                ui.label(RichText::new(k).strong());
                ui.add(egui::Label::new(v).wrap().selectable(true));
                ui.end_row();
            };
            row(ui, "主體", c.subject.clone());
            row(ui, "簽發者", c.issuer.clone());
            row(ui, "序號", c.serial.clone());
            row(ui, "生效日", format_ts(c.not_before));
            row(ui, "到期日", format_ts(c.not_after));
            ui.label(RichText::new("狀態").strong());
            ui.label(status_text(status));
            ui.end_row();
            row(ui, "簽章演算法", c.signature_algorithm.clone());
            row(ui, "公鑰", c.public_key.clone());
            if !c.subject_alt_names.is_empty() {
                row(ui, "SAN", c.subject_alt_names.join("\n"));
            }
            row(
                ui,
                "CA",
                if c.is_ca {
                    c.path_len
                        .map(|n| format!("是（pathLen={n}）"))
                        .unwrap_or_else(|| "是".into())
                } else {
                    "否".into()
                },
            );
            if !c.key_usage.is_empty() {
                row(ui, "金鑰用途", c.key_usage.join(", "));
            }
            if !c.ext_key_usage.is_empty() {
                row(ui, "延伸金鑰用途", c.ext_key_usage.join(", "));
            }
            if let Some(k) = &c.subject_key_id {
                row(ui, "SKI", k.clone());
            }
            if let Some(k) = &c.authority_key_id {
                row(ui, "AKI", k.clone());
            }
            row(
                ui,
                "自簽",
                if c.self_signed {
                    "是".into()
                } else {
                    "否".into()
                },
            );
            row(ui, "SHA-1", c.sha1.clone());
            row(ui, "SHA-256", c.sha256.clone());
        });
}

/// 從 DN 取 CN。
pub fn short_dn(dn: &str) -> String {
    dn.split(',')
        .map(|p| p.trim())
        .find_map(|p| p.strip_prefix("CN="))
        .map(|s| s.to_string())
        .unwrap_or_else(|| dn.to_string())
}

/// 支援開啟的副檔名。
pub const CERT_EXTS: &[&str] = &[
    "jks", "jceks", "keystore", "p12", "pfx", "pem", "crt", "cer", "der", "p7b", "key",
];

/// 選擇要開啟的憑證 / 憑證庫檔案（可多選）。
pub fn pick_cert_files() -> Vec<PathBuf> {
    rfd::FileDialog::new()
        .add_filter("憑證庫 / 憑證 / 私鑰", CERT_EXTS)
        .add_filter("所有檔案", &["*"])
        .pick_files()
        .unwrap_or_default()
}

/// 選擇單一檔案。
pub fn pick_cert_file() -> Option<PathBuf> {
    rfd::FileDialog::new()
        .add_filter("憑證庫 / 憑證 / 私鑰", CERT_EXTS)
        .add_filter("所有檔案", &["*"])
        .pick_file()
}
