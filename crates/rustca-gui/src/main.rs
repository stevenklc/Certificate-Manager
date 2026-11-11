//! RUST-CA 圖形介面（Windows）。
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod devshot;
mod fonts;
mod graph;
mod handshake;
mod manage;
mod tools;
mod widgets;

fn main() -> eframe::Result {
    rustca_core::init_local_offset();
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("RUST-CA 憑證庫管理工具")
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([900.0, 560.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };
    // 支援以命令列參數或「開啟檔案」關聯直接帶入檔案
    let files: Vec<std::path::PathBuf> = std::env::args_os().skip(1).map(Into::into).collect();
    eframe::run_native(
        "RUST-CA",
        options,
        Box::new(move |cc| {
            fonts::install(&cc.egui_ctx);
            Ok(Box::new(app::App::new(files)))
        }),
    )
}
