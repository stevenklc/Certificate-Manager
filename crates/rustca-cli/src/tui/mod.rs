//! 終端機互動介面（TUI），操作方式仿 k9s：
//! 透過 SSH 就能使用，不需要 X11 / 圖形環境。

mod app;
mod text;
mod ui;

use std::path::{Path, PathBuf};

use anyhow::Result;

pub use app::App;

/// 會被當成憑證庫開啟的副檔名（目錄參數展開時使用）。
const STORE_EXTS: &[&str] = &[
    "jks", "jceks", "keystore", "truststore", "ks", "p12", "pfx", "pem", "crt", "cer", "der",
    "p7b", "p7c",
];

/// 啟動 TUI。`files` 可以是檔案或目錄（目錄只展開第一層的憑證庫檔案）。
pub fn run(files: Vec<PathBuf>, password: Option<String>, warn_days: i64) -> Result<()> {
    let mut app = App::new(password, warn_days);
    for f in files {
        if f.is_dir() {
            let mut found = expand_dir(&f);
            if found.is_empty() {
                app.error(format!("目錄 {} 中沒有憑證庫檔案", f.display()));
            }
            found.sort();
            app.queue.extend(found);
        } else {
            app.queue.push_back(f);
        }
    }
    let mut terminal = ratatui::init();
    let res = app.run(&mut terminal);
    ratatui::restore();
    res
}

fn expand_dir(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return vec![];
    };
    rd.filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file() && looks_like_store(p))
        .collect()
}

fn looks_like_store(p: &Path) -> bool {
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if name == "cacerts" || name == "jssecacerts" {
        return true;
    }
    p.extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .is_some_and(|e| STORE_EXTS.contains(&e.as_str()))
}

#[cfg(test)]
mod tests {
    use super::app::{App, View};
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn store_file_detection() {
        assert!(looks_like_store(Path::new("/opt/java/lib/security/cacerts")));
        assert!(looks_like_store(Path::new("server.JKS")));
        assert!(looks_like_store(Path::new("a/b/client.p12")));
        assert!(!looks_like_store(Path::new("readme.txt")));
        assert!(!looks_like_store(Path::new("server.key")));
    }

    #[test]
    fn every_view_renders_without_files() {
        let mut app = App::new(None, 30);
        let mut term = Terminal::new(TestBackend::new(100, 30)).unwrap();
        for v in [
            View::Main,
            View::Detail,
            View::Search,
            View::Expiry,
            View::Handshake,
            View::Help,
        ] {
            app.view = v;
            term.draw(|f| ui::draw(f, &mut app)).unwrap();
        }
        // 很窄的終端機也不能 panic
        let mut term = Terminal::new(TestBackend::new(20, 6)).unwrap();
        app.view = View::Main;
        term.draw(|f| ui::draw(f, &mut app)).unwrap();
        let screen = format!("{:?}", term.backend().buffer());
        assert!(!screen.is_empty());
    }

    #[test]
    fn opens_queued_files_and_renders() {
        let dir = std::env::temp_dir().join(format!("rustca-tui-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // 以 core 的簽發功能產生一張自簽憑證
        use rustca_core::forge::{issue_chain, CertSpec, Profile};
        let issued = issue_chain(&[CertSpec::new("tui.example.com", Profile::Server)], None)
            .expect("簽發測試憑證");
        let pem = issued[0].cert.to_pem();
        let f = dir.join("tui.pem");
        std::fs::write(&f, pem).unwrap();
        let found = expand_dir(&dir);
        assert_eq!(found, vec![f.clone()]);

        let mut app = App::new(None, 30);
        app.queue.push_back(f);
        app.process_queue();
        assert_eq!(app.stores.len(), 1);
        assert_eq!(app.visible.len(), 1);
        let mut term = Terminal::new(TestBackend::new(120, 30)).unwrap();
        term.draw(|f| ui::draw(f, &mut app)).unwrap();
        let screen: String = term
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(screen.contains("tui.example.com"), "{screen}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
