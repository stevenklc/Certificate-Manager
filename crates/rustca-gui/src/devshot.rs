//! 開發用：自動截圖（僅 debug build）。
//! RUST_CA_SCREENSHOT=out.png       截圖輸出路徑
//! RUST_CA_SCREENSHOT_TAB=handshake 切到交握分頁並執行本機模擬

use eframe::egui;

pub struct DevShot {
    pub path: std::path::PathBuf,
    pub tab: String,
    frames: u32,
    requested: bool,
}

impl DevShot {
    pub fn from_env() -> Option<Self> {
        if !cfg!(debug_assertions) {
            return None;
        }
        let path = std::env::var_os("RUST_CA_SCREENSHOT")?;
        Some(DevShot {
            path: path.into(),
            tab: std::env::var("RUST_CA_SCREENSHOT_TAB").unwrap_or_default(),
            frames: 0,
            requested: false,
        })
    }

    /// 每個 frame 呼叫；回傳 true 表示截圖完成、應關閉。
    pub fn tick(&mut self, ctx: &egui::Context) -> bool {
        self.frames += 1;
        ctx.request_repaint();
        if !self.requested && self.frames > 40 {
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(Default::default()));
            self.requested = true;
        }
        let shot = ctx.input(|i| {
            i.raw.events.iter().find_map(|e| match e {
                egui::Event::Screenshot { image, .. } => Some(image.clone()),
                _ => None,
            })
        });
        if let Some(img) = shot {
            let _ = std::fs::write(
                &self.path,
                encode_png(img.width() as u32, img.height() as u32, img.as_raw()),
            );
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return true;
        }
        false
    }
}

/// 最簡 PNG 編碼（RGBA，deflate stored blocks，不壓縮）。
fn encode_png(w: u32, h: u32, rgba: &[u8]) -> Vec<u8> {
    fn crc32(data: &[u8]) -> u32 {
        let mut c = 0xffff_ffffu32;
        for &b in data {
            c ^= b as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xedb8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
        }
        !c
    }
    fn chunk(out: &mut Vec<u8>, kind: &[u8], data: &[u8]) {
        out.extend((data.len() as u32).to_be_bytes());
        let mut body = kind.to_vec();
        body.extend(data);
        out.extend(&body);
        out.extend(crc32(&body).to_be_bytes());
    }
    let mut raw = Vec::with_capacity((w * h * 4 + h) as usize);
    for y in 0..h as usize {
        raw.push(0);
        raw.extend(&rgba[y * w as usize * 4..(y + 1) * w as usize * 4]);
    }
    let mut z = vec![0x78, 0x01];
    let mut chunks = raw.chunks(65535).peekable();
    while let Some(c) = chunks.next() {
        z.push(if chunks.peek().is_none() { 1 } else { 0 });
        z.extend((c.len() as u16).to_le_bytes());
        z.extend((!(c.len() as u16)).to_le_bytes());
        z.extend(c);
    }
    let (mut a, mut b) = (1u32, 0u32);
    for &x in &raw {
        a = (a + x as u32) % 65521;
        b = (b + a) % 65521;
    }
    z.extend(((b << 16) | a).to_be_bytes());

    let mut out = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    let mut ihdr = Vec::new();
    ihdr.extend(w.to_be_bytes());
    ihdr.extend(h.to_be_bytes());
    ihdr.extend([8, 6, 0, 0, 0]);
    chunk(&mut out, b"IHDR", &ihdr);
    chunk(&mut out, b"IDAT", &z);
    chunk(&mut out, b"IEND", &[]);
    out
}
