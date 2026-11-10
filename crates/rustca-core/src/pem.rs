//! PEM 區塊解析。

use base64::Engine;

use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct PemBlock {
    pub label: String,
    pub der: Vec<u8>,
}

/// 判斷資料看起來是否為 PEM 文字。
pub fn looks_like_pem(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(&data[..data.len().min(64 * 1024)]);
    text.contains("-----BEGIN ")
}

/// 解析所有 PEM 區塊（忽略區塊外的文字，例如 openssl 輸出的 Bag Attributes）。
pub fn parse_all(data: &[u8]) -> Result<Vec<PemBlock>> {
    let text = String::from_utf8_lossy(data);
    let mut blocks = Vec::new();
    let mut current: Option<(String, String)> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            let label = rest.trim_end_matches('-').trim().to_string();
            current = Some((label, String::new()));
        } else if let Some(rest) = line.strip_prefix("-----END ") {
            let label = rest.trim_end_matches('-').trim();
            if let Some((cur_label, body)) = current.take() {
                if cur_label != label {
                    return Err(Error::format(format!(
                        "PEM 區塊標記不一致：BEGIN {cur_label} / END {label}"
                    )));
                }
                let der = base64::engine::general_purpose::STANDARD
                    .decode(body.as_bytes())
                    .map_err(|e| Error::format(format!("PEM base64 解碼失敗：{e}")))?;
                blocks.push(PemBlock {
                    label: cur_label,
                    der,
                });
            }
        } else if let Some((_, body)) = current.as_mut() {
            // 跳過舊式加密 PEM 的標頭行（Proc-Type / DEK-Info）
            if line.contains(':') {
                continue;
            }
            body.push_str(line);
        }
    }
    Ok(blocks)
}

/// 將 DER 轉成 PEM 文字。
pub fn encode(label: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let der = (0u8..200).collect::<Vec<_>>();
        let text = format!("garbage\n{}", encode("CERTIFICATE", &der));
        let blocks = parse_all(text.as_bytes()).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].label, "CERTIFICATE");
        assert_eq!(blocks[0].der, der);
    }
}
