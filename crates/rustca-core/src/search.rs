//! 憑證庫關鍵字搜尋。

use serde::Serialize;

use crate::cert::CertInfo;
use crate::model::{Entry, Keystore};

#[derive(Debug, Clone, Serialize)]
pub struct FieldMatch {
    pub field: &'static str,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchHit {
    pub alias: String,
    pub entry_index: usize,
    /// 命中的憑證在條目鏈中的位置；None 表示只命中別名
    pub cert_index: Option<usize>,
    pub cert_name: Option<String>,
    pub matches: Vec<FieldMatch>,
}

fn normalize_hex(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_lowercase()
}

/// 關鍵字比對器（不分大小寫；十六進位關鍵字會忽略冒號與空白，可用來找序號或指紋）。
pub struct Matcher {
    lower: String,
    hex: Option<String>,
}

impl Matcher {
    pub fn new(keyword: &str) -> Self {
        let kw = keyword.trim();
        let lower = kw.to_lowercase();
        let hex_candidate = normalize_hex(kw);
        let is_hex_like = !kw.is_empty()
            && hex_candidate.len() >= 4
            && kw
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == ' ' || c == '-');
        Matcher {
            lower,
            hex: is_hex_like.then_some(hex_candidate),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.lower.is_empty()
    }

    pub fn text(&self, value: &str) -> bool {
        !self.lower.is_empty() && value.to_lowercase().contains(&self.lower)
    }

    pub fn hex(&self, value: &str) -> bool {
        match &self.hex {
            Some(h) => normalize_hex(value).contains(h.as_str()),
            None => self.text(value),
        }
    }

    pub fn cert(&self, c: &CertInfo) -> Vec<FieldMatch> {
        let mut m = Vec::new();
        let mut push = |field: &'static str, value: &str| {
            m.push(FieldMatch {
                field,
                value: value.to_string(),
            })
        };
        if self.text(&c.subject) {
            push("主體", &c.subject);
        }
        if self.text(&c.issuer) {
            push("簽發者", &c.issuer);
        }
        for san in &c.subject_alt_names {
            if self.text(san) {
                push("SAN", san);
            }
        }
        if self.hex(&c.serial) {
            push("序號", &c.serial);
        }
        if self.hex(&c.sha1) {
            push("SHA-1", &c.sha1);
        }
        if self.hex(&c.sha256) {
            push("SHA-256", &c.sha256);
        }
        if self.text(&c.signature_algorithm) {
            push("簽章演算法", &c.signature_algorithm);
        }
        if self.text(&c.public_key) {
            push("公鑰", &c.public_key);
        }
        for u in c.key_usage.iter().chain(c.ext_key_usage.iter()) {
            if self.text(u) {
                push("金鑰用途", u);
            }
        }
        if let Some(k) = &c.subject_key_id {
            if self.hex.is_some() && self.hex(k) {
                push("SKI", k);
            }
        }
        m
    }

    pub fn entry(&self, idx: usize, e: &Entry) -> Vec<SearchHit> {
        let mut hits = Vec::new();
        let alias_hit = self.text(&e.alias);
        for (ci, c) in e.chain.iter().enumerate() {
            let mut matches = self.cert(c);
            if alias_hit && ci == 0 {
                matches.insert(
                    0,
                    FieldMatch {
                        field: "別名",
                        value: e.alias.clone(),
                    },
                );
            }
            if !matches.is_empty() {
                hits.push(SearchHit {
                    alias: e.alias.clone(),
                    entry_index: idx,
                    cert_index: Some(ci),
                    cert_name: Some(c.display_name()),
                    matches,
                });
            }
        }
        if alias_hit && e.chain.is_empty() {
            hits.push(SearchHit {
                alias: e.alias.clone(),
                entry_index: idx,
                cert_index: None,
                cert_name: None,
                matches: vec![FieldMatch {
                    field: "別名",
                    value: e.alias.clone(),
                }],
            });
        }
        hits
    }
}

/// 在憑證庫中搜尋關鍵字。
pub fn search(ks: &Keystore, keyword: &str) -> Vec<SearchHit> {
    let m = Matcher::new(keyword);
    if m.is_empty() {
        return vec![];
    }
    ks.entries
        .iter()
        .enumerate()
        .flat_map(|(i, e)| m.entry(i, e))
        .collect()
}
