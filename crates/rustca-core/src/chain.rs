//! 憑證鏈組建與檢查。

use std::collections::HashSet;

use serde::Serialize;

use crate::cert::{CertInfo, ValidityStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LinkSource {
    /// 來自條目本身儲存的憑證鏈
    Entry,
    /// 從憑證庫（或額外信任庫）其他憑證找到的簽發者
    Pool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChainLink {
    pub cert: CertInfo,
    pub source: LinkSource,
    /// 本憑證是否由下一張憑證簽署（最後一張若為自簽則為自身驗證結果）
    pub signature_ok: Option<bool>,
    pub validity: ValidityStatus,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChainEnd {
    /// 結束於自簽根憑證
    Root,
    /// 找不到簽發者
    MissingIssuer { issuer: String },
    /// 鏈中出現循環或過長
    Loop,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuiltChain {
    pub links: Vec<ChainLink>,
    pub end: ChainEnd,
    pub problems: Vec<String>,
}

impl BuiltChain {
    pub fn is_complete(&self) -> bool {
        matches!(self.end, ChainEnd::Root) && self.problems.is_empty()
    }
}

const MAX_DEPTH: usize = 16;

fn issued_by(child: &CertInfo, parent: &CertInfo) -> bool {
    if child.raw_issuer != parent.raw_subject {
        return false;
    }
    match (&child.authority_key_id, &parent.subject_key_id) {
        (Some(a), Some(s)) => a == s,
        _ => true,
    }
}

/// 從 `start`（條目儲存的憑證鏈，終端憑證在前）出發，輔以 `pool` 補齊至根憑證。
pub fn build_chain(start: &[CertInfo], pool: &[&CertInfo], now: i64, warn_days: i64) -> BuiltChain {
    let mut links: Vec<ChainLink> = Vec::new();
    let mut problems = Vec::new();
    let Some(first) = start.first() else {
        return BuiltChain {
            links,
            end: ChainEnd::MissingIssuer {
                issuer: String::new(),
            },
            problems: vec!["沒有任何憑證".into()],
        };
    };

    let mut seen = HashSet::new();
    let mut current = first.clone();
    let mut current_source = LinkSource::Entry;
    let end;

    loop {
        if !seen.insert(current.sha256.clone()) || links.len() >= MAX_DEPTH {
            end = ChainEnd::Loop;
            problems.push("憑證鏈出現循環或過長".into());
            break;
        }
        let validity = current.status_at(now, warn_days);

        if current.self_signed {
            links.push(ChainLink {
                cert: current,
                source: current_source,
                signature_ok: Some(true),
                validity,
            });
            end = ChainEnd::Root;
            break;
        }

        // 1. 先找條目本身鏈中的下一張  2. 再從 pool 找
        let mut candidates: Vec<(CertInfo, LinkSource)> = start
            .iter()
            .filter(|c| issued_by(&current, c))
            .map(|c| (c.clone(), LinkSource::Entry))
            .collect();
        candidates.extend(
            pool.iter()
                .filter(|c| issued_by(&current, c))
                .map(|c| ((*c).clone(), LinkSource::Pool)),
        );

        let mut chosen = None;
        let mut fallback = None;
        for (cand, src) in candidates {
            if cand.sha256 == current.sha256 {
                continue;
            }
            match current.verify_signed_by(&cand) {
                Some(true) => {
                    chosen = Some((cand, src, Some(true)));
                    break;
                }
                None if fallback.is_none() => fallback = Some((cand, src, None)),
                Some(false) if fallback.is_none() => fallback = Some((cand, src, Some(false))),
                _ => {}
            }
        }
        let next = chosen.or(fallback);

        match next {
            Some((parent, src, sig)) => {
                if sig == Some(false) {
                    problems.push(format!(
                        "「{}」的簽章無法用「{}」的公鑰驗證",
                        current.display_name(),
                        parent.display_name()
                    ));
                }
                links.push(ChainLink {
                    cert: current,
                    source: current_source,
                    signature_ok: sig,
                    validity,
                });
                current = parent;
                current_source = src;
            }
            None => {
                let issuer = current.issuer.clone();
                links.push(ChainLink {
                    cert: current,
                    source: current_source,
                    signature_ok: None,
                    validity,
                });
                problems.push(format!("找不到簽發者：{issuer}"));
                end = ChainEnd::MissingIssuer { issuer };
                break;
            }
        }
    }

    for (i, l) in links.iter().enumerate() {
        if l.validity.is_bad() {
            problems.push(format!(
                "第 {} 層「{}」{}",
                i,
                l.cert.display_name(),
                l.validity.label()
            ));
        }
        if i > 0 && !l.cert.is_ca {
            problems.push(format!(
                "第 {} 層「{}」不是 CA 憑證（BasicConstraints CA=false），卻用來簽發下層憑證",
                i,
                l.cert.display_name()
            ));
        }
    }
    // 條目中有未被使用到的憑證，通常代表順序錯誤或多餘憑證
    let used: HashSet<_> = links.iter().map(|l| l.cert.sha256.as_str()).collect();
    for c in start {
        if !used.contains(c.sha256.as_str()) {
            problems.push(format!(
                "條目中的憑證「{}」不在組出的鏈上",
                c.display_name()
            ));
        }
    }

    BuiltChain {
        links,
        end,
        problems,
    }
}

// ───────────── 簽發關係圖 ─────────────

/// 簽發關係圖中的一個節點（前序排列）。
#[derive(Debug, Clone, Serialize)]
pub struct TreeNode {
    pub cert: CertInfo,
    pub depth: usize,
    /// 父節點在 `IssuanceTree::nodes` 的索引；最上層為 None
    pub parent: Option<usize>,
    /// 本憑證的簽章能否用父節點公鑰驗證
    pub signature_ok: Option<bool>,
    /// 位於「目標憑證 → 根」的路徑上
    pub on_path: bool,
    pub is_target: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct IssuanceTree {
    pub nodes: Vec<TreeNode>,
    /// 最上層憑證不是自簽根時，記錄缺少的簽發者
    pub missing_issuer: Option<String>,
    /// 節點過多而截斷
    pub truncated: bool,
}

const MAX_TREE_NODES: usize = 400;

/// 以已組好的憑證鏈（終端在前）找出最上層憑證，
/// 再從它往下列出 `pool` 中所有由它（間接）簽發的憑證。
pub fn issuance_tree(chain: &BuiltChain, pool: &[&CertInfo]) -> IssuanceTree {
    let mut tree = IssuanceTree {
        nodes: vec![],
        missing_issuer: match &chain.end {
            ChainEnd::MissingIssuer { issuer } => Some(issuer.clone()),
            _ => None,
        },
        truncated: false,
    };
    let Some(top) = chain.links.last() else {
        return tree;
    };
    let target = &chain.links[0].cert.sha256;
    let path: HashSet<&str> = chain.links.iter().map(|l| l.cert.sha256.as_str()).collect();

    // 候選：pool + 鏈本身（去重）
    let mut seen = HashSet::new();
    let mut all: Vec<&CertInfo> = Vec::new();
    for c in chain
        .links
        .iter()
        .map(|l| &l.cert)
        .chain(pool.iter().copied())
    {
        if seen.insert(c.sha256.as_str()) {
            all.push(c);
        }
    }

    let mut visited = HashSet::new();
    // (憑證, 深度, 父節點索引, 簽章)
    let mut stack: Vec<(&CertInfo, usize, Option<usize>, Option<bool>)> = vec![(
        &top.cert,
        0,
        None,
        top.signature_ok.filter(|_| top.cert.self_signed),
    )];
    while let Some((cert, depth, parent, sig)) = stack.pop() {
        if !visited.insert(cert.sha256.as_str()) {
            continue;
        }
        if tree.nodes.len() >= MAX_TREE_NODES {
            tree.truncated = true;
            break;
        }
        let idx = tree.nodes.len();
        tree.nodes.push(TreeNode {
            cert: cert.clone(),
            depth,
            parent,
            signature_ok: sig,
            on_path: path.contains(cert.sha256.as_str()),
            is_target: &cert.sha256 == target,
        });
        if depth >= MAX_DEPTH {
            continue;
        }
        let mut children: Vec<&CertInfo> = all
            .iter()
            .copied()
            .filter(|c| {
                c.sha256 != cert.sha256
                    && !c.self_signed
                    && !visited.contains(c.sha256.as_str())
                    && issued_by(c, cert)
            })
            .collect();
        // 路徑上的優先，其次 CA，再依名稱；堆疊後進先出，所以反向推入
        children.sort_by_key(|c| {
            (
                !path.contains(c.sha256.as_str()),
                !c.is_ca,
                c.display_name().to_lowercase(),
            )
        });
        for c in children.into_iter().rev() {
            let sig = c.verify_signed_by(cert);
            stack.push((c, depth + 1, Some(idx), sig));
        }
    }
    tree
}
