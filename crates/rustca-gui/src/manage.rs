//! 憑證庫管理對話框：新增、匯入、刪除、改名、更新憑證、修改密碼、另存新檔。

use std::path::{Path, PathBuf};

use eframe::egui::{self, RichText};
use rustca_core::edit::{CertFormat, Verification, WriteOptions};
use rustca_core::forge::{self, CertSpec, KeyAlg, Profile, Signer};
use rustca_core::{
    edit, load_file, now_ts, CertInfo, Entry, EntryKind, KeyState, Keystore, LoadOptions, Secret,
    StoreFormat,
};

use crate::widgets::{pick_cert_file, pick_cert_files, trunc_label, GREEN, RED, YELLOW};

const MIN_PW: usize = 6;

pub enum Kind {
    NewStore {
        path: Option<PathBuf>,
        format: StoreFormat,
        pw: String,
        pw2: String,
        /// 選填：由多個憑證 / 私鑰檔組成內容
        asm: Box<Assembly>,
    },
    /// 批次匯入多個憑證 / 私鑰檔到既有憑證庫
    Assemble {
        store: usize,
        asm: Box<Assembly>,
        overwrite: bool,
    },
    ImportCert {
        store: usize,
        file: Option<PathBuf>,
        file_pw: String,
        alias: String,
        overwrite: bool,
    },
    ImportKey {
        store: usize,
        /// true：憑證檔 + 私鑰檔；false：另一個憑證庫
        pair: bool,
        src: Option<PathBuf>,
        src_pw: String,
        src_alias: String,
        cert: Option<PathBuf>,
        key: Option<PathBuf>,
        alias: String,
        key_pw: String,
        key_pw2: String,
        overwrite: bool,
    },
    Rename {
        store: usize,
        old: String,
        new: String,
    },
    UpdateCert {
        store: usize,
        alias: String,
        file: Option<PathBuf>,
        file_pw: String,
    },
    KeyPass {
        store: usize,
        alias: String,
        current: String,
        new: String,
        new2: String,
    },
    /// 驗證私鑰密碼是否正確
    CheckKeyPass {
        store: usize,
        alias: String,
        pw: String,
    },
    StorePass {
        store: usize,
        new: String,
        new2: String,
        also_keys: bool,
    },
    Delete {
        store: usize,
        alias: String,
    },
    SaveAs {
        store: usize,
        path: Option<PathBuf>,
        format: StoreFormat,
        pw: String,
        pw2: String,
        /// PKCS#12 舊版相容演算法
        legacy: bool,
    },
    /// 有未儲存的變更時確認關閉；None 表示關閉程式
    ConfirmClose {
        store: Option<usize>,
    },
    /// 轉換憑證檔格式（PEM / DER / P7B）
    ConvertCert {
        file: Option<PathBuf>,
        file_pw: String,
        format: CertFormat,
        with_key: bool,
    },
    /// 製作憑證鏈
    GenChain(Box<GenChain>),
}

/// 由多個憑證 / 私鑰檔組成憑證庫內容。
#[derive(Default)]
pub struct Assembly {
    pub files: Vec<PathBuf>,
    /// 來源檔密碼（.p12 / .jks / 加密私鑰）
    pub pw: String,
    pub plan: edit::AssemblyPlan,
    /// 無法讀取的檔案
    pub errors: Vec<String>,
}

impl Assembly {
    pub fn reload(&mut self) {
        self.errors.clear();
        let mut loaded = Vec::new();
        for f in &self.files {
            let opts = LoadOptions {
                password: nonempty(&self.pw),
                key_password: None,
            };
            // 有密碼先用密碼讀，失敗再不帶密碼（.cer / .pem 不需要密碼）
            let r = load_file(f, &opts).or_else(|e| {
                if opts.password.is_some() {
                    load_file(f, &LoadOptions::default()).map_err(|_| e)
                } else {
                    Err(e)
                }
            });
            match r {
                Ok(ks) => loaded.push(ks),
                Err(e) if e.is_password_problem() => self.errors.push(format!(
                    "{}：需要密碼或密碼錯誤，請填「來源檔密碼」",
                    file_name(f)
                )),
                Err(e) => self.errors.push(format!("{}：{e}", file_name(f))),
            }
        }
        self.plan = edit::plan_assembly(&loaded);
    }

    fn selected(&self) -> usize {
        self.plan.keys.iter().filter(|k| k.include).count()
            + self.plan.certs.iter().filter(|c| c.include).count()
    }

    /// 套用前檢查：別名不可空白或重複。
    fn check(&self) -> Result<(), String> {
        let mut seen = std::collections::HashSet::new();
        let aliases = self
            .plan
            .keys
            .iter()
            .filter(|k| k.include)
            .map(|k| &k.alias)
            .chain(
                self.plan
                    .certs
                    .iter()
                    .filter(|c| c.include)
                    .map(|c| &c.alias),
            );
        for a in aliases {
            let a = a.trim();
            if a.is_empty() {
                return Err("有條目的別名是空白".into());
            }
            if !seen.insert(a.to_lowercase()) {
                return Err(format!("別名「{a}」重複"));
            }
        }
        Ok(())
    }
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

/// 「憑證 / 私鑰檔」選取與預覽（放在表單 Grid 的一列中）。
fn assembly_ui(ui: &mut egui::Ui, label: &str, a: &mut Assembly) {
    ui.label(label);
    ui.vertical(|ui| {
        let mut reload = false;
        ui.horizontal_wrapped(|ui| {
            if ui
                .button("📂 選擇憑證 / 私鑰檔…")
                .on_hover_text("可多選：.cer / .crt / .pem / .key / .p7b / .p12 / .jks")
                .clicked()
            {
                for f in pick_cert_files() {
                    if !a.files.contains(&f) {
                        a.files.push(f);
                    }
                }
                reload = true;
            }
            if !a.files.is_empty() {
                if ui.button("清除").clicked() {
                    *a = Assembly::default();
                }
                ui.weak(format!("已選 {} 個檔案", a.files.len()))
                    .on_hover_text(
                        a.files
                            .iter()
                            .map(|f| f.display().to_string())
                            .collect::<Vec<_>>()
                            .join("\n"),
                    );
            }
        });
        ui.horizontal(|ui| {
            ui.label("來源檔密碼");
            let r = ui.add(
                egui::TextEdit::singleline(&mut a.pw)
                    .password(true)
                    .hint_text(".p12 / .jks / 加密私鑰才需要")
                    .desired_width(180.0),
            );
            if r.lost_focus() && !a.files.is_empty() {
                reload = true;
            }
            if !a.files.is_empty() && ui.small_button("🔄 重新分析").clicked() {
                reload = true;
            }
        });
        if reload {
            a.reload();
        }
        if a.files.is_empty() {
            ui.weak(
                "私鑰會依公鑰自動配對憑證，並用一起選取的 CA 憑證補齊憑證鏈；其餘憑證成為信任憑證",
            );
            return;
        }
        let now = now_ts();
        egui::Grid::new("asm_plan")
            .num_columns(5)
            .striped(true)
            .spacing([10.0, 4.0])
            .show(ui, |ui| {
                ui.strong("");
                ui.strong("別名");
                ui.strong("類型");
                ui.strong("憑證");
                ui.strong("來源");
                ui.end_row();
                for k in a.plan.keys.iter_mut() {
                    ui.checkbox(&mut k.include, "");
                    ui.add_sized([170.0, 20.0], egui::TextEdit::singleline(&mut k.alias));
                    let t = format!("🔑 私鑰條目（鏈 {}）", k.chain.len());
                    if k.complete {
                        ui.colored_label(GREEN, t)
                            .on_hover_text("憑證鏈完整，連到自簽根憑證");
                    } else {
                        ui.colored_label(YELLOW, format!("{t} ⚠"))
                            .on_hover_text("找不到上層 CA，憑證鏈不完整；可再加入 CA 的 .cer");
                    }
                    cert_cell(ui, &k.chain[0], now);
                    trunc_label(ui, RichText::new(&k.source).weak(), 260.0);
                    ui.end_row();
                }
                for c in a.plan.certs.iter_mut() {
                    ui.checkbox(&mut c.include, "");
                    ui.add_sized([170.0, 20.0], egui::TextEdit::singleline(&mut c.alias));
                    ui.label(format!("信任憑證 · {}", c.cert.role()));
                    cert_cell(ui, &c.cert, now);
                    trunc_label(ui, RichText::new(&c.source).weak(), 260.0);
                    ui.end_row();
                }
            });
        for p in a.plan.problems.iter().chain(&a.errors) {
            ui.colored_label(YELLOW, format!("⚠ {p}"));
        }
        if a.plan.keys.is_empty() && a.plan.certs.is_empty() {
            ui.colored_label(YELLOW, "沒有可加入的憑證");
        }
    });
    ui.end_row();
}

fn cert_cell(ui: &mut egui::Ui, c: &CertInfo, now: i64) {
    let st = c.status_at(now, 30);
    let text = format!(
        "{} · 到期 {}",
        c.display_name(),
        rustca_core::format_ts(c.not_after)
            .chars()
            .take(10)
            .collect::<String>()
    );
    let color = crate::widgets::status_color(st);
    trunc_label(ui, RichText::new(text).color(color), 300.0).on_hover_text(format!(
        "主體：{}\n簽發者：{}\n{}",
        c.subject,
        c.issuer,
        st.label()
    ));
}

/// 「製作憑證鏈」表單。
pub struct GenChain {
    pub store: usize,
    /// None＝建立新的根 CA；Some(alias)＝用庫中 CA 簽發
    pub issuer: Option<String>,
    pub root_cn: String,
    /// 中繼 CA，每行一個 CN
    pub inters: String,
    pub make_leaf: bool,
    pub leaf_cn: String,
    /// SAN，以逗號或換行分隔
    pub sans: String,
    pub profile: Profile,
    pub key: KeyAlg,
    pub ca_key: KeyAlg,
    pub days: u32,
    pub ca_days: u32,
    pub org: String,
    pub ou: String,
    pub country: String,
    pub alias: String,
    pub keep_ca_keys: bool,
    pub key_pw: String,
    pub key_pw2: String,
}

impl GenChain {
    pub fn new(store: usize) -> Self {
        GenChain {
            store,
            issuer: None,
            root_cn: "My Root CA".into(),
            inters: "My Issuing CA".into(),
            make_leaf: true,
            leaf_cn: String::new(),
            sans: String::new(),
            profile: Profile::Server,
            key: KeyAlg::Rsa2048,
            ca_key: KeyAlg::Rsa2048,
            days: 825,
            ca_days: 3650,
            org: String::new(),
            ou: String::new(),
            country: "TW".into(),
            alias: String::new(),
            keep_ca_keys: false,
            key_pw: String::new(),
            key_pw2: String::new(),
        }
    }
}

pub struct Dialog {
    pub kind: Kind,
    pub error: Option<String>,
}

impl From<Kind> for Dialog {
    fn from(kind: Kind) -> Self {
        Dialog { kind, error: None }
    }
}

/// 執行結果，由 App 套用到狀態上。
pub enum Effect {
    Modified(usize, String),
    /// 已修改，並附上憑證鏈驗證結果
    Verified(usize, String, Verification),
    /// 不影響憑證庫的動作（例如輸出檔案）
    Done(String),
    Saved(usize, String),
    Created(Box<Keystore>, String),
    Close(Option<usize>),
}

pub fn guess_format(path: &Path) -> StoreFormat {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("p12" | "pfx") => StoreFormat::Pkcs12,
        Some("jceks") => StoreFormat::Jceks,
        _ => StoreFormat::Jks,
    }
}

fn ext_of(f: StoreFormat) -> &'static str {
    match f {
        StoreFormat::Pkcs12 => "p12",
        StoreFormat::Jceks => "jceks",
        _ => "jks",
    }
}

fn nonempty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

fn new_pw(a: &str, b: &str) -> Result<String, String> {
    if a.chars().count() < MIN_PW {
        Err(format!("密碼至少需要 {MIN_PW} 個字元"))
    } else if a != b {
        Err("兩次輸入的密碼不一致".into())
    } else {
        Ok(a.to_string())
    }
}

fn load_src(path: &Option<PathBuf>, pw: &str, what: &str) -> Result<Keystore, String> {
    let path = path.as_ref().ok_or_else(|| format!("請選擇{what}"))?;
    load_file(
        path,
        &LoadOptions {
            password: nonempty(pw),
            key_password: None,
        },
    )
    .map_err(|e| {
        if e.is_password_problem() {
            format!("{}：需要密碼或密碼錯誤（{e}）", path.display())
        } else {
            format!("{}：{e}", path.display())
        }
    })
}

fn editable(ks: &Keystore) -> Result<(), String> {
    if !edit::is_writable(ks.format) {
        return Err(format!(
            "{} 格式無法直接編輯，請先「另存新檔」轉成 JKS / PKCS#12",
            ks.format
        ));
    }
    if ks.store_password.is_none() {
        return Err("此憑證庫未以密碼開啟，請先按「解鎖」輸入密碼".into());
    }
    Ok(())
}

fn first_key_entry(ks: &Keystore, alias: &str) -> Result<Entry, String> {
    let e = if alias.trim().is_empty() {
        ks.private_key_entries().next()
    } else {
        ks.entry(alias.trim())
    };
    e.cloned()
        .ok_or_else(|| format!("{} 中找不到私鑰條目", ks.name()))
}

/// 執行對話框的動作。成功時才會修改 `stores`。
pub fn apply(kind: &Kind, stores: &mut [Keystore]) -> Result<Effect, String> {
    let s = |e: rustca_core::Error| e.to_string();
    match kind {
        Kind::NewStore {
            path,
            format,
            pw,
            pw2,
            asm,
        } => {
            let path = path.as_ref().ok_or("請選擇檔案位置")?;
            if path.exists() {
                return Err(format!("{} 已存在", path.display()));
            }
            let pw = new_pw(pw, pw2)?;
            asm.check()?;
            let mut ks = edit::new_keystore(path, *format, &pw).map_err(s)?;
            let n = edit::apply_assembly(&mut ks, &asm.plan, false).map_err(s)?;
            edit::save(&mut ks, None, None, false).map_err(s)?;
            let mut msg = format!("已建立 {} 憑證庫：{}", ks.format, path.display());
            if n > 0 {
                msg.push_str(&format!("（{n} 個條目）"));
            }
            Ok(Effect::Created(Box::new(ks), msg))
        }
        Kind::Assemble {
            store,
            asm,
            overwrite,
        } => {
            let mut ks = stores[*store].clone();
            editable(&ks)?;
            if asm.selected() == 0 {
                return Err("請選擇要匯入的憑證 / 私鑰檔".into());
            }
            asm.check()?;
            let n = edit::apply_assembly(&mut ks, &asm.plan, *overwrite).map_err(s)?;
            stores[*store] = ks;
            Ok(Effect::Modified(*store, format!("已批次匯入 {n} 個條目")))
        }
        Kind::ImportCert {
            store,
            file,
            file_pw,
            alias,
            overwrite,
        } => {
            let mut ks = stores[*store].clone();
            editable(&ks)?;
            let src = load_src(file, file_pw, "憑證檔")?;
            let certs: Vec<CertInfo> = src.all_certs().into_iter().cloned().collect();
            let added = edit::import_certs(&mut ks, alias.trim(), &certs, *overwrite).map_err(s)?;
            stores[*store] = ks;
            Ok(Effect::Modified(
                *store,
                format!("已匯入 {} 張信任憑證：{}", added.len(), added.join("、")),
            ))
        }
        Kind::ImportKey {
            store,
            pair,
            src,
            src_pw,
            src_alias,
            cert,
            key,
            alias,
            key_pw,
            key_pw2,
            overwrite,
        } => {
            let mut ks = stores[*store].clone();
            editable(&ks)?;
            let alias = alias.trim();
            let entry = if *pair {
                let cks = load_src(cert, "", "憑證檔")?;
                let kks = load_src(key, src_pw, "私鑰檔")?;
                let certs: Vec<CertInfo> = cks.all_certs().into_iter().cloned().collect();
                let k = first_key_entry(&kks, "")?;
                edit::entry_from_cert_and_key(alias, &certs, &k).map_err(s)?
            } else {
                let sks = load_src(src, src_pw, "來源憑證庫")?;
                first_key_entry(&sks, src_alias)?
            };
            let kp = if ks.format != StoreFormat::Pkcs12 && !key_pw.is_empty() {
                Some(new_pw(key_pw, key_pw2)?)
            } else {
                None
            };
            edit::import_key_entry(&mut ks, alias, &entry, kp.as_deref(), *overwrite).map_err(s)?;
            let subject = entry.leaf().map(|c| c.display_name()).unwrap_or_default();
            stores[*store] = ks;
            Ok(Effect::Modified(
                *store,
                format!(
                    "已匯入金鑰對「{alias}」（{subject}，鏈 {} 張）",
                    entry.chain.len()
                ),
            ))
        }
        Kind::Rename { store, old, new } => {
            let mut ks = stores[*store].clone();
            editable(&ks)?;
            edit::rename_entry(&mut ks, old, new.trim()).map_err(s)?;
            stores[*store] = ks;
            let mut msg = format!("已將「{old}」改名為「{}」", new.trim());
            if matches!(stores[*store].format, StoreFormat::Jks | StoreFormat::Jceks)
                && new.trim() != new.trim().to_lowercase()
            {
                msg.push_str("（JKS / JCEKS 儲存時別名會轉成小寫）");
            }
            Ok(Effect::Modified(*store, msg))
        }
        Kind::UpdateCert {
            store,
            alias,
            file,
            file_pw,
        } => {
            let mut ks = stores[*store].clone();
            editable(&ks)?;
            let src = load_src(file, file_pw, "新憑證檔")?;
            let certs: Vec<CertInfo> = src.all_certs().into_iter().cloned().collect();
            // 替換後驗證；驗證失敗不套用
            let (notes, v) = edit::replace_chain(&mut ks, alias, &certs).map_err(s)?;
            stores[*store] = ks;
            let mut msg = format!("已替換「{alias}」的憑證鏈，驗證通過");
            if !notes.is_empty() {
                msg.push_str(&format!("（{}）", notes.join("；")));
            }
            Ok(Effect::Verified(*store, msg, v))
        }
        Kind::KeyPass {
            store,
            alias,
            current,
            new,
            new2,
        } => {
            let mut ks = stores[*store].clone();
            editable(&ks)?;
            let locked = ks
                .entry(alias)
                .is_some_and(|e| matches!(e.key, KeyState::Locked(_)));
            if locked {
                if current.is_empty() {
                    return Err("此私鑰尚未解密，請輸入目前的私鑰密碼".into());
                }
                edit::unlock_entry(&mut ks, alias, current).map_err(s)?;
            }
            let pw = new_pw(new, new2)?;
            edit::set_key_password(&mut ks, alias, &pw).map_err(s)?;
            stores[*store] = ks;
            Ok(Effect::Modified(
                *store,
                format!("已修改「{alias}」的私鑰密碼"),
            ))
        }
        Kind::CheckKeyPass { store, alias, pw } => {
            let ks = &mut stores[*store];
            if edit::check_key_password(ks, alias, pw).map_err(s)? {
                let locked = ks
                    .entry(alias)
                    .is_some_and(|e| matches!(e.key, KeyState::Locked(_)));
                if locked {
                    edit::unlock_entry(ks, alias, pw).map_err(s)?;
                    Ok(Effect::Done(format!(
                        "✔「{alias}」的私鑰密碼正確，私鑰已解開"
                    )))
                } else {
                    Ok(Effect::Done(format!("✔「{alias}」的私鑰密碼正確")))
                }
            } else {
                Err(format!("✘「{alias}」的私鑰密碼不正確"))
            }
        }
        Kind::StorePass {
            store,
            new,
            new2,
            also_keys,
        } => {
            let mut ks = stores[*store].clone();
            editable(&ks)?;
            let pw = new_pw(new, new2)?;
            edit::set_store_password(&mut ks, &pw, *also_keys).map_err(s)?;
            stores[*store] = ks;
            let msg = if *also_keys || stores[*store].format == StoreFormat::Pkcs12 {
                "已修改憑證庫密碼（私鑰密碼原本相同者一併修改）"
            } else {
                "已修改憑證庫密碼（私鑰維持原密碼）"
            };
            Ok(Effect::Modified(*store, msg.into()))
        }
        Kind::Delete { store, alias } => {
            let mut ks = stores[*store].clone();
            editable(&ks)?;
            let e = edit::delete_entry(&mut ks, alias).map_err(s)?;
            stores[*store] = ks;
            Ok(Effect::Modified(
                *store,
                format!("已刪除「{}」（{}）", e.alias, e.kind),
            ))
        }
        Kind::SaveAs {
            store,
            path,
            format,
            pw,
            pw2,
            legacy,
        } => {
            let path = path.as_ref().ok_or("請選擇儲存位置")?;
            let mut ks = stores[*store].clone();
            if ks.store_password.is_none() {
                ks.store_password = Some(Secret::new(new_pw(pw, pw2)?));
            }
            let rep = edit::save_with(
                &mut ks,
                Some(path),
                Some(*format),
                true,
                WriteOptions {
                    pkcs12_legacy: *legacy,
                },
            )
            .map_err(s)?;
            stores[*store] = ks;
            Ok(Effect::Saved(*store, save_message(&rep)))
        }
        Kind::ConfirmClose { store } => Ok(Effect::Close(*store)),
        Kind::ConvertCert {
            file,
            file_pw,
            format,
            with_key,
        } => convert_cert(file, file_pw, *format, *with_key),
        Kind::GenChain(g) => gen_chain(g, stores),
    }
}

fn convert_cert(
    file: &Option<PathBuf>,
    file_pw: &str,
    format: CertFormat,
    with_key: bool,
) -> Result<Effect, String> {
    let src = load_src(file, file_pw, "來源檔案")?;
    let mut certs = src.all_certs();
    if certs.is_empty() {
        return Err("來源中沒有憑證".into());
    }
    let mut note = String::new();
    if format == CertFormat::Der && certs.len() > 1 {
        note = format!("（DER 只能存一張，已輸出第一張；共 {} 張）", certs.len());
        certs.truncate(1);
    }
    let mut data = edit::encode_certs(&certs, format).map_err(|e| e.to_string())?;
    if with_key {
        let e = src.private_key_entries().next().ok_or("來源中沒有私鑰")?;
        data.extend(
            edit::private_key_pem(e)
                .map_err(|e| e.to_string())?
                .into_bytes(),
        );
    }
    let stem = file
        .as_ref()
        .and_then(|p| p.file_stem())
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "cert".into());
    let Some(out) = rfd::FileDialog::new()
        .set_file_name(format!("{stem}.{}", format.extension()))
        .save_file()
    else {
        return Err("已取消".into());
    };
    std::fs::write(&out, data).map_err(|e| format!("寫入失敗：{e}"))?;
    Ok(Effect::Done(format!(
        "已輸出 {} 張憑證{}（{}）：{}{note}",
        certs.len(),
        if with_key { " + 未加密私鑰" } else { "" },
        format.label(),
        out.display()
    )))
}

fn slug(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

/// 可作為簽發者的條目：私鑰已解密的 CA。
pub fn issuer_candidates(ks: &Keystore) -> Vec<String> {
    ks.private_key_entries()
        .filter(|e| matches!(e.key, KeyState::Decrypted { .. }))
        .filter(|e| e.chain.first().is_some_and(|c| c.is_ca))
        .map(|e| e.alias.clone())
        .collect()
}

fn gen_chain(g: &GenChain, stores: &mut [Keystore]) -> Result<Effect, String> {
    let s = |e: rustca_core::Error| e.to_string();
    let mut ks = stores[g.store].clone();
    editable(&ks)?;
    let kp = if ks.format != StoreFormat::Pkcs12 && !g.key_pw.is_empty() {
        Some(new_pw(&g.key_pw, &g.key_pw2)?)
    } else {
        None
    };
    let subject = |cn: &str, with_ou: bool| forge::Subject {
        cn: cn.trim().to_string(),
        o: g.org.clone(),
        ou: if with_ou { g.ou.clone() } else { String::new() },
        c: g.country.clone(),
        ..Default::default()
    };
    let leaf = g.make_leaf.then(|| {
        let mut sp = CertSpec::new(g.leaf_cn.trim(), g.profile);
        sp.subject = subject(&g.leaf_cn, true);
        sp.key = g.key;
        sp.days = g.days;
        sp.sans = g
            .sans
            .split([',', '\n', ';'])
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect();
        sp
    });
    let leaf_alias = |l: &CertSpec| {
        if g.alias.trim().is_empty() {
            slug(&l.subject.cn)
        } else {
            g.alias.trim().to_string()
        }
    };

    let (alias, msg) = if let Some(ia) = &g.issuer {
        let leaf = leaf.ok_or("用既有 CA 簽發時需要建立終端憑證")?;
        let ie = ks.entry(ia).ok_or("找不到簽發者")?.clone();
        let KeyState::Decrypted { format, der } = &ie.key else {
            return Err("簽發者的私鑰尚未解密".into());
        };
        let ca = ie.chain.first().ok_or("簽發者沒有憑證")?;
        let ikey = edit::to_pkcs8(*format, der).map_err(s)?;
        let issued = forge::issue(
            &leaf,
            Some(Signer {
                cert: ca,
                key_pkcs8: &ikey,
            }),
            None,
        )
        .map_err(s)?;
        let mut chain = vec![issued.cert.clone()];
        chain.extend(ie.chain.iter().cloned());
        let a = leaf_alias(&leaf);
        edit::add_key_entry(&mut ks, &a, chain, issued.key_pkcs8, kp.as_deref(), false)
            .map_err(s)?;
        let msg = format!("已由「{ia}」簽發「{a}」");
        (Some(a), msg)
    } else {
        let mk = |cn: &str, p: Profile| {
            let mut sp = CertSpec::new(cn.trim(), p);
            sp.subject = subject(cn, false);
            sp.key = g.ca_key;
            sp.days = g.ca_days;
            sp
        };
        let mut specs = vec![mk(&g.root_cn, Profile::RootCa)];
        for l in g.inters.lines().filter(|l| !l.trim().is_empty()) {
            specs.push(mk(l, Profile::IntermediateCa));
        }
        let n_ca = specs.len();
        if let Some(l) = &leaf {
            specs.push(l.clone());
        }
        let issued = forge::issue_chain(&specs, None).map_err(s)?;
        let keep = g.keep_ca_keys || leaf.is_none();
        for (i, it) in issued.iter().take(n_ca).enumerate() {
            let a = slug(&it.cert.display_name());
            if keep {
                let chain: Vec<CertInfo> =
                    issued[..=i].iter().rev().map(|x| x.cert.clone()).collect();
                edit::add_key_entry(
                    &mut ks,
                    &a,
                    chain,
                    it.key_pkcs8.clone(),
                    kp.as_deref(),
                    false,
                )
                .map_err(s)?;
            } else {
                edit::import_certs(&mut ks, &a, std::slice::from_ref(&it.cert), false)
                    .map_err(s)?;
            }
        }
        match &leaf {
            Some(l) => {
                let a = leaf_alias(l);
                let chain: Vec<CertInfo> = issued.iter().rev().map(|x| x.cert.clone()).collect();
                let it = issued.last().unwrap();
                edit::add_key_entry(
                    &mut ks,
                    &a,
                    chain,
                    it.key_pkcs8.clone(),
                    kp.as_deref(),
                    false,
                )
                .map_err(s)?;
                (
                    Some(a.clone()),
                    format!("已製作憑證鏈：{} 層 CA → 「{a}」", n_ca),
                )
            }
            None => (
                None,
                format!("已建立 {} 層 CA（含私鑰，可再用來簽發）", n_ca),
            ),
        }
    };
    let v = match &alias {
        Some(a) => Some(edit::verify_entry(&ks, a, now_ts()).map_err(s)?),
        None => None,
    };
    stores[g.store] = ks;
    Ok(match v {
        Some(v) => Effect::Verified(g.store, msg, v),
        None => Effect::Modified(g.store, msg),
    })
}

/// 直接儲存（寫回原檔，建立備份）。
pub fn save_in_place(ks: &mut Keystore) -> Result<String, String> {
    editable(ks)?;
    let mut copy = ks.clone();
    let rep = edit::save(&mut copy, None, None, true).map_err(|e| e.to_string())?;
    *ks = copy;
    Ok(save_message(&rep))
}

fn save_message(rep: &edit::SaveReport) -> String {
    let mut msg = format!("已儲存：{}", rep.path.display());
    if let Some(b) = &rep.backup {
        msg.push_str(&format!(
            "（備份：{}）",
            b.file_name().unwrap_or_default().to_string_lossy()
        ));
    }
    for w in &rep.warnings {
        msg.push_str(&format!("　⚠ {w}"));
    }
    msg
}

/// 匯出條目的憑證（或整條鏈）為 PEM 檔。
pub fn export_entry(e: &Entry, chain: bool) -> Result<Option<String>, String> {
    let certs: Vec<&CertInfo> = if chain {
        e.chain.iter().collect()
    } else {
        e.chain.first().into_iter().collect()
    };
    if certs.is_empty() {
        return Err("此條目沒有憑證".into());
    }
    let Some(path) = rfd::FileDialog::new()
        .set_file_name(format!("{}.pem", e.alias))
        .add_filter("PEM", &["pem", "crt", "cer"])
        .save_file()
    else {
        return Ok(None);
    };
    let data = edit::export_certs(&certs, true).map_err(|e| e.to_string())?;
    std::fs::write(&path, data).map_err(|e| format!("寫入失敗：{e}"))?;
    Ok(Some(format!(
        "已匯出 {} 張憑證：{}",
        certs.len(),
        path.display()
    )))
}

// ───────────── UI ─────────────

fn pw_field(ui: &mut egui::Ui, label: &str, v: &mut String, hint: &str) {
    ui.label(label);
    ui.add(
        egui::TextEdit::singleline(v)
            .password(true)
            .hint_text(hint)
            .desired_width(240.0),
    );
    ui.end_row();
}

fn text_field(ui: &mut egui::Ui, label: &str, v: &mut String, hint: &str) {
    ui.label(label);
    ui.add(
        egui::TextEdit::singleline(v)
            .hint_text(hint)
            .desired_width(240.0),
    );
    ui.end_row();
}

/// 檔案欄位；選了新檔案時回傳 true。
fn file_field(ui: &mut egui::Ui, label: &str, v: &mut Option<PathBuf>) -> bool {
    ui.label(label);
    let mut changed = false;
    ui.horizontal(|ui| {
        if ui.button("📂 選擇…").clicked() {
            if let Some(p) = pick_cert_file() {
                *v = Some(p);
                changed = true;
            }
        }
        match v {
            Some(p) => trunc_label(ui, p.display().to_string(), 420.0),
            None => ui.weak("（未選擇）"),
        };
    });
    ui.end_row();
    changed
}

fn save_field(
    ui: &mut egui::Ui,
    v: &mut Option<PathBuf>,
    format: &mut StoreFormat,
    default_name: &str,
) {
    ui.label("檔案");
    ui.horizontal(|ui| {
        if ui.button("📂 選擇位置…").clicked() {
            let name = v
                .as_ref()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| default_name.to_string());
            if let Some(p) = rfd::FileDialog::new()
                .set_file_name(name)
                .add_filter("Java KeyStore", &["jks", "keystore"])
                .add_filter("JCEKS", &["jceks"])
                .add_filter("PKCS#12", &["p12", "pfx"])
                .save_file()
            {
                *format = guess_format(&p);
                *v = Some(p);
            }
        }
        match v {
            Some(p) => trunc_label(ui, p.display().to_string(), 420.0),
            None => ui.weak("（未選擇）"),
        };
    });
    ui.end_row();
    ui.label("格式");
    ui.horizontal(|ui| {
        let before = *format;
        ui.radio_value(format, StoreFormat::Jks, "JKS");
        ui.radio_value(format, StoreFormat::Jceks, "JCEKS");
        ui.radio_value(format, StoreFormat::Pkcs12, "PKCS#12");
        // 切換格式時順便更新副檔名
        if *format != before {
            if let Some(p) = v.as_mut() {
                p.set_extension(ext_of(*format));
            }
        }
    });
    ui.end_row();
}

fn default_alias(p: &Path) -> String {
    p.file_stem()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

fn title(kind: &Kind) -> &'static str {
    match kind {
        Kind::NewStore { .. } => "🆕 新增憑證庫",
        Kind::Assemble { .. } => "📥 批次匯入憑證 / 私鑰檔",
        Kind::ImportCert { .. } => "➕ 匯入信任憑證",
        Kind::ImportKey { .. } => "➕ 匯入金鑰對",
        Kind::Rename { .. } => "✏ 修改別名",
        Kind::UpdateCert { .. } => "🔄 更新憑證",
        Kind::KeyPass { .. } => "🔑 修改私鑰密碼（key pass）",
        Kind::CheckKeyPass { .. } => "🔍 驗證私鑰密碼（key pass）",
        Kind::StorePass { .. } => "🔐 修改憑證庫密碼（store pass）",
        Kind::Delete { .. } => "🗑 刪除條目",
        Kind::SaveAs { .. } => "💾 另存新檔 / 轉換格式",
        Kind::ConfirmClose { .. } => "⚠ 尚未儲存",
        Kind::ConvertCert { .. } => "🔁 轉換憑證格式",
        Kind::GenChain(_) => "🏭 製作憑證鏈",
    }
}

/// 顯示對話框。回傳 Some(true)＝確定、Some(false)＝取消。
pub fn show(d: &mut Dialog, ctx: &egui::Context, stores: &[Keystore]) -> Option<bool> {
    let mut result = None;
    let mut ok_label = "確定";
    // 破壞性動作不接受 Enter 快速確認
    let enter_ok = !matches!(d.kind, Kind::Delete { .. } | Kind::ConfirmClose { .. });
    let max_h = crate::tools::max_window_height(ctx);
    egui::Window::new(title(&d.kind))
        .collapsible(false)
        .resizable(false)
        .max_height(max_h)
        .max_width(crate::tools::max_window_width(ctx))
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            let store_name = |i: &usize| stores.get(*i).map(|s| s.name()).unwrap_or_default();
            // 欄位多時（如製作憑證鏈）可捲動，底部的確定 / 取消永遠看得到
            egui::ScrollArea::both()
                .max_height((max_h - 110.0).max(120.0))
                // 螢幕放得下就完整顯示，放不下才出現水平捲軸
                .min_scrolled_width(crate::tools::max_window_width(ctx) - 30.0)
                .show(ui, |ui| {
            egui::Grid::new("manage_form")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| match &mut d.kind {
                    Kind::NewStore {
                        path,
                        format,
                        pw,
                        pw2,
                        asm,
                    } => {
                        save_field(ui, path, format, "keystore.jks");
                        pw_field(ui, "憑證庫密碼", pw, "至少 6 個字元");
                        pw_field(ui, "再次輸入", pw2, "");
                        assembly_ui(ui, "內容（選填）", asm);
                        ok_label = if asm.selected() > 0 { "建立並加入" } else { "建立空的憑證庫" };
                    }
                    Kind::Assemble {
                        store,
                        asm,
                        overwrite,
                    } => {
                        ui.label("匯入到");
                        ui.strong(store_name(store));
                        ui.end_row();
                        assembly_ui(ui, "檔案", asm);
                        ui.label("");
                        ui.checkbox(overwrite, "別名已存在時覆蓋");
                        ui.end_row();
                        ok_label = "匯入";
                    }
                    Kind::ImportCert {
                        store,
                        file,
                        file_pw,
                        alias,
                        overwrite,
                    } => {
                        ui.label("匯入到");
                        ui.strong(store_name(store));
                        ui.end_row();
                        if file_field(ui, "憑證檔", file) && alias.is_empty() {
                            *alias = file.as_deref().map(default_alias).unwrap_or_default();
                        }
                        pw_field(ui, "檔案密碼", file_pw, "從 .p12 / .jks 取憑證時才需要");
                        text_field(ui, "別名", alias, "多張憑證時自動加 -2、-3…");
                        ui.label("");
                        ui.checkbox(overwrite, "別名已存在時覆蓋");
                        ui.end_row();
                        ok_label = "匯入";
                    }
                    Kind::ImportKey {
                        store,
                        pair,
                        src,
                        src_pw,
                        src_alias,
                        cert,
                        key,
                        alias,
                        key_pw,
                        key_pw2,
                        overwrite,
                    } => {
                        let is_p12 = stores
                            .get(*store)
                            .is_some_and(|s| s.format == StoreFormat::Pkcs12);
                        ui.label("匯入到");
                        ui.strong(store_name(store));
                        ui.end_row();
                        ui.label("來源");
                        ui.horizontal(|ui| {
                            ui.radio_value(pair, false, "另一個憑證庫（.p12 / .jks）");
                            ui.radio_value(pair, true, "憑證檔 + 私鑰檔");
                        });
                        ui.end_row();
                        if *pair {
                            if file_field(ui, "憑證檔", cert) && alias.is_empty() {
                                *alias = cert.as_deref().map(default_alias).unwrap_or_default();
                            }
                            file_field(ui, "私鑰檔", key);
                            pw_field(ui, "私鑰檔密碼", src_pw, "未加密可留空");
                        } else {
                            if file_field(ui, "來源檔案", src) && alias.is_empty() {
                                *alias = src.as_deref().map(default_alias).unwrap_or_default();
                            }
                            pw_field(ui, "來源密碼", src_pw, "");
                            text_field(ui, "來源別名", src_alias, "留空＝第一個私鑰條目");
                        }
                        text_field(ui, "新別名", alias, "");
                        if !is_p12 {
                            pw_field(ui, "私鑰密碼", key_pw, "留空＝與憑證庫密碼相同");
                            if !key_pw.is_empty() {
                                pw_field(ui, "再次輸入", key_pw2, "");
                            }
                        }
                        ui.label("");
                        ui.checkbox(overwrite, "別名已存在時覆蓋");
                        ui.end_row();
                        ok_label = "匯入";
                    }
                    Kind::Rename { old, new, .. } => {
                        ui.label("目前別名");
                        ui.strong(old.as_str());
                        ui.end_row();
                        text_field(ui, "新別名", new, "");
                    }
                    Kind::UpdateCert {
                        store,
                        alias,
                        file,
                        file_pw,
                    } => {
                        let is_key = stores
                            .get(*store)
                            .and_then(|s| s.entry(alias))
                            .is_some_and(|e| e.kind == EntryKind::PrivateKey);
                        ui.label("別名");
                        ui.strong(alias.as_str());
                        ui.end_row();
                        file_field(ui, "新憑證檔", file);
                        pw_field(ui, "檔案密碼", file_pw, "從 .p12 / .jks 取憑證時才需要");
                        ui.label("");
                        ui.weak(if is_key {
                            "私鑰條目：以新的憑證鏈取代（續約 / CA 回覆），\n會檢查憑證與私鑰相符，並用憑證庫中的 CA 補齊鏈"
                        } else {
                            "信任憑證：以新憑證取代"
                        });
                        ui.end_row();
                        ok_label = "更新";
                    }
                    Kind::KeyPass {
                        store,
                        alias,
                        current,
                        new,
                        new2,
                    } => {
                        let locked = stores
                            .get(*store)
                            .and_then(|s| s.entry(alias))
                            .is_some_and(|e| matches!(e.key, KeyState::Locked(_)));
                        ui.label("別名");
                        ui.strong(alias.as_str());
                        ui.end_row();
                        if locked {
                            pw_field(ui, "目前私鑰密碼", current, "此私鑰尚未解密");
                        }
                        pw_field(ui, "新私鑰密碼", new, "至少 6 個字元");
                        pw_field(ui, "再次輸入", new2, "");
                    }
                    Kind::CheckKeyPass { store, alias, pw } => {
                        ui.label("憑證庫");
                        ui.strong(store_name(store));
                        ui.end_row();
                        ui.label("別名");
                        ui.strong(alias.as_str());
                        ui.end_row();
                        pw_field(ui, "私鑰密碼", pw, "要檢查的 key pass");
                        ui.label("");
                        ui.weak("只檢查，不會修改憑證庫；若私鑰尚未解密，密碼正確時會順便解開");
                        ui.end_row();
                        ok_label = "驗證";
                    }
                    Kind::StorePass {
                        store,
                        new,
                        new2,
                        also_keys,
                    } => {
                        let is_p12 = stores
                            .get(*store)
                            .is_some_and(|s| s.format == StoreFormat::Pkcs12);
                        ui.label("憑證庫");
                        ui.strong(store_name(store));
                        ui.end_row();
                        pw_field(ui, "新密碼", new, "至少 6 個字元");
                        pw_field(ui, "再次輸入", new2, "");
                        ui.label("");
                        if is_p12 {
                            ui.weak("PKCS#12 只有一個密碼，私鑰會一併修改");
                        } else {
                            ui.checkbox(
                                also_keys,
                                "私鑰密碼原本與憑證庫相同者一併修改（取消＝同 keytool -storepasswd）",
                            );
                        }
                        ui.end_row();
                    }
                    Kind::Delete { store, alias } => {
                        ui.label("憑證庫");
                        ui.strong(store_name(store));
                        ui.end_row();
                        ui.label("別名");
                        ui.colored_label(RED, RichText::new(alias.as_str()).strong());
                        ui.end_row();
                        ui.label("");
                        ui.weak("刪除後需按「儲存」才會寫入檔案");
                        ui.end_row();
                        ok_label = "刪除";
                    }
                    Kind::SaveAs {
                        store,
                        path,
                        format,
                        pw,
                        pw2,
                        legacy,
                    } => {
                        let need_pw = stores
                            .get(*store)
                            .is_some_and(|s| s.store_password.is_none());
                        let default = stores
                            .get(*store)
                            .and_then(|s| s.path.file_stem())
                            .map(|n| format!("{}.{}", n.to_string_lossy(), ext_of(*format)))
                            .unwrap_or_else(|| "keystore.jks".into());
                        save_field(ui, path, format, &default);
                        if need_pw {
                            pw_field(ui, "憑證庫密碼", pw, "新檔案的密碼，至少 6 個字元");
                            pw_field(ui, "再次輸入", pw2, "");
                        }
                        if *format == StoreFormat::Pkcs12 {
                            ui.label("");
                            ui.colored_label(
                                YELLOW,
                                "PKCS#12 只有一個密碼，私鑰密碼會改為與憑證庫相同",
                            );
                            ui.end_row();
                            ui.label("");
                            ui.checkbox(
                                legacy,
                                "舊版相容 PKCS#12（3DES + HmacSHA1，給 Java 8u301 / 11.0.12 以前使用）",
                            );
                            ui.end_row();
                        }
                        ok_label = "儲存";
                    }
                    Kind::ConvertCert {
                        file,
                        file_pw,
                        format,
                        with_key,
                    } => {
                        file_field(ui, "來源檔案", file);
                        pw_field(ui, "來源密碼", file_pw, "來源為 .p12 / .jks 時才需要");
                        ui.label("輸出格式");
                        ui.vertical(|ui| {
                            for f in CertFormat::ALL {
                                ui.radio_value(format, f, f.label());
                            }
                        });
                        ui.end_row();
                        if *format == CertFormat::Pem {
                            ui.label("");
                            ui.checkbox(with_key, "一併輸出私鑰（未加密，請妥善保管）");
                            ui.end_row();
                        } else {
                            *with_key = false;
                        }
                        ui.label("");
                        ui.weak("按「轉換」後選擇輸出位置；憑證庫格式轉換請用「另存新檔 / 轉換」");
                        ui.end_row();
                        ok_label = "轉換…";
                    }
                    Kind::GenChain(g) => {
                        gen_chain_ui(ui, g, stores);
                        ok_label = "製作";
                    }
                    Kind::ConfirmClose { store } => {
                        ui.label("");
                        ui.label(match store {
                            Some(i) => format!("「{}」有尚未儲存的變更，確定要關閉？", store_name(i)),
                            None => "有憑證庫尚未儲存，確定要結束程式？".into(),
                        });
                        ui.end_row();
                        ok_label = "不儲存，直接關閉";
                    }
                });
                });
            if let Some(e) = &d.error {
                ui.add_space(4.0);
                ui.add(egui::Label::new(RichText::new(format!("✘ {e}")).color(RED)).wrap());
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button(RichText::new(ok_label).strong()).clicked()
                    || (enter_ok && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                {
                    result = Some(true);
                }
                if ui.button("取消").clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                    result = Some(false);
                }
            });
        });
    result
}

fn key_combo(ui: &mut egui::Ui, id: &str, v: &mut KeyAlg) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(v.label())
        .width(110.0)
        .show_ui(ui, |ui| {
            for k in KeyAlg::ALL {
                ui.selectable_value(v, k, k.label());
            }
        });
}

fn gen_chain_ui(ui: &mut egui::Ui, g: &mut GenChain, stores: &[Keystore]) {
    let Some(ks) = stores.get(g.store) else {
        return;
    };
    let issuers = issuer_candidates(ks);
    ui.label("存入");
    ui.strong(ks.name());
    ui.end_row();

    ui.label("簽發方式");
    ui.vertical(|ui| {
        let mut use_existing = g.issuer.is_some();
        ui.radio_value(&mut use_existing, false, "建立新的根 CA（自簽）");
        if ui
            .add_enabled(
                !issuers.is_empty(),
                egui::RadioButton::new(use_existing, "用此憑證庫中的 CA 簽發"),
            )
            .on_disabled_hover_text("此憑證庫沒有含私鑰的 CA 條目")
            .clicked()
        {
            use_existing = true;
        }
        if use_existing && g.issuer.is_none() {
            g.issuer = issuers.first().cloned();
            g.make_leaf = true;
        } else if !use_existing {
            g.issuer = None;
        }
    });
    ui.end_row();

    if let Some(iss) = g.issuer.as_mut() {
        ui.label("簽發者 CA");
        egui::ComboBox::from_id_salt("gen_issuer")
            .selected_text(iss.clone())
            .show_ui(ui, |ui| {
                for a in &issuers {
                    ui.selectable_value(iss, a.clone(), a);
                }
            });
        ui.end_row();
    } else {
        text_field(ui, "根 CA 名稱（CN）", &mut g.root_cn, "");
        ui.label("中繼 CA（每行一個）");
        ui.add(
            egui::TextEdit::multiline(&mut g.inters)
                .hint_text("留空＝由根 CA 直接簽發")
                .desired_rows(2)
                .desired_width(240.0),
        );
        ui.end_row();
        ui.label("CA 金鑰 / 天數");
        ui.horizontal(|ui| {
            key_combo(ui, "gen_ca_key", &mut g.ca_key);
            ui.add(
                egui::DragValue::new(&mut g.ca_days)
                    .range(1..=36500)
                    .suffix(" 天"),
            );
        });
        ui.end_row();
        ui.label("");
        ui.checkbox(&mut g.keep_ca_keys, "保存 CA 私鑰（之後可再用來簽發）");
        ui.end_row();
    }

    ui.label("");
    let mut make_leaf = g.make_leaf;
    ui.add_enabled(
        g.issuer.is_none(),
        egui::Checkbox::new(&mut make_leaf, "建立終端憑證（Server / Client）"),
    );
    g.make_leaf = make_leaf;
    ui.end_row();
    if g.make_leaf {
        text_field(ui, "CN", &mut g.leaf_cn, "例如 api.example.com");
        ui.label("SAN");
        ui.add(
            egui::TextEdit::singleline(&mut g.sans)
                .hint_text("api.example.com, 10.0.0.5, DNS:*.example.com")
                .desired_width(240.0),
        );
        ui.end_row();
        ui.label("用途");
        ui.horizontal(|ui| {
            ui.radio_value(&mut g.profile, Profile::Server, "Server");
            ui.radio_value(&mut g.profile, Profile::Client, "Client");
            ui.radio_value(&mut g.profile, Profile::ServerClient, "兩者");
        });
        ui.end_row();
        ui.label("金鑰 / 天數");
        ui.horizontal(|ui| {
            key_combo(ui, "gen_key", &mut g.key);
            ui.add(
                egui::DragValue::new(&mut g.days)
                    .range(1..=36500)
                    .suffix(" 天"),
            );
        });
        ui.end_row();
        text_field(ui, "別名", &mut g.alias, "留空＝使用 CN");
        if ks.format != StoreFormat::Pkcs12 {
            pw_field(ui, "私鑰密碼", &mut g.key_pw, "留空＝與憑證庫密碼相同");
            if !g.key_pw.is_empty() {
                pw_field(ui, "再次輸入", &mut g.key_pw2, "");
            }
        }
    }
    text_field(ui, "組織（O）", &mut g.org, "選填");
    if g.make_leaf {
        text_field(ui, "部門（OU）", &mut g.ou, "選填，只用於終端憑證");
    }
    text_field(ui, "國家（C）", &mut g.country, "兩碼，例如 TW");
}
