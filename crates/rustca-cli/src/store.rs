//! 開啟憑證庫並處理密碼（參數 → 環境變數 → 互動輸入）。

use std::io::IsTerminal;
use std::path::Path;

use anyhow::{Context, Result};
use clap::Args;
use rustca_core::{load_file, KeyState, Keystore, LoadOptions};

#[derive(Args, Clone, Default)]
pub struct PasswordArgs {
    /// 憑證庫密碼
    #[arg(short, long, env = "RUST_CA_PASSWORD", hide_env_values = true)]
    pub password: Option<String>,
    /// 私鑰密碼（預設與憑證庫密碼相同）
    #[arg(long, env = "RUST_CA_KEY_PASSWORD", hide_env_values = true)]
    pub key_password: Option<String>,
}

pub struct StoreOpener {
    args: PasswordArgs,
}

impl StoreOpener {
    pub fn new(args: PasswordArgs) -> Self {
        StoreOpener { args }
    }

    pub fn with_password(password: Option<String>) -> Self {
        StoreOpener {
            args: PasswordArgs {
                password,
                key_password: None,
            },
        }
    }

    /// 開啟憑證庫。`need_keys` 為 true 時，若私鑰仍鎖住會再詢問密碼。
    pub fn open(&self, path: &Path, need_keys: bool) -> Result<Keystore> {
        let mut opts = LoadOptions {
            password: self.args.password.clone(),
            key_password: self.args.key_password.clone(),
        };
        let interactive = std::io::stdin().is_terminal();
        let name = path.display();

        let ks = match load_file(path, &opts) {
            Ok(ks) => ks,
            Err(e) if e.is_password_problem() && opts.password.is_none() && interactive => {
                opts.password = Some(prompt(&format!("請輸入 {name} 的密碼："))?);
                load_file(path, &opts).with_context(|| format!("無法開啟 {name}"))?
            }
            Err(e) => return Err(anyhow::Error::new(e).context(format!("無法開啟 {name}"))),
        };

        let locked = || {
            ks.private_key_entries()
                .any(|e| matches!(e.key, KeyState::Locked(_)))
        };
        if need_keys && locked() && interactive {
            if opts.password.is_none() {
                opts.password = Some(prompt(&format!("請輸入 {name} 的密碼："))?);
            } else {
                opts.key_password = Some(prompt(&format!("請輸入 {name} 的私鑰密碼："))?);
            }
            return load_file(path, &opts).with_context(|| format!("無法開啟 {name}"));
        }
        Ok(ks)
    }
}

fn prompt(msg: &str) -> Result<String> {
    rpassword::prompt_password(msg).context("讀取密碼失敗")
}
