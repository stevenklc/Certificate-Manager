use thiserror::Error;

/// 核心函式庫的錯誤型別。
#[derive(Debug, Error)]
pub enum Error {
    #[error("讀取檔案失敗：{0}")]
    Io(#[from] std::io::Error),

    /// 需要密碼才能開啟（例如 PKCS#12）。
    #[error("需要密碼：{0}")]
    NeedPassword(String),

    /// 密碼錯誤（完整性檢查或 MAC 驗證失敗）。
    #[error("密碼錯誤：{0}")]
    WrongPassword(String),

    #[error("格式錯誤：{0}")]
    Format(String),

    #[error("不支援：{0}")]
    Unsupported(String),

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn format(msg: impl Into<String>) -> Self {
        Error::Format(msg.into())
    }

    /// 是否為「缺少或錯誤密碼」類型的錯誤，呼叫端可據此再次詢問密碼。
    pub fn is_password_problem(&self) -> bool {
        matches!(self, Error::NeedPassword(_) | Error::WrongPassword(_))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
