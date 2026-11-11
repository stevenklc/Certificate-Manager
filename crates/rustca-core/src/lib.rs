//! RUST-CA 核心函式庫：
//! * 讀取 JKS、JCEKS、PKCS#12、PEM、DER、PKCS#7
//! * 憑證有效期限與憑證鏈分析
//! * 關鍵字搜尋
//! * TLS 交握模擬（本機雙端 / 連線遠端 Server）

pub mod cert;
pub mod chain;
pub mod der;
pub mod edit;
pub mod error;
pub mod forge;
pub mod javacompat;
pub mod jks;
pub mod loader;
pub mod model;
pub mod pem;
pub mod role;
pub mod search;
pub mod tls;

pub use cert::{format_ts, init_local_offset, now_ts, parse_date, CertInfo, ValidityStatus};
pub use chain::{
    build_chain, issuance_forest, issuance_tree, BuiltChain, ChainEnd, ChainLink, IssuanceTree,
    TreeNode,
};
pub use error::{Error, Result};
pub use loader::{detect_format, load_bytes, load_file, LoadOptions};
pub use model::{Entry, EntryKind, Integrity, KeyFormat, KeyState, Keystore, Secret, StoreFormat};
pub use search::{search, Matcher, SearchHit};
