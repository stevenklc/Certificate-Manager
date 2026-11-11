//! 說明視窗：名詞解釋與功能介紹。

use eframe::egui::{self, RichText};

use crate::widgets::BLUE;

type Items = &'static [(&'static str, &'static str)];

const TERMS: &[(&str, Items)] = &[
    (
        "檔案與格式",
        &[
            ("憑證（Certificate）", "公開的身分證明，內含主體名稱、公鑰、有效期限，並由簽發者（CA）簽章。常見副檔名 .cer / .crt / .pem，可以公開給任何人。"),
            ("私鑰（Private Key）", "與憑證公鑰成對的秘密金鑰，用來證明「我就是憑證上的主體」。常見副檔名 .key，必須妥善保管，絕對不要外流或放進版本控制。"),
            ("憑證庫（Keystore 檔案）", "把憑證、私鑰集中存放的檔案，以密碼保護。Java 程式（Tomcat、Spring Boot…）通常使用 JKS 或 PKCS#12。"),
            ("JKS", "Java KeyStore，Java 專屬格式（.jks），所有 Java 版本都能讀。Java 9 起官方建議改用 PKCS#12。"),
            ("JCEKS", "JKS 的加強版（.jceks），私鑰加密較強，可存放對稱金鑰，也是 Java 專屬格式。"),
            ("PKCS#12", "跨平台的標準憑證庫格式（.p12 / .pfx），Windows、OpenSSL、Java 都支援。私鑰密碼固定等於憑證庫密碼。"),
            ("PEM", "以 -----BEGIN ...----- 開頭的文字格式，可以放憑證、私鑰或兩者，用記事本就能打開。"),
            ("DER", "二進位格式的單張憑證，Windows 常用 .cer 副檔名。"),
            ("P7B（PKCS#7）", "可放多張憑證（通常是整條憑證鏈）的格式，不含私鑰，常見於 CA 回覆的憑證。"),
            ("舊版相容 PKCS#12", "新版 PKCS#12 使用 AES 加密，需 Java 8u301 / 11.0.12 以上；要給更舊的 Java 讀取，請另存為舊版相容（3DES + HmacSHA1）。"),
        ],
    ),
    (
        "憑證庫的內容",
        &[
            ("Keystore（金鑰庫）", "含有私鑰的憑證庫，代表「自己的身分」。Server 用它提供 HTTPS；mTLS 時 Client 用它送出 Client 憑證。"),
            ("Truststore（信任庫）", "只放信任的憑證（通常是 CA）的憑證庫，用來「驗證對方」。例如 Java 內建的 cacerts。不需要私鑰。"),
            ("私鑰條目（PrivateKeyEntry）", "憑證庫中的一筆「私鑰 + 憑證鏈」，可當作 TLS 身分。"),
            ("信任憑證（trustedCertEntry）", "憑證庫中只有一張憑證、沒有私鑰的條目，用來信任這張憑證（或它簽發的憑證）。"),
            ("別名（Alias）", "憑證庫中每個條目的名稱。JKS / JCEKS 儲存時會轉成小寫。程式設定 keyAlias 時就是指這個。"),
            ("store pass（憑證庫密碼）", "開啟整個憑證庫、驗證完整性用的密碼。"),
            ("key pass（私鑰密碼）", "加密單一私鑰的密碼。JKS / JCEKS 可以和 store pass 不同；PKCS#12 一定相同。"),
            ("完整性（Integrity）", "以 store pass 驗證檔案沒有被竄改。沒輸入密碼時仍可檢視憑證，但無法確認完整性、也無法解開私鑰。"),
        ],
    ),
    (
        "憑證與憑證鏈",
        &[
            ("CA（憑證機構）", "負責簽發憑證的單位或憑證。CA 憑證的 BasicConstraints 為 CA=true，才能拿來簽發其他憑證。"),
            ("根 CA（Root CA）", "自己簽給自己（自簽）的 CA，是信任的起點。信任庫裡放的通常就是根 CA。"),
            ("中繼 CA（Intermediate CA）", "由根 CA（或上層中繼 CA）簽發、再用來簽發終端憑證的 CA。Server 送出憑證時應一併送出中繼 CA。"),
            ("終端憑證（Leaf / End-entity）", "實際給網站、服務或使用者用的憑證，不是 CA，不能再簽發憑證。"),
            ("自簽憑證（Self-signed）", "簽發者就是自己的憑證。根 CA 一定是自簽；非 CA 的自簽憑證常用於測試。"),
            ("憑證鏈（Certificate Chain）", "從終端憑證 → 中繼 CA → 根 CA 一層層的簽發關係。對方要能從你的憑證一路驗證到它信任的根 CA，交握才會成功。"),
            ("主體（Subject）/ CN", "憑證的擁有者名稱，例如 CN=api.example.com, O=公司。CN 是其中的「一般名稱」。"),
            ("簽發者（Issuer）", "簽發這張憑證的 CA 名稱，應等於上一層 CA 的主體。"),
            ("SAN（主體別名）", "憑證涵蓋的主機名稱 / IP 清單，例如 DNS:api.example.com、DNS:*.example.com、IP:10.0.0.5。瀏覽器與新版程式只看 SAN 判斷主機名稱。"),
            ("萬用字元憑證（*.example.com）", "涵蓋 example.com 下一層的所有名稱（a.example.com），但不含 example.com 本身，也不含 a.b.example.com。"),
            ("有效期限", "生效日（Not Before）到到期日（Not After）。過期或尚未生效的憑證會被拒絕。"),
            ("序號（Serial）", "CA 給每張憑證的唯一編號。"),
            ("指紋（SHA-1 / SHA-256）", "整張憑證的雜湊值，用來快速確認兩張憑證是否完全相同。"),
            ("SKI / AKI", "主體金鑰識別碼 / 授權金鑰識別碼。子憑證的 AKI 應等於簽發者的 SKI，用來找出正確的上層 CA。"),
            ("簽章演算法", "CA 簽這張憑證用的演算法，例如 sha256WithRSAEncryption。MD5、SHA-1 已不安全，新版 Java 與瀏覽器會拒絕。"),
            ("RSA / EC", "公鑰演算法。RSA 建議 2048 bits 以上；EC（P-256 / P-384）金鑰短、速度快，安全性相當。"),
            ("憑證釘選（Pinning）", "在信任庫直接放對方的終端憑證，只信任那一張。對方續約換憑證後就必須重新匯入，一般建議改放 CA。"),
        ],
    ),
    (
        "TLS 與用途",
        &[
            ("TLS / HTTPS", "加密連線的協定。HTTPS 就是 HTTP 跑在 TLS 上。"),
            ("交握（Handshake）", "建立 TLS 連線時雙方交換憑證、協商加密方式的過程。憑證鏈不完整、不被信任、主機名稱不符、過期都會讓交握失敗。"),
            ("Server（伺服器端）", "提供服務的一方（例如網站、API）。必須有 keystore（私鑰 + 憑證鏈），把憑證送給 Client 驗證。"),
            ("Client（用戶端）", "發起連線的一方（瀏覽器、呼叫 API 的程式）。用 truststore 驗證 Server 的憑證；一般情況下不需要私鑰。"),
            ("mTLS（雙向 TLS）", "Server 也要求 Client 出示憑證。這時 Client 需要自己的 keystore（私鑰 + 憑證），Server 需要能驗證 Client 的 truststore。"),
            ("serverAuth", "延伸金鑰用途（EKU）之一，表示憑證可以當作 Server 憑證。有 EKU 但不含 serverAuth 的憑證不能用於 HTTPS 伺服器。"),
            ("clientAuth", "延伸金鑰用途（EKU）之一，表示憑證可以在 mTLS 中當作 Client 憑證。"),
            ("延伸金鑰用途（EKU）", "限制憑證用途的擴充欄位，例如 serverAuth、clientAuth、codeSigning。沒有 EKU 表示不限制。"),
            ("金鑰用途（Key Usage）", "限制金鑰能做什麼，例如 Digital Signature、Key Encipherment、Key Cert Sign（只有 CA 會有）。TLS 憑證至少要有 Digital Signature（RSA 也可用 Key Encipherment）。"),
            ("SNI", "Client 在交握時告訴 Server 要連的主機名稱，讓同一個 IP 上的多個網站送出各自的憑證。"),
            ("主機名稱驗證", "Client 檢查 Server 憑證的 SAN 是否涵蓋它要連的名稱，不符就拒絕（即使憑證鏈完全正確）。"),
            ("TLS 檢查（企業 Proxy）", "公司 Proxy 可能用公司自己的 CA 重新簽發外部網站的憑證，這時看到的不是 Server 的真實憑證鏈（結果上方會出現黃色提醒）。只用 Java cacerts 驗證會失敗（UnknownIssuer），要加入公司的根 CA 或使用系統憑證庫。要判斷另一台主機（走不同 proxy）能否交握，請在那台主機上執行 Linux 版 rust-ca。"),
        ],
    ),
];

const FEATURES: &[(&str, Items)] = &[
    (
        "憑證庫分頁",
        &[
            ("開啟檔案", "按「📂 開啟檔案」或直接把檔案拖進視窗。支援 JKS、JCEKS、PKCS#12、PEM、CER/DER、P7B；需要密碼時會詢問，也可以不輸入密碼先檢視。"),
            ("左側檔案清單", "每個檔案會標示格式、條目數，以及是 🔑 Keystore、🛡 Truststore 或兩者都有。選「全部檔案」可以跨檔案瀏覽與搜尋。"),
            ("搜尋與排序", "上方搜尋框可搜尋別名、主體、簽發者、SAN、序號、指紋；點欄位標題可升冪 / 降冪排序。"),
            ("憑證鏈", "點選條目後下方顯示憑證鏈與每張憑證的內容；缺少的 CA 會從其他已開啟的檔案自動補齊。點鏈中其他層的憑證可跳到它的條目。"),
            ("簽發關係圖", "下方的「🌳 簽發關係圖」或工具列的大畫面版本，畫出誰簽發了誰。可切換只看目前條目或整個憑證庫，點兩下跳到所在條目。"),
            ("右鍵選單", "在清單、憑證鏈、關係圖上按右鍵，可以改名、替換憑證鏈、改 / 驗證私鑰密碼、驗證憑證鏈、匯出、刪除。"),
        ],
    ),
    (
        "管理工具列",
        &[
            ("匯入憑證 / 匯入金鑰對", "加入信任憑證，或從另一個憑證庫、「憑證檔 + 私鑰檔」加入私鑰條目。"),
            ("批次匯入", "一次選取多個 cer / key / p12，自動用公鑰配對私鑰與憑證、補齊憑證鏈，預覽後再加入。"),
            ("改憑證庫密碼 / 改私鑰密碼", "修改 store pass 或單一條目的 key pass（PKCS#12 只有一個密碼）。"),
            ("驗證私鑰密碼", "輸入密碼檢查是否為該私鑰的 key pass，不會修改檔案。"),
            ("替換憑證鏈", "同一別名換上新憑證（續約、匯入 CA 回覆），替換後自動驗證；驗證失敗不會套用。"),
            ("儲存 / 另存新檔", "修改後檔案旁會顯示「● 未儲存」；儲存前自動備份 .bak。另存時可轉換成 JKS / JCEKS / PKCS#12。"),
            ("製作憑證鏈", "產生新的根 CA → 中繼 CA → Server / Client 憑證，或用庫中的 CA 簽發新憑證（測試環境用）。"),
            ("Java 相容性測試", "用本機各版本 Java 的 keytool 實際讀取憑證庫並解開私鑰，確認哪些 Java 版本能用。"),
            ("用途檢查", "選擇要當作 Server keystore、Client keystore（mTLS）或 Truststore，檢查是否適合並列出問題。"),
        ],
    ),
    (
        "其他工具",
        &[
            ("新增憑證庫", "建立空的憑證庫，或選取多個現成的 cer / key 一次組成憑證庫。"),
            ("轉換憑證格式", "在 PEM、DER（.cer）、P7B 之間轉換，也可以從憑證庫取出憑證鏈或私鑰。"),
            ("交握模擬：本機", "選 Server 身分、雙方信任庫（可開 mTLS），在本機模擬交握，看能不能成功、失敗原因是什麼。"),
            ("交握模擬：遠端", "連到真實的網域或 API 網址，取得對方的憑證鏈並驗證；可設定 Proxy、SNI、TLS 版本、Client 憑證，網址含路徑時會送出 HTTP 請求。"),
            ("CLI（rust-ca.exe）", "所有功能都有命令列版本，可在 Windows 與 Linux 使用，例如 rust-ca list、rust-ca handshake remote、rust-ca manage check-role。執行 rust-ca --help 查看說明。"),
        ],
    ),
];

#[derive(Default)]
pub struct Help {
    tab: usize,
    query: String,
}

impl Help {
    /// 回傳 false 表示使用者關閉視窗。
    pub fn ui(&mut self, ctx: &egui::Context) -> bool {
        let mut open = true;
        let mut close = false;
        let max_h = crate::tools::max_window_height(ctx);
        egui::Window::new("❓ 說明")
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_width(720.0)
            .default_height(560.0)
            .max_height(max_h)
            .max_width(crate::tools::max_window_width(ctx))
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.tab, 0, RichText::new("📖 名詞解釋").strong());
                    ui.selectable_value(&mut self.tab, 1, RichText::new("🛠 功能介紹").strong());
                    ui.separator();
                    ui.label("🔍");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.query)
                            .hint_text("搜尋，例如 clientAuth、truststore")
                            .desired_width(220.0),
                    );
                });
                ui.separator();
                let data = if self.tab == 0 { TERMS } else { FEATURES };
                let q = self.query.trim().to_lowercase();
                egui::ScrollArea::vertical()
                    .max_height((max_h - 130.0).max(120.0))
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        let mut any = false;
                        for (section, items) in data {
                            let hits: Vec<_> = items
                                .iter()
                                .filter(|(t, d)| {
                                    q.is_empty()
                                        || t.to_lowercase().contains(&q)
                                        || d.to_lowercase().contains(&q)
                                })
                                .collect();
                            if hits.is_empty() {
                                continue;
                            }
                            any = true;
                            egui::CollapsingHeader::new(RichText::new(*section).strong())
                                .id_salt(("help", self.tab, *section))
                                .default_open(true)
                                .open(if q.is_empty() { None } else { Some(true) })
                                .show(ui, |ui| {
                                    for (t, d) in hits {
                                        ui.label(RichText::new(*t).color(BLUE).strong());
                                        ui.add(egui::Label::new(*d).wrap());
                                        ui.add_space(6.0);
                                    }
                                });
                        }
                        if !any {
                            ui.weak("找不到符合的項目");
                        }
                    });
                if crate::tools::close_button(ui) {
                    close = true;
                }
            });
        open && !close
    }
}
