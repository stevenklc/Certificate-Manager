# RUST-CA

用 Rust 寫的憑證庫（keystore）檢視與 TLS 交握模擬工具，分成兩個程式：

| 程式 | 平台 | 用途 |
|---|---|---|
| `rust-ca`（CLI） | Windows / Linux | 命令列查詢、腳本與排程使用，支援 JSON 輸出 |
| `rust-ca-gui`（GUI） | Windows | 圖形介面，可拖曳開檔、即時搜尋、點選查看憑證鏈 |

## 功能

- **讀取格式**：JKS、JCEKS、PKCS#12（.p12/.pfx）、PEM、DER（.cer/.crt）、PKCS#7（.p7b）
  - JKS / JCEKS 會驗證完整性，並解密私鑰（Sun KeyProtector 與 PBEWithMD5AndTripleDES）
  - 沒有密碼也能列出憑證，只是不驗證完整性、不解密私鑰
- **有效期限**：顯示生效日、到期日、剩餘天數；可設定「幾天內到期」的提醒門檻
- **憑證鏈**：從終端憑證經中繼憑證一路組到根憑證，逐層驗證簽章，並檢查鏈是否完整、有沒有過期、CA 旗標是否正確；也可以拿其他檔案來補齊缺少的 CA
- **關鍵字搜尋**：比對別名、主體、簽發者、SAN、序號、SHA-1／SHA-256 指紋、金鑰用途；不分大小寫，序號和指紋可省略冒號
- **TLS 交握模擬**
  - **本機模擬**：用兩組憑證庫分別扮演 Server 與 Client，在記憶體中完成交握，不需要開任何連接埠
  - **遠端連線**：以 Client 身分連到真實 Server，取得對方送出的憑證鏈
  - 支援 mTLS（雙向 TLS），也能顯示 Server 可接受哪些 Client CA
  - 可指定 TLS 1.2／1.3、SNI，以及「模擬時間」（例如檢查憑證到期後還能不能交握）
  - 逐筆列出交握訊息（ClientHello、Certificate、Alert…）
  - 失敗時以中文說明原因與建議，例如缺根 CA、主機名稱不符 SAN、EKU 不符、Client 憑證不被信任、企業 proxy 進行 TLS 檢查
  - 支援 HTTP CONNECT proxy（含帳密），也會讀取 `HTTPS_PROXY` / `NO_PROXY`

## 建置

需要 Rust 工具鏈（[rustup](https://rustup.rs/)）。Windows 建議使用 MSVC toolchain（需安裝 Visual Studio Build Tools 的「使用 C++ 的桌面開發」）。

```powershell
# Windows：CLI + GUI
cargo build --release
# 產出：target\release\rust-ca.exe、target\release\rust-ca-gui.exe
```

```bash
# Linux：只建 CLI
cargo build --release -p rustca-cli
# 產出：target/release/rust-ca
```

> GUI 以 Windows 為目標。在 Linux 上也能編譯（X11 / Wayland），方便開發時檢查。

## CLI 使用方式

密碼可以用 `-p` 指定、設定環境變數 `RUST_CA_PASSWORD`，或等程式提示時再輸入。建議用提示輸入，避免密碼留在 shell 歷史紀錄裡。

```bash
# 列出條目與到期狀態（可一次多個檔案）
rust-ca list server.jks client.p12

# 顯示憑證詳細資訊（--pem 一併輸出 PEM）
rust-ca show server.jks -a server --pem

# 分析憑證鏈，用 -t 指定 CA 檔案補齊
rust-ca chain server.pem -t truststore.jks -t inter.pem

# 搜尋關鍵字
rust-ca search "Intermediate" *.jks *.p12
rust-ca search 2072DB43 server.jks        # 序號 / 指紋可省略冒號

# 到期檢查：有過期回傳 2、即將到期回傳 1，適合排程
rust-ca expiry *.jks --days 60

# 本機模擬交握
rust-ca handshake local --server server.jks --client-trust truststore.jks
rust-ca handshake local --server server.jks --client-trust truststore.jks \
    --mtls --client client.p12 --server-trust truststore.jks          # 雙向 TLS
rust-ca handshake local --server server.jks --client-trust truststore.jks \
    --tls 1.2 --sni server.demo.local --at 2030-01-01                  # 指定版本、名稱、時間

# 連線遠端 Server
rust-ca handshake remote www.example.com                 # 使用作業系統憑證庫
rust-ca handshake remote api.internal:8443 -t truststore.jks --client client.p12
rust-ca handshake remote www.example.com --insecure      # 不驗證，只看憑證鏈
rust-ca handshake remote www.example.com --proxy http://proxy:8080

# 所有指令都支援 --json
rust-ca --json list server.jks
```

`handshake local` 的各個憑證庫可以分別用 `--server-password`、`--client-password`、`--client-trust-password`、`--server-trust-password` 指定密碼（也有對應的環境變數，例如 `RUST_CA_SERVER_PASSWORD`）。

### 結束代碼

| 代碼 | 意義 |
|---|---|
| 0 | 成功 |
| 1 | 交握失敗、憑證鏈不完整、搜尋無結果、有憑證即將到期 |
| 2 | 有憑證已過期（`expiry`） |
| 10 | 執行錯誤（檔案不存在、密碼錯誤…） |

## GUI 使用方式

1. 執行 `rust-ca-gui.exe`，把檔案拖進視窗，或按「📂 開啟檔案…」。需要密碼時會跳出輸入框。
2. **憑證庫**分頁：左側是已開啟的檔案，中間是條目表格，上方搜尋框可以即時篩選（選「全部檔案」就跨所有檔案搜尋）。點選條目後，下方會顯示憑證鏈和憑證內容，也可以複製 PEM。
3. **交握模擬**分頁：從已開啟的檔案中挑選 Server／Client 身分和信任庫，按「▶ 開始交握」。

## 測試

```bash
cargo test --workspace
```

測試會用 rcgen 產生憑證，涵蓋 JKS 讀寫、憑證鏈、搜尋，以及本機／遠端／proxy 交握的成功與失敗情境。若系統有 Java `keytool`，還會額外用 keytool 產生 JKS、JCEKS、PKCS#12 來驗證解析器。

如果想產生一組示範用 PKI（Root → Intermediate → Server / Client，另含一張過期憑證）來手動試用：

```bash
scripts/gen-test-fixtures.sh            # Linux / WSL
```
```powershell
.\scripts\gen-test-fixtures.ps1          # Windows
```

產出的檔案在 `testdata/`，已列入 `.gitignore`。

## 專案結構

```
crates/
  rustca-core/   核心函式庫：格式解析、憑證資訊、憑證鏈、搜尋、TLS 模擬
  rustca-cli/    命令列工具 rust-ca
  rustca-gui/    圖形介面 rust-ca-gui（eframe / egui）
scripts/         產生測試用憑證庫的腳本
```

## 已知限制

- JCEKS 的秘密金鑰（SecretKey）條目是 Java 序列化物件，遇到時只會顯示該條目，後面的條目無法繼續解析
- PEM 加密私鑰（`ENCRYPTED PRIVATE KEY`）尚不支援，請先用 openssl 解密
- TLS 模擬使用 rustls，只支援 TLS 1.2／1.3。它比 Java／OpenSSL 嚴格，例如不接受 SHA-1 簽章，也不接受 Java 8 keytool 產生的帶 NULL 參數的 ECDSA 憑證。遇到這類情況，診斷訊息會特別說明
- proxy 只支援 HTTP CONNECT（Basic 認證），不支援 NTLM / Kerberos
