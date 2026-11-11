# RUST-CA

用 Rust 寫的憑證庫（keystore）檢視、管理、製作與 TLS 交握模擬工具，分成兩個程式：

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
- **簽發關係圖**（GUI）：選取任一憑證，畫出「誰簽發了它、它又簽發了哪些憑證」的樹狀圖，範圍涵蓋所有已開啟的檔案；連線顏色代表簽章驗證結果，點方框可看憑證內容或跳到所在條目
- **憑證角色**：類型欄除了條目種類（私鑰條目 / 信任憑證），也標出憑證本身是根 CA、中繼 CA、終端或自簽
- **關鍵字搜尋**：比對別名、主體、簽發者、SAN、序號、SHA-1／SHA-256 指紋、金鑰用途；不分大小寫，序號和指紋可省略冒號
- **TLS 交握模擬**
  - **本機模擬**：用兩組憑證庫分別扮演 Server 與 Client，在記憶體中完成交握，不需要開任何連接埠
  - **遠端連線**：以 Client 身分連到真實 Server，取得對方送出的憑證鏈
  - 支援 mTLS（雙向 TLS），也能顯示 Server 可接受哪些 Client CA
  - 可指定 TLS 1.2／1.3、SNI，以及「模擬時間」（例如檢查憑證到期後還能不能交握）
  - 逐筆列出交握訊息（ClientHello、Certificate、Alert…）
  - 失敗時以中文說明原因與建議，例如缺根 CA、主機名稱不符 SAN、EKU 不符、Client 憑證不被信任、企業 proxy 進行 TLS 檢查
  - 支援 HTTP CONNECT proxy（含帳密），自動讀取 `HTTPS_PROXY` / `NO_PROXY` 與 Windows 系統 proxy 設定
  - 遠端目標可以是網域（`host:port`），也可以是 API 網址（`https://host/api/...`）；交握成功後可送出 HTTP 請求（方法、標頭、Body），顯示狀態碼、回應標頭與內容，`Authorization`、Cookie 等敏感標頭會遮蔽
  - Client / Server 身分可以用憑證庫（.jks / .p12），也可以用「憑證檔 + 私鑰檔」（.cer / .crt / .pem + .key）
- **憑證庫管理**（JKS、JCEKS、PKCS#12）
  - 匯入信任憑證、匯入金鑰對（來自另一個憑證庫，或憑證 + 私鑰檔）、刪除、修改別名
  - 同一別名替換憑證 / 憑證鏈（續約、CA 回覆），**替換後自動驗證**：私鑰相符、鏈的順序與簽章、CA 屬性、有效期限、能否連到根憑證；驗證失敗不會套用
  - 修改憑證庫密碼（store pass）與各條目的私鑰密碼（key pass）；不同條目私鑰密碼不同也能處理
  - 儲存前自動備份（`檔名.YYYYMMDD-HHMMSS.bak`），先寫暫存檔再改名，避免寫到一半損毀
  - 寫出的檔案經 Java keytool 驗證可正常讀取
- **格式轉換**
  - 憑證庫：JKS ⇄ JCEKS ⇄ PKCS#12，也能把 PEM 憑證 + 私鑰轉成憑證庫；PKCS#12 可選「舊版相容」演算法（3DES + HmacSHA1）給舊版 Java
  - 憑證：PEM ⇄ DER（.cer）⇄ PKCS#7（.p7b），可從憑證庫取出憑證鏈或私鑰
- **製作憑證庫與憑證鏈**
  - 建立新的空白憑證庫，或**由多個現成的 cer / key 檔組成憑證庫**：一次選取多個 .cer / .crt / .pem / .key / .p7b / .p12，自動用公鑰配對私鑰與憑證、用一起選取的 CA 憑證補齊憑證鏈，其餘 CA 成為信任憑證；建立前可預覽、調整別名、取消勾選（既有憑證庫也可用「📥 批次匯入」）
  - 一次產生「根 CA → 中繼 CA（可多層）→ Server / Client 憑證」，金鑰可選 RSA 2048/3072/4096、EC P-256/P-384，可設定 SAN、有效天數、O / OU / C
  - 可保存 CA 私鑰，之後再用憑證庫中的 CA 簽發新的憑證
- **Java 相容性測試**：自動找出本機安裝的各版本 JDK / JRE（JAVA_HOME、PATH、常見安裝目錄、`~/.jdks`，也可手動加入目錄），用每個版本的 keytool 實際讀取憑證庫並解開每把私鑰，並提示已知的版本限制（例如 PKCS#12 AES 需 Java 8u301+、EdDSA 需 Java 15+）
- **用途檢查**：選擇要當作 Server keystore、Client keystore（mTLS）或 Truststore，檢查是否適合——私鑰與憑證鏈、serverAuth / clientAuth 用途、Key Usage、SAN 是否涵蓋主機名稱、弱演算法；Truststore 則檢查是否只放 CA、有無過期、是否混入私鑰或終端憑證。GUI 左側也會標示每個檔案是 Keystore、Truststore 或兩者都有

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

### 在 Linux / WSL 交叉編譯 Windows 版（不需要 Visual Studio、不需要管理員權限）

```bash
# 一次性準備：下載 llvm-mingw 解壓到 ~/.local/opt，並加入 Rust 的 Windows 目標
mkdir -p ~/.local/opt && cd ~/.local/opt
curl -sSfL https://github.com/mstorsjo/llvm-mingw/releases/download/20261104/llvm-mingw-20261104-ucrt-ubuntu-22.04-x86_64.tar.xz | tar xJ
rustup target add x86_64-pc-windows-gnullvm

# 編譯，產出 dist/windows/rust-ca.exe、rust-ca-gui.exe
scripts/build-windows.sh
```

產出的 exe 只依賴 Windows 10 以上內建的系統 DLL（含 UCRT），複製過去就能執行。

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

# 測試 API：網址含路徑時，交握後自動送出 HTTP 請求
rust-ca handshake remote https://api.internal:8443/health -t truststore.jks
rust-ca handshake remote https://api.internal/v1/orders -t ca.pem \
    --client-cert client.crt --client-key client.key \
    -X POST -H "Authorization: Bearer xxx" -H "Content-Type: application/json" -d '{"id":1}'

# 所有指令都支援 --json
rust-ca --json list server.jks
```

### 憑證庫管理（`rust-ca manage`，簡寫 `m`）

修改類指令預設寫回原檔並建立 `.bak` 備份；加 `-o 新檔` 另存（格式依副檔名），`--no-backup` 不備份。新密碼可用 `--new-password` 或環境變數 `RUST_CA_NEW_PASSWORD`，未指定時會提示輸入兩次。

```bash
# 匯入 / 刪除 / 改名
rust-ca manage import-cert truststore.jks -f partner-ca.cer -a partner-ca --create
rust-ca manage import-key server.jks --cert server.crt --key server.key -a server
rust-ca manage import-key server.jks --from old.p12 --from-alias 1 -a server
# 用途檢查（--as server|client|trust，不指定則依內容判斷；不適合時回傳 2）
rust-ca manage check-role server.jks --as server --host api.example.com
rust-ca manage check-role truststore.jks --as trust
# 由多個 cer + key 組成憑證庫（自動配對、補齊憑證鏈；--dry-run 只看規劃結果）
rust-ca manage assemble servers.jks certs/*.crt certs/*.key ca/*.cer --create
rust-ca manage delete server.jks -a old-server
rust-ca manage rename server.jks -a server -n server-2026

# 替換憑證鏈（續約 / CA 回覆）：替換後自動驗證，失敗不寫入
rust-ca manage replace-chain server.jks -a server -f renewed-chain.p7b
rust-ca manage verify server.jks                     # 單獨驗證所有私鑰條目

# 修改密碼
rust-ca manage passwd server.jks                     # store pass（相同密碼的私鑰一併修改）
rust-ca manage passwd server.jks --keep-key-passwords # 同 keytool -storepasswd
rust-ca manage keypasswd server.jks -a server        # key pass

# 格式轉換
rust-ca manage convert server.jks -o server.p12                 # 憑證庫格式
rust-ca manage convert server.jks -o server-old.p12 --legacy-p12 # 給舊版 Java
rust-ca manage convert server.pem -o server.jks                 # PEM 憑證 + 私鑰 → JKS
rust-ca manage convert-cert server.jks -a server -o chain.p7b   # 憑證格式
rust-ca manage convert-cert chain.p7b -o chain.pem
rust-ca manage convert-cert chain.pem -o leaf.cer                # DER（單張）

# 製作憑證鏈
rust-ca manage gen-chain ca.jks --create --root-cn "My Root CA" --inter-cn "My Issuing CA" -O "My Co" -C TW
rust-ca manage gen-chain ca.jks --issuer my-issuing-ca --cn api.example.com --san api.example.com --san 10.0.0.5
rust-ca manage gen-chain app.p12 --create --cn client01 --profile client --key ec256

# Java 相容性測試（可用 --java 加入其他 JDK 目錄）
rust-ca manage java-test server.jks --java "C:\jdks"
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
2. **憑證庫**分頁：左側是已開啟的檔案，中間是條目表格，上方搜尋框可以即時篩選（選「全部檔案」就跨所有檔案搜尋）；點欄位標題可排序（升冪 ▲ → 降冪 ▼ → 原始順序），「狀態」依已過期 → 即將到期 → 尚未生效 → 有效排列。點選條目後，下方會顯示憑證鏈和憑證內容，也可以複製 PEM。
3. **管理**：選取檔案或條目後，表格上方會出現管理工具列——匯入憑證、匯入金鑰對、改憑證庫密碼、儲存、另存新檔 / 轉換、製作憑證鏈、Java 相容性測試；選取條目時另有改名、替換憑證鏈、改私鑰密碼、驗證私鑰密碼、驗證憑證鏈、匯出、刪除。這些條目動作也可以在表格列、下方憑證鏈或簽發關係圖的方框上**按右鍵**執行。修改後檔案旁會顯示「● 未儲存」，關閉前會提醒。
   - 下方憑證鏈中，點選其他層的憑證會跳到該憑證所在的條目（清單自動捲動過去）；簽發關係圖則是點兩下跳轉。
   - 「驗證私鑰密碼」只檢查 key pass 是否正確，不會修改憑證庫；私鑰尚未解密時，密碼正確就會順便解開。
4. **🆕 新增憑證庫**、**🔁 轉換憑證格式**：在上方工具列。
5. **交握模擬**分頁：從已開啟的檔案中挑選 Server／Client 身分（憑證庫，或憑證檔 + 私鑰檔）和信任庫，按「▶ 開始交握」；每個欄位旁的「📂 加入檔案…」可直接開檔。遠端模式可輸入網域或 API 網址，並設定 HTTP 方法、標頭與 Body。

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
- 寫入 JKS / JCEKS 時別名會轉成小寫（與 keytool 相同）；含 SecretKey 條目的 JCEKS 無法寫回
- 用既有 CA 簽發時，CA 主體不可含重複的屬性型別（例如兩個 OU）
- Java 相容性測試需要本機已安裝 Java；只會測試找得到的版本
- TLS 模擬使用 rustls，只支援 TLS 1.2／1.3。它比 Java／OpenSSL 嚴格，例如不接受 SHA-1 簽章，也不接受 Java 8 keytool 產生的帶 NULL 參數的 ECDSA 憑證。遇到這類情況，診斷訊息會特別說明
- proxy 只支援 HTTP CONNECT（Basic 認證），不支援 NTLM / Kerberos。沒有指定 `--proxy` 時，會依序使用 `HTTPS_PROXY` / `NO_PROXY`、Windows 系統 proxy 設定（含 ProxyOverride 例外清單）
