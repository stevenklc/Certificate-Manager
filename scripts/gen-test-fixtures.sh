#!/usr/bin/env bash
# 用 keytool 產生測試用 PKI（Root → Intermediate → Server / Client）到 ./testdata
# 產出的檔案已列入 .gitignore，請勿 commit。密碼僅供測試：changeit
set -euo pipefail

OUT="${1:-testdata}"
PW="changeit"
mkdir -p "$OUT"
cd "$OUT"
rm -f ./*.jks ./*.p12 ./*.cer ./*.pem ./*.csr

kt() { keytool "$@" -storepass "$PW" -keypass "$PW" 2>/dev/null; }

echo "[1/6] Root CA"
kt -genkeypair -alias root -keyalg RSA -keysize 2048 -validity 3650 \
   -dname "CN=Demo Root CA, O=RUST-CA Demo, C=TW" -ext bc:c -keystore ca.jks -storetype JKS
kt -exportcert -rfc -alias root -keystore ca.jks -file root.pem

echo "[2/6] Intermediate CA"
kt -genkeypair -alias inter -keyalg RSA -keysize 2048 -validity 1825 \
   -dname "CN=Demo Intermediate CA, O=RUST-CA Demo, C=TW" -keystore ca.jks
kt -certreq -alias inter -keystore ca.jks -file inter.csr
kt -gencert -alias root -keystore ca.jks -infile inter.csr -outfile inter.pem -rfc \
   -validity 1825 -ext bc:c=ca:true,pathlen:0 -ext ku:c=keyCertSign,cRLSign
kt -importcert -noprompt -alias root-ca -keystore ca.jks -file root.pem
kt -importcert -alias inter -keystore ca.jks -file inter.pem

echo "[3/6] Server（JKS，含完整鏈）"
kt -genkeypair -alias server -keyalg RSA -keysize 2048 -validity 825 \
   -dname "CN=server.demo.local, O=RUST-CA Demo, C=TW" -keystore server.jks -storetype JKS
kt -certreq -alias server -keystore server.jks -file server.csr
kt -gencert -alias inter -keystore ca.jks -infile server.csr -outfile server.pem -rfc -validity 825 \
   -ext san=dns:server.demo.local,dns:localhost,ip:127.0.0.1 -ext eku=serverAuth -ext ku=digitalSignature,keyEncipherment
kt -importcert -noprompt -alias root -keystore server.jks -file root.pem
kt -importcert -noprompt -alias inter -keystore server.jks -file inter.pem
kt -importcert -alias server -keystore server.jks -file server.pem
# 只含終端憑證的 PEM（用來示範憑證鏈不完整）
kt -exportcert -rfc -alias server -keystore server.jks -file server-leaf.pem

echo "[4/6] Client（PKCS#12）"
kt -genkeypair -alias client -keyalg RSA -keysize 2048 -validity 825 \
   -dname "CN=demo-client, OU=App, O=RUST-CA Demo, C=TW" -keystore client.p12 -storetype PKCS12
kt -certreq -alias client -keystore client.p12 -storetype PKCS12 -file client.csr
kt -gencert -alias inter -keystore ca.jks -infile client.csr -outfile client.pem -rfc -validity 825 \
   -ext eku=clientAuth -ext ku=digitalSignature
kt -importcert -noprompt -alias root -keystore client.p12 -storetype PKCS12 -file root.pem
kt -importcert -noprompt -alias inter -keystore client.p12 -storetype PKCS12 -file inter.pem
kt -importcert -alias client -keystore client.p12 -storetype PKCS12 -file client.pem

echo "[5/6] 信任庫"
kt -importcert -noprompt -alias demo-root -keystore truststore.jks -storetype JKS -file root.pem
kt -genkeypair -alias other -keyalg RSA -keysize 2048 -validity 365 \
   -dname "CN=Other Root CA, O=Elsewhere, C=US" -ext bc:c -keystore other-ca.jks -storetype JKS
kt -exportcert -alias other -keystore other-ca.jks -file other-root.cer
kt -importcert -noprompt -alias other-root -keystore wrong-truststore.jks -storetype JKS -file other-root.cer

echo "[6/6] 已過期的 Server 憑證"
kt -genkeypair -alias expired -keyalg RSA -keysize 2048 -validity 30 \
   -dname "CN=expired.demo.local, O=RUST-CA Demo, C=TW" -keystore expired.jks -storetype JKS
kt -certreq -alias expired -keystore expired.jks -file expired.csr
kt -gencert -alias inter -keystore ca.jks -infile expired.csr -outfile expired.pem -rfc \
   -startdate -400d -validity 30 -ext san=dns:expired.demo.local,dns:localhost -ext eku=serverAuth
kt -importcert -noprompt -alias root -keystore expired.jks -file root.pem
kt -importcert -noprompt -alias inter -keystore expired.jks -file inter.pem
kt -importcert -alias expired -keystore expired.jks -file expired.pem

rm -f ./*.csr
echo "完成：$(pwd)"
ls -1
