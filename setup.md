# pqNK client/server demo（network namespace 版）

## 1. 在 VM 上準備網路環境

```bash
sudo ip netns add client_ns
sudo ip netns add server_ns

sudo ip link add veth-c type veth peer name veth-s
sudo ip link set veth-c netns client_ns
sudo ip link set veth-s netns server_ns

sudo ip netns exec client_ns ip addr add 10.99.0.1/24 dev veth-c
sudo ip netns exec server_ns ip addr add 10.99.0.2/24 dev veth-s

sudo ip netns exec client_ns ip link set veth-c up
sudo ip netns exec client_ns ip link set lo up
sudo ip netns exec server_ns ip link set veth-s up
sudo ip netns exec server_ns ip link set lo up

# 驗證兩邊互通
sudo ip netns exec client_ns ping -c 3 10.99.0.2
```

## 2. 補上依賴版本、編譯

```bash
cd pqnk-demo
go mod tidy      # 會自動抓正確的 hpqc / nyquist 版本號，覆蓋掉 go.mod 裡的佔位版本
go build -o server/server ./server
go build -o client/client ./client
```

## 3. 執行

server 要先跑（它會產生 keypair、把公鑰寫成 `server_pubkey.bin`）：

```bash
cd server
sudo ip netns exec server_ns ./server
```

看到 `監聽於 ... 等待 client 連線` 之後，另開一個 terminal，把 server 產生的
`server_pubkey.bin` 複製一份到 client 執行的目錄（真實部署裡這一步會換成
鏈上查詢，這裡先用檔案模擬）：

```bash
cp server/server_pubkey.bin client/server_pubkey.bin
cd client
sudo ip netns exec client_ns ./client
```

## 4. 預期輸出

client、server 兩邊都會印出 `HandshakeHash`，應該完全一致；並且各自完成
一次 transport 階段的加解密（`hello from client` / `hello from server`）。

## 之後可以加的東西

- `client_pubkey.bin` 換成真正的鏈上查詢 + hash 驗證（目前 client 端程式碼裡
  已經用註解標出該插入驗證邏輯的位置）
- 用 `time`/`hyperfine` 包住 handshake 那段，量測效能，寫進論文的評估章節
- 把 `readFramed`/`writeFramed` 這組長度前綴框架邏輯抽成共用套件，避免
  client/server 兩份程式碼重複