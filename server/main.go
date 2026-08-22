// server 是 pqNK demo 的 responder 端。
//
// 流程：
//  1. 產生（或讀取既有的）server 靜態 KEM keypair
//  2. 把公鑰寫成檔案，模擬「client 之後會透過鏈上 hash 驗證、快取取得」這件事
//     （這個 demo 先用檔案代替，之後你可以換成真正的鏈上查詢邏輯）
//  3. 監聽 TCP，等 client 連上來，跑 pqNK handshake
//  4. handshake 結束後，用衍生出的 CipherState 收發一條測試訊息
package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/katzenpost/hpqc/kem/schemes"

	"github.com/katzenpost/nyquist"
	"github.com/katzenpost/nyquist/cipher"
	"github.com/katzenpost/nyquist/hash"
	"github.com/katzenpost/nyquist/kem"
	"github.com/katzenpost/nyquist/pattern"
	"github.com/katzenpost/nyquist/seec"
)

const (
	listenAddr = "10.99.0.2:9443" // 依你的 netns/veth 設定調整
	pubKeyFile = "server_pubkey.bin"
)

func main() {
	protocol := &nyquist.Protocol{
		Pattern: pattern.PqNK,
		KEM:     schemes.ByName("Kyber768-X25519"),
		Cipher:  cipher.ChaChaPoly,
		Hash:    hash.BLAKE2s,
	}

	seecGenRand, err := seec.GenKeyPRPAES(rand.Reader, 256)
	if err != nil {
		log.Fatalf("seec.GenKeyPRPAES: %v", err)
	}

	// 每次啟動都重新生成一把新的 static keypair。
	// 之後如果你要讓這把 key 在多次啟動之間保持不變（比較貼近真實部署），
	// 改成先檢查有沒有既有的私鑰檔案、有就載入，沒有才新生成。
	_, serverStatic := kem.GenerateKeypair(protocol.KEM, seecGenRand)

	pubBytes, err := serverStatic.Public().MarshalBinary()
	if err != nil {
		log.Fatalf("MarshalBinary: %v", err)
	}
	if err := os.WriteFile(pubKeyFile, pubBytes, 0o644); err != nil {
		log.Fatalf("寫入 %s 失敗: %v", pubKeyFile, err)
	}
	fmt.Printf("[server] 靜態公鑰已寫入 %s（%d bytes）\n", pubKeyFile, len(pubBytes))

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("net.Listen: %v", err)
	}
	defer listener.Close()
	fmt.Printf("[server] 監聽於 %s，等待 client 連線...\n", listenAddr)

	conn, err := listener.Accept()
	if err != nil {
		log.Fatalf("Accept: %v", err)
	}
	defer conn.Close()
	fmt.Printf("[server] client 已連線: %s\n", conn.RemoteAddr())

	serverCfg := &nyquist.HandshakeConfig{
		Protocol: protocol,
		KEM: &nyquist.KEMConfig{
			LocalStatic: serverStatic,
			GenKey:      seec.GenKeyPRPAES,
		},
		IsInitiator: false,
	}

	serverHs, err := nyquist.NewHandshake(serverCfg)
	if err != nil {
		log.Fatalf("NewHandshake: %v", err)
	}
	defer serverHs.Reset()

	// ---- msg1: 讀 client 送來的 skem, e ----
	msg1, err := readFramed(conn)
	if err != nil {
		log.Fatalf("讀取 msg1 失敗: %v", err)
	}
	if _, err := serverHs.ReadMessage(nil, msg1); err != nil {
		log.Fatalf("ReadMessage(msg1) 失敗: %v", err)
	}
	fmt.Printf("[server] 已收到 msg1（%d bytes）\n", len(msg1))

	// ---- msg2: 送出 ekem，pqNK 最後一則，預期 ErrDone ----
	msg2, err := serverHs.WriteMessage(nil, nil)
	if err != nil && err != nyquist.ErrDone {
		log.Fatalf("WriteMessage(msg2) 失敗: %v", err)
	}
	if err := writeFramed(conn, msg2); err != nil {
		log.Fatalf("送出 msg2 失敗: %v", err)
	}
	fmt.Printf("[server] 已送出 msg2（%d bytes），handshake 完成\n", len(msg2))

	status := serverHs.GetStatus()
	fmt.Printf("[server] HandshakeHash = %x\n", status.HandshakeHash)

	// pqNK：server 不應該認證到 client 的靜態公鑰
	if status.KEM.RemoteStatic != nil {
		log.Fatalf("異常：server 竟然拿到了 client 的靜態公鑰")
	}

	// ---- transport 階段：CipherStates[0]=收(對應 client 的送), [1]=送(對應 client 的收) ----
	rx, tx := status.CipherStates[0], status.CipherStates[1]
	defer func() {
		rx.Reset()
		tx.Reset()
	}()

	ct, err := readFramed(conn)
	if err != nil {
		log.Fatalf("讀取應用層訊息失敗: %v", err)
	}
	pt, err := rx.DecryptWithAd(nil, nil, ct)
	if err != nil {
		log.Fatalf("解密失敗: %v", err)
	}
	fmt.Printf("[server] 收到 client 訊息: %q\n", pt)

	reply := []byte("hello from server")
	ctOut, err := tx.EncryptWithAd(nil, nil, reply)
	if err != nil {
		log.Fatalf("加密失敗: %v", err)
	}
	if err := writeFramed(conn, ctOut); err != nil {
		log.Fatalf("送出回覆失敗: %v", err)
	}
	fmt.Println("[server] 已送出回覆，結束")
}

// writeFramed 送出一段長度前綴（4 bytes, big-endian）+ 內容，
// 讓對方不需要事先知道每則訊息的固定長度就能正確讀取。
func writeFramed(w io.Writer, data []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// readFramed 對應 writeFramed，先讀 4 bytes 長度，再讀滿那麼多內容。
func readFramed(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
