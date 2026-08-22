// client 是 pqNK demo 的 initiator 端。
//
// 流程：
//  1. 讀取 server 公鑰（這裡從檔案讀，代表「已經透過鏈上驗證、快取下來的 pk」）
//  2. 連線到 server，跑 pqNK handshake
//  3. handshake 結束後，用衍生出的 CipherState 收發一條測試訊息
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
	"github.com/katzenpost/nyquist/pattern"
	"github.com/katzenpost/nyquist/seec"
)

const (
	serverAddr = "10.99.0.2:9443" // 依你的 netns/veth 設定調整
	pubKeyFile = "server_pubkey.bin"
)

func main() {
	protocol := &nyquist.Protocol{
		Pattern: pattern.PqNK,
		KEM:     schemes.ByName("Kyber768-X25519"),
		Cipher:  cipher.ChaChaPoly,
		Hash:    hash.BLAKE2s,
	}

	pubBytes, err := os.ReadFile(pubKeyFile)
	if err != nil {
		log.Fatalf("讀取 %s 失敗（server 端要先跑一次，把公鑰寫出來）: %v", pubKeyFile, err)
	}

	// ↓↓↓ 這一步，在你真正的設計裡應該換成：
	//   1. 查鏈上 hash commitment
	//   2. 比對這份 pubBytes 的 hash 是否吻合
	//   3. 吻合才繼續往下 Unmarshal、拿去 handshake
	// 這個 demo 先跳過驗證，直接信任這份從檔案讀來的公鑰。
	remoteStatic, err := protocol.KEM.UnmarshalBinaryPublicKey(pubBytes)
	if err != nil {
		log.Fatalf("UnmarshalBinaryPublicKey: %v", err)
	}
	fmt.Printf("[client] 已載入 server 靜態公鑰（%d bytes）\n", len(pubBytes))

	seecGenRand, err := seec.GenKeyPRPAES(rand.Reader, 256)
	if err != nil {
		log.Fatalf("seec.GenKeyPRPAES: %v", err)
	}

	clientCfg := &nyquist.HandshakeConfig{
		Protocol: protocol,
		KEM: &nyquist.KEMConfig{
			RemoteStatic: remoteStatic,
			GenKey:       seec.GenKeyPRPAES,
		},
		IsInitiator: true,
	}

	clientHs, err := nyquist.NewHandshake(clientCfg)
	if err != nil {
		log.Fatalf("NewHandshake: %v", err)
	}
	defer clientHs.Reset()

	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Fatalf("net.Dial: %v", err)
	}
	defer conn.Close()
	fmt.Printf("[client] 已連線到 %s\n", serverAddr)

	// ---- msg1: 送出 skem, e ----
	msg1, err := clientHs.WriteMessage(nil, nil)
	if err != nil {
		log.Fatalf("WriteMessage(msg1) 失敗: %v", err)
	}
	if err := writeFramed(conn, msg1); err != nil {
		log.Fatalf("送出 msg1 失敗: %v", err)
	}
	fmt.Printf("[client] 已送出 msg1（%d bytes）\n", len(msg1))

	// ---- msg2: 讀 server 回覆的 ekem，pqNK 最後一則，預期 ErrDone ----
	msg2, err := readFramed(conn)
	if err != nil {
		log.Fatalf("讀取 msg2 失敗: %v", err)
	}
	if _, err := clientHs.ReadMessage(nil, msg2); err != nil && err != nyquist.ErrDone {
		log.Fatalf("ReadMessage(msg2) 失敗: %v", err)
	}
	fmt.Printf("[client] 已收到 msg2（%d bytes），handshake 完成\n", len(msg2))

	status := clientHs.GetStatus()
	fmt.Printf("[client] HandshakeHash = %x\n", status.HandshakeHash)

	// 驗證：這次認證到的公鑰，確實是我們一開始信任的那把
	if !status.KEM.RemoteStatic.Equal(remoteStatic) {
		log.Fatalf("異常：認證到的公鑰跟預期不符")
	}

	// ---- transport 階段：CipherStates[0]=送, [1]=收 ----
	tx, rx := status.CipherStates[0], status.CipherStates[1]
	defer func() {
		tx.Reset()
		rx.Reset()
	}()

	msg := []byte("hello from client")
	ct, err := tx.EncryptWithAd(nil, nil, msg)
	if err != nil {
		log.Fatalf("加密失敗: %v", err)
	}
	if err := writeFramed(conn, ct); err != nil {
		log.Fatalf("送出訊息失敗: %v", err)
	}
	fmt.Println("[client] 已送出測試訊息")

	replyCt, err := readFramed(conn)
	if err != nil {
		log.Fatalf("讀取回覆失敗: %v", err)
	}
	reply, err := rx.DecryptWithAd(nil, nil, replyCt)
	if err != nil {
		log.Fatalf("解密回覆失敗: %v", err)
	}
	fmt.Printf("[client] 收到 server 回覆: %q\n", reply)
}

func writeFramed(w io.Writer, data []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

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
