// Package webhook は jev-argos が送る Webhook の署名付き送信と、受信側での署名検証を提供する。
//
// 署名の形式 (受信側の実装で検証すること):
//
//	X-Jev-Argos-Timestamp: <UNIX 秒>
//	X-Jev-Argos-Signature: sha256=<hex(HMAC-SHA256(secret, timestamp + "." + body))>
//
// 受信側は Verify で署名を確認し、タイムスタンプが古すぎるもの (再送攻撃) を拒否する。
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

const (
	HeaderTimestamp = "X-Jev-Argos-Timestamp"
	HeaderSignature = "X-Jev-Argos-Signature"
)

// DefaultClient は Webhook の送信に使う既定の HTTP クライアント (タイムアウト 5 秒)。
var DefaultClient = &http.Client{Timeout: 5 * time.Second}

// Post は payload を JSON にして POST する。secret が空でなければ署名を付ける。
// 2xx 以外の応答はエラーとして返す。
func Post(ctx context.Context, client *http.Client, url, secret string, now time.Time, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if client == nil {
		client = DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "jev-argos")
	if secret != "" {
		ts := strconv.FormatInt(now.Unix(), 10)
		req.Header.Set(HeaderTimestamp, ts)
		req.Header.Set(HeaderSignature, "sha256="+Sign(secret, ts, body))
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook %s: %w", url, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook %s: HTTP %d", url, resp.StatusCode)
	}
	return nil
}

// Sign は hex(HMAC-SHA256(secret, timestamp + "." + body)) を返す。
func Sign(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify は受信側で署名とタイムスタンプを検証する。maxAge より古い (または未来の) リクエストは拒否する。
func Verify(secret, timestamp, signature string, body []byte, now time.Time, maxAge time.Duration) bool {
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	if d := now.Sub(time.Unix(ts, 0)); d > maxAge || d < -maxAge {
		return false
	}
	want := "sha256=" + Sign(secret, timestamp, body)
	return hmac.Equal([]byte(signature), []byte(want))
}

// VerifyRequest は http.Request の署名を検証し、本文を返す (受信側の HTTP ハンドラー用)。
func VerifyRequest(r *http.Request, secret string, maxAge time.Duration) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, false
	}
	return body, Verify(secret, r.Header.Get(HeaderTimestamp), r.Header.Get(HeaderSignature), body, time.Now(), maxAge)
}
