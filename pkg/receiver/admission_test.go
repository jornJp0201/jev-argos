package receiver

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/jornJp0201/jev-argos/pkg/buffer"
	"github.com/jornJp0201/jev-argos/pkg/classifier"
)

func fromAdapter(ip string) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000}})
}

func isExhausted(err error) bool { return status.Code(err) == codes.ResourceExhausted }

// 同時に判定する数が上限の 8 割を超えたら正常な応答を断り、上限を超えたらすべて断る。
func TestAdmission_ShedsOKBeforeErrors(t *testing.T) {
	a := newAdmission(Limits{MaxInFlight: 10})
	ctx := context.Background()
	admitted := map[int32]int{}
	for range 20 {
		for _, code := range []int32{0, 7} {
			if _, err := a.admit(ctx, sig("10.0.0.1", "/m", code, 1)); err == nil {
				admitted[code]++
			} else if !isExhausted(err) {
				t.Fatal(err)
			}
		}
	}
	// 判定中が 8 件 (= 10 × 0.8) までは正常な応答も受け付け、そこから上限の 10 件まではエラーだけを受け付ける
	if admitted[0] != 4 || admitted[7] != 6 {
		t.Errorf("admitted = %v, want ok=4 error=6", admitted)
	}
	if got := a.rejected[reasonOverloaded][kindOK].Load(); got != 16 {
		t.Errorf("rejected ok = %d, want 16", got)
	}
}

func TestAdmission_ReleaseFreesSlot(t *testing.T) {
	a := newAdmission(Limits{MaxInFlight: 1})
	release, err := a.admit(context.Background(), sig("10.0.0.1", "/m", 7, 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.admit(context.Background(), sig("10.0.0.1", "/m", 7, 1)); !isExhausted(err) {
		t.Fatalf("err = %v, want ResourceExhausted", err)
	}
	release()
	if _, err := a.admit(context.Background(), sig("10.0.0.1", "/m", 7, 1)); err != nil {
		t.Errorf("after release: %v", err)
	}
}

// アダプターごとの流量制限: 枠が半分を切ったら正常な応答を断り、残りはエラーに使う。時間が経てば枠が戻る。
func TestAdmission_RateLimitPerAdapter(t *testing.T) {
	a := newAdmission(Limits{AdapterRate: 10})
	clock := time.Unix(1_700_000_000, 0)
	a.now = func() time.Time { return clock }
	bff := fromAdapter("192.0.2.10")
	count := func(ctx context.Context, code int32, n int) (ok int) {
		for range n {
			if _, err := a.admit(ctx, sig("198.51.100.1", "/m", code, 1)); err == nil {
				ok++
			}
		}
		return ok
	}
	if got := count(bff, 0, 20); got != 6 { // 枠 10 のうち 5 以上残っている間 (10, 9, ..., 5)
		t.Errorf("ok admitted = %d, want 6", got)
	}
	if got := count(bff, 7, 20); got != 4 { // 残りの 4 はエラーに使える
		t.Errorf("errors admitted = %d, want 4", got)
	}
	if got := count(fromAdapter("192.0.2.11"), 0, 1); got != 1 {
		t.Error("another adapter must have its own limit")
	}
	clock = clock.Add(time.Second) // 1 秒で 10 件ぶん戻る
	if got := count(bff, 0, 20); got != 6 {
		t.Errorf("after refill: ok admitted = %d, want 6", got)
	}
	if ok, errs := a.rejected[reasonRateLimited][kindOK].Load(), a.rejected[reasonRateLimited][kindError].Load(); ok != 28 || errs != 16 {
		t.Errorf("rejected ok = %d, error = %d, want 28 and 16", ok, errs)
	}
}

func TestAdmission_ForgetsAdapters(t *testing.T) {
	a := newAdmission(Limits{AdapterRate: 10})
	for i := range maxAdapters + 10 {
		a.admit(fromAdapter(net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)).String()), sig("x", "/m", 7, 1))
	}
	if len(a.adapters) > maxAdapters {
		t.Errorf("adapters = %d, want at most %d", len(a.adapters), maxAdapters)
	}
}

// 断ったシグナルは統計に記録せず、Stats で数えられる。HTTP では 429 を返す。
func TestServer_LimitsAndStats(t *testing.T) {
	srv := NewServer(buffer.NewMemoryBuffer(), classifier.NewDefault(), nil, Options{Logger: quietLogger, Limits: Limits{AdapterRate: 2}})
	defer srv.Close()
	ts := httptest.NewServer(srv.HTTPHandler("tok"))
	defer ts.Close()

	var codes []int
	for range 3 {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/signals",
			strings.NewReader(`{"user_context":{"client_ip":"198.51.100.1"},"request_context":{"method":"/m"},"response_context":{"status_code":0}}`))
		req.Header.Set("Authorization", "Bearer tok")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		codes = append(codes, res.StatusCode)
	}
	// 枠 2: 1 件目は受け付け、2 件目からは半分 (1) を切るので正常な応答は断る
	if codes[0] != 200 || codes[2] != http.StatusTooManyRequests {
		t.Errorf("status codes = %v, want 200 first and 429 last", codes)
	}
	st := srv.Stats()
	if st.Evaluated[1] == 0 || st.RateLimitedOK == 0 || st.InFlight != 0 {
		t.Errorf("stats = %+v", st)
	}
}

// 受け付けの判断 (同時実行数と流量制限) にかかる時間 (8 並列、アダプター 16 台)。
//
//	go test -run '^$' -bench Admission -benchmem ./pkg/receiver/
func BenchmarkAdmission(b *testing.B) {
	a := newAdmission(Limits{MaxInFlight: 1 << 30, AdapterRate: 1e12})
	s := sig("198.51.100.1", "/m", 0, 1)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		ctx := fromAdapter(fmt.Sprintf("192.0.2.%d", time.Now().UnixNano()%16))
		for pb.Next() {
			release, err := a.admit(ctx, s)
			if err != nil {
				b.Error(err)
				return
			}
			release()
		}
	})
}
