package receiver

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	jevargosv1 "github.com/jornJp0201/jev-argos/gen/v1"
)

// Limits は判定サーバーを守るための上限 (Options.Limits)。0 の項目は制限しない。
//
// どちらの上限も、上限に近づくと正常な応答のシグナルから先に断る。正常な応答は大半が Level 1 で、
// サーバーではレイテンシの基準値とダッシュボードの件数にしか使わない。攻撃の判定に使うのはエラーのシグナルなので、
// 過負荷のときもエラーは最後まで受け付ける (攻撃者が大量の正常なリクエストで判定を妨げられないように)。
type Limits struct {
	// MaxInFlight は同時に判定するシグナルの上限。超えたシグナルは ResourceExhausted で断る。
	// 判定中の数が MaxInFlight の ShedRatio 倍を超えたら、正常な応答のシグナルを断る。
	MaxInFlight int
	ShedRatio   float64 // 0 なら 0.8
	// AdapterRate は 1 つのアダプター (接続元の IP) から受け付ける 1 秒あたりのシグナル数。超えた分は ResourceExhausted で断る。
	// 手元の枠 (AdapterBurst) が半分を切ったら、正常な応答のシグナルを断り、残りの半分はエラーのために取っておく。
	AdapterRate  float64
	AdapterBurst int // 0 なら AdapterRate (1 秒分)
}

// 断った理由と、シグナルの種類 (Stats.Rejected の添字)。
const (
	reasonRateLimited = iota
	reasonOverloaded
	numReasons
)

const (
	kindOK = iota
	kindError
	numKinds
)

// maxAdapters は流量制限のために覚えておくアダプターの数の上限 (接続元を偽ってメモリを使い切らせないように)。
const maxAdapters = 10000

type admission struct {
	limits   Limits
	inFlight atomic.Int64
	rejected [numReasons][numKinds]atomic.Uint64

	mu       sync.Mutex
	adapters map[string]*bucket
	now      func() time.Time
}

func newAdmission(l Limits) *admission {
	if l.ShedRatio <= 0 || l.ShedRatio > 1 {
		l.ShedRatio = 0.8
	}
	if l.AdapterBurst <= 0 {
		l.AdapterBurst = max(1, int(l.AdapterRate))
	}
	return &admission{limits: l, adapters: make(map[string]*bucket), now: time.Now}
}

// admit はシグナルを受け付けるかを決める。受け付けた場合は、判定し終えたら release を呼ぶ。
func (a *admission) admit(ctx context.Context, signal *jevargosv1.SecuritySignal) (release func(), err error) {
	kind := kindOK
	if signal.GetResponseContext().GetStatusCode() != 0 {
		kind = kindError
	}
	if a.limits.AdapterRate > 0 && !a.take(adapterOf(ctx), kind) {
		a.rejected[reasonRateLimited][kind].Add(1)
		return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded for this adapter")
	}
	n := a.inFlight.Add(1)
	if limit := int64(a.limits.MaxInFlight); limit > 0 {
		shedAt := int64(float64(limit) * a.limits.ShedRatio)
		if n > limit || (kind == kindOK && n > shedAt) {
			a.inFlight.Add(-1)
			a.rejected[reasonOverloaded][kind].Add(1)
			return nil, status.Error(codes.ResourceExhausted, "server overloaded")
		}
	}
	return func() { a.inFlight.Add(-1) }, nil
}

// take は adapter の枠を 1 つ使う。正常な応答は枠が半分以上残っているときだけ使える。
func (a *admission) take(adapter string, kind int) bool {
	now := a.now()
	burst := float64(a.limits.AdapterBurst)
	a.mu.Lock()
	defer a.mu.Unlock()
	b, ok := a.adapters[adapter]
	if !ok {
		if len(a.adapters) >= maxAdapters {
			a.evictFull(now)
		}
		b = &bucket{tokens: burst, at: now}
		a.adapters[adapter] = b
	}
	b.refill(now, a.limits.AdapterRate, burst)
	need := 1.0
	if kind == kindOK {
		need = burst / 2 // 残りの半分はエラーのために取っておく
	}
	if b.tokens < max(need, 1) {
		return false
	}
	b.tokens--
	return true
}

// evictFull は枠が満タンに戻った (しばらく送ってこない) アダプターを忘れる。それでも空かなければすべて忘れる。
func (a *admission) evictFull(now time.Time) {
	burst := float64(a.limits.AdapterBurst)
	for k, b := range a.adapters {
		if b.refill(now, a.limits.AdapterRate, burst); b.tokens >= burst {
			delete(a.adapters, k)
		}
	}
	if len(a.adapters) >= maxAdapters {
		clear(a.adapters)
	}
}

// bucket はトークンバケット。
type bucket struct {
	tokens float64
	at     time.Time
}

func (b *bucket) refill(now time.Time, rate, burst float64) {
	b.tokens = min(burst, b.tokens+now.Sub(b.at).Seconds()*rate)
	b.at = now
}

type adapterKey struct{}

// withAdapter は HTTP で受信したシグナルの接続元を ctx に入れる (gRPC は peer から取る)。
func withAdapter(ctx context.Context, remoteAddr string) context.Context {
	return context.WithValue(ctx, adapterKey{}, hostOf(remoteAddr))
}

// adapterOf はシグナルを送ってきたアダプターの識別子 (接続元の IP) を返す。
func adapterOf(ctx context.Context) string {
	if a, ok := ctx.Value(adapterKey{}).(string); ok {
		return a
	}
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		return hostOf(p.Addr.String())
	}
	return ""
}

func hostOf(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
