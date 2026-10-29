package client

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"

	jevargosv1 "github.com/jev-argos/jev-argos/gen/v1"
)

// BlocklistWatcher はコントロールサーバーの遮断リスト (ControlService.WatchBlocklist) を購読し、手元に保持する。
// IsBlocked は手元のコピーを見るだけなので、リクエストごとに通信は発生しない。
// 接続が切れた場合は自動で再接続し、その間は最後に受け取った一覧で判定を続ける (期限切れは手元で解除する)。
type BlocklistWatcher struct {
	client jevargosv1.ControlServiceClient
	logger *slog.Logger

	mu      sync.RWMutex
	entries map[string]time.Time // IP -> 期限 (ゼロ値なら無期限)
	ready   atomic.Bool
}

// NewBlocklistWatcher は購読を始める。ctx のキャンセルで止まる。
func NewBlocklistWatcher(ctx context.Context, conn grpc.ClientConnInterface, logger *slog.Logger) *BlocklistWatcher {
	if logger == nil {
		logger = slog.Default()
	}
	w := &BlocklistWatcher{client: jevargosv1.NewControlServiceClient(conn), logger: logger, entries: make(map[string]time.Time)}
	go w.run(ctx)
	return w
}

// IsBlocked は IP が遮断中か。
func (w *BlocklistWatcher) IsBlocked(ip string) bool {
	w.mu.RLock()
	expires, ok := w.entries[normalizeIP(ip)]
	w.mu.RUnlock()
	return ok && (expires.IsZero() || time.Now().Before(expires))
}

// Ready は最初の一覧 (SNAPSHOT) を受け取ったか。
func (w *BlocklistWatcher) Ready() bool { return w.ready.Load() }

func (w *BlocklistWatcher) run(ctx context.Context) {
	delay := time.Second
	for ctx.Err() == nil {
		err := w.watch(ctx)
		if ctx.Err() != nil {
			return
		}
		w.logger.Debug("jev-argos blocklist stream ended; reconnecting", "err", err, "in", delay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, 30*time.Second)
	}
}

func (w *BlocklistWatcher) watch(ctx context.Context) error {
	stream, err := w.client.WatchBlocklist(ctx, &jevargosv1.WatchBlocklistRequest{})
	if err != nil {
		return err
	}
	for {
		ev, err := stream.Recv()
		if err != nil {
			return err
		}
		w.apply(ev)
	}
}

func (w *BlocklistWatcher) apply(ev *jevargosv1.BlocklistEvent) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ev.GetKind() == jevargosv1.BlocklistEvent_SNAPSHOT {
		w.entries = make(map[string]time.Time)
		w.ready.Store(true)
	}
	for _, e := range ev.GetEntries() {
		if e.GetTargetType() != "ip" {
			continue
		}
		if ev.GetKind() == jevargosv1.BlocklistEvent_REMOVED {
			delete(w.entries, normalizeIP(e.GetTarget()))
			continue
		}
		var expires time.Time
		if ms := e.GetExpiresAtUnixMs(); ms > 0 {
			expires = time.UnixMilli(ms)
		}
		w.entries[normalizeIP(e.GetTarget())] = expires
	}
}
