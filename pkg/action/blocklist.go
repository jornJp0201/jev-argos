// Package action は判定結果を実際の防御につなぐ Action Emitter (設計書 2 章・6.2) を提供する。
//
//   - Blocklist: 遮断中の送信元の一覧。Level 4 の自動遮断と、承認された遮断が登録される。
//     アダプターは ControlService.WatchBlocklist で購読し、遮断中の送信元をアプリ側で拒否する。
//   - Executor: 承認されたアクションの実行。IP 遮断は Blocklist に登録し、
//     それ以外 (セッション無効化・アカウント停止など) はアプリへ Webhook で実行を依頼する。
package action

import (
	"context"
	"sort"
	"sync"
	"time"
)

// TargetIP は IP アドレスを対象とする遮断。
const TargetIP = "ip"

// 遮断の登録元。
const (
	SourceLevel4   = "jev_level4" // Jev が Level 4 と判定して自動遮断
	SourceApproval = "approval"   // 承認キューで管理者が承認
	SourceAdmin    = "admin"      // 管理者が手動で遮断
)

// DefaultBlockTTL は自動遮断・承認による遮断の既定の期間。
const DefaultBlockTTL = 15 * time.Minute

// Entry は遮断リストの 1 件。
type Entry struct {
	TargetType string    `json:"target_type"`
	Target     string    `json:"target"`
	Reason     string    `json:"reason"`
	Source     string    `json:"source"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at,omitzero"` // ゼロ値なら無期限
}

func (e Entry) expired(now time.Time) bool {
	return !e.ExpiresAt.IsZero() && !now.Before(e.ExpiresAt)
}

// EventKind は遮断リストの変更の種類。
type EventKind int

const (
	EventAdded EventKind = iota + 1
	EventRemoved
)

// Event は遮断リストの変更通知。
type Event struct {
	Kind  EventKind
	Entry Entry
}

// Blocklist は遮断リストの保存先。
type Blocklist interface {
	// Block は対象を遮断する。既に遮断中なら内容と期限を上書きする。
	Block(ctx context.Context, e Entry) error
	// Unblock は遮断を解除する。遮断されていなければ何もしない。
	Unblock(ctx context.Context, targetType, target string) error
	// List は期限内の遮断を返す。
	List(ctx context.Context) ([]Entry, error)
	// IsBlocked は対象が遮断中かを返す。
	IsBlocked(ctx context.Context, targetType, target string) (bool, error)
	// Subscribe は追加・解除 (期限切れを含む) の通知を受け取るチャネルを返す。cancel で購読を解除する。
	Subscribe() (events <-chan Event, cancel func())
}

func key(targetType, target string) string { return targetType + "\x00" + target }

// subscribers は Blocklist 実装で共通の購読者管理。
type subscribers struct {
	mu   sync.Mutex
	subs map[chan Event]struct{}
}

func (s *subscribers) subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 256)
	s.mu.Lock()
	if s.subs == nil {
		s.subs = make(map[chan Event]struct{})
	}
	s.subs[ch] = struct{}{}
	s.mu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			s.mu.Lock()
			delete(s.subs, ch)
			s.mu.Unlock()
			close(ch)
		})
	}
}

// publish は購読者に通知する。受信が追いつかない購読者への通知は捨てる
// (購読者は再接続時の SNAPSHOT で最新状態に戻れる)。
func (s *subscribers) publish(ev Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// MemoryBlocklist はプロセス内メモリの Blocklist。単一インスタンス構成・開発用。
// 複数インスタンスでは RedisBlocklist を使うこと (遮断がインスタンス間で共有されない)。
type MemoryBlocklist struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]Entry
	subs    subscribers
}

var _ Blocklist = (*MemoryBlocklist)(nil)

func NewMemoryBlocklist() *MemoryBlocklist {
	return newMemoryBlocklist(time.Now)
}

func newMemoryBlocklist(now func() time.Time) *MemoryBlocklist {
	return &MemoryBlocklist{now: now, entries: make(map[string]Entry)}
}

func (b *MemoryBlocklist) Block(_ context.Context, e Entry) error {
	if e.CreatedAt.IsZero() {
		e.CreatedAt = b.now()
	}
	b.mu.Lock()
	b.entries[key(e.TargetType, e.Target)] = e
	b.mu.Unlock()
	b.subs.publish(Event{Kind: EventAdded, Entry: e})
	return nil
}

func (b *MemoryBlocklist) Unblock(_ context.Context, targetType, target string) error {
	b.mu.Lock()
	e, ok := b.entries[key(targetType, target)]
	delete(b.entries, key(targetType, target))
	b.mu.Unlock()
	if ok {
		b.subs.publish(Event{Kind: EventRemoved, Entry: e})
	}
	return nil
}

func (b *MemoryBlocklist) List(_ context.Context) ([]Entry, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	out := make([]Entry, 0, len(b.entries))
	for _, e := range b.entries {
		if !e.expired(now) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (b *MemoryBlocklist) IsBlocked(_ context.Context, targetType, target string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.entries[key(targetType, target)]
	return ok && !e.expired(b.now()), nil
}

func (b *MemoryBlocklist) Subscribe() (<-chan Event, func()) { return b.subs.subscribe() }

// Sweep は期限切れの遮断を削除し、解除として通知する。
func (b *MemoryBlocklist) Sweep() {
	now := b.now()
	var removed []Entry
	b.mu.Lock()
	for k, e := range b.entries {
		if e.expired(now) {
			removed = append(removed, e)
			delete(b.entries, k)
		}
	}
	b.mu.Unlock()
	for _, e := range removed {
		b.subs.publish(Event{Kind: EventRemoved, Entry: e})
	}
}

// StartSweeper は interval ごとに Sweep を実行する goroutine を起動する。ctx のキャンセルで停止する。
func (b *MemoryBlocklist) StartSweeper(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	go func() {
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				b.Sweep()
			}
		}
	}()
}
