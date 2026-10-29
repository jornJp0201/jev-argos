package action

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisBlocklist は Redis 上の Blocklist。複数インスタンスで遮断リストを共有し、
// どのインスタンスで遮断しても、全インスタンスに接続したアダプターへ配信される。
//
// キー構成:
//
//	<prefix>block:<type>:<target>   String (Entry の JSON)。期限付きの遮断は Redis の TTL で自動削除
//	<prefix>block-events            Pub/Sub チャネル (追加・解除の通知)
//
// TTL による自動削除は Pub/Sub に通知されないため、購読側は Entry.ExpiresAt で期限切れを判断すること
// (アダプターは期限を見て自動的に解除する)。
type RedisBlocklist struct {
	client redis.UniversalClient
	prefix string
	now    func() time.Time
	logger *slog.Logger
	subs   subscribers
}

var _ Blocklist = (*RedisBlocklist)(nil)

type redisEvent struct {
	Kind  EventKind `json:"kind"`
	Entry Entry     `json:"entry"`
}

// NewRedisBlocklist は RedisBlocklist を作り、他のインスタンスからの通知の受信を始める。
// ctx のキャンセルで受信を止める。
func NewRedisBlocklist(ctx context.Context, client redis.UniversalClient, prefix string, logger *slog.Logger) *RedisBlocklist {
	if prefix == "" {
		prefix = "jevargos:"
	}
	if logger == nil {
		logger = slog.Default()
	}
	b := &RedisBlocklist{client: client, prefix: prefix, now: time.Now, logger: logger}
	go b.relay(ctx)
	return b
}

func (b *RedisBlocklist) entryKey(targetType, target string) string {
	return b.prefix + "block:" + targetType + ":" + target
}

func (b *RedisBlocklist) channel() string { return b.prefix + "block-events" }

func (b *RedisBlocklist) Block(ctx context.Context, e Entry) error {
	if e.CreatedAt.IsZero() {
		e.CreatedAt = b.now()
	}
	var ttl time.Duration
	if !e.ExpiresAt.IsZero() {
		if ttl = e.ExpiresAt.Sub(b.now()); ttl <= 0 {
			return nil // 既に期限切れ
		}
	}
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err := b.client.Set(ctx, b.entryKey(e.TargetType, e.Target), data, ttl).Err(); err != nil {
		return fmt.Errorf("redis blocklist: block: %w", err)
	}
	return b.publish(ctx, Event{Kind: EventAdded, Entry: e})
}

func (b *RedisBlocklist) Unblock(ctx context.Context, targetType, target string) error {
	data, err := b.client.GetDel(ctx, b.entryKey(targetType, target)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("redis blocklist: unblock: %w", err)
	}
	var e Entry
	if err := json.Unmarshal(data, &e); err != nil {
		e = Entry{TargetType: targetType, Target: target}
	}
	return b.publish(ctx, Event{Kind: EventRemoved, Entry: e})
}

func (b *RedisBlocklist) List(ctx context.Context) ([]Entry, error) {
	var out []Entry
	iter := b.client.Scan(ctx, 0, b.prefix+"block:*", 500).Iterator()
	var keys []string
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("redis blocklist: list: %w", err)
	}
	if len(keys) == 0 {
		return out, nil
	}
	values, err := b.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("redis blocklist: list: %w", err)
	}
	now := b.now()
	for _, v := range values {
		s, ok := v.(string)
		if !ok {
			continue // SCAN と MGET の間に期限切れ
		}
		var e Entry
		if json.Unmarshal([]byte(s), &e) == nil && !e.expired(now) {
			out = append(out, e)
		}
	}
	return out, nil
}

func (b *RedisBlocklist) IsBlocked(ctx context.Context, targetType, target string) (bool, error) {
	n, err := b.client.Exists(ctx, b.entryKey(targetType, target)).Result()
	if err != nil {
		return false, fmt.Errorf("redis blocklist: exists: %w", err)
	}
	return n > 0, nil
}

func (b *RedisBlocklist) Subscribe() (<-chan Event, func()) { return b.subs.subscribe() }

func (b *RedisBlocklist) publish(ctx context.Context, ev Event) error {
	data, err := json.Marshal(redisEvent{Kind: ev.Kind, Entry: ev.Entry})
	if err != nil {
		return err
	}
	if err := b.client.Publish(ctx, b.channel(), data).Err(); err != nil {
		return fmt.Errorf("redis blocklist: publish: %w", err)
	}
	return nil
}

// relay は Pub/Sub の通知 (自インスタンスの変更を含む) をこのインスタンスの購読者へ中継する。
func (b *RedisBlocklist) relay(ctx context.Context) {
	ps := b.client.Subscribe(ctx, b.channel())
	defer ps.Close()
	ch := ps.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			var ev redisEvent
			if err := json.Unmarshal([]byte(msg.Payload), &ev); err != nil || !strings.HasPrefix(msg.Channel, b.prefix) {
				b.logger.Warn("redis blocklist: invalid event", "err", err)
				continue
			}
			b.subs.publish(Event{Kind: ev.Kind, Entry: ev.Entry})
		}
	}
}
