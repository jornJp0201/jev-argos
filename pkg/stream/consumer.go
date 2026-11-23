package stream

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/jornJp0201/jev-argos/pkg/guardrail"
	"github.com/jornJp0201/jev-argos/pkg/receiver"
)

// ConsumerOptions は Consumer の設定。
type ConsumerOptions struct {
	// Group は consumer group の名前 (後続処理ごとに 1 つ。例: "notify")。必須。
	// 同じ Group の Consumer 同士はエントリを分け合い、Group が違えばそれぞれが全件を受け取る。
	Group   string
	Emitter receiver.Emitter
	// MinLevel はこの Level 以上の判定だけを Emitter に渡す (0 ならすべて)。
	MinLevel guardrail.Level
	// Flush を指定すると、読んだ分を処理し終えてから処理済み (XACK) にする前に呼ぶ
	// (例: 判定ログをまとめて書く BatchWriter の Flush。書く前に処理済みにすると、停止したときに失われるため)。
	Flush func(context.Context)

	Stream    string        // ストリームのキー (既定 DefaultStream)
	Name      string        // この Consumer の名前 (既定: ホスト名とプロセス ID)
	BatchSize int64         // 1 回に読む件数の上限 (既定 100)
	Block     time.Duration // 新しいエントリを待つ時間 (既定 1 秒)
	// ClaimIdle は、他の Consumer が読んだまま処理済みにしていないエントリを引き取るまでの時間 (既定 30 秒)。
	// その Consumer のプロセスが落ちた場合に、エントリを失わないため。
	ClaimIdle time.Duration
	Logger    *slog.Logger
}

// Consumer はストリームを consumer group で読み、Emitter に渡す。worker 側で使う。
//
// エントリは Emitter に渡し終えてから処理済み (XACK) にする。プロセスが途中で落ちた場合、処理済みにしていない
// エントリは ClaimIdle 後に同じ Group の他の Consumer (または再起動後の自分) が引き取って処理する (at-least-once)。
type Consumer struct {
	client redis.UniversalClient
	opts   ConsumerOptions
}

// NewConsumer は Consumer を返す。Run で読み始める。
func NewConsumer(client redis.UniversalClient, opts ConsumerOptions) (*Consumer, error) {
	if opts.Group == "" || opts.Emitter == nil {
		return nil, errors.New("stream: consumer group and emitter are required")
	}
	if opts.Stream == "" {
		opts.Stream = DefaultStream
	}
	if opts.Name == "" {
		host, _ := os.Hostname()
		opts.Name = fmt.Sprintf("%s-%d", host, os.Getpid())
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 100
	}
	if opts.Block <= 0 {
		opts.Block = time.Second
	}
	if opts.ClaimIdle <= 0 {
		opts.ClaimIdle = 30 * time.Second
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Consumer{client: client, opts: opts}, nil
}

// Run は ctx がキャンセルされるまでストリームを読み続ける。Redis に接続できない間は再試行する。
// ctx のキャンセル後は、読んだ分を処理し終えてから戻る。
func (c *Consumer) Run(ctx context.Context) {
	logger := c.opts.Logger.With("group", c.opts.Group)
	for ctx.Err() == nil {
		if err := c.createGroup(ctx); err != nil {
			logger.Error("create consumer group failed", "err", err)
			sleep(ctx, time.Second)
			continue
		}
		break
	}
	lastClaim := time.Time{}
	for ctx.Err() == nil {
		// 落ちた Consumer が残したエントリを、ClaimIdle の 1/3 ごとに引き取る
		if time.Since(lastClaim) >= c.opts.ClaimIdle/3 {
			lastClaim = time.Now()
			if err := c.claim(ctx); err != nil && ctx.Err() == nil {
				logger.Error("claim pending entries failed", "err", err)
			}
		}
		res, err := c.client.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group:    c.opts.Group,
			Consumer: c.opts.Name,
			Streams:  []string{c.opts.Stream, ">"},
			Count:    c.opts.BatchSize,
			Block:    c.opts.Block,
		}).Result()
		if err != nil {
			if errors.Is(err, redis.Nil) || ctx.Err() != nil {
				continue
			}
			if strings.HasPrefix(err.Error(), "NOGROUP") { // ストリームが消された場合など
				_ = c.createGroup(ctx)
				continue
			}
			logger.Error("read stream failed", "err", err)
			sleep(ctx, time.Second)
			continue
		}
		for _, s := range res {
			c.process(s.Messages)
		}
	}
}

// createGroup は consumer group を作る (既にあれば何もしない)。新しい Group は、作った後に追加された分から読む。
func (c *Consumer) createGroup(ctx context.Context) error {
	err := c.client.XGroupCreateMkStream(ctx, c.opts.Stream, c.opts.Group, "$").Err()
	if err != nil && !strings.HasPrefix(err.Error(), "BUSYGROUP") {
		return err
	}
	return nil
}

// claim は ClaimIdle 以上処理済みになっていないエントリを引き取って処理する。
func (c *Consumer) claim(ctx context.Context) error {
	start := "0-0"
	for {
		msgs, next, err := c.client.XAutoClaim(ctx, &redis.XAutoClaimArgs{
			Stream:   c.opts.Stream,
			Group:    c.opts.Group,
			Consumer: c.opts.Name,
			MinIdle:  c.opts.ClaimIdle,
			Start:    start,
			Count:    c.opts.BatchSize,
		}).Result()
		if err != nil {
			return err
		}
		if len(msgs) > 0 {
			c.opts.Logger.Warn("claimed entries left by another consumer", "group", c.opts.Group, "count", len(msgs))
			c.process(msgs)
		}
		if next == "0-0" || len(msgs) == 0 {
			return nil
		}
		start = next
	}
}

// process はエントリを Emitter に渡し、Flush してから処理済みにする。
// 停止中 (ctx のキャンセル後) でも、読んだ分は処理し終えるよう、ここでは呼び出し元の ctx を使わない。
func (c *Consumer) process(msgs []redis.XMessage) {
	if len(msgs) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ids := make([]string, 0, len(msgs))
	for _, m := range msgs {
		ids = append(ids, m.ID)
		en, err := parse(m)
		if err != nil {
			// 読めないエントリは何度読んでも読めないため、処理済みにして捨てる
			c.opts.Logger.Error("drop malformed stream entry", "group", c.opts.Group, "id", m.ID, "err", err)
			continue
		}
		if en.kind != kindEvent || en.event.Decision.Level < c.opts.MinLevel {
			continue
		}
		c.emit(ctx, en)
	}
	if c.opts.Flush != nil {
		c.opts.Flush(ctx)
	}
	if err := c.client.XAck(ctx, c.opts.Stream, c.opts.Group, ids...).Err(); err != nil {
		// 処理済みにできなかったエントリは ClaimIdle 後に再び処理される (重複しうる)
		c.opts.Logger.Error("ack stream entries failed", "group", c.opts.Group, "count", len(ids), "err", err)
	}
}

func (c *Consumer) emit(ctx context.Context, en entry) {
	defer func() {
		if r := recover(); r != nil {
			c.opts.Logger.Error("emitter panicked", "group", c.opts.Group, "id", en.id, "panic", r)
		}
	}()
	c.opts.Emitter.Emit(ctx, en.event)
}
