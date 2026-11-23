// Package stream は判定結果を Redis Streams で受け渡し、判定と後続処理を別のプロセスに分ける。
//
//	[ 判定サーバー (receiver) × N ]  --- Publisher: XADD --->  Redis Stream  --- Consumer: XREADGROUP --->  [ worker × M ]
//	  受信・判定・自動遮断                                       jevargos:events                          承認キュー・判定ログ・LLM・通知
//
// 判定サーバーは受信と判定 (と最優先の自動遮断) だけを行い、状態を持たないため、台数で横に増やせる。
// 後続処理は処理ごとの consumer group で読むため、どれかが遅れても他は止まらず、遅れた分は Redis に残って後から処理される
// (プロセス内のキューのように、あふれて捨てられることがない)。
//
// ストリームには 2 種類のエントリを流す:
//   - event:   Level 2 以上の判定 1 件 (receiver.Event)
//   - summary: Level 1 の判定の件数とスコアの合計 (判定サーバーごとに 1 秒に 1 回)。ダッシュボード用
package stream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/encoding/protojson"

	jevargosv1 "github.com/jornJp0201/jev-argos/gen/v1"
	"github.com/jornJp0201/jev-argos/pkg/buffer"
	"github.com/jornJp0201/jev-argos/pkg/classifier"
	"github.com/jornJp0201/jev-argos/pkg/guardrail"
	"github.com/jornJp0201/jev-argos/pkg/receiver"
)

const (
	// DefaultStream はストリームのキー。
	DefaultStream = "jevargos:events"
	// DefaultMaxLen はストリームに残すエントリ数の目安 (XADD MAXLEN ~)。
	// 後続処理がこれ以上遅れると、古いエントリから消える。
	DefaultMaxLen = 100000
)

// エントリのフィールド。
const (
	fieldKind = "kind"
	fieldData = "data"

	kindEvent   = "event"
	kindSummary = "summary"
)

// wireEvent はストリームに載せる receiver.Event の形式。
type wireEvent struct {
	Signal     json.RawMessage       `json:"signal"` // protojson
	Features   buffer.Features       `json:"features"`
	Assessment classifier.Assessment `json:"assessment"`
	Decision   guardrail.Decision    `json:"decision"`
}

// Summary は判定サーバー 1 台が SummaryInterval の間に数えた Level 1 の判定。
// 件数は、アダプターが間引いて送った分 (sample_rate) を含めた推定値。
type Summary struct {
	Count    float64 `json:"count"`
	ScoreSum float64 `json:"score_sum"`
}

func encodeEvent(e receiver.Event) (string, error) {
	sig, err := protojson.Marshal(e.Signal)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(wireEvent{Signal: sig, Features: e.Features, Assessment: e.Assessment, Decision: e.Decision})
	return string(data), err
}

func decodeEvent(data string) (receiver.Event, error) {
	var w wireEvent
	if err := json.Unmarshal([]byte(data), &w); err != nil {
		return receiver.Event{}, err
	}
	sig := &jevargosv1.SecuritySignal{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(w.Signal, sig); err != nil {
		return receiver.Event{}, err
	}
	return receiver.Event{Signal: sig, Features: w.Features, Assessment: w.Assessment, Decision: w.Decision}, nil
}

// entry はストリームから読んだ 1 件。kind が kindEvent なら event、kindSummary なら summary が入る。
type entry struct {
	id      string
	kind    string
	event   receiver.Event
	summary Summary
}

func parse(m redis.XMessage) (entry, error) {
	kind, _ := m.Values[fieldKind].(string)
	data, _ := m.Values[fieldData].(string)
	en := entry{id: m.ID, kind: kind}
	var err error
	switch kind {
	case kindEvent:
		en.event, err = decodeEvent(data)
	case kindSummary:
		err = json.Unmarshal([]byte(data), &en.summary)
	default:
		err = fmt.Errorf("unknown kind %q", kind)
	}
	return en, err
}

// Handlers は Tail が読んだエントリを受け取る関数。
type Handlers struct {
	Event   func(receiver.Event)
	Summary func(Summary)
}

// Tail はストリームに新しく追加されたエントリを、すべて h に渡し続ける (ctx のキャンセルで戻る)。
// consumer group を使わないため、Tail を呼んだプロセスはそれぞれ全件を受け取る (ダッシュボードへの配信用)。
// Redis に接続できない間は再試行する。
func Tail(ctx context.Context, client redis.UniversalClient, stream string, h Handlers, onError func(error)) {
	if stream == "" {
		stream = DefaultStream
	}
	last := "$" // 起動後に追加された分から読む
	for ctx.Err() == nil {
		res, err := client.XRead(ctx, &redis.XReadArgs{Streams: []string{stream, last}, Count: 500, Block: time.Second}).Result()
		if err != nil {
			if errors.Is(err, redis.Nil) || ctx.Err() != nil {
				continue
			}
			if onError != nil {
				onError(err)
			}
			sleep(ctx, time.Second)
			continue
		}
		for _, s := range res {
			for _, m := range s.Messages {
				last = m.ID
				en, err := parse(m)
				if err != nil {
					if onError != nil {
						onError(fmt.Errorf("stream entry %s: %w", m.ID, err))
					}
					continue
				}
				switch {
				case en.kind == kindEvent && h.Event != nil:
					h.Event(en.event)
				case en.kind == kindSummary && h.Summary != nil:
					h.Summary(en.summary)
				}
			}
		}
	}
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
