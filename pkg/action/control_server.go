package action

import (
	"time"

	jevargosv1 "github.com/jornJp0201/jev-argos/gen/v1"
)

// ControlServer は遮断リストを配信する gRPC サービス (jevargos.v1.ControlService)。
type ControlServer struct {
	jevargosv1.UnimplementedControlServiceServer
	Blocklist Blocklist
}

var _ jevargosv1.ControlServiceServer = (*ControlServer)(nil)

// WatchBlocklist は現在の遮断リスト全体を送った後、追加・解除を送り続ける。
func (s *ControlServer) WatchBlocklist(_ *jevargosv1.WatchBlocklistRequest, stream jevargosv1.ControlService_WatchBlocklistServer) error {
	// スナップショットより前に購読を始め、その間の変更を取りこぼさないようにする
	events, cancel := s.Blocklist.Subscribe()
	defer cancel()

	entries, err := s.Blocklist.List(stream.Context())
	if err != nil {
		return err
	}
	snapshot := &jevargosv1.BlocklistEvent{Kind: jevargosv1.BlocklistEvent_SNAPSHOT}
	for _, e := range entries {
		snapshot.Entries = append(snapshot.Entries, toProto(e))
	}
	if err := stream.Send(snapshot); err != nil {
		return err
	}

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case ev, ok := <-events:
			if !ok {
				return nil
			}
			kind := jevargosv1.BlocklistEvent_ADDED
			if ev.Kind == EventRemoved {
				kind = jevargosv1.BlocklistEvent_REMOVED
			}
			if err := stream.Send(&jevargosv1.BlocklistEvent{Kind: kind, Entries: []*jevargosv1.BlockEntry{toProto(ev.Entry)}}); err != nil {
				return err
			}
		}
	}
}

func toProto(e Entry) *jevargosv1.BlockEntry {
	var expires int64
	if !e.ExpiresAt.IsZero() {
		expires = e.ExpiresAt.UnixMilli()
	}
	return &jevargosv1.BlockEntry{
		TargetType:      e.TargetType,
		Target:          e.Target,
		Reason:          e.Reason,
		Source:          e.Source,
		ExpiresAtUnixMs: expires,
	}
}

// FromProto は BlockEntry を Entry に変換する (クライアント側で使う)。
func FromProto(p *jevargosv1.BlockEntry) Entry {
	e := Entry{TargetType: p.GetTargetType(), Target: p.GetTarget(), Reason: p.GetReason(), Source: p.GetSource()}
	if ms := p.GetExpiresAtUnixMs(); ms > 0 {
		e.ExpiresAt = time.UnixMilli(ms)
	}
	return e
}
