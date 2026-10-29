// Package api はコントロール用フロントエンド向けの管理 HTTP API を提供する。
//
//	GET    /api/healthz                         死活確認 (認証不要)
//	GET    /api/actions?status=pending          アクション一覧 (status 省略で全件)
//	POST   /api/actions                         管理者による起票 body: {"proposed_action", "target", "reason", "created_by"}
//	GET    /api/actions/{id}                    アクション詳細
//	POST   /api/actions/{id}/approve            承認して実行   body: {"decided_by": "...", "note": "..."}
//	POST   /api/actions/{id}/reject             拒否           body: 同上
//	GET    /api/actions/stream                  アクションの作成・更新を Server-Sent Events で配信
//	GET    /api/blocklist                       遮断中の一覧
//	POST   /api/blocklist                       手動で遮断     body: {"target", "reason", "ttl_seconds", "created_by"}
//	DELETE /api/blocklist?target_type=ip&target=...   遮断の解除
//	GET    /api/blocklist/stream                遮断の追加・解除を SSE で配信
//
// /api/healthz 以外は `Authorization: Bearer <token>` が必須。
// 承認は不可逆な操作の実行につながるため、認証なしでは一切受け付けない。
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jornJp0201/jev-argos/pkg/action"
	"github.com/jornJp0201/jev-argos/pkg/approval"
)

const (
	maxBodyBytes    = 16 << 10
	maxDecidedByLen = 100
	maxNoteLen      = 1000
	maxTargetLen    = 200
	sseHeartbeat    = 15 * time.Second
	executeTimeout  = 10 * time.Second
	maxBlockTTL     = 30 * 24 * time.Hour
)

// Config は Handler の設定。
type Config struct {
	Store    approval.Store
	Executor approval.Executor // nil なら approval.LogExecutor
	// Blocklist を指定すると /api/blocklist を有効にする。
	Blocklist action.Blocklist
	// Routes は管理 API の認証 (AdminToken) の内側に追加するエンドポイント (例: "GET /api/events/stream")。
	Routes map[string]http.HandlerFunc
	// PublicRoutes は管理 API の認証を通さずに追加するエンドポイント。ハンドラー自身で認証すること
	// (例: 送信専用トークンで守るシグナル受信 "POST /api/signals")。
	PublicRoutes map[string]http.Handler
	// AdminToken は管理 API の Bearer トークン。空にはできない。
	AdminToken string
	Logger     *slog.Logger
}

type handler struct {
	store     approval.Store
	executor  approval.Executor
	blocklist action.Blocklist
	token     []byte
	logger    *slog.Logger
	mux       *http.ServeMux
}

// NewHandler は管理 API の http.Handler を返す。
func NewHandler(cfg Config) (http.Handler, error) {
	if cfg.AdminToken == "" {
		return nil, errors.New("api: admin token is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Executor == nil {
		cfg.Executor = approval.LogExecutor{Logger: cfg.Logger}
	}
	mux := http.NewServeMux()
	h := &handler{store: cfg.Store, executor: cfg.Executor, blocklist: cfg.Blocklist, token: []byte(cfg.AdminToken), logger: cfg.Logger, mux: mux}

	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("GET /api/actions", h.auth(h.list))
	mux.Handle("POST /api/actions", h.auth(h.create))
	mux.Handle("GET /api/actions/stream", h.auth(h.stream))
	mux.Handle("GET /api/actions/{id}", h.auth(h.get))
	mux.Handle("POST /api/actions/{id}/approve", h.auth(h.decide(true)))
	mux.Handle("POST /api/actions/{id}/reject", h.auth(h.decide(false)))
	for pattern, fn := range cfg.Routes {
		mux.Handle(pattern, h.auth(fn))
	}
	for pattern, handler := range cfg.PublicRoutes {
		mux.Handle(pattern, handler)
	}
	if h.blocklist != nil {
		mux.Handle("GET /api/blocklist", h.auth(h.listBlocks))
		mux.Handle("POST /api/blocklist", h.auth(h.block))
		mux.Handle("DELETE /api/blocklist", h.auth(h.unblock))
		mux.Handle("GET /api/blocklist/stream", h.auth(h.streamBlocks))
	}
	return h, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

// decodeJSON はリクエストボディを v に読み込む。未知のフィールドは拒否する。
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

type createRequest struct {
	ProposedAction approval.ActionType `json:"proposed_action"`
	Target         string              `json:"target"`
	Reason         string              `json:"reason"`
	CreatedBy      string              `json:"created_by"`
}

// create は管理者がアクションを起票する (例: 調査の結果、アカウント停止を提案する)。
// 起票したアクションも承認待ちになり、承認されるまで実行されない。
func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Target = strings.TrimSpace(req.Target)
	req.Reason = strings.TrimSpace(req.Reason)
	req.CreatedBy = strings.TrimSpace(req.CreatedBy)
	switch {
	case !req.ProposedAction.Known():
		writeError(w, http.StatusBadRequest, "unknown proposed_action")
		return
	case req.Target == "" || len(req.Target) > maxTargetLen:
		writeError(w, http.StatusBadRequest, "target is required (max 200 bytes)")
		return
	case req.CreatedBy == "" || len(req.CreatedBy) > maxDecidedByLen:
		writeError(w, http.StatusBadRequest, "created_by is required (max 100 bytes)")
		return
	case req.Reason == "" || len(req.Reason) > maxNoteLen:
		writeError(w, http.StatusBadRequest, "reason is required (max 1000 bytes)")
		return
	}
	a, err := h.store.Propose(r.Context(), approval.Proposal{
		ProposedAction: req.ProposedAction,
		Target:         req.Target,
		Reason:         req.Reason + " (起票: " + req.CreatedBy + ")",
		Source:         approval.SourceAdmin,
	})
	if errors.Is(err, approval.ErrStoreFull) {
		writeError(w, http.StatusServiceUnavailable, "too many pending actions")
		return
	}
	if err != nil {
		h.internalError(w, err)
		return
	}
	h.logger.Info("action created by admin", "action_id", a.ID, "proposed_action", a.ProposedAction, "target", a.Target, "created_by", req.CreatedBy)
	writeJSON(w, http.StatusCreated, a)
}

func (h *handler) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), h.token) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="jev-argos"`)
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	})
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	status := approval.Status(r.URL.Query().Get("status"))
	switch status {
	case "", approval.StatusPending, approval.StatusApproved, approval.StatusRejected:
	default:
		writeError(w, http.StatusBadRequest, "status must be pending, approved or rejected")
		return
	}
	actions, err := h.store.List(r.Context(), status)
	if err != nil {
		h.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": actions})
}

func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	a, err := h.store.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, approval.ErrNotFound) {
		writeError(w, http.StatusNotFound, "action not found")
		return
	}
	if err != nil {
		h.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

type decisionRequest struct {
	DecidedBy string `json:"decided_by"`
	Note      string `json:"note"`
}

func (h *handler) decide(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req decisionRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		req.DecidedBy = strings.TrimSpace(req.DecidedBy)
		req.Note = strings.TrimSpace(req.Note)
		if req.DecidedBy == "" || len(req.DecidedBy) > maxDecidedByLen {
			writeError(w, http.StatusBadRequest, "decided_by is required (max 100 bytes)")
			return
		}
		if len(req.Note) > maxNoteLen {
			writeError(w, http.StatusBadRequest, "note is too long (max 1000 bytes)")
			return
		}

		a, err := h.store.Decide(r.Context(), r.PathValue("id"), approve, req.DecidedBy, req.Note)
		switch {
		case errors.Is(err, approval.ErrNotFound):
			writeError(w, http.StatusNotFound, "action not found")
			return
		case errors.Is(err, approval.ErrAlreadyDecided):
			// 他の管理者が先に決定した。現在の状態を返して画面を更新できるようにする。
			writeJSON(w, http.StatusConflict, map[string]any{"error": "action already decided", "action": a})
			return
		case err != nil:
			h.internalError(w, err)
			return
		}

		h.logger.Info("action decided", "action_id", a.ID, "status", a.Status, "target", a.Target, "decided_by", a.DecidedBy)
		if approve {
			// 管理者の画面が閉じられても実行は最後まで行う
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), executeTimeout)
			defer cancel()
			execErr := h.executor.Execute(ctx, a)
			if execErr != nil {
				h.logger.Error("execute approved action failed", "action_id", a.ID, "err", execErr)
			}
			if recorded, err := h.store.RecordExecution(ctx, a.ID, execErr); err == nil {
				a = recorded
			} else {
				h.logger.Error("record execution failed", "action_id", a.ID, "err", err)
			}
		}
		writeJSON(w, http.StatusOK, a)
	}
}

func (h *handler) stream(w http.ResponseWriter, r *http.Request) {
	updates, cancel := h.store.Subscribe()
	defer cancel()
	ServeSSE(w, r, h.logger, func(a approval.Action) (string, any) { return "action", a }, nil, updates)
}

type blockRequest struct {
	Target     string `json:"target"`
	Reason     string `json:"reason"`
	TTLSeconds int64  `json:"ttl_seconds"` // 0 なら action.DefaultBlockTTL
	CreatedBy  string `json:"created_by"`
}

func (h *handler) listBlocks(w http.ResponseWriter, r *http.Request) {
	entries, err := h.blocklist.List(r.Context())
	if err != nil {
		h.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

func (h *handler) block(w http.ResponseWriter, r *http.Request) {
	var req blockRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Target = strings.TrimSpace(req.Target)
	req.CreatedBy = strings.TrimSpace(req.CreatedBy)
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl == 0 {
		ttl = action.DefaultBlockTTL
	}
	switch {
	case net.ParseIP(req.Target) == nil:
		writeError(w, http.StatusBadRequest, "target must be an IP address")
		return
	case req.CreatedBy == "" || len(req.CreatedBy) > maxDecidedByLen:
		writeError(w, http.StatusBadRequest, "created_by is required (max 100 bytes)")
		return
	case len(req.Reason) > maxNoteLen:
		writeError(w, http.StatusBadRequest, "reason is too long (max 1000 bytes)")
		return
	case ttl < 0 || ttl > maxBlockTTL:
		writeError(w, http.StatusBadRequest, "ttl_seconds must be between 1 and 2592000")
		return
	}
	now := time.Now()
	e := action.Entry{
		TargetType: action.TargetIP,
		Target:     req.Target,
		Reason:     strings.TrimSpace(req.Reason + " (手動: " + req.CreatedBy + ")"),
		Source:     action.SourceAdmin,
		CreatedAt:  now,
		ExpiresAt:  now.Add(ttl),
	}
	if err := h.blocklist.Block(r.Context(), e); err != nil {
		h.internalError(w, err)
		return
	}
	h.logger.Info("blocked by admin", "target", e.Target, "ttl", ttl, "created_by", req.CreatedBy)
	writeJSON(w, http.StatusCreated, e)
}

func (h *handler) unblock(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	targetType, target := q.Get("target_type"), q.Get("target")
	if targetType == "" {
		targetType = action.TargetIP
	}
	if target == "" {
		writeError(w, http.StatusBadRequest, "target is required")
		return
	}
	if err := h.blocklist.Unblock(r.Context(), targetType, target); err != nil {
		h.internalError(w, err)
		return
	}
	h.logger.Info("unblocked by admin", "target_type", targetType, "target", target)
	w.WriteHeader(http.StatusNoContent)
}

type blockEvent struct {
	Kind  string       `json:"kind"` // "added" | "removed"
	Entry action.Entry `json:"entry"`
}

func (h *handler) streamBlocks(w http.ResponseWriter, r *http.Request) {
	events, cancel := h.blocklist.Subscribe()
	defer cancel()
	ServeSSE(w, r, h.logger, func(ev action.Event) (string, any) {
		kind := "added"
		if ev.Kind == action.EventRemoved {
			kind = "removed"
		}
		return "block", blockEvent{Kind: kind, Entry: ev.Entry}
	}, nil, events)
}

// ServeSSE は initial を送った後、updates を Server-Sent Events として配信する。
// encode は (イベント名, データ) を返す。クライアントの切断か updates のクローズで終了する。
func ServeSSE[T any](w http.ResponseWriter, r *http.Request, logger *slog.Logger, encode func(T) (string, any), initial []T, updates <-chan T) {
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no") // リバースプロキシのバッファリングを無効化
	w.WriteHeader(http.StatusOK)

	write := func(s string) bool {
		if _, err := w.Write([]byte(s)); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !write(": connected\n\n") {
		return
	}
	send := func(u T) bool {
		name, v := encode(u)
		data, err := json.Marshal(v)
		if err != nil {
			logger.Error("marshal sse event", "err", err)
			return true
		}
		return write("event: " + name + "\ndata: " + string(data) + "\n\n")
	}
	for _, u := range initial {
		if !send(u) {
			return
		}
	}

	heartbeat := time.NewTicker(sseHeartbeat)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			if !write(": heartbeat\n\n") {
				return
			}
		case u, ok := <-updates:
			if !ok || !send(u) {
				return
			}
		}
	}
}

func (h *handler) internalError(w http.ResponseWriter, err error) {
	h.logger.Error("api error", "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
