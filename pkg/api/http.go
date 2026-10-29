// Package api はコントロール用フロントエンド向けの管理 HTTP API を提供する。
//
//	GET  /api/healthz                     死活確認 (認証不要)
//	GET  /api/actions?status=pending      アクション一覧 (status 省略で全件)
//	GET  /api/actions/{id}                アクション詳細
//	POST /api/actions/{id}/approve        承認   body: {"decided_by": "...", "note": "..."}
//	POST /api/actions/{id}/reject         拒否   body: 同上
//	GET  /api/actions/stream              アクションの作成・更新を Server-Sent Events で配信
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
	"net/http"
	"strings"
	"time"

	"github.com/jev-argos/jev-argos/pkg/approval"
)

const (
	maxBodyBytes      = 16 << 10
	maxDecidedByLen   = 100
	maxNoteLen        = 1000
	sseHeartbeat      = 15 * time.Second
	executeTimeout    = 5 * time.Second
	streamEventAction = "action"
)

// Config は Handler の設定。
type Config struct {
	Store    approval.Store
	Executor approval.Executor // nil なら approval.LogExecutor
	// AdminToken は管理 API の Bearer トークン。空にはできない。
	AdminToken string
	Logger     *slog.Logger
}

type handler struct {
	store    approval.Store
	executor approval.Executor
	token    []byte
	logger   *slog.Logger
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
	h := &handler{store: cfg.Store, executor: cfg.Executor, token: []byte(cfg.AdminToken), logger: cfg.Logger}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("GET /api/actions", h.auth(h.list))
	mux.Handle("GET /api/actions/stream", h.auth(h.stream))
	mux.Handle("GET /api/actions/{id}", h.auth(h.get))
	mux.Handle("POST /api/actions/{id}/approve", h.auth(h.decide(true)))
	mux.Handle("POST /api/actions/{id}/reject", h.auth(h.decide(false)))
	return mux, nil
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
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
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
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), executeTimeout)
			defer cancel()
			if err := h.executor.Execute(ctx, a); err != nil {
				h.logger.Error("execute approved action failed", "action_id", a.ID, "err", err)
			}
		}
		writeJSON(w, http.StatusOK, a)
	}
}

func (h *handler) stream(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no") // リバースプロキシのバッファリングを無効化
	w.WriteHeader(http.StatusOK)

	updates, cancel := h.store.Subscribe()
	defer cancel()

	write := func(s string) bool {
		if _, err := w.Write([]byte(s)); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !write(": connected\n\n") {
		return
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
		case a := <-updates:
			data, err := json.Marshal(a)
			if err != nil {
				h.logger.Error("marshal action", "err", err)
				continue
			}
			if !write("event: " + streamEventAction + "\ndata: " + string(data) + "\n\n") {
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
