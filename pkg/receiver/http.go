package receiver

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	jevargosv1 "github.com/jev-argos/jev-argos/gen/v1"
	"github.com/jev-argos/jev-argos/pkg/guardrail"
)

const (
	maxIngestBody  = 1 << 20
	maxIngestBatch = 500
)

var unmarshalSignal = protojson.UnmarshalOptions{DiscardUnknown: true}

// HTTPHandler は HTTP (JSON) でシグナルを受け付けるハンドラーを返す (gRPC を使えない環境向け)。
//
//	POST /api/signals        body: SecuritySignal の JSON (proto と同じフィールド名)  → ReportResponse の JSON
//	POST /api/signals/batch  body: {"signals": [SecuritySignal, ...]} (最大 500 件)    → ReportResponse の JSON
//
// `Authorization: Bearer <token>` (送信専用トークン) が必須。管理 API のトークンとは分けること
// (BFF に配るトークンで承認操作ができないように)。
func (s *Server) HTTPHandler(token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/signals", s.handleSignal)
	mux.HandleFunc("POST /api/signals/batch", s.handleBatch)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" || !ok || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) handleSignal(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxIngestBody))
	if err != nil {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "body too large")
		return
	}
	var sig jevargosv1.SecuritySignal
	if err := unmarshalSignal.Unmarshal(body, &sig); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid signal JSON: "+err.Error())
		return
	}
	e, err := s.Evaluate(r.Context(), &sig)
	if err != nil {
		writeGRPCError(w, err)
		return
	}
	writeResponse(w, &jevargosv1.ReportResponse{Accepted: true, ImmediateActionLevel: int32(e.Decision.Level)})
}

func (s *Server) handleBatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Signals []json.RawMessage `json:"signals"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxIngestBody)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.Signals) > maxIngestBatch {
		writeJSONError(w, http.StatusBadRequest, "too many signals (max 500)")
		return
	}
	// StreamSignals と同じく、不正なシグナルは読み飛ばして残りを処理する
	accepted := true
	var maxLevel guardrail.Level
	for _, raw := range req.Signals {
		var sig jevargosv1.SecuritySignal
		if err := unmarshalSignal.Unmarshal(raw, &sig); err != nil {
			accepted = false
			continue
		}
		e, err := s.Evaluate(r.Context(), &sig)
		if err != nil {
			accepted = false
			continue
		}
		maxLevel = max(maxLevel, e.Decision.Level)
	}
	writeResponse(w, &jevargosv1.ReportResponse{Accepted: accepted, ImmediateActionLevel: int32(maxLevel)})
}

func writeResponse(w http.ResponseWriter, resp *jevargosv1.ReportResponse) {
	data, _ := protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func writeGRPCError(w http.ResponseWriter, err error) {
	st, _ := status.FromError(err)
	code := http.StatusInternalServerError
	switch st.Code() {
	case codes.InvalidArgument:
		code = http.StatusBadRequest
	case codes.Unavailable:
		code = http.StatusServiceUnavailable
	}
	writeJSONError(w, code, st.Message())
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
