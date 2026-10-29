package api

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jev-argos/jev-argos/pkg/approval"
)

const token = "test-token"

type recordingExecutor struct {
	mu       sync.Mutex
	executed []approval.Action
}

func (r *recordingExecutor) Execute(_ context.Context, a approval.Action) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.executed = append(r.executed, a)
	return nil
}

func (r *recordingExecutor) snapshot() []approval.Action {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]approval.Action(nil), r.executed...)
}

func setup(t *testing.T) (*httptest.Server, *approval.MemoryStore, *recordingExecutor) {
	t.Helper()
	store := approval.NewMemoryStore()
	exec := &recordingExecutor{}
	h, err := NewHandler(Config{
		Store:      store,
		Executor:   exec,
		AdminToken: token,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, store, exec
}

func propose(t *testing.T, store approval.Store, ip string) approval.Action {
	t.Helper()
	a, err := store.Propose(context.Background(), approval.Proposal{
		SignalID: "sig-" + ip, ProposedAction: approval.ActionBlockIP, Target: ip, Reason: "test",
		Evidence: approval.Evidence{Score: 3.7, Confidence: 0.6, Level: 3, Downgraded: true, ClientIP: ip},
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func do(t *testing.T, srv *httptest.Server, method, path, body, auth string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func TestNewHandler_RequiresToken(t *testing.T) {
	if _, err := NewHandler(Config{Store: approval.NewMemoryStore()}); err == nil {
		t.Error("want error without admin token")
	}
}

func TestAuth(t *testing.T) {
	srv, store, _ := setup(t)
	a := propose(t, store, "10.0.0.1")

	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/actions"},
		{"GET", "/api/actions/" + a.ID},
		{"POST", "/api/actions/" + a.ID + "/approve"},
		{"POST", "/api/actions/" + a.ID + "/reject"},
		{"GET", "/api/actions/stream"},
	} {
		for _, auth := range []string{"", "wrong-token"} {
			resp, _ := do(t, srv, tc.method, tc.path, `{"decided_by":"x"}`, auth)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s with %q: status %d, want 401", tc.method, tc.path, auth, resp.StatusCode)
			}
		}
	}
	if got, _ := store.Get(context.Background(), a.ID); got.Status != approval.StatusPending {
		t.Error("unauthenticated request changed the action")
	}

	if resp, _ := do(t, srv, "GET", "/api/healthz", "", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("healthz: status %d, want 200", resp.StatusCode)
	}
}

func TestListAndGet(t *testing.T) {
	srv, store, _ := setup(t)
	a := propose(t, store, "10.0.0.1")
	b := propose(t, store, "10.0.0.2")
	store.Decide(context.Background(), b.ID, false, "alice", "")

	resp, body := do(t, srv, "GET", "/api/actions?status=pending", "", token)
	var list struct{ Actions []approval.Action }
	if err := json.Unmarshal(body, &list); err != nil || resp.StatusCode != 200 {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	if len(list.Actions) != 1 || list.Actions[0].ID != a.ID {
		t.Errorf("pending list = %+v", list.Actions)
	}
	// JSON のフィールド名は仕様どおり
	for _, key := range []string{`"action_id"`, `"signal_id"`, `"proposed_action":"block_ip"`, `"reason"`, `"status":"pending"`, `"evidence"`} {
		if !strings.Contains(string(body), key) {
			t.Errorf("response missing %s: %s", key, body)
		}
	}

	if resp, _ := do(t, srv, "GET", "/api/actions?status=bogus", "", token); resp.StatusCode != 400 {
		t.Errorf("bad status filter: %d, want 400", resp.StatusCode)
	}
	if resp, _ := do(t, srv, "GET", "/api/actions/"+a.ID, "", token); resp.StatusCode != 200 {
		t.Errorf("get: %d, want 200", resp.StatusCode)
	}
	if resp, _ := do(t, srv, "GET", "/api/actions/act_missing", "", token); resp.StatusCode != 404 {
		t.Errorf("get missing: %d, want 404", resp.StatusCode)
	}
}

func TestApproveExecutesAndRejectDoesNot(t *testing.T) {
	srv, store, exec := setup(t)
	a := propose(t, store, "10.0.0.1")
	b := propose(t, store, "10.0.0.2")

	resp, body := do(t, srv, "POST", "/api/actions/"+a.ID+"/approve", `{"decided_by":" alice ","note":"probing confirmed"}`, token)
	var got approval.Action
	json.Unmarshal(body, &got)
	if resp.StatusCode != 200 || got.Status != approval.StatusApproved || got.DecidedBy != "alice" || got.DecisionNote != "probing confirmed" {
		t.Errorf("approve: %d %s", resp.StatusCode, body)
	}

	resp, body = do(t, srv, "POST", "/api/actions/"+b.ID+"/reject", `{"decided_by":"bob"}`, token)
	json.Unmarshal(body, &got)
	if resp.StatusCode != 200 || got.Status != approval.StatusRejected {
		t.Errorf("reject: %d %s", resp.StatusCode, body)
	}

	if executed := exec.snapshot(); len(executed) != 1 || executed[0].ID != a.ID {
		t.Errorf("executed = %+v, want only the approved action", executed)
	}
}

func TestDecide_Conflict(t *testing.T) {
	srv, store, exec := setup(t)
	a := propose(t, store, "10.0.0.1")
	do(t, srv, "POST", "/api/actions/"+a.ID+"/reject", `{"decided_by":"alice"}`, token)

	resp, body := do(t, srv, "POST", "/api/actions/"+a.ID+"/approve", `{"decided_by":"bob"}`, token)
	var conflict struct {
		Action approval.Action
	}
	json.Unmarshal(body, &conflict)
	if resp.StatusCode != http.StatusConflict || conflict.Action.Status != approval.StatusRejected || conflict.Action.DecidedBy != "alice" {
		t.Errorf("second decision: %d %s", resp.StatusCode, body)
	}
	if len(exec.snapshot()) != 0 {
		t.Error("rejected action must not be executed by a later approve")
	}
}

func TestDecide_ValidatesBody(t *testing.T) {
	srv, store, _ := setup(t)
	a := propose(t, store, "10.0.0.1")

	for _, body := range []string{
		``,
		`not json`,
		`{}`,
		`{"decided_by":"   "}`,
		`{"decided_by":"` + strings.Repeat("x", 101) + `"}`,
		`{"decided_by":"alice","note":"` + strings.Repeat("x", 1001) + `"}`,
		`{"decided_by":"alice","status":"approved"}`, // 未知のフィールド
	} {
		if resp, _ := do(t, srv, "POST", "/api/actions/"+a.ID+"/approve", body, token); resp.StatusCode != 400 {
			t.Errorf("body %.40q: status %d, want 400", body, resp.StatusCode)
		}
	}
	if resp, _ := do(t, srv, "POST", "/api/actions/act_missing/approve", `{"decided_by":"alice"}`, token); resp.StatusCode != 404 {
		t.Errorf("missing: %d, want 404", resp.StatusCode)
	}
	if got, _ := store.Get(context.Background(), a.ID); got.Status != approval.StatusPending {
		t.Error("invalid requests changed the action")
	}
}

func TestStream(t *testing.T) {
	srv, store, _ := setup(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/api/actions/stream", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q", ct)
	}

	reader := bufio.NewReader(resp.Body)
	readEvent := func() approval.Action {
		t.Helper()
		var event, data string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read stream: %v", err)
			}
			line = strings.TrimRight(line, "\n")
			switch {
			case strings.HasPrefix(line, "event: "):
				event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				data = strings.TrimPrefix(line, "data: ")
			case line == "" && data != "":
				if event != "action" {
					t.Fatalf("event = %q, want action", event)
				}
				var a approval.Action
				if err := json.Unmarshal([]byte(data), &a); err != nil {
					t.Fatal(err)
				}
				return a
			}
		}
	}

	// 購読開始 (": connected") を待ってから変更を起こす
	if line, _ := reader.ReadString('\n'); !strings.HasPrefix(line, ": connected") {
		t.Fatalf("first line = %q", line)
	}
	a := propose(t, store, "10.0.0.1")
	if got := readEvent(); got.ID != a.ID || got.Status != approval.StatusPending {
		t.Errorf("first event = %+v", got)
	}
	do(t, srv, "POST", "/api/actions/"+a.ID+"/approve", `{"decided_by":"alice"}`, token)
	if got := readEvent(); got.ID != a.ID || got.Status != approval.StatusApproved {
		t.Errorf("second event = %+v", got)
	}
}
