package receiver

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jornJp0201/jev-argos/pkg/buffer"
	"github.com/jornJp0201/jev-argos/pkg/classifier"
)

func TestHTTPHandler(t *testing.T) {
	var observed []Event
	srv := NewServer(buffer.NewMemoryBuffer(), classifier.NewDefault(), &recorder{}, Options{
		Logger:   quietLogger,
		Observer: func(e Event) { observed = append(observed, e) },
	})
	defer srv.Close()
	ts := httptest.NewServer(srv.HTTPHandler("ingest-token"))
	defer ts.Close()

	post := func(path, body, token string) (int, string) {
		req, _ := http.NewRequest("POST", ts.URL+path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	sig := `{"signal_id":"h1","user_context":{"client_ip":"203.0.113.9"},"request_context":{"protocol":"http","method":"GET /admin"},"response_context":{"status_code":7}}`

	if code, _ := post("/api/signals", sig, ""); code != 401 {
		t.Errorf("no token: %d", code)
	}
	if code, _ := post("/api/signals", sig, "admin-token"); code != 401 {
		t.Errorf("wrong token: %d", code)
	}
	code, body := post("/api/signals", sig, "ingest-token")
	if code != 200 || !strings.Contains(body, `"accepted":true`) || !strings.Contains(body, `"immediate_action_level":1`) {
		t.Errorf("single: %d %s", code, body)
	}
	// camelCase のフィールド名と未知のフィールドも受け付ける (proto JSON の仕様・前方互換)
	if code, _ := post("/api/signals", `{"userContext":{"clientIp":"10.0.0.1"},"futureField":1}`, "ingest-token"); code != 200 {
		t.Errorf("camelCase / unknown field: %d", code)
	}
	if code, _ := post("/api/signals", `{"signal_id":"no-ip"}`, "ingest-token"); code != 400 {
		t.Errorf("missing client_ip: %d", code)
	}
	if code, _ := post("/api/signals", `not json`, "ingest-token"); code != 400 {
		t.Errorf("invalid json: %d", code)
	}

	var batch strings.Builder
	batch.WriteString(`{"signals":[{"user_context":{}}`) // 不正 (client_ip なし) は読み飛ばす
	for i := range 30 {
		batch.WriteString(`,{"user_context":{"client_ip":"198.51.100.7"},"request_context":{"method":"/m` + string(rune('0'+i%5)) + `"},"response_context":{"status_code":7}}`)
	}
	batch.WriteString("]}")
	code, body = post("/api/signals/batch", batch.String(), "ingest-token")
	if code != 200 || !strings.Contains(body, `"accepted":false`) || !strings.Contains(body, `"immediate_action_level":4`) {
		t.Errorf("batch: %d %s", code, body)
	}
	if len(observed) != 32 { // 単発 2 件 + バッチ 30 件 (Level 1 も Observer に届く)
		t.Errorf("observed = %d, want 32", len(observed))
	}
}

func TestHTTPHandler_DisabledWithoutToken(t *testing.T) {
	srv := NewServer(buffer.NewMemoryBuffer(), classifier.NewDefault(), &recorder{}, Options{Logger: quietLogger})
	defer srv.Close()
	ts := httptest.NewServer(srv.HTTPHandler(""))
	defer ts.Close()
	req, _ := http.NewRequest("POST", ts.URL+"/api/signals", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer ")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 401 {
		t.Errorf("empty token must never authenticate: %d", resp.StatusCode)
	}
}
