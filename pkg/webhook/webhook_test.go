package webhook

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerify_RejectsStaleAndTampered(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	body := []byte(`{"x":1}`)
	ts := "1700000000"
	sig := "sha256=" + Sign("k", ts, body)
	if !Verify("k", ts, sig, body, now, time.Minute) {
		t.Fatal("valid signature rejected")
	}
	if Verify("k", ts, sig, []byte(`{"x":2}`), now, time.Minute) {
		t.Error("tampered body accepted")
	}
	if Verify("other", ts, sig, body, now, time.Minute) {
		t.Error("wrong secret accepted")
	}
	if Verify("k", ts, sig, body, now.Add(2*time.Minute), time.Minute) {
		t.Error("stale timestamp accepted (replay)")
	}
	if Verify("k", "not-a-number", sig, body, now, time.Minute) {
		t.Error("invalid timestamp accepted")
	}
}

func TestPost(t *testing.T) {
	var gotSigned bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, gotSigned = VerifyRequest(r, "s", time.Minute)
		if r.URL.Path == "/fail" {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	if err := Post(context.Background(), nil, srv.URL+"/ok", "s", time.Now(), map[string]int{"a": 1}); err != nil || !gotSigned {
		t.Errorf("post: err=%v signed=%v", err, gotSigned)
	}
	if err := Post(context.Background(), nil, srv.URL+"/fail", "", time.Now(), 1); err == nil {
		t.Error("non-2xx must be an error")
	}
}
