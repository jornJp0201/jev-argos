package metrics

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandler(t *testing.T) {
	h := Handler(func(context.Context) []Family {
		return []Family{
			Map("jevargos_events_dropped_total", "Events dropped.", Counter, "lane", map[string]uint64{"notify": 3, "block": 0}),
			{Name: "jevargos_inflight", Help: "In flight.\nNow.", Type: Gauge, Samples: []Sample{{Value: 1.5}}},
		}
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	want := `# HELP jevargos_events_dropped_total Events dropped.
# TYPE jevargos_events_dropped_total counter
jevargos_events_dropped_total{lane="block"} 0
jevargos_events_dropped_total{lane="notify"} 3
# HELP jevargos_inflight In flight.\nNow.
# TYPE jevargos_inflight gauge
jevargos_inflight 1.5
`
	if string(body) != want {
		t.Errorf("body:\n%s\nwant:\n%s", body, want)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Errorf("content type = %q", ct)
	}
}

func TestLabelEscape(t *testing.T) {
	var b strings.Builder
	Write(&b, []Family{{Name: "m", Type: Gauge, Samples: []Sample{{Labels: []string{"k", "a\"b\\c\n"}, Value: 1}}}})
	if !strings.Contains(b.String(), `m{k="a\"b\\c\n"} 1`) {
		t.Errorf("got %q", b.String())
	}
}
