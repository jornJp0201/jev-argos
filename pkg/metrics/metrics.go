// Package metrics はメトリクスを Prometheus のテキスト形式 (text/plain; version=0.0.4) で書き出す。
//
// 値は scrape のたびに集める (Handler に渡した関数を呼ぶ)。外部のライブラリには依存しない。
//
// [差し替えポイント] OpenTelemetry など他の形式で出したい場合は、Handler の代わりに同じ集め方で別の出力を書く。
package metrics

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// 種類。
const (
	Counter = "counter"
	Gauge   = "gauge"
)

// Family は同じ名前のメトリクスの集まり。
type Family struct {
	Name    string
	Help    string
	Type    string // Counter または Gauge
	Samples []Sample
}

// Sample は 1 つの値。Labels は名前と値の組を交互に並べる (例: "lane", "notify")。
type Sample struct {
	Labels []string
	Value  float64
}

// Write は fams を Prometheus のテキスト形式で w に書く。
func Write(w io.Writer, fams []Family) error {
	bw := bufio.NewWriter(w)
	for _, f := range fams {
		fmt.Fprintf(bw, "# HELP %s %s\n# TYPE %s %s\n", f.Name, escapeHelp(f.Help), f.Name, f.Type)
		for _, s := range f.Samples {
			bw.WriteString(f.Name)
			if len(s.Labels) > 0 {
				bw.WriteByte('{')
				for i := 0; i+1 < len(s.Labels); i += 2 {
					if i > 0 {
						bw.WriteByte(',')
					}
					fmt.Fprintf(bw, "%s=%q", s.Labels[i], escapeLabel(s.Labels[i+1]))
				}
				bw.WriteByte('}')
			}
			bw.WriteByte(' ')
			bw.WriteString(strconv.FormatFloat(s.Value, 'g', -1, 64))
			bw.WriteByte('\n')
		}
	}
	return bw.Flush()
}

// Handler は collect が返すメトリクスを書き出す http.Handler を返す。collect は scrape のたびに呼ばれる。
func Handler(collect func(ctx context.Context) []Family) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		fams := collect(ctx)
		slices.SortStableFunc(fams, func(a, b Family) int { return strings.Compare(a.Name, b.Name) })
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = Write(w, fams)
	})
}

// Map は名前ごとの値を、label の値として 1 つの Family にする (例: Lane ごとの捨てた数)。順序は名前順。
func Map(name, help, typ, label string, values map[string]uint64) Family {
	f := Family{Name: name, Help: help, Type: typ}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		f.Samples = append(f.Samples, Sample{Labels: []string{label, k}, Value: float64(values[k])})
	}
	return f
}

func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

// escapeLabel は %q で書くための前処理 (%q は Go の文字列リテラルとしてエスケープし、Prometheus の形式と互換)。
func escapeLabel(s string) string { return strings.ToValidUTF8(s, "?") }
