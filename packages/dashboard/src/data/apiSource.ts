// コントロールサーバーの判定と LLM 分析を受け取る DataSource (GET /api/events/stream)。
// 認証ヘッダーは開発サーバーのプロキシ (vite.config.ts) または本番のリバースプロキシが付与する。

import type { DataSource, DecisionEvent, Level, LlmAnalysis } from "../types";

interface ServerDecision {
  signal: DecisionEvent["signal"];
  features: DecisionEvent["features"];
  score: number;
  confidence: number;
  level: number;
  downgraded: boolean;
}

interface ServerAnalysis {
  signal_id: string;
  client_ip: string;
  analysis: {
    status: "done" | "failed";
    provider: string;
    masked: boolean;
    summary?: string;
    factors?: string[];
    recommendation?: string;
    recommended_action?: string;
    error?: string;
  };
}

export class ApiDataSource implements DataSource {
  readonly label = "コントロールサーバー";
  readonly isDemo = false;

  subscribe(handlers: Parameters<DataSource["subscribe"]>[0]): () => void {
    handlers.onStatus?.("connecting");
    // EventSource は切断時に自動で再接続する (再接続のたびに直近の判定が送り直されるため、受信側で重複を除く)
    const es = new EventSource("/api/events/stream");
    es.addEventListener("open", () => handlers.onStatus?.("live"));
    es.addEventListener("error", () => handlers.onStatus?.("offline"));
    es.addEventListener("decision", (e) => {
      const d = JSON.parse((e as MessageEvent<string>).data) as ServerDecision;
      handlers.onEvent({
        signal: d.signal,
        features: d.features,
        score: d.score,
        confidence: d.confidence,
        level: Math.min(4, Math.max(1, d.level)) as Level,
        downgraded: d.downgraded,
      });
    });
    es.addEventListener("analysis", (e) => {
      const m = JSON.parse((e as MessageEvent<string>).data) as ServerAnalysis;
      const a = m.analysis;
      const llm: LlmAnalysis = {
        status: a.status,
        provider: a.provider,
        masked: a.masked,
        ...(a.summary !== undefined && { summary: a.summary }),
        ...(a.factors !== undefined && { factors: a.factors }),
        ...(a.recommendation !== undefined && { recommendation: a.recommendation }),
        ...(a.recommended_action !== undefined && { recommended_action: a.recommended_action }),
        ...(a.error !== undefined && { error: a.error }),
      };
      handlers.onLlmUpdate(m.signal_id, m.client_ip, llm);
    });
    return () => es.close();
  }
}
