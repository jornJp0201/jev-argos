// コントロールサーバーの判定イベント (Go: receiver.Event) に対応する型。
// フィールド名は proto / DB (jev_decision_logs) と揃えて snake_case にしている。

export type Level = 1 | 2 | 3 | 4;

export interface SecuritySignal {
  signal_id: string;
  timestamp: string;
  source_service: string;
  trace_id: string;
  user_context: {
    user_id: string;
    user_role: string;
    client_ip: string;
    user_agent: string;
  };
  request_context: {
    protocol: "grpc" | "http";
    method: string;
  };
  response_context: {
    status_code: number;
    latency_ms: number;
  };
}

/** Sliding Window Buffer の特徴量 (設計書 5.1.1 Step 1)。 */
export interface Features {
  ip_error_count_1m: number;
  unique_denied_methods_5m: number;
  latency_spike_ratio: number;
}

export interface LlmAnalysis {
  status: "pending" | "done" | "unavailable";
  /** 解析モデル名 (例: "mock")。 */
  model?: string;
  summary?: string;
  factors?: string[];
  recommendation?: string;
}

export interface DecisionEvent {
  signal: SecuritySignal;
  features: Features;
  score: number; // S ∈ [0, 4]
  confidence: number; // C ∈ [0, 1]
  level: Level;
  /** S >= 3.5 だが C < 0.8 のため Level 4 → 3 に格下げした。 */
  downgraded: boolean;
  /** Level 2 以上のみ。 */
  llm?: LlmAnalysis;
}

/** ダッシュボードのデータ取得元。実 API 実装に差し替えられるようにする。 */
export interface DataSource {
  /** データ元の表示名 (例: "デモデータ")。 */
  readonly label: string;
  readonly isDemo: boolean;
  /** 新しいイベントと、LLM 解析結果の更新を購読する。戻り値で購読解除。 */
  subscribe(handlers: {
    onEvent: (e: DecisionEvent) => void;
    onLlmUpdate: (signalId: string, llm: LlmAnalysis) => void;
  }): () => void;
}
