// 判定ルールの定数と、デモデータ用の判定ロジック。
// 定数と式は Go 側 (pkg/guardrail, pkg/classifier の HeuristicModel) と同じ値にしている。
// 実運用ではスコア・確信度・レベルはコントロールサーバーが算出し、ダッシュボードは表示するだけ。

import type { Features, Level } from "../types";

export const MAX_SCORE = 4;
export const BLOCK_SCORE = 3.5;
export const BLOCK_CONFIDENCE = 0.8;
export const LEVEL2_SCORE = 1.5;
export const LEVEL3_SCORE = 2.5;

/** 特徴量が最大寄与になる値 (Go: errorCountSaturation 等)。 */
export const SATURATION = {
  ip_error_count_1m: 30,
  unique_denied_methods_5m: 5,
  latency_spike_ratio: 5,
} as const;

const clamp01 = (v: number) => Math.max(0, Math.min(1, v));

export function normalizedFeatures(f: Features): [number, number, number] {
  return [
    clamp01(f.ip_error_count_1m / SATURATION.ip_error_count_1m),
    clamp01(f.unique_denied_methods_5m / SATURATION.unique_denied_methods_5m),
    clamp01((f.latency_spike_ratio - 1) / (SATURATION.latency_spike_ratio - 1)),
  ];
}

export function evaluate(f: Features): { score: number; confidence: number } {
  const norm = normalizedFeatures(f);
  const weights = [0.9, 0.9, 0.6];
  let benign = 1;
  let active = 0;
  norm.forEach((v, i) => {
    benign *= 1 - weights[i]! * v;
    if (v >= 0.5) active++;
  });
  const p = 1 - benign;
  if (p < 0.5) return { score: MAX_SCORE * p, confidence: 1 - p };
  const n = f.ip_error_count_1m + f.unique_denied_methods_5m;
  const volume = n / (n + 10);
  const corroboration = Math.min(active, 2) / 2;
  return { score: MAX_SCORE * p, confidence: 0.5 * volume + 0.5 * corroboration };
}

export function decide(score: number, confidence: number): { level: Level; downgraded: boolean } {
  if (score >= BLOCK_SCORE && confidence >= BLOCK_CONFIDENCE) return { level: 4, downgraded: false };
  if (score >= BLOCK_SCORE) return { level: 3, downgraded: true };
  if (score >= LEVEL3_SCORE) return { level: 3, downgraded: false };
  if (score >= LEVEL2_SCORE) return { level: 2, downgraded: false };
  return { level: 1, downgraded: false };
}

export const LEVEL_INFO: Record<Level, { label: string; action: string }> = {
  1: { label: "L1", action: "静観 / 記録のみ" },
  2: { label: "L2", action: "LLM 非同期分析" },
  3: { label: "L3", action: "深層解析 + 人間へ通知" },
  4: { label: "L4", action: "即時遮断" },
};

export const GRPC_STATUS: Record<number, string> = {
  0: "OK",
  1: "CANCELLED",
  3: "INVALID_ARGUMENT",
  4: "DEADLINE_EXCEEDED",
  5: "NOT_FOUND",
  7: "PERMISSION_DENIED",
  8: "RESOURCE_EXHAUSTED",
  13: "INTERNAL",
  14: "UNAVAILABLE",
  16: "UNAUTHENTICATED",
};
