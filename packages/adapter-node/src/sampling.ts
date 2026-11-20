// 正常な応答を間引いて送るための判定 (ReporterOptions.sampling)。Go 版 (pkg/client の Sampling) と同じ動き。
//
// サーバーは正常な応答を、API ごとの普段の処理時間 (レイテンシの基準値) の計算にしか使わない。
// 攻撃の判定に使う統計 (エラー数・権限エラーを起こした API の数) はエラーだけから数えるため、
// エラーをすべて送れば、正常な応答を間引いても判定は変わらない。リクエストの大半は正常な応答なので、送る量が大きく減る。
//
// - エラー (status_code !== 0) はすべて送る
// - 遅い応答は必ず送る (処理時間の急増を見逃さないため)。遅いかどうかは、手元で API ごとに求めた平均と比べる
// - それ以外の正常な応答は rate の割合だけ送る。送ったシグナルには sample_rate を付け、
//   サーバーは 1/sample_rate 件ぶんとして基準値やダッシュボードの件数に反映する

import type { SecuritySignal } from "./signal.js";

export interface SamplingOptions {
  /** 正常な応答を送る割合 (例: 0.1 なら 10 件に 1 件)。0 以下または 1 以上なら間引かない。サーバーは 0.01 未満を 0.01 として扱う。 */
  rate: number;
  /** API ごとの手元の平均の何倍を超えたら必ず送るか (既定 2)。 */
  slowFactor?: number;
  /** これを超えたら必ず送る処理時間 (ms)。既定では使わない。 */
  slowThresholdMs?: number;
  /** 0 以上 1 未満の乱数 (テスト用。既定 Math.random)。 */
  random?: () => number;
}

/** 手元で平均を持つ API の数の上限。超えた API は平均を持たず、slowThresholdMs だけで遅いかを判断する。 */
const MAX_SAMPLED_METHODS = 10000;
/** 手元の平均 (EWMA) の平滑化係数 (サーバーの基準値と同じ)。 */
const ALPHA = 0.1;

export class Sampler {
  private readonly rate: number;
  private readonly slowFactor: number;
  private readonly slowThresholdMs: number | undefined;
  private readonly random: () => number;
  private readonly mean = new Map<string, number>();

  /** rate が 0 以下または 1 以上なら undefined (間引かない) を返す。 */
  static create(opts: SamplingOptions | undefined): Sampler | undefined {
    if (!opts || !(opts.rate > 0 && opts.rate < 1)) return undefined;
    return new Sampler(opts);
  }

  private constructor(opts: SamplingOptions) {
    this.rate = opts.rate;
    this.slowFactor = opts.slowFactor && opts.slowFactor > 0 ? opts.slowFactor : 2;
    this.slowThresholdMs = opts.slowThresholdMs;
    this.random = opts.random ?? Math.random;
  }

  /** シグナルを送るかを返す。送る場合は、間引いたときだけ signal.sample_rate を設定する。 */
  keep(signal: SecuritySignal): boolean {
    const resp = signal.response_context;
    if (resp.status_code !== 0) return true;
    const latency = resp.latency_ms;
    if (this.slowThresholdMs !== undefined && this.slowThresholdMs > 0 && latency > this.slowThresholdMs) return true;

    const method = signal.request_context.method;
    const mean = this.mean.get(method);
    if (mean === undefined) {
      if (this.mean.size < MAX_SAMPLED_METHODS) {
        this.mean.set(method, latency);
        return true; // 初めて見る API は、サーバーの基準値の初期値になるので送る
      }
    } else {
      this.mean.set(method, mean + ALPHA * (latency - mean));
      if (latency > mean * this.slowFactor) return true;
    }
    if (this.random() >= this.rate) return false;
    signal.sample_rate = this.rate;
    return true;
  }
}
