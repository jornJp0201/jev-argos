// jev-argos コントロールサーバーへ SecuritySignal を送る軽量クライアント (設計書 4 章 Phase 1)。
//
// report() は送信を setImmediate でイベントループの次のターンに回してすぐ戻るため、
// 呼び出し元 (メイン RPC の処理) を待たせない。送信の失敗・タイムアウト・過負荷時の破棄は
// すべて内部で吸収し、メインの処理には決して例外を投げない (Fire-and-Forget)。

import { fileURLToPath } from "node:url";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import type { ReportResponse, SecuritySignal } from "./signal.js";

/** シグナルの送信先。インターセプターはこのインターフェースだけに依存する。 */
export interface Reporter {
  report(signal: SecuritySignal): void;
}

export interface ReporterOptions {
  /** コントロールサーバーのアドレス (例: "localhost:50051")。 */
  target: string;
  /** 接続の認証情報 (既定: 平文)。本番では grpc.credentials.createSsl() 等を指定すること。 */
  credentials?: grpc.ChannelCredentials;
  /** 1 件の送信のタイムアウト (既定 500ms)。 */
  timeoutMs?: number;
  /** 同時に送信中にできる件数の上限 (既定 1000)。超えた分は破棄する。 */
  maxInFlight?: number;
  /** signal.proto の場所 (既定: パッケージ同梱の proto/signal.proto)。 */
  protoPath?: string;
  /** 送信に失敗したときに呼ばれる。 */
  onError?: (err: Error, signal: SecuritySignal) => void;
  /** サーバーの応答を受け取ったときに呼ばれる (例: immediate_action_level が 4 なら遮断処理)。 */
  onResponse?: (res: ReportResponse, signal: SecuritySignal) => void;
  /**
   * バッチ送信 (設計書 4 章 Phase 2)。指定すると、maxSize 件たまるか flushIntervalMs が経過するたびに
   * StreamSignals でまとめて送る。送信回数が減るため高トラフィック時に向く。
   * onResponse はバッチ単位になり (immediate_action_level はバッチ内の最大値、signal はバッチの最後の 1 件)、
   * 遮断には BlocklistWatcher を使うこと。
   */
  batch?: { maxSize?: number; flushIntervalMs?: number };
}

export interface ReporterStats {
  sent: number;
  failed: number;
  dropped: number;
  inFlight: number;
}

type ReportSignalFn = (
  signal: SecuritySignal,
  options: grpc.CallOptions,
  callback: (err: grpc.ServiceError | null, res?: ReportResponse) => void,
) => grpc.ClientUnaryCall;

type StreamSignalsFn = (
  options: grpc.CallOptions,
  callback: (err: grpc.ServiceError | null, res?: ReportResponse) => void,
) => grpc.ClientWritableStream<SecuritySignal>;

interface SignalServiceClient extends grpc.Client {
  ReportSignal: ReportSignalFn;
  StreamSignals: StreamSignalsFn;
}

type SignalServiceCtor = new (target: string, creds: grpc.ChannelCredentials) => SignalServiceClient;

const DEFAULT_PROTO_PATH = fileURLToPath(new URL("../proto/signal.proto", import.meta.url));
const serviceCache = new Map<string, SignalServiceCtor>();

function loadSignalService(protoPath: string): SignalServiceCtor {
  let ctor = serviceCache.get(protoPath);
  if (!ctor) {
    const def = protoLoader.loadSync(protoPath, { keepCase: true, longs: Number, defaults: true });
    const pkg = grpc.loadPackageDefinition(def) as unknown as {
      jevargos: { v1: { SignalService: SignalServiceCtor } };
    };
    ctor = pkg.jevargos.v1.SignalService;
    serviceCache.set(protoPath, ctor);
  }
  return ctor;
}

export class SignalReporter implements Reporter {
  private readonly client: SignalServiceClient;
  private readonly timeoutMs: number;
  private readonly maxInFlight: number;
  private readonly onError: ReporterOptions["onError"];
  private readonly onResponse: ReporterOptions["onResponse"];
  private readonly counters = { sent: 0, failed: 0, dropped: 0 };
  private inFlight = 0;
  private closed = false;
  private idleWaiters: Array<() => void> = [];
  private readonly batch: { maxSize: number; flushIntervalMs: number } | undefined;
  private pending: SecuritySignal[] = [];
  private flushTimer: ReturnType<typeof setTimeout> | undefined;

  constructor(opts: ReporterOptions) {
    const Service = loadSignalService(opts.protoPath ?? DEFAULT_PROTO_PATH);
    this.client = new Service(opts.target, opts.credentials ?? grpc.credentials.createInsecure());
    this.timeoutMs = opts.timeoutMs ?? 500;
    this.maxInFlight = opts.maxInFlight ?? 1000;
    this.onError = opts.onError;
    this.onResponse = opts.onResponse;
    if (opts.batch) {
      this.batch = { maxSize: opts.batch.maxSize ?? 50, flushIntervalMs: opts.batch.flushIntervalMs ?? 100 };
    }
  }

  /** シグナルを非同期に送信する。すぐに戻り、例外は投げない。 */
  report(signal: SecuritySignal): void {
    if (this.closed || this.inFlight + this.pending.length >= this.maxInFlight) {
      this.counters.dropped++;
      return;
    }
    if (this.batch) {
      this.pending.push(signal);
      if (this.pending.length >= this.batch.maxSize) {
        setImmediate(() => this.flush());
      } else if (!this.flushTimer) {
        this.flushTimer = setTimeout(() => this.flush(), this.batch.flushIntervalMs);
        this.flushTimer.unref?.();
      }
      return;
    }
    this.inFlight++;
    setImmediate(() => this.send(signal));
  }

  get stats(): ReporterStats {
    return { ...this.counters, inFlight: this.inFlight };
  }

  /** 新しい送信の受付を止め、送信中のシグナルを待ってから接続を閉じる。 */
  async close(): Promise<void> {
    this.closed = true;
    this.flush(); // バッチ送信の待ちを送り切る
    if (this.inFlight > 0) {
      await new Promise<void>((resolve) => this.idleWaiters.push(resolve));
    }
    this.client.close();
  }

  private send(signal: SecuritySignal): void {
    try {
      this.client.ReportSignal(signal, { deadline: Date.now() + this.timeoutMs }, (err, res) => {
        if (err) {
          this.counters.failed++;
          this.safely(() => this.onError?.(err, signal));
        } else {
          this.counters.sent++;
          if (res) this.safely(() => this.onResponse?.(res, signal));
        }
        this.done();
      });
    } catch (err) {
      // シリアライズ失敗など、呼び出し自体が同期的に失敗した場合
      this.counters.failed++;
      this.safely(() => this.onError?.(err as Error, signal));
      this.done();
    }
  }

  /** たまっているシグナルを StreamSignals でまとめて送る (バッチ送信)。 */
  private flush(): void {
    clearTimeout(this.flushTimer);
    this.flushTimer = undefined;
    const batch = this.pending.splice(0, this.batch?.maxSize ?? this.pending.length);
    if (batch.length === 0) return;
    if (this.pending.length > 0) setImmediate(() => this.flush());
    this.inFlight += batch.length;
    const last = batch[batch.length - 1]!;
    const finish = (err: Error | null, res?: ReportResponse) => {
      if (err) {
        this.counters.failed += batch.length;
        this.safely(() => this.onError?.(err, last));
      } else {
        this.counters.sent += batch.length;
        if (res) this.safely(() => this.onResponse?.(res, last));
      }
      this.done(batch.length);
    };
    try {
      const deadline = Date.now() + this.timeoutMs * Math.max(1, Math.ceil(batch.length / 10));
      const stream = this.client.StreamSignals({ deadline }, (err, res) => finish(err, res));
      for (const s of batch) stream.write(s);
      stream.end();
    } catch (err) {
      finish(err as Error);
    }
  }

  private done(n = 1): void {
    this.inFlight -= n;
    if (this.inFlight === 0) {
      for (const resolve of this.idleWaiters.splice(0)) resolve();
    }
  }

  /** 利用側のコールバックの例外がメイン処理に漏れないようにする。 */
  private safely(fn: () => void): void {
    try {
      fn();
    } catch {
      // 無視する
    }
  }
}
