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

interface SignalServiceClient extends grpc.Client {
  ReportSignal: ReportSignalFn;
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

  constructor(opts: ReporterOptions) {
    const Service = loadSignalService(opts.protoPath ?? DEFAULT_PROTO_PATH);
    this.client = new Service(opts.target, opts.credentials ?? grpc.credentials.createInsecure());
    this.timeoutMs = opts.timeoutMs ?? 500;
    this.maxInFlight = opts.maxInFlight ?? 1000;
    this.onError = opts.onError;
    this.onResponse = opts.onResponse;
  }

  /** シグナルを非同期に送信する。すぐに戻り、例外は投げない。 */
  report(signal: SecuritySignal): void {
    if (this.closed || this.inFlight >= this.maxInFlight) {
      this.counters.dropped++;
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

  private done(): void {
    this.inFlight--;
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
