// コントロールサーバーの遮断リスト (ControlService.WatchBlocklist) を購読し、手元に保持する。
// ミドルウェア / インターセプターに渡すと、遮断中の送信元からのリクエストを拒否する。
//
// 判定 (isBlocked) は手元のコピーを見るだけなので、リクエストごとに通信は発生しない。
// コントロールサーバーとの接続が切れた場合は自動で再接続し、その間は最後に受け取った一覧で判定を続ける
// (期限切れの遮断は手元で自動的に解除する)。

import { fileURLToPath } from "node:url";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { normalizeIp } from "./signal.js";

export interface BlockEntry {
  target_type: string; // "ip"
  target: string;
  reason: string;
  source: string; // "jev_level4" | "approval" | "admin"
  /** 遮断の期限 (UNIX ミリ秒)。0 なら無期限。 */
  expires_at_unix_ms: number;
}

interface BlocklistEvent {
  kind: "KIND_UNSPECIFIED" | "SNAPSHOT" | "ADDED" | "REMOVED";
  entries: BlockEntry[];
}

/** 遮断中かを判定できるもの。ミドルウェア / インターセプターはこのインターフェースだけに依存する。 */
export interface BlockChecker {
  isBlocked(ip: string): boolean;
}

export interface BlocklistWatcherOptions {
  /** コントロールサーバーの gRPC アドレス (SignalReporter の target と同じ)。 */
  target: string;
  credentials?: grpc.ChannelCredentials;
  /** 再接続の待ち時間の上限 (既定 30 秒)。1 秒から倍々に延ばす。 */
  maxReconnectDelayMs?: number;
  protoPath?: string;
  /** 遮断リストが変わったときに呼ばれる (ログやメトリクス用)。 */
  onChange?: (entries: BlockEntry[]) => void;
  /** 購読が切れたときに呼ばれる (自動で再接続する)。 */
  onError?: (err: Error) => void;
}

type WatchFn = (req: object) => grpc.ClientReadableStream<BlocklistEvent>;
interface ControlServiceClient extends grpc.Client {
  WatchBlocklist: WatchFn;
}
type ControlServiceCtor = new (target: string, creds: grpc.ChannelCredentials) => ControlServiceClient;

const DEFAULT_PROTO_PATH = fileURLToPath(new URL("../proto/signal.proto", import.meta.url));

function loadControlService(protoPath: string): ControlServiceCtor {
  const def = protoLoader.loadSync(protoPath, { keepCase: true, longs: Number, enums: String, defaults: true });
  const pkg = grpc.loadPackageDefinition(def) as unknown as { jevargos: { v1: { ControlService: ControlServiceCtor } } };
  return pkg.jevargos.v1.ControlService;
}

const key = (type: string, target: string) => `${type}\u0000${target}`;

export class BlocklistWatcher implements BlockChecker {
  private readonly client: ControlServiceClient;
  private readonly entries = new Map<string, BlockEntry>();
  private readonly opts: BlocklistWatcherOptions;
  private stream: grpc.ClientReadableStream<BlocklistEvent> | undefined;
  private reconnectTimer: ReturnType<typeof setTimeout> | undefined;
  private delayMs = 1_000;
  private closed = false;
  private synced = false;

  constructor(opts: BlocklistWatcherOptions) {
    this.opts = opts;
    this.delayMs = Math.min(1_000, opts.maxReconnectDelayMs ?? 30_000);
    const Service = loadControlService(opts.protoPath ?? DEFAULT_PROTO_PATH);
    this.client = new Service(opts.target, opts.credentials ?? grpc.credentials.createInsecure());
    this.connect();
  }

  /** IP が遮断中か。期限切れの遮断は false。 */
  isBlocked(ip: string): boolean {
    const e = this.entries.get(key("ip", normalizeIp(ip)));
    if (!e) return false;
    if (e.expires_at_unix_ms > 0 && e.expires_at_unix_ms <= Date.now()) {
      this.entries.delete(key(e.target_type, e.target));
      return false;
    }
    return true;
  }

  /** 期限内の遮断の一覧。 */
  list(): BlockEntry[] {
    const now = Date.now();
    return [...this.entries.values()].filter((e) => e.expires_at_unix_ms === 0 || e.expires_at_unix_ms > now);
  }

  /** 最初の一覧 (SNAPSHOT) を受け取ったか。 */
  get ready(): boolean {
    return this.synced;
  }

  close(): void {
    this.closed = true;
    clearTimeout(this.reconnectTimer);
    this.stream?.cancel();
    this.client.close();
  }

  private connect(): void {
    if (this.closed) return;
    const stream = this.client.WatchBlocklist({});
    this.stream = stream;
    stream.on("data", (ev: BlocklistEvent) => {
      this.delayMs = Math.min(1_000, this.opts.maxReconnectDelayMs ?? 30_000);
      this.apply(ev);
    });
    stream.on("error", (err: grpc.ServiceError) => {
      if (this.closed || err.code === grpc.status.CANCELLED) return;
      this.safely(() => this.opts.onError?.(err));
      this.scheduleReconnect();
    });
    stream.on("end", () => this.scheduleReconnect());
  }

  private scheduleReconnect(): void {
    if (this.closed || this.reconnectTimer) return;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      this.connect();
    }, this.delayMs);
    this.reconnectTimer.unref?.(); // 再接続待ちでプロセスの終了を妨げない
    this.delayMs = Math.min(this.delayMs * 2, this.opts.maxReconnectDelayMs ?? 30_000);
  }

  private apply(ev: BlocklistEvent): void {
    if (ev.kind === "SNAPSHOT") {
      this.entries.clear();
      this.synced = true;
    }
    for (const e of ev.entries ?? []) {
      const k = key(e.target_type, e.target);
      if (ev.kind === "REMOVED") this.entries.delete(k);
      else this.entries.set(k, e);
    }
    this.safely(() => this.opts.onChange?.(this.list()));
  }

  private safely(fn: () => void): void {
    try {
      fn();
    } catch {
      // 利用側のコールバックの例外は無視する
    }
  }
}
