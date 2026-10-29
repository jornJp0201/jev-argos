// テスト用の gRPC サーバー群: シグナルを受け取る擬似コントロールサーバーと、監視対象のアプリサーバー。

import { fileURLToPath } from "node:url";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import type { ReportResponse, SecuritySignal } from "../signal.js";

const PROTO_PATH = fileURLToPath(new URL("../../proto/signal.proto", import.meta.url));

function bind(server: grpc.Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.bindAsync("127.0.0.1:0", grpc.ServerCredentials.createInsecure(), (err, port) =>
      err ? reject(err) : resolve(port),
    );
  });
}

export interface Collector {
  target: string;
  signals: SecuritySignal[];
  /** n 件以上受信するまで待つ。 */
  waitFor(n: number, timeoutMs?: number): Promise<SecuritySignal[]>;
  close(): void;
}

/** jev-argos コントロールサーバーの代わりにシグナルを記録するサーバー。 */
export async function startCollector(
  respond: (s: SecuritySignal) => ReportResponse = () => ({ accepted: true, immediate_action_level: 1 }),
): Promise<Collector> {
  const def = protoLoader.loadSync(PROTO_PATH, { keepCase: true, longs: Number, defaults: true });
  const pkg = grpc.loadPackageDefinition(def) as any;
  const signals: SecuritySignal[] = [];
  const server = new grpc.Server();
  server.addService(pkg.jevargos.v1.SignalService.service, {
    ReportSignal: (call: grpc.ServerUnaryCall<SecuritySignal, ReportResponse>, cb: grpc.sendUnaryData<ReportResponse>) => {
      signals.push(call.request);
      cb(null, respond(call.request));
    },
  });
  const port = await bind(server);
  return {
    target: `127.0.0.1:${port}`,
    signals,
    async waitFor(n, timeoutMs = 2000) {
      const deadline = Date.now() + timeoutMs;
      while (signals.length < n) {
        if (Date.now() > deadline) throw new Error(`timed out waiting for ${n} signals (got ${signals.length})`);
        await new Promise((r) => setTimeout(r, 5));
      }
      return signals;
    },
    close: () => server.forceShutdown(),
  };
}

// 監視対象のアプリ: proto 無しで Buffer をそのまま送受信する単一メソッドのサービス。
// リクエスト本文で振る舞いを切り替える: "deny" → PERMISSION_DENIED, "slow:<ms>" → 遅延して OK, それ以外 → OK。
const identity = (b: Buffer) => b;
export const echoService: grpc.ServiceDefinition = {
  Say: {
    path: "/test.EchoService/Say",
    requestStream: false,
    responseStream: false,
    requestSerialize: identity,
    requestDeserialize: identity,
    responseSerialize: identity,
    responseDeserialize: identity,
  },
};

export interface EchoClient extends grpc.Client {
  Say(
    req: Buffer,
    md: grpc.Metadata,
    opts: grpc.CallOptions,
    cb: (err: grpc.ServiceError | null, res?: Buffer) => void,
  ): grpc.ClientUnaryCall;
}

const EchoClientCtor = grpc.makeGenericClientConstructor(echoService, "EchoService") as unknown as new (
  target: string,
  creds: grpc.ChannelCredentials,
  options?: grpc.ClientOptions,
) => EchoClient;

export function newEchoClient(target: string, options?: grpc.ClientOptions): EchoClient {
  return new EchoClientCtor(target, grpc.credentials.createInsecure(), options);
}

export async function startApp(interceptors: grpc.ServerInterceptor[] = []): Promise<{ target: string; close(): void }> {
  const server = new grpc.Server({ interceptors });
  server.addService(echoService, {
    Say: (call: grpc.ServerUnaryCall<Buffer, Buffer>, cb: grpc.sendUnaryData<Buffer>) => {
      const body = call.request.toString();
      if (body === "deny") {
        cb({ code: grpc.status.PERMISSION_DENIED, details: "user 42 may not access /admin" });
        return;
      }
      const delay = body.startsWith("slow:") ? Number(body.slice(5)) : 0;
      setTimeout(() => cb(null, Buffer.from(`echo:${body}`)), delay);
    },
  });
  const port = await bind(server);
  return { target: `127.0.0.1:${port}`, close: () => server.forceShutdown() };
}

/** Say を呼び、エラーも値として返す。 */
export function say(
  client: EchoClient,
  body: string,
  md = new grpc.Metadata(),
  opts: grpc.CallOptions = {},
): Promise<{ err: grpc.ServiceError | null; res?: Buffer | undefined }> {
  return new Promise((resolve) => client.Say(Buffer.from(body), md, opts, (err, res) => resolve({ err, res })));
}
