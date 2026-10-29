// gRPC インターセプター: RPC ごとに IP・User-Agent・ステータス・レイテンシを観測し、
// RPC の完了後に Reporter へ SecuritySignal を渡す。
//
//   - createServerInterceptor: Node.js で gRPC サーバーを提供する BFF / バックエンド用。
//     接続元 IP は TCP 接続から取得する。
//   - createClientInterceptor: BFF がバックエンドへ gRPC を呼び出す側用。
//     エンドユーザーの IP は、BFF が送信メタデータに載せた x-forwarded-for / x-real-ip から取得する。
//
// どちらもシグナルの組み立て・送信で起きた例外は握りつぶし、アプリの RPC には影響させない。

import * as grpc from "@grpc/grpc-js";
import type { Reporter } from "./reporter.js";
import { buildSignal, normalizeIp, type CallObservation, type SignalOptions } from "./signal.js";

function reportSafely(reporter: Reporter, obs: CallObservation, opts: SignalOptions): void {
  try {
    reporter.report(buildSignal(obs, opts));
  } catch {
    // 監視の失敗でアプリを止めない
  }
}

/** gRPC サーバー用インターセプター。`new grpc.Server({ interceptors: [...] })` に渡す。 */
export function createServerInterceptor(reporter: Reporter, opts: SignalOptions): grpc.ServerInterceptor {
  return (methodDescriptor, call) => {
    const startedAt = performance.now();
    let metadata = new grpc.Metadata();
    let reported = false;

    const finish = (statusCode: number, details: string) => {
      if (reported) return;
      reported = true;
      let connectionIp = "";
      try {
        connectionIp = normalizeIp(call.getConnectionInfo().remoteAddress);
      } catch {
        // 接続情報が取れなくても送信は続ける
      }
      reportSafely(
        reporter,
        {
          method: methodDescriptor.path,
          metadata,
          connectionIp,
          statusCode,
          errorMessage: details,
          latencyMs: performance.now() - startedAt,
        },
        opts,
      );
    };

    return new grpc.ServerInterceptingCall(call, {
      start: (next) => {
        next({
          onReceiveMetadata: (md, nextMd) => {
            metadata = md;
            nextMd(md);
          },
          // クライアントの切断・期限切れでは sendStatus が呼ばれないため、ここで記録する
          onCancel: () => finish(grpc.status.CANCELLED, "cancelled"),
        });
      },
      sendStatus: (status, nextStatus) => {
        finish(status.code, status.details ?? "");
        nextStatus(status);
      },
    });
  };
}

/** gRPC クライアント用インターセプター。クライアント生成時の `interceptors` オプションに渡す。 */
export function createClientInterceptor(reporter: Reporter, opts: SignalOptions): grpc.Interceptor {
  // 送信メタデータの x-forwarded-for は BFF 自身が設定するものなので、常に信頼する
  const clientOpts: SignalOptions = { ...opts, trustProxyHeaders: true };

  return (options, nextCall) => {
    const method = options.method_definition.path;
    let startedAt = 0;
    let metadata = new grpc.Metadata();

    return new grpc.InterceptingCall(nextCall(options), {
      start: (md, listener, next) => {
        startedAt = performance.now();
        metadata = md.clone();
        next(md, {
          onReceiveStatus: (status, nextStatus) => {
            reportSafely(
              reporter,
              {
                method,
                metadata,
                connectionIp: "",
                statusCode: status.code,
                errorMessage: status.details,
                latencyMs: performance.now() - startedAt,
              },
              clientOpts,
            );
            nextStatus(status);
          },
        });
      },
    });
  };
}
