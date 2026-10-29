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
import type { BlockChecker } from "./blocklist.js";
import type { Reporter } from "./reporter.js";
import { buildSignal, normalizeIp, resolveClientIp, type CallObservation, type SignalOptions } from "./signal.js";

export interface ServerInterceptorOptions extends SignalOptions {
  /**
   * 遮断リスト (通常は BlocklistWatcher)。指定すると、遮断中の IP からの RPC を
   * PERMISSION_DENIED で拒否する (アプリのハンドラーは呼ばれない)。
   */
  blocklist?: BlockChecker | undefined;
}

function reportSafely(reporter: Reporter, obs: CallObservation, opts: SignalOptions): void {
  try {
    reporter.report(buildSignal(obs, opts));
  } catch {
    // 監視の失敗でアプリを止めない
  }
}

/** gRPC サーバー用インターセプター。`new grpc.Server({ interceptors: [...] })` に渡す。 */
export function createServerInterceptor(reporter: Reporter, opts: ServerInterceptorOptions): grpc.ServerInterceptor {
  return (methodDescriptor, call) => {
    const startedAt = performance.now();
    let metadata = new grpc.Metadata();
    let reported = false;
    let connectionIp = "";
    try {
      connectionIp = normalizeIp(call.getConnectionInfo().remoteAddress);
    } catch {
      // 接続情報が取れなくても処理と送信は続ける
    }

    const finish = (statusCode: number, details: string) => {
      if (reported) return;
      reported = true;
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
            if (opts.blocklist?.isBlocked(resolveClientIp(md, connectionIp, opts.trustProxyHeaders))) {
              // 遮断中の送信元: ハンドラーへ進ませずに拒否する (この RPC もシグナルとして送る)
              finish(grpc.status.PERMISSION_DENIED, "blocked by jev-argos");
              call.sendStatus({ code: grpc.status.PERMISSION_DENIED, details: "blocked by jev-argos" });
              return;
            }
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
