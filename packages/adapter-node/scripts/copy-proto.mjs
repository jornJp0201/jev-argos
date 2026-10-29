// リポジトリ直下の proto/ をパッケージに同梱する (実行時に proto-loader で読み込むため)。
import { cpSync } from "node:fs";

cpSync(new URL("../../../proto", import.meta.url), new URL("../proto", import.meta.url), { recursive: true });
