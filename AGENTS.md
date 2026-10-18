# AI Agent Identity Lab — 作業ガイド

## 目的と構成

書籍原稿を含まない、独立した ID 実験サンプル。`entra/lab.py` は実 Entra の OBO／委任／アプリ権限を比較し、`entra/report_safety.py` が公開レポートの閉じたスキーマと整合性を検査する。`keycloak/run.mjs` は pinned Keycloak 26.8.1 の実験的 ID-JAG **受信機**を試し、`--federated-mcp` では `keycloak/federated-mcp.mjs` の**独自** broker と最小 MCP を使う。ネイティブ Entra ID-JAG 発行、ネイティブ Keycloak ID-JAG 発行、安定版 EMA 完全準拠を主張しない。

```text
entra/                  Python 3.11+; lab.py / report_safety.py / unittest / requirements.txt
keycloak/               Node.js 22+; run.mjs / federated-mcp.mjs / node --test
examples/author-run/    著者の過去のサニタイズ済み結果。読者の実行証拠ではない
scripts/lab.ps1         準備・診断・実行・結果検証・片付け
scripts/capture-terminal.ps1 実際のネイティブコンソールを撮影
```

Keycloak は Docker Desktop Linux コンテナーとループバックポート **18080** を使用する。Entra 実験は Windows PowerShell 5.1/7、Azure CLI v2、明示的に許可された既存セッション、`%LOCALAPPDATA%` の Windows ACL 保護ストレージが必要。macOS/Linux では Keycloak の直接 Node 実行のみ。設定の詳細はサブフォルダ README を読むこと。

## まず安全に確認

リポジトリルートからの**オフライン**作業:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r entra\requirements.txt
Set-Location entra
..\.venv\Scripts\python.exe -m unittest -v
Set-Location ..
npm run check --prefix keycloak
npm run test:unit --prefix keycloak
```

Pythonオフライン65件、Nodeオフライン10件は実テナントでの成功を示さない。Node側はnpm依存なし。必要なアクションだけを `.\scripts\lab.ps1 -Action Test` の形で選ぶ。EntraRunとFederatedを終えてからCleanupを行う。CIは認証情報なしのオフライン検査に限定する。

## 禁止・要注意

- 本人の明示的な指示なしに `az login`、トークン取得、`EntraRun`、`Federated`、`Cleanup`、実 Docker 統合テストを実行しない。`Setup`／`Doctor` に自動ログイン・クラウド変更を追加しない。
- `EntraRun` は毎回 **新しい 2 アプリと各 SP**、本人へのカスタムスコープ同意・アプリロール割り当て・24 時間の秘密を作る。既存アプリやテナントポリシーを変更せず、拒否の自動再試行や MFA 回避をしない。`EntraResume` は完了済みプロビジョニング専用。`Federated` は同じ読者の成功した private run が必要。`Cleanup` は全 Federated 後。
- トークン、CLI 生出力、プライベート状態／ハンドル、実 ID、環境変数、資格情報、未確認スクリーンショットを印字／コミット／外部送信しない。レポートの伏字化は認証ではない。報告前に [SECURITY.md](SECURITY.md) に従う。
- `examples/author-run/` を新たな成功の代わりに使わない。失敗・部分成功を成功に書き換えない。実行後の `entra/reports/`、`keycloak/results/` は作業時点の成果物であり、ソースツリーには初期出力がない。
- ランチャーとキャプチャの出力許可リストを維持する。HTMLダッシュボードではなく、実際に実行した端末の画面を用いる。
- `-ShowRawTokens` は本人がローカル端末で明示的に選ぶ手動確認専用。AIツール／CI／撮影／ログへ渡さず、自動実行しない。公開用の `TokenEncoded`／`TokenHeader`／`TokenPayload` は同じ実行の検証済み・マスク済み抜粋だけを表示し、追加取得しない。抜粋も閉じたスキーマと観測ダイジェストで保護する。Base64urlの元ペイロードや署名を公開しない。

技術的根拠と運用詳細: [entra/README.md](entra/README.md)、[keycloak/README.md](keycloak/README.md)、[keycloak/FEDERATED.md](keycloak/FEDERATED.md)。PR の手順は [CONTRIBUTING.md](CONTRIBUTING.md)。
