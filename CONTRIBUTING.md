# コントリビューション

小さく再現可能な変更を歓迎します。実テナントの識別子やシークレットを提出しないでください。

## 開発環境

Windows PowerShell 5.1/7、Python 3.11+、Node.js 22+ を用意してください。Keycloak の実行には Docker Desktop（Linux コンテナー）が必要です。Entra 実行には Azure CLI v2 と、明示的に許可されたテナント／本人のセッションが必要です。通常の開発・CI では **クラウド認証を行わないオフラインテスト**を優先します。リポジトリルートから:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r entra\requirements.txt
Set-Location entra
..\.venv\Scripts\python.exe -m unittest -v
Set-Location ..
npm run check --prefix keycloak
npm run test:unit --prefix keycloak
```

`npm install`は不要です（Node標準ライブラリのみ）。この手順はAzureにアクセスしません。ランチャーの `.\scripts\lab.ps1 -Action Test` も利用できます。Windows ARM64でpipが失敗するときは [README.md](README.md) の注意を確認し、Azure CLI配布物へ依存パッケージを導入しないでください。

## 変更とプルリクエスト

1. Issue を確認し、フォークから目的が明確なブランチを作成します。
2. 小さなコミットで変更し、関係するオフラインテストを追加／更新します。Python は標準ライブラリの `unittest`、Node は `node --test` と `node --check` を使用します。新しい依存は必要性とライセンスを説明してください。
3. PR には変更理由、実行したコマンドと結果、未検証の点、安全性・互換性への影響を書きます。実テナントを使ったテストは必須ではありません。実行したと主張する場合のみ、権限と後片付けの結果を機密情報なしで説明してください。
4. レビューを受け、指摘に対応します。過去の著者実行例や「成功」形の架空データを読者の実測として提出しないでください。

クラウドに関する変更では、新規の専用オブジェクトだけを扱い、既存のポリシー・アプリ・ユーザーを変更しない設計を守ってください。失敗の再試行や削除対象の拡大で通してはなりません。`entra/report_safety.py` の公開スキーマ・実験結果の整合性チェックと、`keycloak/owned-container.mjs` の ID／所有 nonce 確認を崩さないでください。スクリーンショット、プライベート状態、トークン、Azure CLI 出力を PR に貼らないでください。

## Issue とセキュリティ

バグは期待結果／実際の結果、最小の再現手順、OS・PowerShell・Python・Node・Docker・Azure CLI のバージョン、対象モードと安全なエラーコードを添えて Issue に報告してください。機密情報の疑いがある場合は公開 Issue を開かず、[SECURITY.md](SECURITY.md) に従ってください。

## Claude Code を使う場合

最初に [AGENTS.md](AGENTS.md) と対象の `entra/README.md` または `keycloak/README.md` を読ませ、実行範囲をオフラインテストなどに限定してください。本人の事前確認なしに `az login`、`EntraRun`、`Federated`、`Cleanup`、実クラウド操作を任せないでください。生成物も通常のコードレビューとプライバシーチェックの対象です。
