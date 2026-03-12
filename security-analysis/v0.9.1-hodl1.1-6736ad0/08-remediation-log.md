# セキュリティ対応ログ

| 項目 | 内容 |
|------|------|
| 対応日 | 2026-03-12 |
| 対象 | 07-findings-summary.md の即時対応項目 (CRITICAL) |

---

## 対応済み項目

### 1. `.dockerignore` に `.env` を追加 (INF-H1)

| 項目 | 内容 |
|------|------|
| 対象脅威 | INF-H1: `.dockerignore` に `.env` が未除外（ビルドコンテキストへの機密情報混入） |
| 深刻度 | HIGH |
| 対応内容 | `.dockerignore` に `.env` を追加し、Docker ビルドコンテキストから除外 |
| 対応ファイル | `.dockerignore` |

### 2. `.env` ファイルからクライアントシークレットを削除 (DP-01)

| 項目 | 内容 |
|------|------|
| 対象脅威 | DP-01: `.env` ファイルに OAuth クライアントシークレットがハードコード |
| 深刻度 | CRITICAL |
| 対応内容 | `.env` ファイルからクライアントシークレットを削除 |

### 3. Secret Manager の IAM ポリシーを最小権限に変更 (S-04, I-01, INF-M8)

| 項目 | 内容 |
|------|------|
| 対象脅威 | S-04 / I-01: 全ユーザーの Google OAuth トークンが単一の Secret Manager シークレットに保存。漏洩時の爆発半径が最大 |
| 深刻度 | CRITICAL |
| 対応内容 | 以下の 3 点を実施 |

#### 3a. Cloud Run 専用サービスアカウントの作成

デフォルト Compute Engine サービスアカウント（`Editor` ロール付き）の使用をやめ、最小権限の専用サービスアカウント `gws-mcp-runtime` を作成。

```
gcloud iam service-accounts create gws-mcp-runtime \
  --display-name="GWS MCP Gateway Runtime" \
  --project=astute-psyche-489408-g2
```

#### 3b. シークレット単位の IAM バインディング

プロジェクトレベルではなくシークレット単位で最小限のロールを付与。

| シークレット | ロール | 理由 |
|-------------|--------|------|
| `gws-mcp-sessions` | `roles/secretmanager.secretVersionManager` | セッションの読み書きが必要 |
| `gws-oauth-client-id` | `roles/secretmanager.secretAccessor` | 読み取りのみ |
| `gws-oauth-client-secret` | `roles/secretmanager.secretAccessor` | 読み取りのみ |

#### 3c. デフォルト Compute Engine SA のバインディング削除

`gws-oauth-client-id` および `gws-oauth-client-secret` に残存していたデフォルト Compute Engine SA (`756600426975-compute@developer.gserviceaccount.com`) の `secretAccessor` バインディングを削除。

#### 3d. Cloud Run デプロイワークフローの更新

`deploy-cloud-run.yml` に `--service-account` フラグを追加し、専用 SA を使用するよう変更。

```yaml
--service-account=gws-mcp-runtime@${{ vars.GCP_PROJECT_ID }}.iam.gserviceaccount.com
```

### 最終状態の確認

プロジェクトレベルの IAM ポリシーに Secret Manager 関連ロールを持つアカウントがないことを確認済み。

各シークレットの IAM ポリシー（確認済み）:

| シークレット | メンバー | ロール |
|-------------|----------|--------|
| `gws-mcp-sessions` | `gws-mcp-runtime@...` | `secretVersionManager` |
| `gws-oauth-client-id` | `gws-mcp-runtime@...` | `secretAccessor` |
| `gws-oauth-client-secret` | `gws-mcp-runtime@...` | `secretAccessor` |

---

## 未対応項目（残存）

07-findings-summary.md のロードマップ 5.2 以降を参照。
