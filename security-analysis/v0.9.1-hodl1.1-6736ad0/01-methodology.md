# セキュリティ分析方法論

## 1. 分析フレームワーク

本分析では以下のフレームワーク・手法を組み合わせて包括的なセキュリティ評価を行う。

### 1.1 STRIDE 脅威モデリング

Microsoft が開発した脅威分類モデルを用いて、システムの各コンポーネントに対する脅威を体系的に特定する。

| カテゴリ | 説明 | 本プロジェクトでの主な対象 |
|----------|------|--------------------------|
| **S**poofing (なりすまし) | 他者になりすましてアクセス | OAuth フロー、Bearer トークン |
| **T**ampering (改ざん) | データや設定の不正な変更 | 権限設定 YAML、API リクエスト |
| **R**epudiation (否認) | 操作の否認が可能な状態 | 監査ログの欠如 |
| **I**nformation Disclosure (情報漏洩) | 機密情報の意図しない露出 | トークン、認証情報、エラーメッセージ |
| **D**enial of Service (サービス拒否) | サービスの可用性低下 | レート制限なし、メモリ枯渇 |
| **E**levation of Privilege (権限昇格) | 意図しない権限の取得 | 権限制御バイパス |

### 1.2 OWASP Top 10 チェック

OWASP Top 10 (2021) に基づく脆弱性カテゴリを確認する。

| # | カテゴリ | 本プロジェクトでの関連性 |
|---|---------|----------------------|
| A01 | Broken Access Control | 権限制御 (permissions.yaml)、OAuth スコープ |
| A02 | Cryptographic Failures | AES-256-GCM 暗号化、鍵管理 |
| A03 | Injection | パストラバーサル、URL インジェクション |
| A04 | Insecure Design | アーキテクチャ設計上の欠陥 |
| A05 | Security Misconfiguration | 環境変数、デフォルト設定 |
| A06 | Vulnerable Components | 依存ライブラリの脆弱性 |
| A07 | Authentication Failures | OAuth フロー、セッション管理 |
| A08 | Software and Data Integrity | 権限設定の整合性 |
| A09 | Security Logging and Monitoring | 監査ログ、異常検知 |
| A10 | SSRF | Discovery Document URL、API エンドポイント |

### 1.3 分析対象のレイヤー

```
┌─────────────────────────────────────────┐
│  Layer 7: アプリケーション層              │ ← 入力検証、ビジネスロジック
├─────────────────────────────────────────┤
│  Layer 6: 認証・認可層                   │ ← OAuth, Bearer トークン, RBAC
├─────────────────────────────────────────┤
│  Layer 5: データ保護層                   │ ← 暗号化 (保存時/転送時)
├─────────────────────────────────────────┤
│  Layer 4: トランスポート層               │ ← TLS, HTTP ヘッダー
├─────────────────────────────────────────┤
│  Layer 3: インフラ層                     │ ← Cloud Run, Secret Manager, IAM
├─────────────────────────────────────────┤
│  Layer 2: 依存関係層                     │ ← Cargo クレート、サプライチェーン
├─────────────────────────────────────────┤
│  Layer 1: 構成管理層                     │ ← 環境変数、設定ファイル、Git
└─────────────────────────────────────────┘
```

## 2. 分析手法

### 2.1 ソースコード静的分析

| 対象 | 分析内容 |
|------|---------|
| `src/auth.rs` | 認証ロジック、トークン取得フロー |
| `src/credential_store.rs` | 暗号化実装、鍵管理 |
| `src/token_storage.rs` | トークンキャッシュ、永続化 |
| `src/oauth_config.rs` | OAuth クライアント設定管理 |
| `src/mcp_server/oauth.rs` | Gateway OAuth フロー、セッション管理 |
| `src/mcp_server/http.rs` | HTTP エンドポイント、CORS、リクエスト処理 |
| `src/mcp_server/permissions.rs` | 権限制御、スコープ・メソッドフィルタ |
| `src/mcp_server/session_store.rs` | セッション永続化 (Secret Manager) |
| `src/mcp_server/jsonrpc.rs` | JSON-RPC レスポンス構築 |
| `src/validate.rs` | 入力検証ヘルパー |
| `src/executor.rs` | API リクエスト実行、レスポンス処理 |
| `src/helpers/mod.rs` | URL エンコーディング、リソース名検証 |
| `src/main.rs` | エントリーポイント、環境変数処理 |
| `src/client.rs` | HTTP クライアント設定 |

### 2.2 構成・設定レビュー

| 対象 | 分析内容 |
|------|---------|
| `Cargo.toml` | 依存関係、暗号ライブラリバージョン |
| `.env` / `.env.example` | 環境変数、シークレット管理 |
| `config/permissions.yaml` | 権限設定の妥当性 |
| `SECURITY.md` | セキュリティポリシー |

### 2.3 アーキテクチャレビュー

| 対象 | 分析内容 |
|------|---------|
| `specs/remote-mcp-gateway/design.md` | 設計上のセキュリティ判断 |
| `specs/remote-mcp-gateway/requirements.md` | セキュリティ要件の充足度 |
| データフロー | トークン・認証情報のライフサイクル |
| 信頼境界 | コンポーネント間の信頼関係 |

### 2.4 GCP インフラ実態検証 (gcloud)

デプロイ済みの Cloud Run 環境に対して gcloud コマンドで実態を確認し、設計ドキュメントとの差分を特定する。

#### Step 1: アーキテクチャダイアグラム作成

設計ドキュメント (`specs/remote-mcp-gateway/design.md`) とソースコードから、以下のダイアグラムを作成する:
- コンポーネント図 (Cloud Run, Secret Manager, Google OAuth, Workspace API)
- データフロー図 (トークンのライフサイクル)
- 信頼境界図

#### Step 2: gcloud による実態検証

以下のコマンドで本番環境の設定を確認する:

```bash
# Cloud Run サービス設定 (インスタンス数、メモリ、CPU、タイムアウト、Ingress)
gcloud run services describe <service-name> --region <region> --format yaml

# Cloud Run の IAM ポリシー (誰がサービスを呼べるか)
gcloud run services get-iam-policy <service-name> --region <region>

# サービスアカウントに付与された IAM ロール
gcloud projects get-iam-policy <project-id> \
  --flatten="bindings[].members" \
  --filter="bindings.members:<service-account>"

# Secret Manager シークレット設定
gcloud secrets describe <secret-name> --project <project-id>

# Secret Manager の IAM ポリシー (誰がシークレットにアクセスできるか)
gcloud secrets get-iam-policy <secret-name> --project <project-id>

# Cloud Run の環境変数・シークレット参照
gcloud run services describe <service-name> --region <region> \
  --format="yaml(spec.template.spec.containers[0].env)"

# Cloud Run のネットワーク設定 (VPC Connector, Ingress)
gcloud run services describe <service-name> --region <region> \
  --format="yaml(spec.template.metadata.annotations)"

# Cloud Logging の設定確認 (ログルーターのシンク)
gcloud logging sinks list --project <project-id>

# OAuth 同意画面の設定 (公開/内部、検証状態)
# ※ gcloud では直接取得不可、Cloud Console で確認
```

#### Step 3: 設計と実態の差分分析

Step 1 のダイアグラムと Step 2 の実態を突き合わせ、以下を確認する:
- 設計で意図した設定と実際の設定に乖離がないか
- IAM ロールが最小権限原則に従っているか
- 不要なサービスやリソースが残っていないか
- Cloud Run の公開設定が意図通りか

## 3. 包括的分析で行うべき項目チェックリスト

### 認証・認可
- [ ] OAuth 2.0 / PKCE フロー実装の正当性
- [ ] Bearer トークンの生成・検証・失効
- [ ] セッション管理 (生成、バインド、有効期限)
- [ ] 権限制御 (RBAC) の実装整合性
- [ ] 未認証アクセスの拒否
- [ ] スコープの最小権限原則の適用

### データ保護
- [ ] 保存時暗号化 (AES-256-GCM) の実装正当性
- [ ] 鍵管理 (生成、保存、ローテーション)
- [ ] 転送時暗号化 (TLS)
- [ ] 機密データのメモリ管理
- [ ] ログへの機密情報出力防止

### 入力検証
- [ ] パストラバーサル防止
- [ ] URL インジェクション防止
- [ ] JSON パース時のバリデーション
- [ ] リソース名バリデーション
- [ ] リクエストサイズ制限

### インフラ・運用
- [ ] Cloud Run セキュリティ設定 (gcloud で実態確認)
- [ ] Secret Manager 権限 (gcloud で IAM ポリシー確認)
- [ ] サービスアカウント権限の最小化 (gcloud で実態確認)
- [ ] CORS 設定
- [ ] レート制限
- [ ] 監査ログ (Cloud Logging 連携状態の確認)
- [ ] アーキテクチャダイアグラムと実態の差分

### 依存関係
- [ ] 既知脆弱性のあるクレート
- [ ] サプライチェーンリスク
- [ ] ライセンスコンプライアンス

## 4. 重要な観点

### 4.1 AI エージェントからの入力

本プロジェクトは Claude Desktop / Claude Code などの AI エージェントから呼び出される。AGENTS.md にも明記されている通り、**入力は常に敵対的であり得る**と想定する必要がある。

### 4.2 マルチテナント環境

MCP Gateway は約20名の社員が共有する。ユーザー間のデータ分離と権限分離が正しく機能しているかが重要。

### 4.3 OAuth トークンのサーバーサイド保持

設計上、Google OAuth トークンはサーバー側で保持される。トークンの漏洩・不正利用はユーザーの Google Workspace データ全体に影響するため、保管方法が極めて重要。

### 4.4 Secret Manager への一括保存

全ユーザーのセッション情報が単一の Secret Manager シークレットに保存される設計。この「爆発半径」は分析の重要ポイント。
