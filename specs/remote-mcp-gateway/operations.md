# Remote MCP Gateway - 運用ガイド

## 概要

MCP Gateway の Cloud Run 環境における初回セットアップと運用手順をまとめる。

- 初回インフラセットアップ (Firestore データベース作成、暗号化鍵、サービスアカウント、IAM)
- Firestore TTL ポリシー設定
- Data Access 監査ログの有効化

---

## 0. 初回インフラセットアップ

初めてデプロイする際に必要な GCP リソースの作成手順。

### 前提条件

- `gcloud` CLI がインストール済みで認証済み
- 対象 GCP プロジェクトに対する `Owner` または十分な権限
- 必要な API が有効化済み:

```bash
PROJECT_ID="<your-gcp-project-id>"

gcloud services enable \
  firestore.googleapis.com \
  secretmanager.googleapis.com \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  --project="${PROJECT_ID}"
```

### 0.1 Firestore データベースの作成

MCP Gateway はデフォルト DB ではなく、専用の名前付きデータベースを使用する。

```bash
gcloud firestore databases create \
  --database="mcp-gateway" \
  --location="asia-northeast1" \
  --type=firestore-native \
  --project="${PROJECT_ID}"
```

| パラメータ | 値 | 備考 |
|-----------|-----|------|
| `--database` | `mcp-gateway` | 環境変数 `GWS_FIRESTORE_DATABASE` のデフォルト値と一致させる |
| `--location` | `asia-northeast1` | Cloud Run と同じリージョンを推奨 |
| `--type` | `firestore-native` | Native モード (Datastore モードではない) |

> **注意**: データベースのロケーションは作成後に変更できない。Cloud Run サービスと同じリージョンにすることでレイテンシを最小化する。

### 0.2 サービスアカウントの作成

```bash
SA_NAME="gws-mcp-runtime"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

gcloud iam service-accounts create "${SA_NAME}" \
  --display-name="GWS MCP Gateway Runtime" \
  --project="${PROJECT_ID}"
```

### 0.3 IAM ロールの付与

#### 必要な IAM ロール

| ロール | リソースレベル | 用途 |
|--------|-------------|------|
| `roles/datastore.user` | プロジェクト | Firestore の読み書き (セッション、トークン管理) |
| `roles/secretmanager.secretAccessor` | シークレット単位 | 暗号化鍵・OAuth クライアント資格情報の読み取り |
| `roles/logging.logWriter` | プロジェクト | Cloud Logging への構造化ログ書き込み (Cloud Run のデフォルト) |

#### 付与すべきでないロール

| ロール | 理由 |
|--------|------|
| `roles/secretmanager.admin` | シークレットの作成・削除権限は不要。読み取りのみで十分 |
| `roles/datastore.owner` | インデックス管理やスキーマ変更は不要。`datastore.user` で十分 |
| `roles/editor` | プロジェクト全体への広範なアクセスは最小権限の原則に反する |

#### プロジェクトレベルのロール付与

```bash
# Firestore 読み書き
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/datastore.user"

# Cloud Logging 書き込み (Cloud Run のデフォルトで付与済みの場合あり)
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/logging.logWriter"
```

### 0.4 Secret Manager シークレットの作成

Gateway は以下の 3 つのシークレットを使用する。

| シークレット名 | 内容 | 設定方法 |
|---------------|------|---------|
| `mcp-gateway-encryption-key` | Firestore データの AES-256-GCM 暗号化鍵 (32 bytes) | 下記手順で生成 |
| `gws-oauth-client-id` | Google OAuth Client ID | Google Cloud Console で取得した値を設定 |
| `gws-oauth-client-secret` | Google OAuth Client Secret | Google Cloud Console で取得した値を設定 |

#### 暗号化鍵の生成と保存

```bash
# 32 バイトのランダム鍵を生成し Secret Manager に保存
openssl rand 32 | gcloud secrets create "mcp-gateway-encryption-key" \
  --data-file=- \
  --project="${PROJECT_ID}"
```

#### OAuth クライアント資格情報の保存

```bash
# Google Cloud Console → APIs & Services → Credentials で取得した値を設定
echo -n "<your-oauth-client-id>" | gcloud secrets create "gws-oauth-client-id" \
  --data-file=- \
  --project="${PROJECT_ID}"

echo -n "<your-oauth-client-secret>" | gcloud secrets create "gws-oauth-client-secret" \
  --data-file=- \
  --project="${PROJECT_ID}"
```

#### シークレット単位のアクセス権付与

```bash
for SECRET_NAME in "mcp-gateway-encryption-key" "gws-oauth-client-id" "gws-oauth-client-secret"; do
  gcloud secrets add-iam-policy-binding "${SECRET_NAME}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/secretmanager.secretAccessor" \
    --project="${PROJECT_ID}"
done
```

### 0.5 設定の確認

```bash
# Firestore データベースの確認
gcloud firestore databases list --project="${PROJECT_ID}"

# サービスアカウントのロール確認
gcloud projects get-iam-policy "${PROJECT_ID}" \
  --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:${SA_EMAIL}" \
  --format="table(bindings.role)"

# シークレットのアクセス権確認
gcloud secrets get-iam-policy "mcp-gateway-encryption-key" \
  --project="${PROJECT_ID}"
```

---

## 1. Firestore TTL ポリシー設定

Firestore TTL ポリシーにより、期限切れドキュメントが自動削除される。

> **注意**: TTL による削除は結果整合性 (数分〜最大 24 時間の遅延)。アプリケーションコードでも `expires_at` を検証し、期限切れドキュメントは無効として扱う。

### 対象コレクションと TTL

| コレクション | TTL フィールド | 有効期間 | 備考 |
|-------------|---------------|---------|------|
| `bearer_sessions` | `expires_at` | 1 時間 | Bearer Token セッション |
| `refresh_tokens` | `expires_at` | 7 日 | Refresh Token エントリ |
| `pending_auths` | `expires_at` | 15 分 | OAuth 認可フロー中間状態 |
| `pending_codes` | `expires_at` | 10 分 | 認可コード交換待ち |
| `registered_clients` | `expires_at` | 7 日 | 動的クライアント登録 |
| `user_sessions` | — | TTL なし | Google 連携セッション (明示的削除のみ) |

### 設定手順

#### 前提条件

- `gcloud` CLI がインストール済み
- 対象 GCP プロジェクトに対する `Owner` または `Cloud Datastore Index Admin` 権限

#### データベース情報

| 項目 | 値 | 環境変数 |
|------|-----|---------|
| プロジェクト ID | (デプロイ先の GCP プロジェクト) | `GWS_FIRESTORE_PROJECT` |
| データベース ID | `mcp-gateway` (デフォルト) | `GWS_FIRESTORE_DATABASE` |

#### TTL ポリシーの有効化

```bash
# 変数設定
PROJECT_ID="<your-gcp-project-id>"
DATABASE_ID="mcp-gateway"

# bearer_sessions (1 時間)
gcloud firestore fields ttls update expires_at \
  --collection-group=bearer_sessions \
  --enable-ttl \
  --project="${PROJECT_ID}" \
  --database="${DATABASE_ID}"

# refresh_tokens (7 日)
gcloud firestore fields ttls update expires_at \
  --collection-group=refresh_tokens \
  --enable-ttl \
  --project="${PROJECT_ID}" \
  --database="${DATABASE_ID}"

# pending_auths (15 分)
gcloud firestore fields ttls update expires_at \
  --collection-group=pending_auths \
  --enable-ttl \
  --project="${PROJECT_ID}" \
  --database="${DATABASE_ID}"

# pending_codes (10 分)
gcloud firestore fields ttls update expires_at \
  --collection-group=pending_codes \
  --enable-ttl \
  --project="${PROJECT_ID}" \
  --database="${DATABASE_ID}"

# registered_clients (7 日)
gcloud firestore fields ttls update expires_at \
  --collection-group=registered_clients \
  --enable-ttl \
  --project="${PROJECT_ID}" \
  --database="${DATABASE_ID}"
```

> `user_sessions` は TTL を設定しない。Google Refresh Token が `invalid_grant` を返した時点でアプリケーションが明示的に削除する。

#### 設定の確認

```bash
gcloud firestore fields ttls list \
  --project="${PROJECT_ID}" \
  --database="${DATABASE_ID}"
```

各コレクションの `expires_at` フィールドに `ACTIVE` ステータスの TTL ポリシーが表示されることを確認する。

---

## 2. Data Access 監査ログの有効化

Firestore (Cloud Datastore) の Data Access 監査ログを有効化し、不正アクセスの検知・追跡を可能にする。

### 監査ログの種類

| ログ種別 | 説明 | デフォルト |
|---------|------|-----------|
| Admin Activity | スキーマ変更、インデックス作成等 | 常に有効 (無料) |
| Data Read | ドキュメントの読み取り | **無効** (要手動有効化) |
| Data Write | ドキュメントの書き込み・削除 | **無効** (要手動有効化) |

### 設定手順 (Console)

1. [Google Cloud Console](https://console.cloud.google.com/) にアクセス
2. **IAM & Admin** → **Audit Logs** に移動
3. サービスリストから **Cloud Datastore API** を検索してチェック
4. 以下のログタイプを有効化:
   - **Data Read** にチェック
   - **Data Write** にチェック
5. **Save** をクリック

### 設定手順 (gcloud CLI)

```bash
PROJECT_ID="<your-gcp-project-id>"

# 現在の IAM ポリシーを取得
gcloud projects get-iam-policy "${PROJECT_ID}" --format=json > /tmp/policy.json
```

`/tmp/policy.json` の `auditConfigs` セクションに以下を追加 (既存の `auditConfigs` がある場合はマージ):

```json
{
  "auditConfigs": [
    {
      "service": "datastore.googleapis.com",
      "auditLogConfigs": [
        { "logType": "DATA_READ" },
        { "logType": "DATA_WRITE" }
      ]
    }
  ]
}
```

```bash
# ポリシーを適用
gcloud projects set-iam-policy "${PROJECT_ID}" /tmp/policy.json
```

### ログの確認

Cloud Logging で以下のフィルタを使用:

```
resource.type="audited_resource"
protoPayload.serviceName="datastore.googleapis.com"
protoPayload.resourceName:"databases/mcp-gateway"
```

### コストに関する注意

Data Access 監査ログは Cloud Logging の取り込み量としてカウントされる。MCP Gateway の利用規模 (20 名) では大きなコストにはならないが、必要に応じて [ログルーターの除外フィルタ](https://cloud.google.com/logging/docs/routing/overview) で取り込み量を制御できる。

