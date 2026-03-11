# 06 - インフラ・デプロイメントセキュリティ分析

## 分析概要

| 項目 | 内容 |
|------|------|
| 分析者 | Agent E |
| 分析日 | 2026-03-11 |
| 対象コミット | `6736ad0` (custom ブランチ HEAD) |
| 分析範囲 | Dockerfile、依存関係、HTTP クライアント設定、権限設定、環境変数管理、Cloud Run 構成 |
| gcloud 実態検証 | **未実施**（サンドボックス環境の制約により gcloud コマンドの実行が許可されなかった） |

## 1. コンテナ・Dockerfile セキュリティ

### 1.1 マルチステージビルド

**リスクレベル: INFO**

Dockerfile はマルチステージビルドを採用しており、ビルドツールやソースコードがランタイムイメージに含まれない。

```
FROM rust:1.93-slim-bookworm AS builder  # ビルドステージ
FROM debian:bookworm-slim               # ランタイムステージ
```

ランタイムイメージには `gws` バイナリ、`ca-certificates`、`config/` ディレクトリのみがコピーされる。これはベストプラクティスに沿った構成。

### 1.2 コンテナが root ユーザーで実行される

**リスクレベル: MEDIUM**

**ファイル:** `/home/vitocchi/work/gws-cli/Dockerfile`

Dockerfile に `USER` ディレクティブが存在しない。コンテナは root ユーザー (UID 0) で実行される。万が一コンテナ内でコード実行の脆弱性が悪用された場合、攻撃者は root 権限を持つことになる。

**推奨対応:**
```dockerfile
RUN adduser --disabled-password --gecos '' --uid 10001 appuser
USER appuser
```

### 1.3 .dockerignore に .env が含まれていない

**リスクレベル: HIGH**

**ファイル:** `/home/vitocchi/work/gws-cli/.dockerignore`

`.dockerignore` に `.env` ファイルが除外対象として記載されていない。開発者のローカル `.env` ファイルにはOAuth クライアントシークレットなどの機密情報が含まれる可能性があるが、`docker build` 実行時にビルドコンテキストに含まれ得る。

現在の `.dockerignore` は `*.md` を除外しているが、`.env` は明示的に除外されていない。`COPY` 命令は `Cargo.toml`, `Cargo.lock`, `src/`, `registry/`, `templates/` のみを対象としているため Docker イメージ自体には入らないが、ビルドコンテキストへの送信は発生する。

**推奨対応:**
```
# .dockerignore に追加
.env
.env.*
```

### 1.4 ベースイメージのバージョン固定

**リスクレベル: LOW**

ビルドステージは `rust:1.93-slim-bookworm`、ランタイムは `debian:bookworm-slim` を使用。メジャーバージョンまでは固定されているが、特定のパッチバージョンやダイジェストによる固定はされていない。サプライチェーン攻撃のリスクを低減するためにはダイジェスト固定が望ましい。

## 2. 依存関係セキュリティ

### 2.1 暗号ライブラリのバージョン

**リスクレベル: INFO**

**ファイル:** `/home/vitocchi/work/gws-cli/Cargo.toml`

| クレート | バージョン指定 | 用途 | 評価 |
|----------|-------------|------|------|
| `aes-gcm` | `0.10` | AES-256-GCM 暗号化 | RustCrypto 系、メンテナンス良好 |
| `sha2` | `0.10` | SHA-256 ハッシュ (PKCE) | RustCrypto 系、メンテナンス良好 |
| `rand` | `0.8` | 乱数生成 | 標準的な選択 |
| `base64` | `0.22.1` | Base64 エンコード | 安定版 |

暗号ライブラリは RustCrypto エコシステムの標準的な選択であり、既知の問題はない。

### 2.2 TLS 実装の選択

**リスクレベル: INFO**

**ファイル:** `/home/vitocchi/work/gws-cli/Cargo.toml`

```toml
reqwest = { version = "0.12", features = ["json", "stream", "rustls-tls-native-roots"], default-features = false }
```

`rustls-tls-native-roots` を使用しており、OpenSSL ではなく rustls による TLS を使用。`default-features = false` により不要な機能を無効化している。rustls は Rust で実装されたメモリ安全な TLS ライブラリであり、C 言語ベースの OpenSSL に比べてメモリ安全性が高い。

ただし、ランタイムの Dockerfile では `libssl-dev` がインストールされていないため、実際に rustls が使われていることが確認できる（OpenSSL がランタイムに存在しない）。

### 2.3 cargo audit 未実施

**リスクレベル: MEDIUM**

`cargo-audit` がインストールされていないため、既知の脆弱性の自動チェックを実行できなかった。CI/CD パイプラインに `cargo audit` を組み込むことを推奨する。

**推奨対応:**
- CI に `cargo audit` ステップを追加
- `cargo deny` の導入も検討（ライセンスチェックも兼ねる）

### 2.4 依存関係の幅広い範囲指定

**リスクレベル: LOW**

多くの依存関係がメジャーバージョンのみの指定 (`"1"`, `"0.12"` 等) となっている。`Cargo.lock` が存在しビルドの再現性は確保されているが、`lock` ファイルの更新時に意図しないバージョンアップが発生する可能性がある。

## 3. HTTP クライアント設定

### 3.1 リトライ制御

**リスクレベル: INFO**

**ファイル:** `/home/vitocchi/work/gws-cli/src/client.rs`

HTTP クライアントは 429 (Too Many Requests) に対して最大 3 回のリトライを行い、`Retry-After` ヘッダーを尊重する。指数バックオフ (1s, 2s, 4s) のフォールバックも実装されている。Google Workspace API のレート制限に対する適切な対応。

### 3.2 HTTP クライアントのタイムアウト未設定

**リスクレベル: MEDIUM**

**ファイル:** `/home/vitocchi/work/gws-cli/src/client.rs`

`reqwest::Client::builder()` にタイムアウトが設定されていない。悪意のあるレスポンスや遅延するエンドポイントに対して無期限に待機し、リソースを占有する可能性がある。

```rust
reqwest::Client::builder()
    .default_headers(headers)
    .build()  // timeout 未設定
```

**推奨対応:**
```rust
reqwest::Client::builder()
    .default_headers(headers)
    .timeout(std::time::Duration::from_secs(30))
    .connect_timeout(std::time::Duration::from_secs(10))
    .build()
```

## 4. MCP Gateway HTTP サーバー設定

### 4.1 リクエストボディサイズ制限の欠如

**リスクレベル: HIGH**

**ファイル:** `/home/vitocchi/work/gws-cli/src/mcp_server/http.rs`

axum Router にリクエストボディサイズ制限 (`DefaultBodyLimit`) が設定されていない。axum のデフォルトは 2MB だが、明示的な制限が設定されていないため、巨大なリクエストボディによるメモリ消費攻撃のリスクがある。特に `handle_post` ハンドラーはボディを `String` として受け取るため、メモリに全て読み込まれる。

**推奨対応:**
```rust
use axum::extract::DefaultBodyLimit;

let app = Router::new()
    // ... routes ...
    .layer(DefaultBodyLimit::max(1024 * 1024)) // 1MB
```

### 4.2 セキュリティヘッダーの欠如

**リスクレベル: MEDIUM**

**ファイル:** `/home/vitocchi/work/gws-cli/src/mcp_server/http.rs`

以下の標準的なセキュリティレスポンスヘッダーが設定されていない:

- `Strict-Transport-Security` (HSTS)
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy`

Cloud Run は HTTPS を強制するが、HSTS ヘッダーを設定することでブラウザベースのクライアントに対して追加の保護を提供できる。MCP Gateway は主に API クライアントからの利用だが、OAuth コールバックエンドポイントはブラウザ経由でアクセスされる。

### 4.3 CORS 設定

**リスクレベル: LOW**

**ファイル:** `/home/vitocchi/work/gws-cli/src/mcp_server/http.rs` (L95-110, L982-1012)

CORS の Origin 検証は2箇所に実装されている:

1. `validate_origin()` -- MCP エンドポイント用。Origin ヘッダーがない場合は許可 (`return true`)。
2. `build_cors_headers()` -- OAuth エンドポイント用。同一のロジック。

デフォルト (allowed_origins 未設定時) では localhost 系のオリジンのみ許可される。Cloud Run 環境では `--allow-origin` フラグで明示的にオリジンを指定する運用が想定される。

**懸念点:** Origin ヘッダーがない場合 (非ブラウザクライアント) は常に許可される設計。API クライアント (Claude Desktop 等) はブラウザではないため Origin を送信しない。この設計自体は意図的と思われるが、ドキュメント化されるべき。

### 4.4 レート制限の欠如

**リスクレベル: HIGH**

**ファイル:** `/home/vitocchi/work/gws-cli/src/mcp_server/http.rs`

MCP Gateway のエンドポイントにレート制限が実装されていない。コードコメントに「future per-client rate limiting」への言及があるが (`oauth.rs:97`)、未実装のまま。

Cloud Run 自体にはインスタンス数による暗黙のスループット制限があるが、以下のリスクが存在する:
- 認証エンドポイントへのブルートフォース攻撃
- `/token` エンドポイントへの大量リクエスト
- MCP エンドポイント経由での Google Workspace API の過剰呼び出し

**推奨対応:**
- `tower::limit::RateLimitLayer` の導入
- 特に `/token`, `/authorize`, `/register` エンドポイントに対するレート制限

### 4.5 セッション数制限

**リスクレベル: INFO**

**ファイル:** `/home/vitocchi/work/gws-cli/src/mcp_server/oauth.rs`

セッション数の上限が設定されている:

| リソース | 上限 |
|----------|------|
| Bearer セッション | 100,000 |
| Pending codes | 10,000 |
| Pending auths | 10,000 |
| Registered clients | 10,000 |

約20名の利用を想定するシステムとしては十分な上限。`cleanup_expired()` も呼び出されており、期限切れセッションのクリーンアップが行われている。

## 5. Secret Manager セキュリティ

### 5.1 全セッションの単一シークレット保存

**リスクレベル: HIGH**

**ファイル:** `/home/vitocchi/work/gws-cli/src/mcp_server/session_store.rs`

全ユーザーのセッション情報（Google OAuth リフレッシュトークンを含む）が単一の Secret Manager シークレットに JSON blob として保存される。この設計には以下のリスクがある:

1. **爆発半径が大きい**: シークレットが漏洩した場合、全ユーザーの Google OAuth トークンが一度に露出する
2. **バージョン増加**: セッション変更のたびに新バージョンが作成されるが、古いバージョンの削除処理が実装されていない。Secret Manager のバージョンが無限に蓄積する
3. **競合状態**: 複数インスタンスが同時にセッションを更新した場合、後勝ちとなりセッションデータが失われる可能性がある

**推奨対応:**
- ユーザーごとに個別のシークレットを使用する、またはサーバーサイド暗号化レイヤーを追加
- 古いシークレットバージョンの自動削除ロジックの実装
- 楽観的ロック (ETag) の実装

### 5.2 Secret Manager の自動作成

**リスクレベル: MEDIUM**

**ファイル:** `/home/vitocchi/work/gws-cli/src/mcp_server/session_store.rs` (L79-119)

`ensure_secret_exists()` メソッドはシークレットが存在しない場合に自動作成する。これはサービスアカウントに `secretmanager.secrets.create` 権限が必要であることを意味し、最小権限原則に反する。本番環境ではシークレットを事前に作成し、サービスアカウントにはバージョンの読み書き権限のみを付与すべき。

README.custom.md にも `Secret Manager Admin` ロールが必要と記載されており、過剰な権限が前提となっている。

**推奨対応:**
- 本番環境ではシークレットを事前作成（Terraform 等のIaC で管理）
- サービスアカウントには `roles/secretmanager.secretVersionManager` のみ付与
- `ensure_secret_exists()` を本番では無効化するオプションの追加

### 5.3 Secret Manager レプリケーション設定

**リスクレベル: LOW**

**ファイル:** `/home/vitocchi/work/gws-cli/src/mcp_server/session_store.rs` (L101)

シークレット作成時に `"replication": { "automatic": {} }` が設定される。自動レプリケーションは Google が管理するリージョンにデータが保存される。コンプライアンス要件によってはリージョン指定が必要な場合がある。

## 6. 環境変数・シークレット管理

### 6.1 .env ファイルの自動読み込み

**リスクレベル: LOW**

**ファイル:** `/home/vitocchi/work/gws-cli/src/main.rs` (L49)

```rust
let _ = dotenvy::dotenv();
```

`.env` ファイルが存在する場合に自動的に読み込まれる。開発環境では便利だが、本番コンテナに `.env` ファイルが混入した場合に意図しない環境変数が設定される可能性がある。`.gitignore` には `.env` が含まれているが、`.dockerignore` には含まれていない（前述の 1.3 参照）。

### 6.2 機密環境変数の管理

**リスクレベル: INFO**

**ファイル:** `/home/vitocchi/work/gws-cli/.env.example`

以下の機密性の高い環境変数が使用される:

| 変数名 | 機密度 | 推奨保管先 |
|--------|--------|-----------|
| `GOOGLE_WORKSPACE_CLI_CLIENT_ID` | 中 | Secret Manager |
| `GOOGLE_WORKSPACE_CLI_CLIENT_SECRET` | 高 | Secret Manager |
| `GOOGLE_WORKSPACE_CLI_TOKEN` | 高 | Secret Manager |
| `GWS_GATEWAY_BASE_URL` | 低 | 環境変数 |

Cloud Run ではこれらを Secret Manager から参照として設定することが推奨される。Dockerfile のコメントにもこの構成が示唆されている。

## 7. 権限設定 (permissions.yaml)

### 7.1 権限設定の全体評価

**リスクレベル: INFO**

**ファイル:** `/home/vitocchi/work/gws-cli/config/permissions.yaml`

RBAC (Role-Based Access Control) が YAML ファイルで定義されており、`admin` と `reader` の2つのロールが設定されている。

| ロール | ユーザー数 | 特徴 |
|--------|-----------|------|
| `admin` | 8名 | 閲覧 + 作成・更新（削除系は除外） |
| `reader` | 12名 | 閲覧のみ |

### 7.2 admin ロールの権限範囲

**リスクレベル: MEDIUM**

`admin` ロールは `drive.files.create`, `drive.files.update`, `sheets.spreadsheets.batchUpdate` など書き込み系のメソッドを許可している。削除系メソッドは適切に除外されているが、以下は注意が必要:

- `drive.files.create` -- 新規ファイル作成が可能（ストレージ消費）
- `sheets.spreadsheets.batchUpdate` -- スプレッドシートの構造変更が可能
- `calendar.events.insert` / `calendar.events.update` -- 他者のカレンダーへの予定追加・変更（権限次第）

AI エージェントからの入力は敵対的であり得るという前提（AGENTS.md, methodology 4.1）を考慮すると、admin ロールに書き込み権限を付与することのリスクは認識しておくべき。

### 7.3 実名・メールアドレスのソースコード内記載

**リスクレベル: MEDIUM**

**ファイル:** `/home/vitocchi/work/gws-cli/config/permissions.yaml`

全ユーザーの実名とメールアドレスがYAMLファイルに平文で記載されており、Git リポジトリに含まれている。これは以下の点で問題がある:

- 組織構造（役職、部署）が公開リポジトリから推測可能
- メールアドレスがフィッシング攻撃のターゲットリストとなり得る
- リポジトリがフォーク・クローンされた場合に個人情報が拡散する

**推奨対応:**
- ユーザーマッピングを外部データソース（Google Workspace Directory API 等）から動的に取得する設計への変更
- 少なくともコメントの実名を削除し、メールアドレスのみとする

## 8. Cloud Run 構成（コードベースからの推測）

### 8.1 推定されるデプロイ構成

gcloud による実態検証は未実施のため、コードベースと Dockerfile から推定される構成を記載する。

| 設定項目 | 推定値 | 根拠 |
|----------|--------|------|
| リスニングポート | 8080 | Dockerfile の `ENV PORT=8080` |
| バインドアドレス | 0.0.0.0 | ENTRYPOINT の `--host 0.0.0.0` |
| TLS 終端 | Cloud Run (外部) | アプリケーション側に TLS 設定なし |
| サービス公開範囲 | 要確認 | Ingress 設定は gcloud で要確認 |
| 認証方式 | OAuth 2.0 + PKCE | アプリケーション層で実装 |

### 8.2 Cloud Run の Ingress 設定に関する懸念

**リスクレベル: MEDIUM** (検証未実施)

Cloud Run サービスが `--ingress=all` で公開されている場合、インターネットから直接アクセス可能となる。MCP Gateway は OAuth による認証を実装しているが、以下を確認すべき:

- Ingress 設定が `internal-and-cloud-load-balancing` ではないか
- Cloud Armor (WAF) が前段に配置されているか
- IAM による呼び出し元制限 (`allUsers` vs 特定サービスアカウント)

### 8.3 サービスアカウント権限

**リスクレベル: MEDIUM** (検証未実施)

README.custom.md に `Secret Manager Admin` ロールが必要と記載されている。これは以下の権限を含む過剰なロール:

- `secretmanager.secrets.create` -- シークレットの新規作成
- `secretmanager.secrets.delete` -- シークレットの削除
- `secretmanager.secrets.get` -- シークレットメタデータの取得
- `secretmanager.versions.add` -- バージョンの追加
- `secretmanager.versions.access` -- バージョンの読み取り
- `secretmanager.versions.destroy` -- バージョンの削除

最小権限原則に従えば、以下のみで十分:
- `secretmanager.versions.add`
- `secretmanager.versions.access`
- `secretmanager.versions.list`

## 9. 監査ログ

### 9.1 Cloud Logging 対応のフォーマッター

**リスクレベル: INFO**

**ファイル:** `/home/vitocchi/work/gws-cli/src/mcp_server.rs` (L184-315)

Cloud Logging 互換の JSON フォーマッター (`CloudLoggingFormat`) が実装されており、`severity`, `timestamp`, `message` フィールドを含む構造化ログを出力する。Cloud Run の標準出力は自動的に Cloud Logging に取り込まれるため、追加設定なしでログが収集される。

### 9.2 ツール呼び出しの監査ログ

**リスクレベル: INFO**

**ファイル:** `/home/vitocchi/work/gws-cli/src/mcp_server.rs` (L1148-1168)

各ツール呼び出しに対して以下の情報がログに記録される:

- ユーザーのメールアドレス (`email`)
- 呼び出されたメソッド ID (`method_id`)
- 結果 (`result`: "success" / "error")
- エラーメッセージ（失敗時）

### 9.3 認証イベントの監査ログ不足

**リスクレベル: MEDIUM**

以下の認証関連イベントがログに記録されていない:

- ログイン成功・失敗
- トークンリフレッシュ
- セッション作成・削除
- 無効なベアラートークンによるアクセス試行
- CORS オリジン拒否

セキュリティインシデントの検知・調査に重要な情報が欠落している。

**推奨対応:**
- 認証成功/失敗イベントのログ出力追加
- 異常なアクセスパターン検知のための Cloud Monitoring アラート設定

## 10. サプライチェーンリスク

### 10.1 依存クレートの概要

**リスクレベル: LOW**

主要な依存関係は広く使われている Rust エコシステムのクレート:

| カテゴリ | クレート | リスク評価 |
|----------|---------|-----------|
| Web フレームワーク | `axum 0.8` | 低 -- Tokio チームがメンテナンス |
| HTTP クライアント | `reqwest 0.12` | 低 -- 広範な利用実績 |
| シリアライゼーション | `serde 1`, `serde_json 1` | 低 -- Rust エコシステムの事実上の標準 |
| 暗号 | `aes-gcm 0.10`, `sha2 0.10` | 低 -- RustCrypto プロジェクト |
| 認証 | `yup-oauth2 12` | 中 -- Google 公式ではないが広く利用 |
| TUI | `ratatui 0.30.0`, `crossterm 0.29.0` | 低 -- CLI モードのみで使用 |

### 10.2 キーリングクレート

**リスクレベル: LOW**

`keyring 3.6.3` が依存に含まれている。CLI モード（ローカル実行）でのクレデンシャル保存に使用されると思われる。Cloud Run 環境では使用されないが、コンパイルされたバイナリに含まれる。

## 発見事項サマリー

### CRITICAL

なし

### HIGH

| # | 発見事項 | 対象ファイル |
|---|---------|-------------|
| H-1 | .dockerignore に .env が未除外 | `.dockerignore` |
| H-2 | リクエストボディサイズ制限の欠如 | `src/mcp_server/http.rs` |
| H-3 | レート制限の欠如 | `src/mcp_server/http.rs` |
| H-4 | 全セッションの単一シークレット保存（大きな爆発半径） | `src/mcp_server/session_store.rs` |

### MEDIUM

| # | 発見事項 | 対象ファイル |
|---|---------|-------------|
| M-1 | コンテナが root ユーザーで実行 | `Dockerfile` |
| M-2 | cargo audit 未実施 | (CI/CD) |
| M-3 | HTTP クライアントのタイムアウト未設定 | `src/client.rs` |
| M-4 | セキュリティヘッダーの欠如 (HSTS, X-Content-Type-Options 等) | `src/mcp_server/http.rs` |
| M-5 | Secret Manager のシークレット自動作成（過剰権限） | `src/mcp_server/session_store.rs` |
| M-6 | 実名・メールアドレスのソースコード内記載 | `config/permissions.yaml` |
| M-7 | Cloud Run Ingress 設定の確認が必要 (検証未実施) | (インフラ) |
| M-8 | サービスアカウントへの Secret Manager Admin ロール | (IAM) |
| M-9 | 認証イベントの監査ログ不足 | `src/mcp_server/http.rs` |
| M-10 | admin ロールの書き込み権限範囲 | `config/permissions.yaml` |

### LOW

| # | 発見事項 | 対象ファイル |
|---|---------|-------------|
| L-1 | ベースイメージのダイジェスト固定なし | `Dockerfile` |
| L-2 | 依存関係の幅広い範囲指定 | `Cargo.toml` |
| L-3 | CORS の Origin ヘッダー不在時の許可 | `src/mcp_server/http.rs` |
| L-4 | .env ファイルの自動読み込み | `src/main.rs` |
| L-5 | Secret Manager レプリケーション設定のリージョン指定なし | `src/mcp_server/session_store.rs` |

### INFO

| # | 発見事項 | 対象ファイル |
|---|---------|-------------|
| I-1 | マルチステージビルドの採用（良好） | `Dockerfile` |
| I-2 | rustls の使用（良好） | `Cargo.toml` |
| I-3 | RustCrypto 系暗号ライブラリの使用（良好） | `Cargo.toml` |
| I-4 | Cloud Logging 対応フォーマッター（良好） | `src/mcp_server.rs` |
| I-5 | ツール呼び出し監査ログの実装（良好） | `src/mcp_server.rs` |
| I-6 | セッション数上限の設定（良好） | `src/mcp_server/oauth.rs` |
| I-7 | 環境変数による機密情報管理の設計 | `.env.example`, `Dockerfile` |
| I-8 | HTTP リトライ制御の実装（良好） | `src/client.rs` |

## 未検証項目（gcloud による実態検証が必要）

gcloud コマンドの実行がサンドボックス環境で許可されなかったため、以下の項目は未検証。本番環境で別途確認すべき。

- [ ] Cloud Run サービスの Ingress 設定 (`internal` / `internal-and-cloud-load-balancing` / `all`)
- [ ] Cloud Run の IAM ポリシー (`allUsers` の有無)
- [ ] サービスアカウントに付与された実際の IAM ロール一覧
- [ ] Secret Manager のシークレットに対する IAM ポリシー
- [ ] Cloud Run の環境変数設定（シークレット参照の確認）
- [ ] VPC Connector / VPC ネットワーク設定
- [ ] Cloud Logging のログルーターシンク設定
- [ ] Cloud Monitoring のアラートポリシー
- [ ] Cloud Armor (WAF) の有無
- [ ] OAuth 同意画面の設定（内部/外部、検証状態）
