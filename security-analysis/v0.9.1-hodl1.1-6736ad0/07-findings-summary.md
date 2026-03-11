# セキュリティ分析 統合サマリー

| 項目 | 内容 |
|------|------|
| 分析対象 | gws-cli (HODL1 Fork, `custom` ブランチ) |
| 対象コミット | `6736ad0` |
| 分析日 | 2026-03-11 |
| 担当 | Agent F (統合) — Agent A〜E の分析結果を統合 |

---

## 0. MCP 仕様準拠に関する注記

本分析の一部の指摘事項は、[MCP Authorization Specification (2025-03-26)](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization) に準拠した意図的な設計に起因する。MCP クライアント（Claude Code / Claude Desktop）との互換性を維持するために必要な仕様であり、アプリケーション層での変更は推奨しない。対策はインフラ層（Cloud Run ingress, Cloud Armor 等）で実施すべきである。

| 指摘 ID | 概要 | MCP 仕様根拠 |
|---------|------|-------------|
| F-01 | `/register` エンドポイントが無認証 | Dynamic Client Registration ([RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591)) を **SHOULD** で推奨。RFC 7591 では認証なしが標準 |
| F-08 | `redirect_uri` が任意の HTTPS URL を受容 | 「Redirect URIs **MUST** be either localhost URLs or HTTPS URLs」と規定。Claude Code は `http://localhost:PORT/callback` を使用 |

Third-Party Authorization Flow（MCP サーバーが Google OAuth をバックエンドとして使用し、MCP クライアントに独自の Bearer トークンを発行するパターン）も MCP 仕様で **MAY** として定義されたアーキテクチャであり、本 Gateway はこのパターンに準拠している。

---

## 1. エグゼクティブサマリー

gws-cli MCP Gateway は、全体として堅牢なセキュリティ設計を備えている。OAuth 2.0 + PKCE の実装は RFC 準拠であり、Bearer トークンの暗号学的安全性（256-bit エントロピー）、セッションとトークンのバインディング、トークンローテーション、deny-by-default の RBAC 権限制御など、多くのセキュリティベストプラクティスが適切に実装されている。入力検証においても、`validate.rs` に集約されたヘルパー関数群が AI エージェントからの敵対的入力を想定した多層防御を実現しており、URL エンコードバイパスの防止やパストラバーサル対策が包括的にテストされている。

一方で、最も重大なリスクは**全ユーザーのセッション情報（Google OAuth refresh_token 含む）が単一の Secret Manager シークレットに平文 JSON で一括保存されている点**にある。この設計は「爆発半径（blast radius）」が最大であり、1 件の漏洩で全ユーザー（約 20 名）の Google Workspace データが危険にさらされる。また、`.env` ファイルへのクライアントシークレットのハードコード、レート制限の欠如、権限設定ファイル未指定時のフェイルオープン動作など、運用面での改善が必要な項目が複数確認された。Google Workspace API の仕様上トークンレベルの downscoping が不可能であるという技術的制約も、トークン保管セキュリティの重要性をさらに高めている。

---

## 2. 発見事項の統計

### 2.1 深刻度別集計（全ドキュメント統合・重複排除後）

| 深刻度 | 件数 | 対応期限目安 |
|--------|------|-------------|
| **CRITICAL** | 3 | 即時対応 |
| **HIGH** | 10 | 1週間以内 |
| **MEDIUM** | 20 | 1ヶ月以内 |
| **LOW** | 12 | 次回リリース |
| **INFO** | 22 | 任意 |
| **合計** | **67** | — |

### 2.2 カテゴリ別集計

| 分析カテゴリ | CRITICAL | HIGH | MEDIUM | LOW | INFO | 合計 |
|-------------|----------|------|--------|-----|------|------|
| 脅威モデリング (02) | 2 | 4 | 8 | 5 | 0 | 19 |
| 認証・認可 (03) | 0 | 2 | 5 | 5 | 12 | 24 |
| データ保護 (04) | 1 | 3 | 2 | 1 | 3 | 10 |
| 入力検証 (05) | 0 | 1 | 4 | 4 | 4 | 13 |
| インフラ (06) | 0 | 4 | 10 | 5 | 8 | 27 |

> 注: 複数ドキュメントで重複して報告された項目（Secret Manager 一括保存、レート制限欠如、Origin 検証等）が存在するため、カテゴリ別合計は重複排除後の合計と一致しない。

---

## 3. 重大な発見事項一覧（CRITICAL / HIGH）

### 3.1 CRITICAL

| ID | カテゴリ | 概要 | 参照 |
|----|----------|------|------|
| S-04 / I-01 | 脅威モデリング | 全ユーザーの Google OAuth トークン（refresh_token 含む）が単一の Secret Manager シークレットに保存。漏洩時の爆発半径が最大 | 02-threat-model.md |
| DP-01 | データ保護 | `.env` ファイルに OAuth クライアントシークレットがハードコード | 04-data-protection.md |

### 3.2 HIGH

| ID | カテゴリ | 概要 | 参照 |
|----|----------|------|------|
| I-05 / E-04 | 脅威モデリング | OAuth スコープが全ロールの和集合となり、トークン漏洩時に Gateway 権限制御が無力化（技術的制約として受容済み） | 02-threat-model.md |
| E-01 | 脅威モデリング | メソッドパラメータレベルの権限制御がなく、許可されたメソッド内で悪意ある操作が可能 | 02-threat-model.md |
| E-03 / F-17 | 脅威モデリング / 認証・認可 | `--permissions-file` 未指定時にデフォルト全許可（フェイルオープン） | 02-threat-model.md, 03-authentication-authorization.md |
| F-07 / DP-02 | 認証・認可 / データ保護 | Secret Manager の単一シークレットに全セッション集約（爆発半径・競合状態・バージョン膨張） | 03-authentication-authorization.md, 04-data-protection.md |
| DP-03 | データ保護 | `GoogleTokens` / `UserSession` の `#[derive(Debug)]` がトークンを平文出力する可能性 | 04-data-protection.md |
| DP-04 | データ保護 | Secret Manager の古いバージョンが破棄されず無期限に蓄積 | 04-data-protection.md |
| IV-10 | 入力検証 | API ベース URL の検証不足による SSRF リスク（Discovery Document キャッシュ汚染時） | 05-input-validation.md |
| INF-H1 | インフラ | `.dockerignore` に `.env` が未除外（ビルドコンテキストへの機密情報混入） | 06-infrastructure.md |
| INF-H2 / F-25 | インフラ / 認証・認可 | MCP Gateway 全エンドポイントにレート制限が未実装 | 06-infrastructure.md, 03-authentication-authorization.md |
| INF-H3 | インフラ | リクエストボディサイズ制限が明示的に未設定 | 06-infrastructure.md |

---

## 4. カテゴリ別サマリー

### 4.1 脅威モデリング（02-threat-model.md — Agent A）

STRIDE フレームワークに基づく包括的な脅威分析を実施。全 22 件の脅威を特定。

**最重要リスク:**
- **単一 Secret Manager シークレットへの全セッション集約** (CRITICAL): 1 件の漏洩で約 20 名全員の Google Workspace データが露出
- **パラメータレベル権限制御の欠如** (HIGH): メソッド ID は制御されるが、`userId` パラメータ等の操作は防止できない
- **フェイルオープン** (HIGH): 権限設定ファイル未指定時に全アクセスを許可

**適切に対策されている項目:** OAuth CSRF 防止（state パラメータ + TTL）、PKCE S256 強制、Bearer トークンの十分なエントロピー

### 4.2 認証・認可（03-authentication-authorization.md — Agent B）

全 26 件の発見事項を報告（うち INFO 12 件は肯定的評価）。

**主要なリスク:**
- 権限設定なしでの全メソッド許可（F-17, HIGH）
- Secret Manager 集約保存（F-07, HIGH）
- 無認証の `/register` エンドポイント（F-01, MEDIUM — MCP 仕様準拠、RFC 7591 の標準動作）
- デフォルト OAuth スコープの過剰な範囲（F-02, MEDIUM）
- レート制限の欠如（F-25, MEDIUM）

**堅牢な実装:** PKCE S256 強制、セッション-Bearer バインディング、トークンローテーション、auth code の単回使用保証、deny-by-default RBAC

### 4.3 データ保護（04-data-protection.md — Agent C）

全 10 件の発見事項を報告。保存時・転送時の暗号化設計を分析。

**主要なリスク:**
- `.env` ファイルへのシークレットハードコード（DP-01, CRITICAL）
- Secret Manager の平文 JSON 一括保存（DP-02, HIGH）
- Debug 実装によるトークン平文出力の可能性（DP-03, HIGH）
- Secret Manager バージョンの無期限蓄積（DP-04, HIGH）

**良好な実装:** AES-256-GCM 暗号化の正当な実装、転送時暗号化（rustls + HTTPS 強制）、Cache-Control ヘッダー設定、ファイルパーミッション管理

### 4.4 入力検証（05-input-validation.md — Agent D）

全 13 件の発見事項を報告。入力検証は全体として良好と評価。

**主要なリスク:**
- API ベース URL の検証不足による SSRF リスク（#10, HIGH）
- リクエストボディサイズ制限の未設定（#1, MEDIUM）
- バッチリクエストサイズ上限なし（#2, MEDIUM）
- MCP upload パス検証の不一致（#6, MEDIUM）

**優秀な実装:** `validate.rs` のヘルパー関数群（パストラバーサル防止、URL エンコードバイパス防止、制御文字拒否）、Discovery Schema ベースの JSON バリデーション、包括的なテストカバレッジ

### 4.5 インフラ・デプロイメント（06-infrastructure.md — Agent E）

全 27 件の発見事項を報告。gcloud による実態検証は未実施（サンドボックス制約）。

**主要なリスク:**
- `.dockerignore` に `.env` が未除外（H-1, HIGH）
- リクエストボディサイズ制限の欠如（H-2, HIGH）
- レート制限の欠如（H-3, HIGH）
- Secret Manager 単一シークレット保存（H-4, HIGH）
- コンテナが root ユーザーで実行（M-1, MEDIUM）
- HTTP クライアントのタイムアウト未設定（M-3, MEDIUM）
- サービスアカウントへの過剰な IAM ロール（M-8, MEDIUM）
- 認証イベントの監査ログ不足（M-9, MEDIUM）

**良好な実装:** マルチステージビルド、rustls 採用（メモリ安全な TLS）、Cloud Logging 対応フォーマッター、HTTP リトライ制御

**未検証項目（gcloud 実態検証が必要）:**
- Cloud Run の Ingress 設定・IAM ポリシー
- サービスアカウントの実際の IAM ロール
- Secret Manager の IAM ポリシー
- VPC / Cloud Armor / Cloud Monitoring 設定

---

## 5. 推奨対応ロードマップ

### 5.1 即時対応（CRITICAL — 今すぐ）

| # | 対応項目 | 対象脅威 | 工数目安 |
|---|---------|----------|---------|
| 1 | `.env` ファイルからクライアントシークレットを削除 | DP-01 | 数分 |
| 2 | `.dockerignore` に `.env` / `.env.*` を追加 | INF-H1 | 数分 |
| 3 | Secret Manager の IAM ポリシーを最小権限に変更（`Secret Manager Admin` → `Secret Manager Secret Version Manager`） | S-04, I-01 | 数時間 |

### 5.2 1 週間以内（HIGH）

| # | 対応項目 | 対象脅威 | 工数目安 |
|---|---------|----------|---------|
| 4 | `GoogleTokens` / `UserSession` に手動 `Debug` 実装を追加し、トークンを `[REDACTED]` に置換 | DP-03 | 1時間 |
| 5 | Secret Manager の古いバージョンの自動破棄処理を実装 | DP-04 | 数時間 |
| 6 | MCP Gateway モードで `--permissions-file` を必須化、または未指定時に deny-all | E-03, F-17 | 数時間 |
| 7 | axum Router に `DefaultBodyLimit::max(1MB)` を明示設定 | INF-H3 | 数分 |
| 8 | `/register`, `/authorize`, `/token` エンドポイントにレート制限を導入 | INF-H2, F-25 | 1日 |
| 9 | `build_url` で構築された URL のホスト部分を `*.googleapis.com` の許可リストで検証 | IV-10 | 数時間 |

### 5.3 1 ヶ月以内（MEDIUM）

| # | 対応項目 | 対象脅威 | 工数目安 |
|---|---------|----------|---------|
| 10 | Secret Manager 保存前にアプリケーション層暗号化（AES-256-GCM）を追加 | DP-02 | 1-2日 |
| 11 | 高リスクメソッドのパラメータ検証（`userId` を `"me"` に強制等） | E-01 | 1-2日 |
| 12 | Dockerfile に非 root ユーザー（`USER appuser`）を追加 | INF-M1 | 数時間 |
| 13 | HTTP クライアントにタイムアウト設定を追加（30秒 / connect 10秒） | INF-M3 | 数分 |
| 14 | セキュリティレスポンスヘッダーの追加（HSTS, X-Content-Type-Options 等） | INF-M4 | 数時間 |
| 15 | 認証イベント（成功/失敗/リフレッシュ）の監査ログ出力追加 | INF-M9 | 数時間 |
| 16 | `DEFAULT_OAUTH_SCOPES` を permissions.yaml の `all_scopes_union()` に動的制限 | F-02 | 数時間 |
| 17 | CI に `cargo audit` / `cargo deny` を追加 | INF-M2 | 数時間 |
| 18 | Origin 検証を URL パース後のホスト名厳密比較に改善 | F-21, IV-11 | 数時間 |
| 19 | MCP upload パス検証を `validate.rs` のヘルパーに統一 | IV-6 | 数時間 |
| 20 | JSON-RPC バッチリクエストに要素数上限（例: 50）を追加 | IV-2 | 数分 |
| 21 | `permissions.yaml` から実名コメントを削除 | F-16, INF-M6 | 数分 |
| 22 | gcloud による本番環境の実態検証を実施 | INF-M7, INF-M8 | 数時間 |

### 5.4 次回リリース（LOW）

| # | 対応項目 | 対象脅威 | 工数目安 |
|---|---------|----------|---------|
| 23 | ユーザーごとの Secret Manager シークレット分離を設計・実装 | I-01, DP-02 | 数日 |
| 24 | `zeroize` クレート導入によるメモリ上の機密データゼロクリア | DP-05, I-03 | 1日 |
| 25 | ベースイメージのダイジェスト固定 | INF-L1 | 数時間 |
| 26 | `initialize` を含むバッチリクエストの制御強化 | F-11 | 数時間 |
| 27 | `expires_at` が `None` の場合に安全側に倒す（期限切れ扱い） | F-26 | 数分 |
| 28 | MCP Gateway モードで `GOOGLE_WORKSPACE_CLI_TOKEN` 環境変数を無視するガード追加 | F-03 | 数分 |

---

## 6. 肯定的評価（セキュリティ上の良い実装・設計判断）

### 6.1 認証・認可

- **PKCE S256 の強制**: `plain` を明示的に拒否し、Authorization Code Interception Attack を防止
- **Bearer トークンの暗号学的安全性**: `OsRng` + 32 バイト（256-bit エントロピー）で生成、ブルートフォース攻撃に対して安全
- **セッション-Bearer バインディング**: セッション ID を知っていても異なる Bearer トークンではアクセス不可
- **トークンローテーション**: Bearer トークンのリフレッシュ時に旧トークンを削除し、再利用を防止
- **Auth Code の単回使用保証**: `remove()` で取り出すことで同一コードの再利用を不可能に
- **Google トークンのクライアント非露出**: Google OAuth トークンはサーバーサイドのみで保持、クライアントには Gateway 独自の Bearer トークンのみ返却
- **TTL 管理と lazy cleanup**: 各一時データに適切な有効期限を設定し、期限切れデータの自動クリーンアップを実施
- **Deny-by-default RBAC**: スコープ + メソッドパターンの二層チェック、未登録ユーザーは全拒否

### 6.2 データ保護

- **AES-256-GCM 実装**: NIST 推奨アルゴリズムの正当な実装、毎回異なる nonce、改ざん検知、アトミック書き込み
- **転送時暗号化**: rustls（メモリ安全な TLS）の採用、HTTPS 強制（localhost 除く）、全 Google API 通信で HTTPS 使用
- **Cache-Control: no-store**: トークンエンドポイントのレスポンスに設定、RFC 6749 Section 5.1 準拠
- **client_secret の Debug リダクション**: `OAuthConfig` の Debug 実装で `client_secret` を `[REDACTED]` に置換
- **ファイルパーミッション管理**: `client_secret.json` に 0o600、暗号化ファイルに 0o600 を設定

### 6.3 入力検証

- **`validate.rs` の包括的なヘルパー関数群**: パストラバーサル防止、URL エンコードバイパス防止（`%` 拒否）、制御文字拒否、シンボリックリンク対策
- **Discovery Schema ベースの JSON バリデーション**: 型チェック、必須フィールド検証、enum 値検証、再帰的スキーマ参照解決
- **URL パスセグメントの厳密なエンコーディング**: `NON_ALPHANUMERIC` セットによるパーセントエンコード
- **クエリパラメータの reqwest 委任**: 手動文字列結合を避け、ライブラリの安全なエンコーディングを使用
- **AGENTS.md における明確なガイドライン**: 開発者が正しいパターンを適用しやすい環境

### 6.4 インフラ

- **マルチステージビルド**: ビルドツール・ソースコードがランタイムイメージに含まれない
- **rustls の採用**: OpenSSL 依存を排除し、メモリ安全な TLS 実装を使用
- **Cloud Logging 対応フォーマッター**: 構造化ログにより Cloud Logging との統合が容易
- **ツール呼び出し監査ログ**: ユーザー email、メソッド ID、結果がログに記録
- **セッション数上限の設定**: HashMap ごとの上限によるメモリ枯渇攻撃への基本的防御
- **HTTP リトライ制御**: 429 対応、`Retry-After` ヘッダー尊重、指数バックオフ

---

## 7. 未検証項目

gcloud コマンドによる本番環境の実態検証が未実施（Agent E のサンドボックス制約）のため、以下の項目は別途確認が必要。

- Cloud Run サービスの Ingress 設定
- Cloud Run の IAM ポリシー（`allUsers` の有無）
- サービスアカウントの実際の IAM ロール一覧
- Secret Manager シークレットの IAM ポリシー
- Cloud Run の環境変数設定（Secret Manager 参照の有無）
- VPC Connector / VPC ネットワーク設定
- Cloud Logging のログルーターシンク設定
- Cloud Monitoring のアラートポリシー
- Cloud Armor (WAF) の有無
- OAuth 同意画面の設定（内部/外部、検証状態）
