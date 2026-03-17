# Remote MCP Gateway - Tasks

## 実装ロードマップ

| Phase | タスク | 依存 | ステータス |
|-------|--------|------|-----------|
| 1 | 既存 stdio MCP を Streamable HTTP 対応に変更 | - | DONE |
| 2 | ユーザーごとの OAuth トークン管理 | Phase 1 | DONE |
| 3 | Cloud Run にデプロイ | Phase 2 | DONE |
| 4 | Claude 管理コンソールで組織コネクタとして登録・動作確認 | Phase 3 | TODO |
| 5 | 権限制御 (YAML ホワイトリスト) | Phase 2 | DONE |
| 6 | tools/list のユーザー別フィルタ | Phase 5 | DONE |
| 7 | 利用統計 (Cloud Logging) | Phase 2 | DONE |
| 8 | ステートレス化 (Firestore 移行 + データモデル変更 + トランザクション + エラーハンドリング + 暗号化) | Phase 2 | DONE |
## Phase 詳細

### Phase 1: Streamable HTTP 対応

- [x] HTTP サーバー追加（既存 `mcp_server.rs` の stdio 実装をベースに）
- [x] MCP Streamable HTTP トランスポート実装
- [x] ローカルで HTTP モードでの動作確認

### Phase 2: OAuth トークン管理

- [x] Google OAuth フロー実装（認可エンドポイント、コールバック）
- [x] ユーザー識別（Google email）
- [x] トークンのインメモリ保存（暗号化永続ストレージは Phase 3 で対応）
- [x] トークンリフレッシュ処理
- [x] OAuth 2.1 PKCE フロー対応
- [x] Dynamic Client Registration (RFC 7591)
- [x] MCP エンドポイントの Bearer トークン認証

### Phase 3: Cloud Run デプロイ

- [x] Dockerfile 作成
- [x] CI/CD パイプライン構築
- [x] Secret Manager 連携

### Phase 4: 組織コネクタ登録

- [ ] Claude 管理コンソールでの登録手順確認
- [ ] エンドツーエンド動作確認

### Phase 5: 権限制御

- [x] YAML パーサー実装
- [x] ワイルドカードマッチング実装
- [x] リクエスト時の権限チェックミドルウェア
- [x] 未登録ユーザーの拒否処理

### Phase 6: tools/list フィルタ

- [x] ユーザー権限に基づく tools/list レスポンスフィルタ
- [x] 未登録ユーザーへの空リスト返却

### Phase 7: 利用統計

- [x] 構造化ログ出力（email, timestamp, method ID, result）
- [x] Cloud Logging への連携確認

### Phase 8: ステートレス化 (セキュリティ診断 H-1 〜 H-8 対応)

**H-1: 全状態を Firestore に移行 (ステートレス化)**
- [x] `StateStore` trait 定義 (`state_store.rs`)
- [x] `InMemoryStateStore` 実装 (dev/test 用、現行 HashMap ロジックを移行)
- [x] `FirestoreStateStore` 実装 (Firestore REST API 直接呼び出し)
- [x] `http.rs` を `Mutex<TokenStore>` → `Arc<dyn StateStore>` に移行
- [x] `mcp_server.rs` CLI 引数更新 (`--token-store-backend firestore`)
- [x] `session_store.rs` 削除 (`state_store.rs` に統合)
- [ ] Firestore TTL ポリシー設定手順をドキュメント化

**H-2: データモデル変更 (`user_sessions` 分離)**
- [x] `user_sessions` コレクション追加 (doc ID = email, Google tokens を格納)
- [x] `bearer_sessions` を変更: `UserSession` → `BearerSession {email, bearer_expires_at}` に簡素化
- [x] `refresh_tokens` を変更: `bearer_token` → `email` で参照先を `user_sessions` に変更
- [x] `pending_codes` を変更: `UserSession` → `{email, google_tokens, code_challenge, ...}` に変更
- [x] `StateStore` trait に `user_sessions` 用メソッド追加 (`get_user_session`, `set_user_session`, `delete_user_session`)
- [x] `InMemoryStateStore` に `user_sessions` HashMap 追加 (容量上限 10,000、TTL なし)
- [x] `user_sessions` は Firestore TTL なし (明示的削除のみ)

**H-3: Refresh Token に独立 TTL を付与**
- [x] `RefreshTokenEntry` struct 追加 (`email`, `refresh_expires_at`)
- [x] `BEARER_TOKEN_LIFETIME_SECS` を 86400 → 3600 (1h) に変更
- [x] `REFRESH_TOKEN_LIFETIME_SECS = 604800` (7d) 定数追加
- [x] `handle_token_refresh` で `refresh_expires_at` を検証
- [x] Firestore `refresh_tokens` コレクションに独立 TTL で保存

**H-4: `is_refresh_tokens_full()` 容量チェック漏れ修正**
- [x] `InMemoryStateStore.set_refresh_entry()` で容量チェック実装
- [x] `handle_token_authorization_code` と `handle_token_refresh` でエラー処理

**H-5: Google `invalid_grant` 時のセッション無効化**
- [x] `handle_token_refresh` で Google token refresh 失敗時に `user_session` + `bearer_session` を削除
- [x] `get_valid_google_token` (MCP リクエスト中) で `invalid_grant` 時に `user_session` + `bearer_session` を削除
- [x] 関連する `refresh_token` は次回使用時に `user_session` 不在で `invalid_grant` を返却 (明示的削除不要)
- [x] エラーレスポンスを 400 → 401 Unauthorized に修正

**H-6: Firestore トランザクション (アトミック操作)**
- [x] Token Exchange (authorization_code): PendingCode 削除 + user_session/bearer_session/refresh_token 書き込みをトランザクション化
- [x] Token Refresh: 旧 bearer/refresh 削除 + 新 bearer/refresh 書き込み + user_session 更新をトランザクション化
- [x] `FirestoreStateStore` にトランザクション実行メソッド追加
- [x] `InMemoryStateStore` では Mutex ロック内で同等のアトミック性を確保

**H-7: 認証フローのエラーハンドリング**
- [x] Google 同意拒否 (`error=access_denied`): callback で PendingAuth から `client_redirect_uri` を取得し `?error=access_denied&state=client_state` でリダイレクト
- [x] Google code 交換失敗: `?error=server_error&state=client_state` でリダイレクト
- [x] Google UserInfo API 失敗: `?error=server_error&state=client_state` でリダイレクト
- [x] Firestore 障害時: 503 Service Unavailable を返却

**H-8: Firestore データのアプリケーション層暗号化**
- [x] AES-256-GCM 暗号化・復号ユーティリティ実装 (`encrypt_data()`, `decrypt_data()`)
- [x] Secret Manager から暗号化鍵をロードする処理実装
- [x] `FirestoreStateStore` の読み書きに暗号化・復号を組み込み
- [x] 専用 Firestore データベース作成 (デフォルト DB とは分離)
- [ ] Data Access 監査ログの有効化手順をドキュメント化
- [ ] Cloud Run サービスアカウントに最小権限 IAM 設定
- [x] 構造化ログにトークン値を含めない (プレフィックス/ハッシュのみ記録)
