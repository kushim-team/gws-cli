# Remote MCP Gateway - Tasks

## 実装ロードマップ

| Phase | タスク | 依存 | ステータス |
|-------|--------|------|-----------|
| 1 | 既存 stdio MCP を Streamable HTTP 対応に変更 | - | DONE |
| 2 | ユーザーごとの OAuth トークン管理 | Phase 1 | DONE |
| 3 | Cloud Run にデプロイ | Phase 2 | TODO |
| 4 | Claude 管理コンソールで組織コネクタとして登録・動作確認 | Phase 3 | TODO |
| 5 | 権限制御 (YAML ホワイトリスト) | Phase 2 | DONE |
| 6 | tools/list のユーザー別フィルタ | Phase 5 | DONE |
| 7 | 利用統計 (Cloud Logging) | Phase 2 | TODO |
| 8 | ステートレス化 (Firestore 移行 + 独立 TTL + 容量チェック修正) | Phase 2 | TODO |

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

- [ ] Dockerfile 作成
- [ ] CI/CD パイプライン構築
- [ ] Secret Manager 連携

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
- [ ] Cloud Logging への連携確認

### Phase 8: ステートレス化 (セキュリティ診断 H-1, H-2, H-3 対応)

**H-1: 全状態を Firestore に移行 (ステートレス化)**
- [ ] `StateStore` trait 定義 (`state_store.rs`)
- [ ] `InMemoryStateStore` 実装 (dev/test 用、現行 HashMap ロジックを移行)
- [ ] `FirestoreStateStore` 実装 (Firestore REST API 直接呼び出し)
- [ ] `http.rs` を `Mutex<TokenStore>` → `Arc<dyn StateStore>` に移行
- [ ] `mcp_server.rs` CLI 引数更新 (`--token-store-backend firestore`)
- [ ] `session_store.rs` 削除 (`state_store.rs` に統合)
- [ ] Firestore TTL ポリシー設定手順をドキュメント化

**H-2: Refresh Token に独立 TTL を付与**
- [ ] `RefreshTokenEntry` struct 追加 (`bearer_token`, `refresh_expires_at`)
- [ ] `BEARER_TOKEN_LIFETIME_SECS` を 86400 → 3600 (1h) に変更
- [ ] `REFRESH_TOKEN_LIFETIME_SECS = 604800` (7d) 定数追加
- [ ] `handle_token_refresh` で `refresh_expires_at` を検証
- [ ] Firestore `refresh_tokens` コレクションに独立 TTL で保存

**H-3: `is_refresh_tokens_full()` 容量チェック漏れ修正**
- [ ] `InMemoryStateStore.set_refresh_entry()` で容量チェック実装
- [ ] `handle_token_authorization_code` と `handle_token_refresh` でエラー処理

**H-4: Firestore データのアプリケーション層暗号化**
- [ ] AES-256-GCM 暗号化・復号ユーティリティ実装 (`encrypt_data()`, `decrypt_data()`)
- [ ] Secret Manager から暗号化鍵をロードする処理実装
- [ ] `FirestoreStateStore` の読み書きに暗号化・復号を組み込み
- [ ] 専用 Firestore データベース作成 (デフォルト DB とは分離)
- [ ] Data Access 監査ログの有効化手順をドキュメント化
- [ ] Cloud Run サービスアカウントに最小権限 IAM 設定
