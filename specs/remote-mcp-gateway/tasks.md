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

- [ ] 構造化ログ出力（email, timestamp, method ID, result）
- [ ] Cloud Logging への連携確認
