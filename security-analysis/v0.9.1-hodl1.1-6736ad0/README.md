# セキュリティ分析: v0.9.1-hodl1.1 (6736ad0)

## 分析概要

| 項目 | 内容 |
|------|------|
| 対象 | gws-cli (HODL1 Fork, `custom` ブランチ) |
| バージョン | `0.9.1-hodl1.1` |
| 対象コミット | [`6736ad0`](https://github.com/kushim-team/gws-cli/commit/6736ad0c1451585b1d5a4e1b5b3af1d9e79bb0f4) (custom ブランチ HEAD) |
| 分析日 | 2026-03-11 |
| 分析範囲 | ソースコード静的分析、アーキテクチャレビュー、設定・依存関係レビュー |

## 分析対象システムの概要

gws-cli は Google Workspace API を操作する Rust 製 CLI ツールであり、HODL1 Fork では MCP (Model Context Protocol) Gateway として HTTP サーバーモードで動作し、Claude Desktop / Claude Code から組織コネクタとして利用される。約20名規模の社内利用を想定している。

### アーキテクチャ構成

```
Claude Desktop / Code  ──(MCP over HTTPS)──▶  MCP Gateway (Cloud Run)
                                                  │
                                          ┌───────┼───────┐
                                          │       │       │
                                       認証層  権限制御層 ログ層
                                       (OAuth)  (YAML)  (Cloud Logging)
                                          │       │       │
                                          └───────┼───────┘
                                                  │
                                          Google Workspace API
```

## 分析ドキュメント一覧

| # | ドキュメント | 内容 | ステータス |
|---|-------------|------|-----------|
| 1 | [01-methodology.md](01-methodology.md) | 分析方法論・フレームワーク・プランニング | 完了 |
| 2 | [02-threat-model.md](02-threat-model.md) | 脅威モデリング (STRIDE) | 完了 |
| 3 | [03-authentication-authorization.md](03-authentication-authorization.md) | 認証・認可分析 | 完了 |
| 4 | [04-data-protection.md](04-data-protection.md) | データ保護分析 (保存時・転送時) | 完了 |
| 5 | [05-input-validation.md](05-input-validation.md) | 入力検証・インジェクション対策分析 | 完了 |
| 6 | [06-infrastructure.md](06-infrastructure.md) | インフラ・デプロイメント分析 | 完了 |
| 7 | [07-findings-summary.md](07-findings-summary.md) | 発見事項サマリー・推奨事項 | 完了 |

## 発見事項サマリー

| 深刻度 | 件数 |
|--------|------|
| **CRITICAL** | 3 |
| **HIGH** | 10 |
| **MEDIUM** | 20 |
| **LOW** | 12 |
| **INFO** | 22 |
| **合計** | **67** |

詳細は [07-findings-summary.md](07-findings-summary.md) を参照。

## エージェント割り当て計画

各分析ドキュメントは独立したエージェントに並列実行させた。

| エージェント | 担当ドキュメント | 読んだソースファイル |
|-------------|-----------------|---------------------|
| Agent A | 02-threat-model.md | 全体構成の理解: `specs/remote-mcp-gateway/design.md`, `requirements.md`, `README.custom.md`, `AGENTS.md` |
| Agent B | 03-authentication-authorization.md | `src/auth.rs`, `src/oauth_config.rs`, `src/mcp_server/oauth.rs`, `src/mcp_server/http.rs`, `src/mcp_server/permissions.rs`, `src/mcp_server/session_store.rs` |
| Agent C | 04-data-protection.md | `src/credential_store.rs`, `src/token_storage.rs`, `src/mcp_server/session_store.rs`, `src/oauth_config.rs`, `.env`, `.env.example` |
| Agent D | 05-input-validation.md | `src/validate.rs`, `src/executor.rs`, `src/helpers/mod.rs`, `src/mcp_server/http.rs`, `src/mcp_server/jsonrpc.rs` |
| Agent E | 06-infrastructure.md | `Cargo.toml`, `src/client.rs`, `src/main.rs`, `.dockerignore`, `config/permissions.yaml` |
| Agent F | 07-findings-summary.md | 02〜06 の全分析結果を統合 |
