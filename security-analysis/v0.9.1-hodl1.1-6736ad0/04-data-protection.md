# データ保護分析 (保存時・転送時)

## 分析概要

| 項目 | 内容 |
|------|------|
| 担当 | Agent C |
| 分析日 | 2026-03-11 |
| 対象コミット | `6736ad0` (custom ブランチ HEAD) |
| 分析対象ファイル | `src/credential_store.rs`, `src/token_storage.rs`, `src/mcp_server/session_store.rs`, `src/mcp_server/oauth.rs`, `src/oauth_config.rs`, `.env`, `.env.example`, `Cargo.toml` |

## 発見事項サマリー

| # | 深刻度 | 概要 |
|---|--------|------|
| DP-01 | **CRITICAL** | `.env` ファイルに OAuth クライアントシークレットがハードコードされている |
| DP-02 | **HIGH** | Secret Manager に全ユーザーのセッション情報が平文 JSON で一括保存（爆発半径大） |
| DP-03 | **HIGH** | `GoogleTokens` / `UserSession` の Debug 実装がトークンを平文出力 |
| DP-04 | **HIGH** | Secret Manager の古いバージョンが破棄されず蓄積 |
| DP-05 | **MEDIUM** | 機密データのメモリ上 zeroize 処理が欠如 |
| DP-06 | **MEDIUM** | OAuth クライアント設定 (`client_secret.json`) が暗号化なしで保存 |
| DP-07 | **LOW** | 暗号鍵ローテーション機構の欠如 |
| DP-08 | **INFO** | AES-256-GCM 実装は概ね正当 |
| DP-09 | **INFO** | 転送時暗号化は適切に設計されている |
| DP-10 | **INFO** | トークンレスポンスの `Cache-Control: no-store` ヘッダーは適切 |

---

## 1. 保存時暗号化 (AES-256-GCM)

### DP-08: AES-256-GCM 実装の正当性評価 [INFO]

**ファイル:** `src/credential_store.rs`

**分析結果:** 実装は暗号学的に正当であり、主要なベストプラクティスに準拠している。

**良い点:**
- **アルゴリズム選択:** AES-256-GCM は NIST 推奨の認証付き暗号化アルゴリズムであり、適切な選択
- **Nonce 生成:** `Aes256Gcm::generate_nonce(&mut OsRng)` により OS のCSPRNG から12バイトのランダム nonce を生成。毎回異なる nonce が使用されることをテストで検証済み（`each_encryption_produces_different_output`）
- **Nonce 管理:** `nonce || ciphertext` の形式で保存し、復号時に先頭12バイトを nonce として分離。標準的なアプローチ
- **改ざん検知:** GCM の認証タグにより改ざんを検出（`decrypt_rejects_tampered_ciphertext` テストで検証済み）
- **短すぎるデータの拒否:** `data.len() < 12` チェックで不正な入力を早期拒否
- **アトミック書き込み:** `atomic_write` / `atomic_write_async` により、書き込み途中でのクラッシュによるファイル破損を防止
- **ファイルパーミッション:** Unix 環境で暗号化ファイルに 0o600、ディレクトリに 0o700 を設定

**ライブラリバージョン (`Cargo.toml`):**
- `aes-gcm = "0.10"` — 現時点の最新安定版。既知の脆弱性なし
- `rand = "0.8"` — 安定版。CSPRNG (`OsRng`) を使用
- `keyring = "3.6.3"` — OS キーリング連携

**懸念事項:**
- 非 Unix 環境（Windows）ではファイルパーミッション設定がスキップされる（`#[cfg(not(unix))]` ブロックでは `std::fs::write` のみ）。Cloud Run は Linux なので本番環境での影響はないが、開発環境での Windows 利用時にはリスクとなる

---

### DP-07: 暗号鍵ローテーション機構の欠如 [LOW]

**ファイル:** `src/credential_store.rs`

**問題:** `get_or_create_key()` は鍵を一度生成すると永続的に使用し続ける。鍵ローテーション機構が存在しない。

**詳細:**
- 鍵は OS キーリングまたはファイル (`~/.config/gws/.encryption_key`) に保存
- `OnceLock<[u8; 32]>` でプロセス寿命中キャッシュされる
- キーリングからファイルへのマイグレーションロジックは存在するが、鍵自体の更新（ローテーション）は不可能
- CLI ツールのローカル認証情報保護が主目的であり、MCP Gateway サーバーモードでは `credential_store` は使用されないため、影響は限定的

**リスク:** 鍵が漏洩した場合、過去に暗号化された全データが復号可能。ただし、これは CLI ローカル利用時の話であり、サーバーモードの Secret Manager とは独立。

**推奨事項:**
- 現時点では Low リスク。将来的に鍵ローテーション + 再暗号化コマンドの追加を検討

---

## 2. 鍵管理

### 鍵生成の評価

**ファイル:** `src/credential_store.rs` (行122-124)

```rust
let mut key = [0u8; 32];
rand::thread_rng().fill_bytes(&mut key);
```

- `rand::thread_rng()` は内部的に OS の CSPRNG をシードに使用するため、暗号学的に安全
- 256ビット（32バイト）の鍵長は AES-256 に適切
- Bearer トークン生成 (`oauth.rs` 行190-194) では `rand::rngs::OsRng` を直接使用しており、こちらも適切

### 鍵保存の評価

**優先順位:** OS キーリング > ローカルファイル（フォールバック）

- **OS キーリング:** `keyring` クレートを使用。OS の安全な認証情報ストア（macOS Keychain, Linux Secret Service, Windows Credential Manager）に保存
- **フォールバック:** `~/.config/gws/.encryption_key` に Base64 エンコードで保存。Unix では 0o600 パーミッション
- **マイグレーション:** ファイルからキーリングへの自動マイグレーション、成功時にファイル削除

---

## 3. Secret Manager によるセッション永続化

### DP-02: 全ユーザーセッション情報の単一シークレット一括保存 [HIGH]

**ファイル:** `src/mcp_server/session_store.rs`

**問題:** 約20名のユーザーの全セッション情報（Google OAuth access_token, refresh_token, email, bearer_token）が単一の Secret Manager シークレットに JSON blob として保存されている。

**詳細:**

保存されるデータ構造:
```json
{
  "bearer-token-A": {
    "email": "user-a@company.com",
    "google_tokens": {
      "access_token": "ya29.xxx",
      "refresh_token": "1//xxx",
      "expires_at": 1741700000
    },
    "bearer_expires_at": 1741700000
  },
  "bearer-token-B": { "...": "..." }
}
```

**リスクの要因:**
1. **爆発半径（Blast Radius）:** シークレットが漏洩した場合、全ユーザーの Google OAuth トークン（refresh_token 含む）が一度に漏洩する。refresh_token は長期間有効であり、Google Workspace のメール、ドライブ、カレンダー等への全アクセスを可能にする
2. **アプリケーション層での暗号化なし:** Secret Manager の保存データは平文 JSON。Secret Manager 自体の暗号化（Google 管理の暗号鍵による保存時暗号化）に完全依存している
3. **アクセス制御の粒度:** Secret Manager の IAM は「シークレット単位」であり、「特定ユーザーのセッションだけ読む」という細粒度のアクセス制御は不可能
4. **HashMap キーとして bearer トークン自体が使われている:** シークレットの内容を読めれば、bearer トークンもすべて取得できる

**推奨事項:**
- **短期:** アプリケーション層での暗号化を追加（Secret Manager 保存前に AES-256-GCM で暗号化）。暗号鍵は別の Secret Manager シークレットに保存
- **中期:** ユーザーごとにシークレットを分離（`sessions-{user-hash}` 形式）して爆発半径を縮小
- **長期:** 専用のセッションストア（Cloud Firestore + Field Level Encryption 等）への移行を検討

---

### DP-04: Secret Manager の古いバージョンが破棄されずに蓄積 [HIGH]

**ファイル:** `src/mcp_server/session_store.rs`

**問題:** `save()` メソッドは `addVersion` API を呼び出して新しいバージョンを作成するが、古いバージョンの破棄（`destroyVersion`）を行わない。

**影響:**
1. **過去のトークンが残存:** セッションが期限切れや更新で Bearer マップから削除されても、古い Secret Manager バージョンには以前の refresh_token が残り続ける
2. **コスト:** バージョンが無制限に増加し、ストレージコストが発生（セッション更新のたびに新バージョンが作成される）
3. **攻撃面の拡大:** Secret Manager へのアクセス権を持つ攻撃者が、`versions/list` API で全バージョンを列挙し、過去のトークンを取得できる

**推奨事項:**
- `save()` の後に古いバージョン（latest - N 以前）を `destroy` する処理を追加
- Secret Manager のシークレットにバージョン上限やローテーション期限を設定

---

## 4. 転送時暗号化 (TLS)

### DP-09: 転送時暗号化の設計評価 [INFO]

**良い点:**
- **HTTP クライアント:** `reqwest` は `rustls-tls-native-roots` フィーチャーで構成されており（`Cargo.toml` 行41）、TLS をデフォルトで使用。`default-features = false` により OpenSSL 依存を排除し、Rust 純正の TLS 実装を使用
- **Gateway Base URL 検証:** `validate_gateway_base_url()` (`oauth.rs` 行215-229) が HTTPS を強制（localhost 除く）
- **Redirect URI 検証:** `validate_redirect_uri()` (`oauth.rs` 行198-212) が HTTPS を強制（localhost 除く）
- **Google API 通信:** トークンエンドポイント (`https://oauth2.googleapis.com/token`)、userinfo エンドポイント (`https://www.googleapis.com/oauth2/v2/userinfo`)、Secret Manager API (`https://secretmanager.googleapis.com/v1/...`) すべて HTTPS
- **Cloud Run:** Cloud Run はデフォルトで HTTPS を終端し、Ingress で TLS を処理

**注意点:**
- Cloud Run 内部（ロードバランサーからコンテナ）の通信は Google のインフラ内で暗号化される（ALTS）が、アプリケーションレベルでは HTTP で待ち受けている。これは Cloud Run の標準的なアーキテクチャであり問題ではない

---

### DP-10: トークンレスポンスの Cache-Control ヘッダー [INFO]

**ファイル:** `src/mcp_server/http.rs`

**良い点:**
- トークン発行エンドポイント（`/token`）のレスポンスに `Cache-Control: no-store` が設定されている（行775, 行864）
- トークンリフレッシュレスポンスにも同様に設定済み
- これにより中間プロキシやブラウザキャッシュへのトークン漏洩を防止

---

## 5. 機密データのメモリ管理

### DP-05: 機密データの zeroize 処理の欠如 [MEDIUM]

**該当ファイル:** `src/credential_store.rs`, `src/mcp_server/oauth.rs`

**問題:** 暗号鍵、トークン、パスワード等の機密データがメモリから安全に消去されない。

**詳細:**
1. **暗号鍵:** `get_or_create_key()` で生成される `[u8; 32]` 鍵は `OnceLock` でプロセス寿命中キャッシュされ、プロセス終了まで消去されない。中間変数の `key` もスコープを抜けた後 Rust の通常の Drop で解放されるが、メモリ内容は明示的に上書きされない
2. **OAuth トークン:** `GoogleTokens` の `access_token`, `refresh_token` は `String` 型であり、`Drop` 時にゼロクリアされない。Rust の `String` はヒープ上のバッファを解放するが、内容を上書きしないため、ページングやコアダンプで漏洩する可能性がある
3. **Bearer トークン:** `HashMap<String, UserSession>` のキーとして保持。同様の問題

**影響:**
- プロセスのメモリダンプ（コアダンプ、`/proc/pid/mem` 読み取り）で機密データが取得可能
- Cloud Run 環境では攻撃面は限定的だが、ローカル開発環境ではリスクが高い

**推奨事項:**
- `zeroize` クレートの導入を検討。`Zeroizing<Vec<u8>>` ラッパーを使用して暗号鍵やトークンの安全な消去を保証
- ただし Cloud Run のコンテナ環境では攻撃面が限定的であり、優先度は中程度

---

## 6. ログへの機密情報出力防止

### DP-03: GoogleTokens / UserSession の Debug 実装がトークンを平文出力 [HIGH]

**ファイル:** `src/mcp_server/oauth.rs`

**問題:** `GoogleTokens` と `UserSession` は `#[derive(Debug)]` を使用しており、`Debug` フォーマットで `access_token`、`refresh_token` が平文で出力される。

**対照的に、`OAuthConfig` は手動 Debug 実装で `client_secret` を `[REDACTED]` に置換しており（行51-59）、この対策が `GoogleTokens` に適用されていない。**

**影響:**
- `{:?}` フォーマットでログ出力された場合、Cloud Logging にトークンが記録される
- `tracing::warn!` や `eprintln!` でのエラーハンドリング時に意図せずトークンが出力されるリスク
- 現時点のコードでは `GoogleTokens` を直接 Debug 出力している箇所は確認されていないが、将来のコード変更で容易に発生し得る「地雷」状態

**推奨事項:**
- `GoogleTokens` に手動 `Debug` 実装を追加し、`access_token` と `refresh_token` を `[REDACTED]` に置換
- `UserSession` も同様に、内包する `GoogleTokens` のフィールドを秘匿
- `Serialize` の derive も同様のリスクがある（ログライブラリが serialize を使用する場合）。ただし現時点では Secret Manager への保存に必要なため、ログ出力パスで serialize が呼ばれないことを確認する必要がある

---

## 7. OAuth クライアント設定の保護

### DP-06: OAuth クライアント設定が暗号化なしで保存 [MEDIUM]

**ファイル:** `src/oauth_config.rs`

**問題:** `save_client_config()` は `client_secret.json` を平文 JSON で保存する。ファイルパーミッション (0o600) は設定されるが、暗号化は行われない。

**詳細:**
- `client_secret` は Google OAuth の「installed application」タイプのシークレットであり、公開クライアント扱いのため機密性は相対的に低い
- ただし、`client_secret` が漏洩した場合、攻撃者がフィッシング攻撃でこのアプリケーションになりすますことが可能

**推奨事項:**
- `credential_store.rs` と同様の暗号化を適用することを検討
- ただし、`yup-oauth2` ライブラリが `client_secret.json` を直接読み取る場合、暗号化の適用が困難な場合がある。その場合はファイルパーミッションによる保護を維持

---

## 8. .env ファイルのシークレット管理

### DP-01: .env ファイルに OAuth クライアントシークレットがハードコードされている [CRITICAL]

**ファイル:** `.env`

**問題:** `.env` ファイルに実際の OAuth クライアント ID とクライアントシークレットがハードコードされている。

```
GOOGLE_WORKSPACE_CLI_CLIENT_ID=756600426975-...apps.googleusercontent.com
GOOGLE_WORKSPACE_CLI_CLIENT_SECRET=GOCSPX-...
```

**緩和要因:**
- `.gitignore` に `.env` が含まれているため、Git リポジトリには追跡されない
- OAuth の「installed application」タイプの `client_secret` は厳密には公開シークレットに近い（Google のドキュメントでも「confidential ではない」と記載）

**それでもリスクがある理由:**
- 開発者のローカルマシンに平文で存在し、バックアップやファイル共有で漏洩する可能性がある
- `.env` ファイルは誤ってコピー&ペーストされたり、スクリーンショットに含まれやすい
- 他の環境変数（将来追加される可能性のある、より機密性の高い値）との混在リスク

**推奨事項:**
- `.env` ファイルからクライアントシークレットを削除し、`gws auth setup` コマンド経由でのみ設定する運用に統一
- `.env.example` のコメントアウトされた形式を維持し、実際の値は含めない

---

## 9. チェックリスト結果

| チェック項目 | 結果 | 参照 |
|-------------|------|------|
| 保存時暗号化 (AES-256-GCM) の実装正当性 | 合格 | DP-08 |
| 鍵管理 (生成、保存) | 合格（ローテーション機構は欠如） | DP-07 |
| 転送時暗号化 (TLS) | 合格 | DP-09 |
| 機密データのメモリ管理 | 要改善 | DP-05 |
| ログへの機密情報出力防止 | 要改善 | DP-03 |

---

## 10. データフロー図（機密データのライフサイクル）

```
[ユーザーブラウザ]
    |
    | (1) OAuth 認可コード (HTTPS)
    v
[MCP Gateway (Cloud Run)]
    |
    | (2) 認可コード -> Google トークンエンドポイント (HTTPS)
    v
[Google OAuth]
    |
    | (3) access_token + refresh_token 返却 (HTTPS)
    v
[MCP Gateway メモリ]
    |  +-- HashMap<bearer_token, UserSession>
    |  |   +-- UserSession { email, GoogleTokens { access_token, refresh_token } }
    |  |
    |  | (4) セッション永続化 (HTTPS)
    |  v
    |  [Secret Manager]
    |     +-- 単一シークレット: 全ユーザーの JSON blob (平文)
    |        +-- version 1: { "bearer-A": {...}, "bearer-B": {...} }
    |        +-- version 2: (更新後) ... 古いバージョンが残存
    |        +-- ...
    |
    | (5) API 呼び出し時: access_token で Google API へ (HTTPS)
    v
[Google Workspace API]
```

**信頼境界の整理:**
- ブラウザ <-> Cloud Run: HTTPS (Cloud Run 管理)
- Cloud Run <-> Google OAuth/API: HTTPS (reqwest + rustls)
- Cloud Run <-> Secret Manager: HTTPS + メタデータサーバー認証
- Cloud Run 内メモリ: 暗号化なし（平文でトークン保持）

---

## 11. 推奨事項の優先順位

| 優先度 | 発見事項 | 推奨アクション | 工数目安 |
|--------|---------|---------------|---------|
| 1 | DP-01 | `.env` からシークレットを削除 | 即時（数分） |
| 2 | DP-03 | `GoogleTokens` に手動 Debug 実装（トークン秘匿） | 小（1時間以内） |
| 3 | DP-04 | Secret Manager の古いバージョン破棄処理を追加 | 小（数時間） |
| 4 | DP-02 | Secret Manager 保存前のアプリケーション層暗号化追加 | 中（1-2日） |
| 5 | DP-05 | `zeroize` クレートの導入 | 中（1日） |
| 6 | DP-06 | `client_secret.json` の暗号化検討 | 小（数時間） |
| 7 | DP-07 | 鍵ローテーション機構の設計・実装 | 大（将来的に） |
