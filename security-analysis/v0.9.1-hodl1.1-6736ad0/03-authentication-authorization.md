# 認証・認可セキュリティ分析

## 分析概要

| 項目 | 内容 |
|------|------|
| 分析対象 | 認証・認可レイヤー (OAuth 2.0, Bearer トークン, セッション管理, RBAC) |
| 分析日 | 2026-03-11 |
| 対象コミット | `6736ad0` (custom ブランチ HEAD) |
| 分析者 | Agent B |
| 対象ファイル | `src/auth.rs`, `src/oauth_config.rs`, `src/mcp_server/oauth.rs`, `src/mcp_server/http.rs`, `src/mcp_server/permissions.rs`, `src/mcp_server/session_store.rs` |

---

## 1. アーキテクチャ概要

### 1.1 認証フローの全体像

MCP Gateway は二重の OAuth フローを実装している。

```
Claude Desktop/Code
    |
    +-- (1) POST /register          -> Dynamic Client Registration (RFC 7591)
    +-- (2) GET /authorize           -> Gateway が Google OAuth にリダイレクト
    |       +-- Google 同意画面 -> GET /oauth/callback
    +-- (3) POST /token              -> auth code + PKCE -> Bearer トークン発行
    |
    +-- (4) POST /mcp (Bearer)      -> API リクエスト実行
            +-- Bearer トークン検証
            +-- セッション検証 (Mcp-Session-Id)
            +-- 権限チェック (permissions.yaml)
            +-- Google API 呼び出し (サーバー保持の Google トークン使用)
```

### 1.2 トークンの種類

| トークン | 保持場所 | 有効期限 | 用途 |
|----------|----------|----------|------|
| Gateway Bearer トークン | サーバーメモリ + Secret Manager | 24時間 | クライアント認証 |
| Google Access Token | サーバーメモリ + Secret Manager | ~1時間 | Google API 呼び出し |
| Google Refresh Token | サーバーメモリ + Secret Manager | 長期 | Access Token 更新 |
| Gateway Auth Code | サーバーメモリのみ | 10分 | Bearer トークン発行 |

---

## 2. 発見事項

### F-01: Dynamic Client Registration が無認証 [MEDIUM — MCP 仕様準拠]

**場所:** `src/mcp_server/http.rs` -- `handle_register`

**説明:** `POST /register` エンドポイントは認証なしでアクセス可能である。

**MCP 仕様との関係:** [MCP Authorization Specification (2025-03-26)](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization) では Dynamic Client Registration ([RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591)) の実装を **SHOULD** で推奨している。RFC 7591 では `/register` エンドポイントは認証なしで動作するのが標準的な仕様であり、MCP クライアント（Claude Code / Claude Desktop）がサーバーを事前に知ることなく自動登録できるようにするために必要な設計である。**本指摘は MCP 仕様に準拠した意図的な設計であり、変更は MCP クライアントとの互換性を損なう。**

**影響:**
- DoS 攻撃: 最大 10,000 件のクライアント登録によるメモリ消費
- 不正なクライアント登録を起点とした OAuth フロー開始

**緩和要素:**
- `MAX_REGISTERED_CLIENTS = 10,000` の上限あり
- registered_clients はインメモリのみ (再起動で消去)
- Cloud Run の ingress 制御で外部からのアクセスを制限可能

**推奨対策:**
- Cloud Run のアクセス制御 (IAM / ingress) で `/register` エンドポイントへのアクセスを信頼できるネットワークに制限（アプリケーション層での認証追加は MCP 仕様と非互換）
- レート制限の導入を検討

---

### F-02: OAuth スコープの過剰な初期要求 [MEDIUM]

**場所:** `src/mcp_server/oauth.rs` -- `DEFAULT_OAUTH_SCOPES`

**説明:** Google OAuth の同意画面で要求されるデフォルトスコープが非常に広い。

```rust
pub const DEFAULT_OAUTH_SCOPES: &str = "\
    openid email profile \
    https://www.googleapis.com/auth/drive \
    https://www.googleapis.com/auth/gmail.modify \
    https://www.googleapis.com/auth/calendar \
    https://www.googleapis.com/auth/spreadsheets \
    https://www.googleapis.com/auth/documents \
    https://www.googleapis.com/auth/presentations \
    https://www.googleapis.com/auth/chat.messages \
    https://www.googleapis.com/auth/tasks";
```

**影響:**
- `gmail.modify` は Gmail の読み取り・送信・削除が可能。permissions.yaml では `gmail.readonly` のみを admin ロールに許可しているにもかかわらず、OAuth トークン自体は `gmail.modify` 権限を保持
- Google Workspace API では token-level downscoping が不可能なため、permissions.yaml をバイパスして直接 API を叩けば `gmail.modify` 操作が可能 (ただし Bearer トークンがサーバーサイド保持のため、直接 API を叩くにはサーバー侵害が必要)

**緩和要素:**
- `permissions.yaml` の `all_scopes_union()` が設定されている場合、そちらが使われる (コード上はそのロジックが存在)
- Google トークンはクライアントに露出しない (サーバーサイド保持)

**推奨対策:**
- `DEFAULT_OAUTH_SCOPES` を permissions.yaml の `all_scopes_union()` 結果に動的に制限する実装が確実に有効化されていることを確認
- `gmail.modify` を `gmail.readonly` に変更することを検討 (admin ロールでも gmail は readonly のため)

---

### F-03: `GOOGLE_WORKSPACE_CLI_TOKEN` 環境変数によるトークン直接注入 [MEDIUM]

**場所:** `src/auth.rs` -- `get_token()` 関数 (L91-97)

**説明:** `GOOGLE_WORKSPACE_CLI_TOKEN` 環境変数が設定されている場合、全ての認証メカニズムをバイパスして生のアクセストークンが使用される。

```rust
if let Ok(token) = std::env::var("GOOGLE_WORKSPACE_CLI_TOKEN") {
    if !token.is_empty() {
        return Ok(token);
    }
}
```

**影響:**
- CLI モード (ローカル利用) では便利な機能だが、MCP Gateway モード (Cloud Run) でこの環境変数が設定されると、全ユーザーが同一の Google トークンを使用することになり、ユーザー分離が完全に崩壊する
- トークンの有効期限検証なし

**緩和要素:**
- MCP Gateway モードでは `src/mcp_server/oauth.rs` の `get_valid_google_token()` が使用され、`src/auth.rs` の `get_token()` は直接呼ばれない
- Cloud Run の環境変数にこのトークンを設定する運用は想定されていない

**推奨対策:**
- MCP Gateway モードで `GOOGLE_WORKSPACE_CLI_TOKEN` が設定されている場合に警告を出すか、明示的に無視するガード追加を検討

---

### F-04: セッションと Bearer トークンのバインディングが堅牢 [INFO]

**場所:** `src/mcp_server/http.rs` -- `validate_session()` (L112-139)

**説明:** MCP セッションは初期化時に Bearer トークンにバインドされ、後続リクエストで Bearer トークンの一致が検証される。これにより、セッション ID を知っていても別の Bearer トークンではアクセスできない。

```rust
let bearer = extract_bearer_token(headers).unwrap_or_default();
if bearer != *bound_bearer {
    return Err((StatusCode::FORBIDDEN, "Bearer token does not match session owner").into_response());
}
```

**評価:** 良好な実装。セッションハイジャック防止に有効。

---

### F-05: PKCE (S256) の強制が適切 [INFO]

**場所:** `src/mcp_server/http.rs` -- `handle_authorize()`, `src/mcp_server/oauth.rs` -- `validate_pkce()`

**説明:**
- `code_challenge` パラメータが必須
- `code_challenge_method` は `S256` のみ許可 (`plain` は明示的に拒否)
- トークン交換時に `code_verifier` が必須
- SHA-256 ハッシュによる検証が正しく実装

```rust
"S256" => {
    let digest = sha2::Sha256::digest(code_verifier.as_bytes());
    let computed = base64_url_encode(&digest);
    computed == code_challenge
}
_ => false,
```

**評価:** OAuth 2.0 のベストプラクティスに準拠。Authorization Code Interception Attack を防止。

---

### F-06: Bearer トークンの暗号学的安全性が良好 [INFO]

**場所:** `src/mcp_server/oauth.rs` -- `generate_secure_token()`

**説明:** 256 ビットの暗号学的に安全な乱数を `OsRng` から生成し、base64url エンコードしている。

```rust
pub fn generate_secure_token() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    base64_url_encode(&buf)
}
```

**評価:** 十分なエントロピー (256 bit) を持ち、ブルートフォース攻撃に対して安全。

---

### F-07: 全セッションの単一 Secret Manager シークレットへの集約 [HIGH]

**場所:** `src/mcp_server/session_store.rs` -- `SecretManagerPersistence`

**説明:** 全ユーザーの Bearer セッション (Google OAuth refresh_token を含む) が単一の Secret Manager シークレットに JSON blob として保存される。

**影響:**
- **爆発半径 (Blast Radius):** Secret Manager へのアクセス権を持つ攻撃者は、全ユーザーの Google OAuth refresh_token を一度に取得可能
- **データ競合:** 同時書き込み時の last-writer-wins により、セッションデータが消失する可能性
- **バージョン膨張:** 毎回 addVersion するため、Secret Manager のバージョン数が増加し続ける (古いバージョンの自動破棄なし)

**緩和要素:**
- Secret Manager 自体が暗号化保存
- Cloud Run のサービスアカウントのみがアクセス可能 (IAM で制限)

**推奨対策:**
- ユーザーごとにシークレットを分離するか、暗号化レイヤーを追加
- 古い Secret Manager バージョンの定期的な破棄 (destroy) を実装
- 同時書き込みの競合状態に対する楽観的ロックの導入を検討

---

### F-08: `redirect_uri` 検証が HTTPS or localhost のみ [MEDIUM — MCP 仕様準拠]

**場所:** `src/mcp_server/oauth.rs` -- `validate_redirect_uri()`

**説明:** redirect_uri の検証は「localhost URL または HTTPS URL」のみを許可している。

```rust
pub fn validate_redirect_uri(uri: &str) -> Result<(), String> {
    let lower = uri.to_lowercase();
    if lower.starts_with("https://") {
        return Ok(());
    }
    if lower.starts_with("http://localhost")
        || lower.starts_with("http://127.0.0.1")
        || lower.starts_with("http://[::1]")
    {
        return Ok(());
    }
    Err(...)
}
```

**MCP 仕様との関係:** [MCP Authorization Specification (2025-03-26)](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization) のセキュリティ要件に「Redirect URIs **MUST** be either localhost URLs or HTTPS URLs」と明記されている。現在の実装はこの要件に正確に準拠している。Claude Code はランダムポートの `http://localhost:PORT/callback` をコールバックに使用するため、任意の localhost URL を受け入れる必要がある。また、Claude Desktop（Web ベース）は HTTPS URL を使用する。**特定ドメインへの allowlist 制限は MCP クライアントとの互換性を損なうため推奨しない。**

**残存リスク:**
- `https://evil.example.com/steal-code` のような任意の HTTPS URL が redirect_uri として登録可能
- Dynamic Client Registration 経由で攻撃者が自身の URL を登録し、auth code を窃取する攻撃が理論上可能

**緩和要素:**
- PKCE (S256) が強制されているため、auth code を窃取しても code_verifier なしでは Bearer トークンを取得できない
- Cloud Run の ingress 制御で外部アクセスを制限可能
- `handle_authorize` で redirect_uri が登録済みクライアントの redirect_uris と一致することを検証済み

**推奨対策:**
- 現状の PKCE 強制により実質的な攻撃は困難。MCP 仕様準拠のため redirect_uri の制限強化は不要
- Cloud Run の ingress 制御による保護を確認

---

### F-09: Bearer トークンのリフレッシュメカニズムがトークンローテーションを実装 [INFO]

**場所:** `src/mcp_server/http.rs` -- `handle_token_refresh()`

**説明:** Bearer トークンのリフレッシュ時に、旧トークンを削除して新しいトークンを発行するトークンローテーションが実装されている。

```rust
let session = {
    let mut store = state.token_store.lock().await;
    store.bearer_sessions.remove(&old_bearer)  // 旧トークンを削除
};
// ...
store.bearer_sessions.insert(new_bearer.clone(), session);  // 新トークンを発行
```

**評価:** リフレッシュトークンの再利用を防止し、トークン漏洩時の影響を限定化。良好な実装。

---

### F-10: 未認証アクセスの拒否が適切 [INFO]

**場所:** `src/mcp_server/http.rs` -- `resolve_google_token()`, 各ハンドラー

**説明:** 全ての MCP エンドポイント (`POST /mcp`, `GET /mcp`, `DELETE /mcp`) で Bearer トークン検証が行われ、未認証リクエストには `401 Unauthorized` + `WWW-Authenticate` ヘッダーが返される。

```rust
async fn resolve_google_token(headers: &HeaderMap, state: &AppState) -> Result<String, Response> {
    let bearer = extract_bearer_token(headers)
        .ok_or_else(|| unauthorized_response(state, "Authentication required"))?;
    match oauth::get_valid_google_token(&state.oauth_config, &state.token_store, &bearer).await {
        Ok(token) => Ok(token),
        Err(_) => Err(unauthorized_response(state, "Invalid or expired token")),
    }
}
```

**評価:** OAuth エンドポイント (metadata, authorize, callback, token, register) 以外の全エンドポイントで認証が強制されている。

---

### F-11: `initialize` メソッドでのセッション検証スキップ [LOW]

**場所:** `src/mcp_server/http.rs` -- `handle_post()` (L248-256)

**説明:** `initialize` メソッドを含むリクエストでは `Mcp-Session-Id` の検証がスキップされる。

```rust
let has_initialize = messages
    .iter()
    .any(|m| m.get("method").and_then(|v| v.as_str()) == Some("initialize"));

if !has_initialize {
    if let Err(resp) = validate_session(&headers, &state.sessions).await {
        return resp;
    }
}
```

**影響:**
- バッチリクエストに `initialize` を含めることで、同一バッチ内の他のメソッドもセッション検証なしで実行される
- ただし、Bearer トークン検証は `resolve_google_token` で先に行われるため、認証自体はバイパスされない

**緩和要素:**
- Bearer トークン検証は全リクエストで先行して実施
- `initialize` は新しいセッション ID を発行するだけで、権限昇格にはつながらない

**推奨対策:**
- バッチリクエスト内で `initialize` と他のメソッドを混在させない制御を検討
- `initialize` のみを含むバッチに限定するバリデーションの追加

---

### F-12: 権限チェック (RBAC) の実装が堅牢 [INFO]

**場所:** `src/mcp_server/permissions.rs`

**説明:** 権限制御は以下の二重チェックで構成されている。

1. **スコープチェック:** ロールに定義されたスコープと、API メソッドが要求するスコープの交差を検証
2. **メソッドパターンチェック:** ワイルドカードパターン (`*`, `gmail.*`, `drive.files.list`) による API メソッド ID の一致を検証

```rust
// 両方のチェックが必要 (AND 条件)
if role_def.scopes.is_empty() { return false; }
if role_def.method.is_empty() { return false; }
```

**評価:**
- Deny-by-default: スコープまたはメソッドが空の場合は全拒否
- 未登録ユーザーは全拒否
- ロール定義の整合性検証 (`validate()`) あり
- テストカバレッジが充実

---

### F-13: Google トークンのクライアント非露出 [INFO]

**場所:** `src/mcp_server/http.rs`, `src/mcp_server/oauth.rs`

**説明:** Google OAuth トークン (access_token, refresh_token) はサーバーサイドでのみ保持され、クライアントには Gateway の Bearer トークンのみが返される。

```rust
let resp_body = json!({
    "access_token": bearer_token,  // Gateway 独自の Bearer トークン
    "token_type": "Bearer",
    "expires_in": expires_in,
});
```

**評価:** クライアント (AI エージェント) が Google トークンを直接操作できないため、トークンの窃取リスクが低い。

---

### F-14: Cache-Control ヘッダーの適切な設定 [INFO]

**場所:** `src/mcp_server/http.rs` -- `handle_token_authorization_code()`, `handle_token_refresh()`

**説明:** トークンエンドポイントのレスポンスに `Cache-Control: no-store` が設定されている。

```rust
resp_headers.insert(
    axum::http::header::CACHE_CONTROL,
    HeaderValue::from_static("no-store"),
);
```

**評価:** RFC 6749 Section 5.1 準拠。プロキシやブラウザキャッシュによるトークン漏洩を防止。

---

### F-15: Authorization Code の単回使用保証 [INFO]

**場所:** `src/mcp_server/http.rs` -- `handle_token_authorization_code()` (L712-714)

**説明:** auth code は `pending_codes.remove()` で取り出されるため、同一コードの再利用が不可能。

```rust
let pending_code = {
    let mut store = state.token_store.lock().await;
    store.pending_codes.remove(&code)
};
```

**評価:** Authorization Code Replay Attack を防止。

---

### F-16: `permissions.yaml` に実名・メールアドレスのハードコード [LOW]

**場所:** `config/permissions.yaml`

**説明:** permissions.yaml に約20名の社員の実名 (コメント) とメールアドレスが記載され、Git リポジトリに格納されている。

**影響:**
- リポジトリへのアクセス権を持つ者が組織構造と個人のメールアドレスを取得可能
- 公開リポジトリの場合、個人情報の露出

**緩和要素:**
- プライベートリポジトリであれば影響は限定的
- 権限設定にメールアドレスが必要な構造上、完全な排除は困難

**推奨対策:**
- コメント内の実名を削除し、組織上のロール名のみを残すことを検討
- 可能であれば Google Groups を利用してメールアドレスの直接記載を回避

---

### F-17: `permissions.yaml` 未設定時の全メソッド許可 [HIGH]

**場所:** `src/mcp_server/permissions.rs` -- `filter_tools_by_permissions()` (L218-221)

**説明:** `permissions` が `None` (権限設定ファイルが読み込まれていない) の場合、全ツールが許可される。

```rust
let perms = match perm_ctx.permissions {
    Some(p) => p,
    None => return tools.iter().collect(), // No permissions -> all tools
};
```

**影響:**
- `--permissions` フラグの指定忘れや、ファイルパスの誤りにより、全ユーザーに全メソッドが許可される
- AI エージェントからの悪意ある操作 (ファイル削除、メール送信等) が制御なしで実行される

**緩和要素:**
- Cloud Run のデプロイスクリプト/CI で `--permissions` が常に指定されることが期待される
- OAuth スコープ自体は Google 側で制限

**推奨対策:**
- MCP Gateway モード (HTTP サーバーモード) では `--permissions` の指定を必須にする (未指定時はエラーで起動を拒否)
- 起動時にログに権限設定のステータスを明示的に出力

---

### F-18: tool_name から method_id への変換が可逆的でない場合がある [LOW]

**場所:** `src/mcp_server/permissions.rs` -- `tool_name_to_method_id()`

**説明:** ツール名からメソッド ID への変換はアンダースコアをドットに置換するだけである。

```rust
pub(super) fn tool_name_to_method_id(tool_name: &str) -> String {
    tool_name.replace('_', ".")
}
```

**影響:**
- メソッド ID にアンダースコアを含むものがある場合、変換が不正確になる可能性
- 現在の Google Workspace API ではメソッド ID にアンダースコアは使用されていないが、将来的なリスク

**推奨対策:**
- 現時点では問題なし。将来的に API が追加された場合に注意

---

### F-19: 認証コードの TTL 検証が適切 [INFO]

**場所:** `src/mcp_server/http.rs`, `src/mcp_server/oauth.rs`

**説明:** 各一時的なデータに対して適切な TTL が設定されている。

| データ | TTL | 定数 |
|--------|-----|------|
| Pending Auth (認可リクエスト) | 15分 | `PENDING_AUTH_TTL_SECS = 900` |
| Authorization Code | 10分 | `AUTH_CODE_TTL_SECS = 600` |
| Bearer Token | 24時間 | `BEARER_TOKEN_LIFETIME_SECS = 86400` |

lazy cleanup (`cleanup_expired()`) が主要操作のタイミングで呼ばれ、期限切れデータが蓄積しない。

---

### F-20: DoS 耐性のための容量制限 [INFO]

**場所:** `src/mcp_server/oauth.rs`

**説明:** 各 HashMap に上限が設定されている。

| マップ | 上限 |
|--------|------|
| `bearer_sessions` | 100,000 |
| `pending_codes` | 10,000 |
| `pending_auths` | 10,000 |
| `registered_clients` | 10,000 |

**評価:** メモリ枯渇攻撃への基本的な防御が実装されている。20名規模の利用では十分な値。

---

### F-21: Origin 検証の `starts_with` によるサブドメイン攻撃リスク [LOW]

**場所:** `src/mcp_server/http.rs` -- `validate_origin()` (L96-110)

**説明:** Origin ヘッダーの検証に `starts_with` を使用している。

```rust
lower.starts_with("http://localhost")
```

**影響:**
- `http://localhost.evil.com` のような悪意あるドメインが `http://localhost` の starts_with チェックを通過する可能性がある

**緩和要素:**
- Origin ヘッダーにはポートやパスが含まれるため、`http://localhost.evil.com` は `http://localhost` の後にドットが来るが、`http://localhost:8080` のように正規のポート指定も通過する
- ブラウザからのリクエストのみが Origin を送信 (AI エージェントは通常 Origin を送信しない)

**推奨対策:**
- `http://localhost` の後に `:` または `/` または文字列終了のみを許可する、より厳密な検証を実装

---

### F-22: OAuth client_secret の Debug 出力でのリダクション [INFO]

**場所:** `src/mcp_server/oauth.rs` -- `OAuthConfig` の `Debug` 実装 (L51-59)

**説明:** `client_secret` が Debug 出力で `[REDACTED]` に置換される。

```rust
impl std::fmt::Debug for OAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthConfig")
            .field("client_secret", &"[REDACTED]")
            // ...
    }
}
```

**評価:** ログ漏洩防止のベストプラクティス。

---

### F-23: client_secret.json のファイルパーミッション設定 [INFO]

**場所:** `src/oauth_config.rs` -- `save_client_config()` (L88-91)

**説明:** Unix 環境で `client_secret.json` のファイルパーミッションが 600 に設定される。

```rust
#[cfg(unix)]
{
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
}
```

**評価:** ローカル環境でのクレデンシャル保護として適切。

---

### F-24: `GoogleTokens::is_expired()` の 60 秒バッファ [INFO]

**場所:** `src/mcp_server/oauth.rs` -- `GoogleTokens::is_expired()` (L73-77)

**説明:** トークンの有効期限切れ判定に 60 秒のバッファが設けられている。

```rust
pub fn is_expired(&self) -> bool {
    self.expires_at
        .map(|ea| chrono::Utc::now().timestamp() + 60 >= ea)
        .unwrap_or(false)
}
```

**評価:** API 呼び出し中のトークン期限切れを防止する適切な設計。ただし `expires_at` が `None` の場合 `false` (期限切れではない) を返す点は、永続的に有効なトークンとして扱われるため注意。

---

### F-25: レート制限の欠如 [MEDIUM]

**場所:** `src/mcp_server/http.rs` -- 全エンドポイント

**説明:** HTTP エンドポイントにレート制限が実装されていない。

**影響:**
- `/authorize` エンドポイントへの大量リクエストで pending_auths を填充
- `/register` エンドポイントへの大量リクエストで registered_clients を填充
- `/token` エンドポイントへのブルートフォース (ただし 256-bit トークンのため実質不可能)
- `/mcp` エンドポイントへの大量リクエストで Google API クォータを消費

**緩和要素:**
- HashMap の上限による基本的な保護
- Cloud Run のリクエスト同時実行制限
- Google API 側のクォータ制限

**推奨対策:**
- Cloud Run のリクエスト制限、またはアプリケーション層でのレート制限ミドルウェアの導入
- 特に `/register` と `/authorize` に対するレート制限を優先

---

### F-26: `expires_at` が `None` の場合のトークン無期限扱い [LOW]

**場所:** `src/mcp_server/oauth.rs` -- `GoogleTokens::is_expired()` (L77)

**説明:** `expires_at` が `None` の場合、`is_expired()` は `false` を返し、トークンが永続的に有効と見なされる。

**影響:**
- Google トークンレスポンスに `expires_in` が含まれない異常なケースで、期限切れにならないトークンが生成される

**推奨対策:**
- `expires_at` が `None` の場合は安全側に倒して期限切れとみなすか、デフォルトの有効期限 (例: 1時間) を設定

---

## 3. 分析チェックリスト結果

| チェック項目 | 結果 | 参照 |
|-------------|------|------|
| OAuth 2.0 / PKCE フロー実装の正当性 | 良好 | F-05, F-15 |
| Bearer トークンの生成・検証・失効 | 良好 | F-06, F-09, F-19 |
| セッション管理 (生成、バインド、有効期限) | 良好 | F-04, F-19 |
| 権限制御 (RBAC) の実装整合性 | 良好 (ただし未設定時リスクあり) | F-12, F-17 |
| 未認証アクセスの拒否 | 良好 | F-10 |
| スコープの最小権限原則の適用 | 要改善 | F-02, F-17 |

---

## 4. リスクサマリー

| 深刻度 | 件数 | 発見事項 |
|--------|------|----------|
| **CRITICAL** | 0 | -- |
| **HIGH** | 2 | F-07 (Secret Manager 集約), F-17 (permissions 未設定時の全許可) |
| **MEDIUM** | 5 | F-01 (無認証 /register), F-02 (過剰スコープ), F-03 (トークン直接注入), F-08 (redirect_uri 検証), F-25 (レート制限欠如) |
| **LOW** | 5 | F-11 (initialize セッション検証スキップ), F-16 (実名ハードコード), F-18 (tool_name 変換), F-21 (Origin starts_with), F-26 (expires_at None) |
| **INFO** | 12 | F-04, F-05, F-06, F-09, F-10, F-12, F-13, F-14, F-15, F-19, F-20, F-22, F-23, F-24 |

---

## 5. 優先対応推奨事項

### 最優先 (HIGH)

1. **F-17:** MCP Gateway モードで `--permissions` を必須化し、権限設定なしでの起動を防止する
2. **F-07:** Secret Manager に保存するセッションデータの暗号化レイヤー追加、および古いバージョンの定期破棄を実装する

### 次点 (MEDIUM)

3. **F-02:** `DEFAULT_OAUTH_SCOPES` を permissions.yaml の実際の必要スコープに合わせて最小化する
4. **F-25:** `/register` および `/authorize` エンドポイントにレート制限を導入する
5. **F-01:** Cloud Run レベルで `/register` へのアクセスを制限する

### 将来対応 (LOW)

6. **F-21:** Origin 検証をより厳密に実装する
7. **F-11:** `initialize` を含むバッチリクエストの制御を強化する
