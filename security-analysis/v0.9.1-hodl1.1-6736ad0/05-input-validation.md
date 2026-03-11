# 入力検証・インジェクション対策分析

## 分析概要

| 項目 | 内容 |
|------|------|
| 担当 | Agent D |
| 分析日 | 2026-03-11 |
| 対象コミット | `6736ad0` (custom ブランチ HEAD) |
| 分析範囲 | 入力検証、URL インジェクション、パストラバーサル、JSON バリデーション、リクエストサイズ制限 |

## 分析対象ファイル

| ファイル | 目的 |
|----------|------|
| `src/validate.rs` | パス検証、URL エンコーディング、リソース名検証のヘルパー関数群 |
| `src/executor.rs` | API リクエスト構築・実行、URL テンプレート展開、スキーマバリデーション |
| `src/helpers/mod.rs` | サービス固有ヘルパーのディスパッチ |
| `src/mcp_server/http.rs` | MCP Gateway HTTP エンドポイント (axum)、セッション検証、OAuth フロー |
| `src/mcp_server/jsonrpc.rs` | JSON-RPC レスポンス構築 |
| `src/mcp_server.rs` | MCP リクエストハンドラ、ツール呼び出しディスパッチ |
| `AGENTS.md` | 入力検証ガイドライン |

---

## 発見事項一覧

### 1. [MEDIUM] MCP Gateway にリクエストボディサイズ制限が未設定

**場所**: `src/mcp_server/http.rs` (axum Router 構成)

**説明**: axum の `Router` 構成において `DefaultBodyLimit` レイヤーが設定されていない。axum のデフォルトボディ制限は 2MB だが、これは明示的に設定されているわけではなく、フレームワークのデフォルト値に暗黙的に依存している。

`handle_post` では JSON ボディを `body: String` として受け取っており、巨大な JSON ペイロードが送信された場合にメモリを過剰消費する可能性がある。特にバッチリクエスト (`messages` 配列) には要素数の上限がなく、大量のメッセージを含むバッチが処理される。

```rust
// src/mcp_server/http.rs - handle_post
async fn handle_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,  // サイズ制限なし
) -> Response {
```

**リスク**: 悪意のある AI エージェントや攻撃者が大量のバッチメッセージを送信し、メモリ枯渇を引き起こす可能性がある。

**推奨事項**:
- `axum::extract::DefaultBodyLimit::max()` を明示的に設定する (例: 1MB)
- バッチリクエストの `messages` 配列に要素数の上限 (例: 50) を設定する

---

### 2. [MEDIUM] JSON-RPC バッチリクエストに上限がない

**場所**: `src/mcp_server/http.rs` L225-L246

**説明**: JSON-RPC のバッチリクエスト処理において、メッセージ配列のサイズに上限が設定されていない。空の配列に対するチェックは存在するが、最大サイズのチェックがない。

```rust
let (messages, is_batch) = if let Some(arr) = parsed.as_array() {
    (arr.clone(), true)  // 要素数の上限チェックなし
} else {
    (vec![parsed], false)
};
```

各メッセージに対して `handle_request` が順次呼ばれ、それぞれが Discovery Document のフェッチや API 呼び出しを行う可能性がある。数百から数千のメッセージを含むバッチは、サーバーリソースを枯渇させ得る。

**リスク**: DoS 攻撃ベクトル。AI エージェントが意図せず大量のリクエストをバッチ送信する可能性もある。

**推奨事項**: バッチサイズに上限 (例: 20-50) を設けて超過分を拒否する。

---

### 3. [LOW] URL パステンプレート展開における堅牢なエンコーディング

**場所**: `src/executor.rs` L601-L646 (`render_path_template`)

**説明**: URL パステンプレートの展開は適切に実装されている。

- `{param}` 形式のプレースホルダーには `encode_path_segment()` (全非英数字文字をパーセントエンコード) が適用される
- `{+param}` 形式 (RFC 6570) のプレースホルダーには `validate_resource_name()` + `encode_path_preserving_slashes()` が適用される

```rust
let encoded = if is_plus {
    let validated = crate::validate::validate_resource_name(&val_str)?;
    crate::validate::encode_path_preserving_slashes(validated)
} else {
    crate::validate::encode_path_segment(&val_str)
};
```

`validate_resource_name()` は `..` セグメント、制御文字、`?`/`#`/`%` を拒否しており、URL インジェクション攻撃に対して十分な防御を提供している。

**評価**: 良好な実装。AGENTS.md のガイドラインに沿っている。

---

### 4. [LOW] クエリパラメータのエンコーディングは reqwest に委任

**場所**: `src/executor.rs` L173-L175

**説明**: クエリパラメータは reqwest の `.query()` メソッドを使用して設定されており、エンコーディングは reqwest ライブラリが自動的に処理する。これは AGENTS.md に記載されたベストプラクティスに従っている。

```rust
for (key, value) in &input.query_params {
    request = request.query(&[(key, value)]);
}
```

**評価**: 適切な実装。手動での文字列結合を避けている。

---

### 5. [INFO] パス検証ヘルパーの包括的テストカバレッジ

**場所**: `src/validate.rs` L244-L569

**説明**: `validate.rs` には以下の検証機能が実装されており、各機能について包括的なテストが存在する:

| 関数 | 目的 | テスト数 |
|------|------|---------|
| `validate_safe_output_dir()` | 出力ディレクトリのパストラバーサル防止 | 7 |
| `validate_safe_dir_path()` | 読取ディレクトリのパストラバーサル防止 | 3 |
| `reject_control_chars()` | 制御文字の拒否 | 4 |
| `encode_path_segment()` | URL パスセグメントのエンコーディング | 8 |
| `encode_path_preserving_slashes()` | スラッシュ保持エンコーディング | 3 |
| `validate_resource_name()` | リソース名のバリデーション | 7 |
| `validate_api_identifier()` | API 識別子のバリデーション | 4 |

特筆事項:
- `validate_resource_name()` は `%` を拒否し、URL エンコードバイパス (`%2e%2e` = `..`) を防止
- `encode_path_segment()` はダブルエンコード問題も防止 (`%40` -> `%2540`)
- シンボリックリンクを経由したパストラバーサルもテスト済み

**評価**: 優秀な実装。AI エージェントからの敵対的入力を想定した多層防御が実現されている。

---

### 6. [MEDIUM] MCP Gateway の upload パス検証が validate.rs を直接使用していない

**場所**: `src/mcp_server.rs` L1099-L1114

**説明**: MCP Gateway 内のアップロードパス検証は、`validate.rs` の `validate_safe_output_dir()` / `validate_safe_dir_path()` ヘルパーを使わず、独自のインライン検証を実施している。

```rust
let upload_path = if let Some(raw) = arguments
    .get("upload")
    .and_then(|v| v.as_str())
    .filter(|s| !s.is_empty())
{
    let p = std::path::Path::new(raw);
    if p.is_absolute() || p.components().any(|c| c == std::path::Component::ParentDir) {
        return Err(GwsError::Validation(format!(
            "Upload path '{}' is not allowed...", raw
        )));
    }
    Some(raw)
} else {
    None
};
```

この検証は:
- 絶対パスを拒否する
- `..` コンポーネントを拒否する

しかし `validate.rs` の検証と比較すると以下が欠けている:
- **制御文字の検証**: `\0`, `\n`, `\t` などが含まれるパスが通過する
- **シンボリックリンクの解決・検証**: CWD 外へのシンボリックリンクをたどる可能性がある
- **正規化 (canonicalize)**: `foo/./bar` のような冗長パスが正規化されない

MCP Gateway は Cloud Run 上で動作するため、ファイルシステムアクセスのリスクは限定的だが、AGENTS.md で定義された一貫性のある検証ポリシーに従うべきである。

**リスク**: シンボリックリンクや制御文字を含むパスによって、意図しないファイルの読み取りが可能になる潜在的リスク。

**推奨事項**: `validate_safe_dir_path()` または専用のアップロードパス検証関数を `validate.rs` に追加し、MCP Gateway から呼び出す。

---

### 7. [LOW] JSON パース時のバリデーションは Discovery Schema に基づく

**場所**: `src/executor.rs` L72-L135 (`parse_and_validate_inputs`), L771-L917 (`validate_body_against_schema` 等)

**説明**: リクエストボディの JSON は以下の多層バリデーションを受ける:

1. **JSON 構文検証**: `serde_json::from_str()` による構文エラーの検出
2. **スキーマバリデーション**: Discovery Document のスキーマ定義に基づく型チェック、必須フィールド検証、enum 値検証、未知プロパティの検出
3. **必須パラメータ検証**: パスパラメータおよびクエリパラメータの必須チェック

スキーマバリデーションは以下をカバーしている:
- 型チェック (string, integer, number, boolean, array, object)
- `$ref` による再帰的なスキーマ参照解決
- 配列要素の個別バリデーション
- ネストされたオブジェクトのプロパティバリデーション
- enum 値の許可リストチェック
- 未定義プロパティの検出と有効プロパティの提示

**評価**: 適切な実装。Discovery Document に定義された構造に対して十分なバリデーションが行われている。

---

### 8. [LOW] JSON-RPC リクエストの最小限の構造検証

**場所**: `src/mcp_server/http.rs` L209-L293

**説明**: JSON-RPC リクエストの処理において、以下の検証が行われている:

- JSON 構文の検証 (`serde_json::from_str`)
- 空バッチの拒否
- `id` / `method` フィールドの存在チェック
- メソッド名の文字列型チェック (`as_str()`)

ただし JSON-RPC 2.0 仕様で要求される以下の厳密な検証は行われていない:
- `jsonrpc` フィールドが `"2.0"` であることの検証
- `id` の型検証 (string, number, null のいずれかであるべき)
- `method` フィールドが仕様で予約された `rpc.` プレフィックスを使用していないことの検証

**リスク**: 直接的なセキュリティリスクは低いが、仕様準拠の観点から改善の余地がある。

**推奨事項**: JSON-RPC 2.0 仕様への完全準拠を検討する。

---

### 9. [INFO] JSON-RPC エラーレスポンスにおける内部情報の最小化

**場所**: `src/mcp_server/jsonrpc.rs`

**説明**: エラーレスポンスは `GwsError` の `to_string()` 表現を返す。`GwsError` の実装次第では、内部パス情報やスタックトレースが含まれる可能性がある。

ただし、`tools/call` の処理では MCP 仕様に従い、ツール実行エラーは `isError: true` の結果として返され、JSON-RPC エラーとはならない設計になっている。これにより、クライアントが詳細なエラー情報を取得できる。

**評価**: エラーハンドリングの設計は MCP 仕様に適合している。内部エラーの詳細が過度に露出していないか、`GwsError` の `Display` 実装を確認することを推奨する。

---

### 10. [HIGH] API ベース URL の検証が不十分

**場所**: `src/executor.rs` L482-L576 (`build_url`)

**説明**: `build_url` 関数は Discovery Document の `base_url` / `root_url` / `service_path` を信頼して URL を構築する。Discovery Document は Google のサーバーから HTTPS 経由で取得されるため、通常は信頼できるソースである。

しかし、以下のシナリオでリスクが生じる:

1. **キャッシュ汚染**: Discovery Document がローカルにキャッシュされている場合、キャッシュファイルが改竄されると任意の URL にリクエストが送信される可能性がある
2. **SSRF の可能性**: 改竄された Discovery Document の `base_url` が内部ネットワークのアドレスに設定された場合、Cloud Run インスタンスから内部リソースへのリクエストが発生する

```rust
let base_url = if let Some(b) = &doc.base_url {
    b.clone()  // Discovery Document からの値をそのまま使用
} else {
    format!("{}{}", doc.root_url, doc.service_path)
};
```

URL 構築後、生成された `full_url` が `googleapis.com` ドメインであることの検証は行われていない。

**リスク**: Discovery Document のキャッシュ汚染により、SSRF やトークン漏洩 (Bearer トークンが任意のサーバーに送信される) が発生する可能性。

**推奨事項**:
- 構築した URL のホスト部分が許可リスト (例: `*.googleapis.com`) に含まれることを検証する
- Discovery Document のキャッシュファイルの整合性検証 (ハッシュ等) を実施する

---

### 11. [MEDIUM] Origin ヘッダー検証のバイパス可能性

**場所**: `src/mcp_server/http.rs` L95-L110 (`validate_origin`)

**説明**: Origin ヘッダーが存在しない場合、検証はスキップされて `true` を返す。

```rust
fn validate_origin(headers: &HeaderMap, allowed_origins: &[String]) -> bool {
    let origin = match headers.get("origin").and_then(|v| v.to_str().ok()) {
        Some(o) => o,
        None => return true,  // Origin ヘッダーなし → 許可
    };
    // ...
}
```

ブラウザベースのクライアントは必ず Origin ヘッダーを送信するが、非ブラウザクライアント (curl, AI エージェントの直接 HTTP 呼び出し) は Origin ヘッダーを送信しない。MCP Gateway は主に AI エージェントからの利用を想定しており、ブラウザ CSRF 攻撃はこのユースケースでは主要な脅威ではない。

また、`allowed_origins` が空の場合はローカルホストのみを許可するフォールバックロジックが存在するが、`starts_with` を使用しているため `http://localhost.evil.com` のような Origin がマッチする可能性がある。

```rust
lower.starts_with("http://localhost")  // "http://localhost.evil.com" もマッチする
```

**リスク**: `starts_with` による Origin 検証が不十分。ただし Bearer トークン認証が必須であるため、実質的な攻撃成功には別途トークン漏洩が必要。

**推奨事項**:
- `starts_with("http://localhost")` の代わりに、URL パース後にホスト名を厳密に比較する
- 例: `http://localhost`, `http://localhost:PORT` のみを許可

---

### 12. [INFO] handle_binary_response の output_path にパス検証がない

**場所**: `src/executor.rs` L303-L348 (`handle_binary_response`)

**説明**: `handle_binary_response` は `output_path` パラメータを受け取り、指定されたパスにファイルを書き込む。CLI モード (MCP Gateway 経由ではない) で使用される場合、`output_path` は `--output` CLI フラグから来る。

```rust
let file_path = if let Some(p) = output_path {
    PathBuf::from(p)  // パス検証なし
} else {
    let ext = mime_to_extension(content_type);
    PathBuf::from(format!("download.{ext}"))
};
```

MCP Gateway 経由の呼び出しでは `output_path` は `None` が渡されるため直接的なリスクはないが、CLI モードでは `--output /etc/cron.d/malicious` のようなパスが指定される可能性がある。

ただし、CLI モードでは AGENTS.md の記載通り「CLI arguments が AI エージェントから来る」シナリオが想定されているため、`validate_safe_output_dir` で検証すべき箇所である。

**推奨事項**: `--output` フラグの値に対して `validate_safe_output_dir` を適用することを検討する。ただし、CLI ユーザーが意図的に絶対パスを指定する正当なユースケースもあるため、MCP モード時のみ制限をかける設計が望ましい。

---

### 13. [INFO] API 識別子バリデーションの適用範囲

**場所**: `src/validate.rs` L227-L242 (`validate_api_identifier`)

**説明**: `validate_api_identifier` は API 名・バージョン文字列に対して英数字・ハイフン・アンダースコア・ドットのみを許可する厳密なバリデーションを提供する。これにより、Discovery Document の URL 構築やキャッシュファイル名へのインジェクションが防止される。

**評価**: 適切な許可リスト方式の実装。

---

## チェックリスト結果

| チェック項目 | 結果 | 詳細 |
|-------------|------|------|
| パストラバーサル防止 | 良好 | `validate.rs` に包括的なヘルパーあり。MCP upload パスは独自実装 (発見事項 #6) |
| URL インジェクション防止 | 良好 | `encode_path_segment` / `validate_resource_name` / reqwest `.query()` の活用 (発見事項 #3, #4) |
| JSON パース時のバリデーション | 良好 | Discovery Schema ベースの多層バリデーション (発見事項 #7) |
| リソース名バリデーション | 優秀 | `%` 拒否による URL エンコードバイパス防止を含む (発見事項 #5) |
| リクエストサイズ制限 | 要改善 | 明示的なボディサイズ制限・バッチサイズ制限なし (発見事項 #1, #2) |

---

## 発見事項サマリー

| # | 深刻度 | タイトル | 対応推奨 |
|---|--------|---------|---------|
| 1 | MEDIUM | リクエストボディサイズ制限の未設定 | 明示的な `DefaultBodyLimit` 設定 |
| 2 | MEDIUM | バッチリクエストサイズ上限なし | バッチサイズ制限の追加 |
| 3 | LOW | URL パステンプレート展開のエンコーディング (良好) | 現状維持 |
| 4 | LOW | クエリパラメータの reqwest 委任 (良好) | 現状維持 |
| 5 | INFO | validate.rs の包括的テスト (優秀) | 現状維持 |
| 6 | MEDIUM | MCP upload パス検証の不一致 | `validate.rs` のヘルパーに統一 |
| 7 | LOW | Discovery Schema ベースの JSON バリデーション (良好) | 現状維持 |
| 8 | LOW | JSON-RPC 構造検証 | 仕様準拠の強化を検討 |
| 9 | INFO | エラーレスポンスの情報最小化 | `GwsError::Display` 実装の確認 |
| 10 | HIGH | API ベース URL の検証不足 (SSRF リスク) | ホスト許可リスト検証の追加 |
| 11 | MEDIUM | Origin 検証の `starts_with` バイパス | URL パース後のホスト名厳密比較 |
| 12 | INFO | バイナリレスポンスの output_path 検証 | MCP モード時のパス制限検討 |
| 13 | INFO | API 識別子バリデーション (適切) | 現状維持 |

### 深刻度別集計

| 深刻度 | 件数 |
|--------|------|
| CRITICAL | 0 |
| HIGH | 1 |
| MEDIUM | 4 |
| LOW | 4 |
| INFO | 4 |

---

## 総合評価

gws-cli の入力検証・インジェクション対策は、**全体として良好に設計・実装されている**。

**強み**:
- `validate.rs` に集約された入力検証ヘルパー群は、AI エージェントからの敵対的入力を明示的に想定した多層防御を実現している
- URL パスセグメントのエンコーディングは `NON_ALPHANUMERIC` セットを使用した厳密なパーセントエンコードが適用されている
- リソース名検証は `%` 文字を拒否し、URL エンコードバイパスを防止している
- AGENTS.md に明確なガイドラインが記載され、開発者が正しいパターンを適用しやすい環境が整っている
- Discovery Document のスキーマに基づく JSON バリデーションが存在する

**改善が必要な領域**:
- MCP Gateway のリクエストサイズ制限 (DoS 耐性)
- MCP upload パス検証の `validate.rs` ヘルパーへの統一
- Discovery Document の base_url に対するホスト許可リスト検証 (SSRF 防止)
- Origin 検証ロジックの厳密化
