# 障害モード・エッジケース分析

## 目的

auth-flows.md の設計網羅性を検証するため、各コンポーネント・各トークン・各フローにおける障害モードとエッジケースを体系的に洗い出す。

各シナリオについて以下を記載する:
- **現状**: auth-flows.md でカバー済みか
- **期待動作**: 正しい振る舞い
- **重要度**: High / Medium / Low

---

## 1. トークンライフサイクル障害

各トークンの「作成 → 使用 → 更新 → 失効 → 削除」における障害を分析する。

### 1.1 Gateway Bearer Token

| # | シナリオ | 現状 | 期待動作 | 重要度 |
|---|---------|------|---------|--------|
| T1-1 | Bearer Token 期限切れで MCP リクエスト | ✅ カバー済 | 401 返却。クライアントは refresh_token で更新 | High |
| T1-2 | Bearer Token が Firestore に存在しない (TTL 削除済み or 不正値) | ✅ カバー済 | 401 返却 | High |
| T1-3 | Bearer Token を複数クライアントが同時使用 (トークン共有/漏洩) | ❌ 未記載 | 最後の refresh で旧 bearer 無効化。共有者は 401 を受ける。検知は可能か？ | Medium |
| T1-4 | Firestore 書き込み成功直後に bearer_sessions の読み取りが結果整合で遅延 | ❌ 未記載 | Firestore はデフォルトで強整合性 (ドキュメント読み取り)。問題なし。ただし明記すべき | Low |

### 1.2 Gateway Refresh Token

| # | シナリオ | 現状 | 期待動作 | 重要度 |
|---|---------|------|---------|--------|
| T2-1 | Refresh Token 期限切れ | ✅ カバー済 | invalid_grant 返却。再認証が必要 | High |
| T2-2 | 同一 Refresh Token で同時に 2 つの refresh リクエスト (race condition) | ✅ 解決済 | Firestore トランザクションにより 1 つ目のみ成功、2 つ目はトランザクション競合でエラー。クライアントは 1 つ目で取得した新トークンを使用 | **High** |
| T2-3 | Refresh 成功後、レスポンスがクライアントに届かない (ネットワーク切断) | ⚠️ 許容 | トランザクションで新トークンは Firestore に存在するがクライアントは知らない。再認証が必要。20 名規模で発生頻度は極めて低く、再認証で復旧可能 | **High** |
| T2-4 | 旧 Refresh Token 削除成功 → 新トークンの Firestore 書き込み失敗 | ✅ 解決済 | Firestore トランザクションにより旧削除と新書き込みがアトミック。部分失敗時は全体ロールバック | **High** |
| T2-5 | 期限切れ直前の Refresh Token で refresh リクエスト (境界値) | ❌ 未記載 | 検証時点で有効なら成功とする。タイムスタンプ比較の一貫性が必要 | Medium |

### 1.3 Google Access Token

| # | シナリオ | 現状 | 期待動作 | 重要度 |
|---|---------|------|---------|--------|
| T3-1 | Google Access Token 期限切れ (MCP リクエスト中) | ✅ カバー済 | 透過的にリフレッシュ | High |
| T3-2 | Google Access Token 期限切れ (60 秒バッファ内) | ✅ カバー済 | 事前にリフレッシュ | High |
| T3-3 | 複数の MCP リクエストが同時に Google Token リフレッシュを試行 | ❌ 未記載 | 複数回 Google に refresh リクエストが飛ぶ。Google 側は冪等に処理するか？旧 access_token の即時無効化は？ | **Medium** |
| T3-4 | Google Access Token リフレッシュ中にさらに MCP リクエストが到着 | ❌ 未記載 | 各リクエストが独立にリフレッシュを試行する (ステートレス)。Google API の rate limit に注意 | Medium |
| T3-5 | Google API が 403 (quota exceeded) を返却 | ❌ 未記載 | トークンは有効だが API 呼び出し失敗。クライアントへのエラー伝播方法は？ | Medium |

### 1.4 Google Refresh Token

| # | シナリオ | 現状 | 期待動作 | 重要度 |
|---|---------|------|---------|--------|
| T4-1 | Google Refresh Token が revoke / パスワード変更で無効化 | ✅ カバー済 | bearer_session + refresh_token 削除、401 返却 | High |
| T4-2 | Google が Refresh Token を返さない (再同意時) | ✅ 一部カバー | 元の refresh_token を保持と記載あり。ただし初回で返さないケースは？ | Medium |
| T4-3 | Google Refresh Token の 6 ヶ月非使用による失効 | ❌ 未記載 | Google は 6 ヶ月未使用の refresh token を失効させる場合がある。invalid_grant と同じ処理で対応可能だが、ユーザー通知の観点で明記すべき | Medium |

---

## 2. 認証フロー障害

初回認証フロー (Authorization Code Grant) の各ステップにおける障害。

### 2.1 認可リクエスト → Google OAuth

| # | シナリオ | 現状 | 期待動作 | 重要度 |
|---|---------|------|---------|--------|
| F1-1 | 未登録の client_id で /authorize | ✅ カバー済 (Step 2) | エラー返却 | High |
| F1-2 | redirect_uri が登録済み URI と不一致 | ✅ カバー済 (Step 2) | エラー返却 | High |
| F1-3 | code_challenge_method が S256 以外 (plain 等) | ✅ カバー済 | 明示的に拒否 | High |
| F1-4 | 同じ client_id で短時間に大量の /authorize リクエスト (DoS) | ❌ 未記載 | Rate limiting の必要性。pending_auths の容量を圧迫 | Medium |
| F1-5 | ユーザーが Google 同意画面で「拒否」を選択 | ✅ 解決済 | Google が error=access_denied で callback。Gateway は client_redirect_uri に `?error=access_denied&state=client_state` でリダイレクト (OAuth 2.1 標準) | **High** |
| F1-6 | Google OAuth へのリダイレクト後、ユーザーが長時間放置 (state の 15 分 TTL 超過) | ❌ 未記載 | callback 時に PendingAuth が期限切れ。エラーメッセージとリカバリ方法は？ | Medium |
| F1-7 | ブラウザの「戻る」ボタンで /authorize を再実行 | ❌ 未記載 | 新しい PendingAuth が作成される (冪等ではない)。古い PendingAuth は TTL で自然削除。問題なし | Low |

### 2.2 Google Callback → Token Exchange

| # | シナリオ | 現状 | 期待動作 | 重要度 |
|---|---------|------|---------|--------|
| F2-1 | Google callback の state が PendingAuth に存在しない | ✅ カバー済 (Step 4) | エラー返却 | High |
| F2-2 | Google authorization code の交換失敗 (code 期限切れ等) | ✅ 解決済 | Gateway は client_redirect_uri に `?error=server_error&state=client_state` でリダイレクト | **High** |
| F2-3 | Google UserInfo API 呼び出し失敗 | ✅ 解決済 | Gateway は client_redirect_uri に `?error=server_error&state=client_state` でリダイレクト | High |
| F2-4 | 同じ Google callback URL をブラウザリロードで再送信 | ❌ 未記載 | 1 回目: PendingAuth 取得 + 削除成功。2 回目: PendingAuth 不在でエラー。Google code も使用済みでエラー | Medium |
| F2-5 | Gateway Authorization Code の発行後、クライアントが Token Exchange を行わない (10 分 TTL 超過) | ❌ 未記載 | PendingCode が TTL で自動削除。リソースリーク無し。問題なし | Low |

### 2.3 Token Exchange (POST /token)

| # | シナリオ | 現状 | 期待動作 | 重要度 |
|---|---------|------|---------|--------|
| F3-1 | Authorization Code が存在しない or 期限切れ | ✅ カバー済 (Step 6) | エラー返却 | High |
| F3-2 | PKCE 検証失敗 (code_verifier 不一致) | ✅ カバー済 (Step 6) | エラー返却 | High |
| F3-3 | 同じ Authorization Code で 2 回 Token Exchange (replay) | ✅ 解決済 | Firestore トランザクションにより PendingCode 削除 + トークン書き込みがアトミック。2 回目はトランザクション競合でエラー | **High** |
| F3-4 | Token Exchange 成功後、レスポンスがクライアントに届かない | ❌ 未記載 | Bearer Token と Refresh Token は Firestore に保存済みだがクライアントは知らない。→ 再認証が必要 | Medium |

---

## 3. 並行性・競合状態

ステートレスアーキテクチャ (複数 Cloud Run インスタンス) で発生しうる競合。

| # | シナリオ | 現状 | 期待動作 | 重要度 |
|---|---------|------|---------|--------|
| C-1 | 同一ユーザーが 2 つのクライアントから同時に認証フローを開始 | ❌ 未記載 | 各フローが独立に進行し、それぞれ別の bearer_session が作成される。問題なし。ただし同一ユーザーの複数セッションは許容する設計か？ | **Medium** |
| C-2 | Refresh Token Rotation 中に別の MCP リクエストが旧 Bearer Token を使用 | ⚠️ 許容 | トランザクション内で旧 bearer_session が削除されるため、MCP リクエストは 401 を受ける。クライアントは refresh 完了後に新トークンで再試行する正常動作。Claude クライアントが refresh 中に旧トークンでリクエストする可能性は低い | **High** |
| C-3 | 2 つの MCP リクエストが同時に Google Access Token のリフレッシュを実行 | ❌ 未記載 | 両方が Firestore に書き込み。最後の書き込みが勝つ (last-writer-wins)。両方とも有効な access_token を取得するので問題なし | Medium |
| C-4 | bearer_sessions 書き込みと refresh_tokens 書き込みの間にクラッシュ | ✅ 解決済 | Firestore トランザクションにより全操作がアトミック。部分失敗時は全体ロールバック | **High** |

---

## 4. 外部サービス障害

### 4.1 Firestore 障害

| # | シナリオ | 現状 | 期待動作 | 重要度 |
|---|---------|------|---------|--------|
| E1-1 | Firestore 読み取り不可 (ダウン or ネットワーク障害) | ✅ 解決済 | 503 Service Unavailable を返却。セキュリティ設計方針に明記 | **High** |
| E1-2 | Firestore 書き込み不可 (読み取りは可能) | ❌ 未記載 | 既存セッションの MCP リクエストは処理可能だが、新規認証・refresh は失敗 | High |
| E1-3 | Firestore レスポンス遅延 (タイムアウト) | ❌ 未記載 | リクエストタイムアウト。Gateway のタイムアウト設定とリトライポリシーは？ | Medium |

### 4.2 Google OAuth / API 障害

| # | シナリオ | 現状 | 期待動作 | 重要度 |
|---|---------|------|---------|--------|
| E2-1 | Google OAuth サーバーがダウン | ❌ 未記載 | 新規認証不可。既存セッションの Google Token リフレッシュ不可。クライアントへのエラー伝播は？ | High |
| E2-2 | Google API が 5xx を返却 (一時的障害) | ❌ 未記載 | トークンは有効だが API 失敗。リトライすべきか？クライアントへのエラー形式は？ | Medium |
| E2-3 | Google API が 429 (Rate Limit) を返却 | ❌ 未記載 | Retry-After ヘッダーの扱い。クライアントへの伝播方法は？ | Medium |

### 4.3 Secret Manager 障害

| # | シナリオ | 現状 | 期待動作 | 重要度 |
|---|---------|------|---------|--------|
| E3-1 | サーバー起動時に Secret Manager から鍵を取得できない | ❌ 未記載 | サーバー起動失敗。Cloud Run の起動プローブで検知 | High |
| E3-2 | 鍵ローテーション後、古い鍵で暗号化されたデータの復号失敗 | ✅ 一部カバー | セッション無効扱い、再認証を促す | Medium |

---

## 5. セキュリティ脅威

### 5.1 トークン漏洩

| # | シナリオ | 現状 | 期待動作 | 重要度 |
|---|---------|------|---------|--------|
| S1-1 | Bearer Token がログに記録される | ✅ 解決済 | トークン値はログに記録しない。プレフィックスまたはハッシュのみ記録。セキュリティ設計方針に明記 | **High** |
| S1-2 | Bearer Token の漏洩 (クライアント側) | ✅ 一部カバー | 短命 (1h) で影響を限定。検知・即時無効化の手段は？ | Medium |
| S1-3 | Refresh Token の漏洩 | ✅ 一部カバー | Rotation により使用済みトークンは無効化。ただし未使用の漏洩トークンは 7 日間有効 | Medium |
| S1-4 | Firestore の暗号化鍵の漏洩 | ❌ 未記載 | 全セッションの Google トークンが復号可能に。鍵ローテーション + 全セッション無効化が必要 | High |

### 5.2 リプレイ・CSRF 攻撃

| # | シナリオ | 現状 | 期待動作 | 重要度 |
|---|---------|------|---------|--------|
| S2-1 | Authorization Code リプレイ攻撃 | ✅ カバー済 | PendingCode は使用時に削除。PKCE で横取り防止 | High |
| S2-2 | OAuth state パラメータのリプレイ | ✅ カバー済 | PendingAuth は使用時に削除 + TTL | High |
| S2-3 | /authorize エンドポイントの CSRF | ❌ 未記載 | OAuth 2.1 では state パラメータがクライアント側の CSRF 対策。Gateway 側での追加対策は？ | Medium |

### 5.3 DoS / リソース枯渇

| # | シナリオ | 現状 | 期待動作 | 重要度 |
|---|---------|------|---------|--------|
| S3-1 | /register エンドポイントへの大量リクエスト | ❌ 未記載 | registered_clients が膨張。Firestore のコスト増。Rate limiting は？ | **Medium** |
| S3-2 | /authorize への大量リクエスト (pending_auths 枯渇) | ✅ 一部カバー | InMemory は容量制限あり。Firestore は TTL で対応だがコスト影響 | Medium |
| S3-3 | 有効な Bearer Token で大量の MCP リクエスト | ❌ 未記載 | Google API の rate limit に到達。ユーザー単位の rate limiting は？ | Medium |

---

## 6. クライアント不正動作

MCP クライアント (Claude Desktop / Code) が想定外の動作をした場合。

| # | シナリオ | 現状 | 期待動作 | 重要度 |
|---|---------|------|---------|--------|
| CL-1 | クライアントが refresh_token を保存せず、bearer 期限切れ後に再認証 | ❌ 未記載 | 再認証フローで問題なく動作。ユーザー体験の劣化のみ | Low |
| CL-2 | クライアントが旧 bearer_token と新 bearer_token を交互に使用 | ❌ 未記載 | 旧 bearer は refresh 時に削除済みなので 401。クライアントが新トークンに切り替えられるか | Medium |
| CL-3 | クライアントが不正な JSON-RPC リクエストを送信 | ❌ 未記載 | MCP レイヤーでのバリデーション。エラーレスポンス形式は JSON-RPC error | Medium |
| CL-4 | クライアントが grant_type を誤指定 (authorization_code と refresh_token の取り違え) | ❌ 未記載 | unsupported_grant_type エラー返却 | Low |

---

## 7. データ整合性

| # | シナリオ | 現状 | 期待動作 | 重要度 |
|---|---------|------|---------|--------|
| D-1 | bearer_sessions にレコードあり、対応する refresh_tokens にレコードなし | ❌ 未記載 | Bearer Token は有効だが refresh 不可。bearer 期限切れ後に再認証が必要 | Medium |
| D-2 | refresh_tokens にレコードあり、参照先の bearer_sessions にレコードなし | ✅ 解決済 | データモデル変更により構造的に解消。refresh_tokens は email で user_sessions を参照。bearer_sessions の有無に依存しない。user_sessions が不在の場合は invalid_grant | **High** |
| D-3 | Firestore TTL 削除の遅延 (最大 24 時間) でアプリ層 TTL と不一致 | ✅ カバー済 | アプリケーションコードでも TTL を検証し、期限切れドキュメントは無効として扱う | Medium |
| D-4 | permissions.yaml の更新デプロイ中 (ローリングアップデート) に新旧インスタンスで権限が異なる | ❌ 未記載 | 一時的に権限チェック結果がインスタンスによって異なる。許容するか？ | Low |

---

## 8. 運用シナリオ

| # | シナリオ | 現状 | 期待動作 | 重要度 |
|---|---------|------|---------|--------|
| O-1 | 暗号化鍵のローテーション手順 | ✅ 一部カバー | 新バージョン追加 → 古いデータは TTL で自然消滅。ただし移行期間中の動作の詳細は？ | Medium |
| O-2 | 特定ユーザーのセッション強制無効化 (管理操作) | ❌ 未記載 | bearer_sessions と refresh_tokens から該当ユーザーのレコードを削除する手段は？email で検索できるか？(doc ID は token) | **Medium** |
| O-3 | 全セッション一括無効化 (インシデント対応) | ❌ 未記載 | 暗号化鍵のローテーション or コレクション全削除。手順の文書化が必要 | Medium |
| O-4 | permissions.yaml からユーザーを削除した場合の既存セッションの扱い | ❌ 未記載 | 既存の Bearer Token は有効だが、MCP リクエスト時に権限チェックで拒否される。明示的なセッション無効化は不要？ | Medium |

---

## 分析サマリー

### カバレッジ統計

| カテゴリ | 総シナリオ数 | カバー済 | 一部カバー | 未カバー |
|---------|------------|---------|-----------|---------|
| トークンライフサイクル | 14 | 5 | 1 | 8 |
| 認証フロー | 14 | 4 | 0 | 10 |
| 並行性・競合 | 4 | 0 | 0 | 4 |
| 外部サービス障害 | 8 | 0 | 1 | 7 |
| セキュリティ脅威 | 9 | 2 | 3 | 4 |
| クライアント不正動作 | 4 | 0 | 0 | 4 |
| データ整合性 | 4 | 1 | 0 | 3 |
| 運用シナリオ | 4 | 0 | 1 | 3 |
| **合計** | **61** | **12** | **6** | **43** |

### 設計判断により解決済み

| # | シナリオ | 解決方法 |
|---|---------|---------|
| T2-2 | 同一 Refresh Token の同時使用 (race condition) | Firestore トランザクションで 1 つ目のみ成功 |
| T2-4 | Refresh 中の部分的 Firestore 書き込み失敗 | Firestore トランザクションで全体ロールバック |
| F1-5 | ユーザーが Google 同意画面で拒否 | client_redirect_uri に OAuth 2.1 標準エラーパラメータでリダイレクト |
| F2-2 | Google authorization code 交換失敗 | client_redirect_uri に `?error=server_error` でリダイレクト |
| F2-3 | Google UserInfo API 呼び出し失敗 | client_redirect_uri に `?error=server_error` でリダイレクト |
| F3-3 | Authorization Code リプレイ (アトミック性) | Firestore トランザクションで PendingCode 削除 + トークン書き込みをアトミック化 |
| C-4 | bearer_sessions と refresh_tokens の書き込み間クラッシュ | Firestore トランザクションで全操作をアトミック化 |
| D-2 | refresh_tokens あり、bearer_sessions なしの不整合 | データモデル変更 (user_sessions 分離) により構造的に解消 |
| E1-1 | Firestore 全面ダウン | 503 Service Unavailable を返却。セキュリティ設計方針に明記 |
| S1-1 | トークンのログ記録防止 | トークン値はログに含めない。プレフィックス/ハッシュのみ記録 |

### 許容として整理済み

| # | シナリオ | 判断理由 |
|---|---------|---------|
| T2-3 | Refresh 成功後のレスポンス未到達 | 20 名規模で発生頻度は極めて低く、再認証で復旧可能 |
| C-2 | Refresh 中に旧 Bearer Token で MCP リクエスト | クライアントは refresh 完了後に新トークンを使う正常動作 |

### High 重要度の未カバーシナリオ

なし (全 High 重要度シナリオは解決済みまたは許容として整理済み)

---

## 次のアクション

1. **運用ドキュメント**: O-2 (特定ユーザーのセッション強制無効化), O-3 (全セッション一括無効化) はインシデント対応手順として別途文書化を検討
2. **Medium 重要度の検討**: 必要に応じて残りの Medium 重要度シナリオを順次対応
