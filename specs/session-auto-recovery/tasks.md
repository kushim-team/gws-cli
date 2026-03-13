# Session Validation Removal: Tasks

- [x] Create specs directory
- [x] Remove `sessions` field from `AppState`
- [x] Delete `validate_session()` function
- [x] Simplify `handle_post()` — remove session validation, keep session_id generation
- [x] Simplify `handle_get()` — remove session validation
- [x] Simplify `handle_delete()` — auth check only
- [x] Update tests to reflect new behavior
- [x] Remove tests for deleted functionality
- [x] Run clippy + tests (all 33 pass)
- [x] Create changeset
