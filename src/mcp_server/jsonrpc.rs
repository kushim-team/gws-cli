use crate::error::GwsError;
use serde_json::{json, Value};

pub(super) fn build_jsonrpc_response(id: &Value, result: Result<Value, GwsError>) -> Value {
    match result {
        Ok(res) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": res
        }),
        Err(e) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32603,
                "message": e.to_string()
            }
        }),
    }
}

pub(super) fn build_parse_error_response() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": Value::Null,
        "error": {
            "code": -32700,
            "message": "Parse error"
        }
    })
}
