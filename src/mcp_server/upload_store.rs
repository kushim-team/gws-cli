// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Temporary in-memory upload store for the MCP Gateway.
//!
//! MCP clients upload files via `POST /upload` and receive an `upload_id`.
//! That ID is then passed to media-upload MCP tools via the `upload_ref`
//! parameter. Entries expire after a configurable TTL and are consumed
//! (removed) on first use.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Default time-to-live for uploaded files (10 minutes).
const DEFAULT_TTL: Duration = Duration::from_secs(600);

/// Maximum upload size (50 MiB).
pub const MAX_UPLOAD_SIZE: usize = 50 * 1024 * 1024;

pub struct UploadEntry {
    pub data: Vec<u8>,
    pub content_type: String,
    created_at: Instant,
}

/// In-memory store for temporary file uploads.
///
/// Thread safety is handled by the caller wrapping this in a
/// `tokio::sync::Mutex`.
pub struct UploadStore {
    entries: HashMap<String, UploadEntry>,
    ttl: Duration,
}

impl UploadStore {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            ttl: DEFAULT_TTL,
        }
    }

    /// Store upload data and return a unique ID.
    pub fn insert(&mut self, data: Vec<u8>, content_type: String) -> String {
        self.evict_expired();
        let id = uuid::Uuid::new_v4().to_string();
        self.entries.insert(
            id.clone(),
            UploadEntry {
                data,
                content_type,
                created_at: Instant::now(),
            },
        );
        id
    }

    /// Take (consume) an upload entry by ID. Returns `None` if the ID
    /// doesn't exist or has expired.
    pub fn take(&mut self, id: &str) -> Option<UploadEntry> {
        let entry = self.entries.remove(id)?;
        if entry.created_at.elapsed() > self.ttl {
            return None;
        }
        Some(entry)
    }

    /// Remove entries older than TTL.
    fn evict_expired(&mut self) {
        let ttl = self.ttl;
        self.entries
            .retain(|_, entry| entry.created_at.elapsed() <= ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_take() {
        let mut store = UploadStore::new();
        let id = store.insert(b"hello".to_vec(), "text/plain".to_string());
        let entry = store.take(&id).unwrap();
        assert_eq!(entry.data, b"hello");
        assert_eq!(entry.content_type, "text/plain");
        // Second take should return None (consumed)
        assert!(store.take(&id).is_none());
    }

    #[test]
    fn test_take_nonexistent() {
        let mut store = UploadStore::new();
        assert!(store.take("nonexistent").is_none());
    }

    #[test]
    fn test_expired_entries_evicted() {
        let mut store = UploadStore {
            entries: HashMap::new(),
            ttl: Duration::from_millis(0),
        };
        let id = store.insert(b"data".to_vec(), "application/octet-stream".to_string());
        // Entry should be expired immediately
        assert!(store.take(&id).is_none());
    }
}
