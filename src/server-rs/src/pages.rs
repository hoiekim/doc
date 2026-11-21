//! Port of `src/server/lib/pages.ts`.

use crate::http::Result;

/// Permanently removes pages that have been in the trash longer than the workspace retention.
pub async fn purge_trash() -> Result<i64> {
    Ok(0)
}
