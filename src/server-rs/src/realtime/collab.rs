//! Port of `src/server/realtime/collab.ts` (the page sessions; filled in once
//! the document model's `Authority` is in place).

use serde_json::{Map, Value};

use super::hub::SocketRef;
use crate::http::Result;

pub async fn join_page(_ws: &SocketRef, _page_id: Option<&Value>, _version: Option<&Value>, _client_id: Option<&Value>) -> Result<()> {
    Ok(())
}

pub async fn leave_page(_ws: &SocketRef, _page_id: Option<&Value>) -> Result<()> {
    Ok(())
}

pub async fn receive_steps(_ws: &SocketRef, _message: &Map<String, Value>) -> Result<()> {
    Ok(())
}

pub async fn update_presence(_ws: &SocketRef, _message: &Map<String, Value>) -> Result<()> {
    Ok(())
}

pub async fn disconnect(_ws: &SocketRef) -> Result<()> {
    Ok(())
}

pub async fn flush_all() -> Result<()> {
    Ok(())
}

/// Which open editors to re-check: `None` is "all".
#[derive(Default)]
pub struct Recheck {
    pub user_ids: Option<Vec<String>>,
    pub page_ids: Option<Vec<String>>,
}

pub async fn refresh_open_sessions(_which: Recheck) -> Result<()> {
    Ok(())
}
