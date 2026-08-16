#![allow(unused_imports, dead_code)]
use super::super::*;

// --- Calendar types ---

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExternalMessagesQuery {
    pub(crate) account_id: String,
    pub(crate) folder: Option<String>,
    pub(crate) page: Option<u64>,
    pub(crate) page_size: Option<u64>,
}



// ─── Admin misc (security_posture, deliverability, observability) ───

