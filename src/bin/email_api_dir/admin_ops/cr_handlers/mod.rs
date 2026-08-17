// cr_handlers/ — Change Request handlers split by HTTP verb (cycle 18)
#![allow(unused_imports, dead_code)]

pub mod read;
pub mod create;
pub mod patch;
pub mod patch_helpers;
pub mod delete;

pub use read::*;
pub use create::*;
pub use patch::*;
pub use delete::*;

// --- AI settings (Phase B1, issue #173) ----------------------------------------
pub(crate) const AI_SETTINGS_ID: &str = "global";
pub(crate) const DEFAULT_AI_MODEL: &str = "qwen/qwen3.7-flash";
