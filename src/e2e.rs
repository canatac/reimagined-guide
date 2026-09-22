// e2e.rs — E2E key management module.
// Zero-knowledge: server stores only encrypted blobs and public keys.

pub mod handlers;
pub mod mongo_adapter;

pub use handlers::*;
pub use mongo_adapter::E2EMongoAdapter;
