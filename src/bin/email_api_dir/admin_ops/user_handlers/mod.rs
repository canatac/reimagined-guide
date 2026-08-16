// Split cohérent de user_handlers en trois sous-modules :
// - crud     : CRUD AdminUserRecord + whoami
// - audit    : audit trail (log_admin_action + api_admin_audit_log)
// - lifecycle: invite / reset-password / revoke-sessions
//
// Les re-exports pub(crate) préservent la surface publique : `use
// admin_ops::user_handlers::*;` continue à voir tous les symboles.

pub(crate) mod audit;
pub(crate) mod crud;
pub(crate) mod lifecycle;

pub(crate) use audit::*;
pub(crate) use crud::*;
pub(crate) use lifecycle::*;
