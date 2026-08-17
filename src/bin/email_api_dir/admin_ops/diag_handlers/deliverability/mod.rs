#![allow(unused_imports, dead_code)]
pub mod diagnostics;
pub mod procedure;
pub mod procedure_update;

pub(crate) use diagnostics::api_admin_deliverability_diagnostics;
pub(crate) use procedure::api_admin_deliverability_procedure;
pub(crate) use procedure_update::api_admin_deliverability_procedure_update;
