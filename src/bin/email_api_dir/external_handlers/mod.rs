// external_handlers — split par domaine
pub(crate) mod openapi;
pub(crate) mod accounts;
pub(crate) mod folders;
pub(crate) mod sync;

pub(crate) use openapi::*;
pub(crate) use accounts::*;
pub(crate) use folders::*;
pub(crate) use sync::*;
