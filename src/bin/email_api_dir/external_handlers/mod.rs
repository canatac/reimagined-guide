// external_handlers — split par domaine
pub(crate) mod accounts;
pub(crate) mod calendar;
pub(crate) mod folders;
pub(crate) mod holidays;
pub(crate) mod import_wizard;
pub(crate) mod openapi;
pub(crate) mod sync;

pub(crate) use accounts::*;
pub(crate) use calendar::*;
pub(crate) use folders::*;
pub(crate) use holidays::*;
pub(crate) use import_wizard::*;
pub(crate) use openapi::*;
pub(crate) use sync::*;
