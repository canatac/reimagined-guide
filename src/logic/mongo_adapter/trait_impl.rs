// mongo_adapter/trait_impl.rs — implémentation du trait `DatabaseInterface`
// pour `MongoDatabaseAdapter`. Les corps de méthodes sont regroupés par domaine
// dans `trait_impl_parts/` et inclus ici via `include!` pour rester sous 250 LOC.

use super::MongoDatabaseAdapter;
use crate::entities::{CalendarEvent, Email};
use crate::logic::{DatabaseInterface, Mailbox, User};
use async_trait::async_trait;
use mongodb::bson;
use mongodb::error::Result;

#[async_trait]
impl DatabaseInterface for MongoDatabaseAdapter {
    include!("trait_impl_parts/users.rs");
    include!("trait_impl_parts/email.rs");
    include!("trait_impl_parts/mailbox.rs");
    include!("trait_impl_parts/calendar.rs");
}
