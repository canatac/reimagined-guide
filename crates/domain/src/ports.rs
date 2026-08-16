//! Ports du domaine — interfaces d'inversion pures (aucun import externe).
//!
//! Cycle 22 : premier port migré depuis `src/logic/traits.rs` (`LogicPort`).
//! Cycle 23 : deuxième port migré — `MailboxSessionPort` (sous-ensemble
//! autonome de `DatabaseInterface` couvrant les opérations de session
//! IMAP sans argument : NOOP, CLOSE, CHECK). Choisi car totalement
//! indépendant de tout type externe (mongodb / bson / entities).

use crate::errors::DomainResult;
use async_trait::async_trait;

/// Port applicatif — orchestration de haut niveau (use-cases).
#[async_trait]
pub trait LogicPort: Send + Sync {
    async fn create_user(
        &self,
        username: &str,
        password: &str,
        mailbox: &str,
    ) -> DomainResult<()>;
}

/// Port session mailbox — opérations IMAP sans argument.
#[async_trait]
pub trait MailboxSessionPort: Send + Sync {
    /// IMAP NOOP — keep-alive / poll d'état.
    async fn noop(&self) -> DomainResult<()>;
    /// IMAP CLOSE — ferme la mailbox sélectionnée sans EXPUNGE explicite.
    async fn close_mailbox(&self) -> DomainResult<()>;
    /// IMAP CHECK — flush de l'état de la mailbox courante.
    async fn check_mailbox(&self) -> DomainResult<()>;
}

/// Port souscription mailbox — IMAP SUBSCRIBE / UNSUBSCRIBE.
#[async_trait]
pub trait MailboxSubscriptionPort: Send + Sync {
    /// IMAP SUBSCRIBE — ajoute la mailbox à la liste des abonnements.
    async fn subscribe_mailbox(&self, mailbox: &str) -> DomainResult<()>;
    /// IMAP UNSUBSCRIBE — retire la mailbox de la liste des abonnements.
    async fn unsubscribe_mailbox(&self, mailbox: &str) -> DomainResult<()>;
}

/// Port mutation email — opérations sur un email identifié par id.
///
/// Cycle 25 (a) : 4ème port migré depuis `DatabaseInterface`.
/// Autonome : signatures 100 % primitives (`&str`).
#[async_trait]
pub trait EmailMutationPort: Send + Sync {
    /// Met à jour un flag IMAP sur l'email `email_id`.
    async fn update_email_flag(&self, email_id: &str, flag: &str) -> DomainResult<()>;
    /// Supprime l'email `email_id`.
    async fn delete_email(&self, email_id: &str) -> DomainResult<()>;
    /// Archive l'email `email_id`.
    async fn archive_email(&self, email_id: &str) -> DomainResult<()>;
}

/// Port CRUD mailbox — création / suppression / renommage.
///
/// Cycle 26 : 5ème port migré depuis `DatabaseInterface`
/// (`src/logic/traits.rs`). Autonome : signatures 100 % primitives
/// (`&str`) et aucun type infrastructure. Regroupe les opérations
/// structurelles sur une mailbox (variante non user-scopée).
#[async_trait]
pub trait MailboxCrudPort: Send + Sync {
    /// IMAP CREATE — crée la mailbox `mailbox`.
    async fn create_mailbox(&self, mailbox: &str) -> DomainResult<()>;
    /// IMAP DELETE — supprime la mailbox `mailbox`.
    async fn delete_mailbox(&self, mailbox: &str) -> DomainResult<()>;
    /// IMAP RENAME — renomme `old_name` vers `new_name`.
    async fn rename_mailbox(&self, old_name: &str, new_name: &str) -> DomainResult<()>;
}


