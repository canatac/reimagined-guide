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
///
/// Correspond à l'ancien `LogicTrait` de `src/logic/traits.rs`, mais
/// s'exprime en termes de `DomainResult` pour rester indépendant de
/// l'infrastructure. Les adapters (ex. `Logic` côté crate racine)
/// implémentent ce port en convertissant leurs erreurs concrètes via
/// `From<mongodb::Error> for DomainError`.
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
///
/// Cycle 23 : extrait de `DatabaseInterface` (`src/logic/traits.rs`).
/// Ces trois primitives ne dépendent d'aucun type infrastructure et
/// constituent la 2ème migration hexagonale (Phase 3).
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
///
/// Cycle 24 : 3ème port migré depuis `DatabaseInterface`
/// (`src/logic/traits.rs`). Autonome : signatures 100 % primitives
/// (`&str`) et pas de types infrastructure. Couvre la variante
/// non-user-scopée héritée ; les variantes `*_for_user` restent pour
/// une migration ultérieure.
#[async_trait]
pub trait MailboxSubscriptionPort: Send + Sync {
    /// IMAP SUBSCRIBE — ajoute la mailbox à la liste des abonnements.
    async fn subscribe_mailbox(&self, mailbox: &str) -> DomainResult<()>;
    /// IMAP UNSUBSCRIBE — retire la mailbox de la liste des abonnements.
    async fn unsubscribe_mailbox(&self, mailbox: &str) -> DomainResult<()>;
}

/// Port CRUD mailbox — création / suppression / renommage (non user-scopé).
///
/// Cycle 25 : 4ème port migré depuis `DatabaseInterface`
/// (`src/logic/traits.rs`). Signatures 100 % primitives (`&str`),
/// aucune dépendance à mongodb / bson / entities. Couvre les
/// variantes historiques non user-scopées ; les `*_for_user`
/// correspondantes restent pour un cycle ultérieur.
#[async_trait]
pub trait MailboxCrudPort: Send + Sync {
    /// CREATE — crée une mailbox par nom.
    async fn create_mailbox(&self, mailbox: &str) -> DomainResult<()>;
    /// DELETE — supprime une mailbox par nom.
    async fn delete_mailbox(&self, mailbox: &str) -> DomainResult<()>;
    /// RENAME — renomme une mailbox (`old_name` → `new_name`).
    async fn rename_mailbox(&self, old_name: &str, new_name: &str) -> DomainResult<()>;
}
