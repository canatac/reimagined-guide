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

/// Port message store / flags — opérations IMAP sur séquences de messages.
///
/// Cycle 27 : 6ème port migré depuis `DatabaseInterface`
/// (`src/logic/traits.rs`). Autonome : signatures 100 % primitives
/// (`&str`, `Vec<String>`, `Vec<u32>`) — aucun type infrastructure.
/// Regroupe les opérations IMAP au niveau messages : SEARCH,
/// EXPUNGE, COPY, STORE flags.
#[async_trait]
pub trait MessageStoreFlagsPort: Send + Sync {
    /// IMAP SEARCH — retourne les UIDs matchant `criteria`.
    async fn search_messages(&self, criteria: &str) -> DomainResult<Vec<u32>>;
    /// IMAP EXPUNGE — purge les messages `\Deleted` et retourne leurs séquences.
    async fn expunge_mailbox(&self) -> DomainResult<Vec<u32>>;
    /// IMAP COPY — copie `sequence_set` vers `target_mailbox`.
    async fn copy_messages(&self, sequence_set: &str, target_mailbox: &str) -> DomainResult<()>;
    /// IMAP STORE — applique `flags` sur `sequence_set` selon `mode` (`+FLAGS` / `-FLAGS` / `FLAGS`).
    async fn store_flags(
        &self,
        sequence_set: &str,
        flags: Vec<String>,
        mode: &str,
    ) -> DomainResult<()>;
}

/// Port lecture emails — requêtes read-only sur emails/mailboxes.
///
/// Cycle 28 : 7ème port migré depuis `DatabaseInterface`
/// (`src/logic/traits.rs`). Autonome : dépend uniquement de
/// `Email` (type domaine pur) et primitives (`&str`). Regroupe
/// les opérations IMAP de lecture emails : FETCH par mailbox / par id.
#[async_trait]
pub trait EmailQueryPort: Send + Sync {
    /// Liste tous les emails de `mailbox`.
    async fn find_emails(&self, mailbox: &str) -> DomainResult<Vec<crate::Email>>;
    /// Récupère un email par son `email_id`, ou `None` s'il n'existe pas.
    async fn find_email(&self, email_id: &str) -> DomainResult<Option<crate::Email>>;
}

/// Port autonome pour la lecture des comptes IMAP externes.
///
/// Port hexagonal (cycle 29, 8ème port) exposant les opérations de
/// **lecture** sur `ExternalImapAccount`. Autonome : dépend uniquement
/// du type domaine `ExternalImapAccount` et de primitives (`&str`).
/// Sépare les responsabilités de query côté domaine des couches
/// d'infrastructure (MongoDB, cache, etc.).
#[async_trait]
pub trait ExternalImapAccountQueryPort: Send + Sync {
    /// Récupère un compte IMAP externe par son `id`, ou `None` s'il n'existe pas.
    async fn find_external_imap_account(
        &self,
        id: &str,
    ) -> DomainResult<Option<crate::ExternalImapAccount>>;
    /// Liste tous les comptes IMAP externes appartenant à `owner_user_id`.
    async fn list_external_imap_accounts_by_owner(
        &self,
        owner_user_id: &str,
    ) -> DomainResult<Vec<crate::ExternalImapAccount>>;
}

/// Port autonome pour lister les mailboxes IMAP d'un utilisateur.
///
/// Port hexagonal (cycle 31, 9ème port) exposant l'opération LIST IMAP.
/// Autonome : dépend uniquement de primitives (`&str`, `String`).
/// Sépare la logique de listing mailbox de l'infrastructure de stockage
/// (MongoDB, filesystem Maildir, etc.).
#[async_trait]
pub trait MailboxListPort: Send + Sync {
    /// Liste les mailboxes de `username` matchant `reference`/`mailbox`
    /// (sémantique IMAP LIST — wildcards `%` et `*` supportés côté impl).
    async fn list_mailboxes(
        &self,
        username: &str,
        reference: &str,
        mailbox: &str,
    ) -> DomainResult<Vec<String>>;
}

/// Port user alias / locale — opérations administratives sur utilisateurs.
///
/// Cycle 30 : 10ème port migré depuis `DatabaseInterface`. Autonome :
/// signatures 100 % primitives (`&str`), aucun type infrastructure.
#[async_trait]
pub trait UserAliasPort: Send + Sync {
    async fn create_alias(&self, alias: &str, target: &str) -> DomainResult<()>;
    async fn update_user_locale(&self, username: &str, locale: &str) -> DomainResult<()>;
}

/// Port user registration — création + authentification comptes.
///
/// Cycle 32 : 10ème port autonome (post cycle31 MailboxListPort). Signatures
/// 100 % primitives (`&str` / `bool`), aucun type infrastructure. Concrètement
/// couvre les opérations `create_user` + `authenticate_user` de la couche
/// `DatabaseInterface` historique.
#[async_trait]
pub trait UserRegistrationPort: Send + Sync {
    /// Crée un utilisateur (username + password + mailbox par défaut).
    async fn register_user(
        &self,
        username: &str,
        password: &str,
        mailbox: &str,
    ) -> DomainResult<()>;

    /// Authentifie (`true` si credentials valides).
    async fn verify_credentials(
        &self,
        username: &str,
        password: &str,
    ) -> DomainResult<bool>;
}

/// Port message search — recherche IMAP SEARCH.
///
/// Cycle 33 : 12ème port autonome. Signatures 100 % primitives (`&str`, `u32`).
/// Couvre l'opération `search_messages` de la couche `DatabaseInterface`
/// historique (sémantique IMAP SEARCH — retourne les UIDs matchant).
#[async_trait]
pub trait MessageSearchPort: Send + Sync {
    /// Recherche les messages correspondant à `criteria` (syntaxe IMAP SEARCH).
    /// Retourne la liste des UIDs matchant.
    async fn search_messages(&self, criteria: &str) -> DomainResult<Vec<u32>>;
}
