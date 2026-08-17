//! Ports du domaine — interfaces d'inversion pures (aucun import externe).
//!
//! Cycle 22 : premier port migré depuis `src/logic/traits.rs` (`LogicPort`).
//! Cycle 23 : deuxième port migré — `MailboxSessionPort` (sous-ensemble
//! autonome de `DatabaseInterface` couvrant les opérations de session
//! IMAP sans argument : NOOP, CLOSE, CHECK). Choisi car totalement
//! indépendant de tout type externe (mongodb / bson / entities).

use crate::errors::DomainResult;
use crate::Email;
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

/// Port calendrier — CRUD événements calendrier utilisateur.
///
/// Cycle 34 : 13ème port autonome. Signatures avec `CalendarEvent`
/// (type domaine pur) + primitives. Couvre les opérations calendar_*
/// de `DatabaseInterface`.
#[async_trait]
pub trait CalendarPort: Send + Sync {
    async fn create_calendar_event(&self, event: &crate::CalendarEvent) -> DomainResult<()>;
    async fn get_calendar_event(
        &self,
        username: &str,
        event_id: &str,
    ) -> DomainResult<Option<crate::CalendarEvent>>;
    async fn delete_calendar_event(
        &self,
        username: &str,
        event_id: &str,
    ) -> DomainResult<()>;
}

/// Port email store — persistance d'un email dans une mailbox utilisateur.
///
/// Cycle 34 : 13ème port autonome. Dépend uniquement du type domaine
/// `Email` et de primitives (`&str`). Couvre l'opération `store_email`
/// de la couche `DatabaseInterface` historique (APPEND IMAP côté domaine).
#[async_trait]
pub trait EmailStorePort: Send + Sync {
    /// Persiste `email` dans `mailbox` pour l'utilisateur `username`.
    async fn store_email(
        &self,
        username: &str,
        mailbox: &str,
        email: &crate::Email,
    ) -> DomainResult<()>;
}

/// Port mail event logging — journal des événements mail (delivered, sent, bounce, etc.).
///
/// Cycle 35 : 15ème port autonome. Signatures 100 % primitives (`&str`),
/// aucun type infrastructure. Couvre l'opération `log_mail_event` de la
/// couche `DatabaseInterface` historique.
#[async_trait]
pub trait MailEventLoggingPort: Send + Sync {
    /// Journalise un événement mail (kind = "delivered" | "sent" | "bounce" | ...).
    async fn log_mail_event(
        &self,
        kind: &str,
        user_id: &str,
        email_id: &str,
        subject: &str,
        from: &str,
        to: &str,
    ) -> DomainResult<()>;
}

/// Port email delivery — dépôt d'un email dans la boîte de réception d'un utilisateur.
///
/// Cycle 36 : 16ème port autonome. Signature 100 % types domaine (`Email`)
/// et primitives (`&str`), aucun type infrastructure. Couvre l'opération
/// `deliver_to_inbox` de la couche `DatabaseInterface` historique.
#[async_trait]
pub trait EmailDeliveryPort: Send + Sync {
    /// Dépose un email dans la boîte INBOX de `username`.
    async fn deliver_to_inbox(&self, username: &str, email: &Email) -> DomainResult<()>;
}

/// Port mailbox status — statut IMAP d'une mailbox (EXISTS, RECENT, UIDNEXT, UIDVALIDITY, UNSEEN).
///
/// Cycle 37 : 17ème port autonome. Signatures 100 % primitives (`&str`, `String`, `u32`).
/// Retourne soit un vecteur de couples clé/valeur (`get_mailbox_status_items`)
/// représentant la réponse IMAP STATUS, autonome et sans dépendance infrastructure.
#[async_trait]
pub trait MailboxStatusPort: Send + Sync {
    /// Récupère le statut d'une mailbox sous forme de couples (clé, valeur).
    ///
    /// Les clés typiques : `MESSAGES`, `RECENT`, `UIDNEXT`, `UIDVALIDITY`, `UNSEEN`.
    async fn get_mailbox_status_items(
        &self,
        username: &str,
        mailbox: &str,
    ) -> DomainResult<Vec<(String, String)>>;
}

/// Port OAuth user — find-or-create d'un utilisateur à partir d'une identité OAuth.
///
/// Cycle 38 : 18ème port autonome. Signatures 100 % primitives (`&str`, `String`),
/// aucun type infrastructure ni dépendance à un type domaine `User` (non exporté).
/// Retourne l'identifiant utilisateur (username) créé ou déjà existant.
#[async_trait]
pub trait OAuthUserPort: Send + Sync {
    /// Récupère ou crée un utilisateur pour l'identité OAuth `(provider, subject)`.
    ///
    /// Retourne le `username` de l'utilisateur.
    async fn find_or_create_oauth_user(
        &self,
        provider: &str,
        subject: &str,
        email: &str,
    ) -> DomainResult<String>;
}

/// Port session mailbox — opérations de session IMAP sans état persistant.
///
/// Cycle 39 : 19ème port autonome. Signatures 100 % primitives, aucun type
/// infrastructure ni domaine. Couvre les commandes IMAP `NOOP`, `CLOSE`,
/// `CHECK` de la couche session historique.
#[async_trait]
pub trait SessionMailboxPort: Send + Sync {
    /// Commande IMAP NOOP — ne fait rien, sert de heartbeat.
    async fn noop(&self) -> DomainResult<()>;

    /// Commande IMAP CLOSE — ferme la mailbox courante pour `username`.
    async fn close_mailbox(&self, username: &str) -> DomainResult<()>;

    /// Commande IMAP CHECK — force la synchronisation de la mailbox courante.
    async fn check_mailbox(&self) -> DomainResult<()>;
}

/// Port mailbox delivery — livraison d'un message brut dans l'INBOX d'un
/// utilisateur.
///
/// Cycle 40 : 20ème port autonome. Signatures 100 % primitives (`&str`),
/// aucun type infrastructure ni domaine.
#[async_trait]
pub trait MailboxDeliveryPort: Send + Sync {
    /// Livre le message RFC 5322 `raw_message` dans l'INBOX de `username`.
    async fn deliver_to_inbox(&self, username: &str, raw_message: &str) -> DomainResult<()>;
}

/// Port message search user — recherche IMAP côté utilisateur.
///
/// Cycle 41 : 21ème port autonome. Signatures 100 % primitives (`&str`, `u32`),
/// aucun type infrastructure ni domaine.
#[async_trait]
pub trait MessageSearchUserPort: Send + Sync {
    /// Recherche des messages pour `username` selon `criteria` IMAP brut.
    ///
    /// Retourne la liste des UIDs correspondants.
    async fn search_messages_for_user(
        &self,
        username: &str,
        criteria: &str,
    ) -> DomainResult<Vec<u32>>;
}

/// Port mailbox list user — commande IMAP LIST côté utilisateur.
///
/// Cycle 41 : 22ème port autonome. Signatures 100 % primitives (`&str`),
/// aucun type infrastructure ni domaine.
#[async_trait]
pub trait MailboxListUserPort: Send + Sync {
    /// Liste les mailboxes de `username` selon `reference` et `mailbox` (motif IMAP LIST).
    ///
    /// Retourne les noms des mailboxes correspondant au motif.
    async fn list_mailboxes_for_user(
        &self,
        username: &str,
        reference: &str,
        mailbox: &str,
    ) -> DomainResult<Vec<String>>;
}

/// Port mailbox expunge user — commande IMAP EXPUNGE côté utilisateur.
///
/// Cycle 42 : 23ème port autonome. Signatures 100 % primitives.
#[async_trait]
pub trait MailboxExpungeUserPort: Send + Sync {
    /// Expunge la mailbox courante de `username`. Retourne les UIDs supprimés.
    async fn expunge_mailbox_for_user(&self, username: &str) -> DomainResult<Vec<u32>>;
}

/// Port message copy user — commande IMAP COPY côté utilisateur.
///
/// Cycle 42 : 24ème port autonome. Signatures 100 % primitives.
#[async_trait]
pub trait MessageCopyUserPort: Send + Sync {
    /// Copie les messages `sequence_set` (syntaxe IMAP) vers `target_mailbox`
    /// pour `username`.
    async fn copy_messages_for_user(
        &self,
        username: &str,
        sequence_set: &str,
        target_mailbox: &str,
    ) -> DomainResult<()>;
}

/// Port user creation — création d'un utilisateur avec sa mailbox initiale.
///
/// Cycle 42 : 23ème port autonome. Signatures 100 % primitives (`&str`),
/// aucun type infrastructure ni domaine.
#[async_trait]
pub trait UserCreationPort: Send + Sync {
    /// Crée l'utilisateur `username` avec `password` et sa `mailbox` initiale.
    async fn create_user(
        &self,
        username: &str,
        password: &str,
        mailbox: &str,
    ) -> DomainResult<()>;
}

/// Port mailbox select — sélection d'une mailbox pour un utilisateur (IMAP SELECT).
///
/// Cycle 42 : 24ème port autonome. Signatures 100 % primitives (`&str`),
/// retourne le nom canonique de la mailbox sélectionnée.
#[async_trait]
pub trait MailboxSelectPort: Send + Sync {
    /// Sélectionne `mailbox` pour `username` et retourne son nom canonique.
    async fn select_mailbox_for_user(
        &self,
        username: &str,
        mailbox: &str,
    ) -> DomainResult<String>;
}

/// Port email fetch — récupération d'un email par identifiant.
///
/// Cycle 43 : 27ème port autonome. Signatures primitives (`&str`) +
/// type domaine `Email` en retour.
#[async_trait]
pub trait EmailFetchPort: Send + Sync {
    /// Récupère l'email `email_id` de `username`, `None` si absent.
    async fn fetch_email(
        &self,
        username: &str,
        email_id: &str,
    ) -> DomainResult<Option<crate::Email>>;
}

/// Port email flag — mutation des flags `\Seen` et `\Flagged`.
///
/// Cycle 43 : 28ème port autonome. Signatures 100 % primitives (`&str`, `u32`, `bool`),
/// aucun type infrastructure ni domaine.
#[async_trait]
pub trait EmailFlagPort: Send + Sync {
    /// Positionne le flag `\Seen` sur le message `uid` de `mailbox` pour `username`.
    async fn set_email_read(
        &self,
        username: &str,
        mailbox: &str,
        uid: u32,
        read: bool,
    ) -> DomainResult<()>;

    /// Positionne le flag `\Flagged` sur le message `uid` de `mailbox` pour `username`.
    async fn set_email_starred(
        &self,
        username: &str,
        mailbox: &str,
        uid: u32,
        starred: bool,
    ) -> DomainResult<()>;
}

/// Port mailbox check — vérification/statut d'une mailbox pour un utilisateur.
///
/// Cycle 44 : 29ème port autonome. Signatures 100 % primitives (`&str`).
#[async_trait]
pub trait MailboxCheckPort: Send + Sync {
    /// Vérifie la mailbox `mailbox` pour `username` (IMAP CHECK/STATUS-like).
    async fn check_mailbox_for_user(
        &self,
        username: &str,
        mailbox: &str,
    ) -> DomainResult<()>;
}

/// Port message move — déplacement d'un message vers une autre mailbox.
///
/// Cycle 44 : 30ème port autonome. Signatures 100 % primitives (`&str`, `u32`).
#[async_trait]
pub trait MessageMovePort: Send + Sync {
    /// Déplace le message `uid` de `source_mailbox` vers `target_mailbox` pour `username`.
    async fn move_email_to_mailbox(
        &self,
        username: &str,
        source_mailbox: &str,
        uid: u32,
        target_mailbox: &str,
    ) -> DomainResult<()>;
}

/// Port auth user — Cycle 45, 31ème port.
#[async_trait]
pub trait AuthUserPort: Send + Sync {
    async fn authenticate_user(&self, username: &str, password: &str) -> Option<String>;
}

/// Port mailbox subscribe — Cycle 45, 32ème port.
#[async_trait]
pub trait MailboxSubscribePort: Send + Sync {
    async fn subscribe_mailbox_for_user(&self, username: &str, mailbox: &str) -> DomainResult<()>;
    async fn unsubscribe_mailbox_for_user(&self, username: &str, mailbox: &str) -> DomainResult<()>;
}
}
