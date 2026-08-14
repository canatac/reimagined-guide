# DATA DICTIONARY — MongoDB `mailserver`

Extrait des `collection::<T>("…")` de :
- [`src/bin/email_api.rs`](../src/bin/email_api.rs)
- [`src/logic/mod.rs`](../src/logic/mod.rs)
- [`src/external_imap/mod.rs`](../src/external_imap/mod.rs)
- [`src/entities.rs`](../src/entities.rs)

Base : `${MONGODB_DATABASE}` (def. `mailserver`).

## Collections

| Collection                    | Type sérialisé              | Source                                    | Usage                                             |
|-------------------------------|-----------------------------|-------------------------------------------|---------------------------------------------------|
| `users`                       | `User` / bson::Document     | `logic/mod.rs:128`, `email_api.rs:2732`   | Comptes utilisateurs, mot de passe (bcrypt)       |
| `mailboxes`                   | `Mailbox`                   | `logic/mod.rs:138,626,800,839,866`        | Boîtes IMAP par user                              |
| `emails`                      | `Email` / bson::Document    | `logic/mod.rs:205,411…757`                | Messages stockés (in/out)                         |
| `archive`                     | `Email`                     | `logic/mod.rs:598`                        | Emails archivés                                   |
| `aliases`                     | bson::Document              | `logic/mod.rs:178`                        | Alias d'adresses                                  |
| `subscriptions`               | `User`                      | `logic/mod.rs:888`                        | Abonnements mailing-list                          |
| `mail_events`                 | bson::Document              | `email_api.rs:264,285`, `logic/mod.rs:247`| Audit trail mail (in/out, statuts)                |
| `smtp_events`                 | bson::Document              | `email_api.rs:3936`                       | Événements SMTP bruts (monitoring)                |
| `auth_events`                 | bson::Document              | `email_api.rs:1614`                       | Login/logout/2FA                                  |
| `two_factor_codes`            | bson::Document              | `email_api.rs:2772`                       | Codes 2FA temporaires                             |
| `password_reset_tokens`       | bson::Document              | `email_api.rs:2844,2912`                  | Jetons de reset                                   |
| `drafts`                      | bson::Document              | `email_api.rs:4150,4233,4273,4510`        | Brouillons                                        |
| `send_queue`                  | bson::Document              | `email_api.rs:1522…3775` (const `SEND_QUEUE_COLL`) | File d'envoi (schedule, undo)             |
| `tenant_state`                | bson::Document              | `email_api.rs:891`                        | État tenant / feature flags                       |
| `admin_runbooks`              | bson::Document              | `email_api.rs:1226,1421`                  | Runbooks admin                                    |
| `ai_settings`                 | bson::Document              | grep global                               | Réglages IA par user                              |
| `calendar_events`             | `CalendarEvent`             | `entities.rs` + email_api.rs              | Événements calendrier                             |
| `external_imap_accounts`      | `ExternalImapAccount`       | `external_imap/mod.rs:133`                | Comptes IMAP externes                             |
| `external_imap_folders`       | `ExternalImapFolder`        | `external_imap/mod.rs:139`                | Dossiers distants + mapping local                 |
| `external_imap_messages`      | `ExternalImapMessage`       | `external_imap/mod.rs:145`                | Messages synchronisés                             |
| `external_imap_sync_runs`     | `ExternalSyncRun`           | `external_imap/mod.rs:151`                | Runs de sync (statut, stats)                      |

## Structs Rust (extraits de `src/entities.rs`)

### `Email`
| Champ            | Type BSON       | Notes                             |
|------------------|-----------------|-----------------------------------|
| id               | String          | UUID                              |
| from             | String          |                                   |
| to               | String          |                                   |
| subject          | String          |                                   |
| body             | String          |                                   |
| headers          | Array<Tuple>    | `Vec<(String,String)>`            |
| flags            | Array<String>   | IMAP flags                        |
| sequence_number  | u32             | IMAP MSN                          |
| uid              | u32             | IMAP UID                          |
| internal_date    | Date            | `bson::DateTime`                  |
| dkim_signature   | String?         |                                   |

### `CalendarEvent`
`id`, `user_id`, `title`, `description`, `start`, `end`, `event_type`
(def. `"default"`), `color` (def. `"#3788d8"`), `location`, `created_at`,
`updated_at`.

### `ExternalImapAccount` (camelCase JSON)
`id`, `ownerUserId`, `provider`, `email`, `authType`, `secretRef?`,
`secretValue?`, `imapHost`, `imapPort` (u16), `imapTls` (bool), `smtpHost?`,
`smtpPort?`, `smtpTls?`, `status`, `lastSyncAt?`, `lastError?`, `createdAt`,
`updatedAt`.

### `ExternalImapFolder`
`id`, `accountId`, `ownerUserId`, `remoteName`, `localRole`, `uidValidity?`,
`highestUid?`, `highestModseq?`, `createdAt`, `updatedAt`.

### `ExternalImapMessage`
`id`, `accountId`, `folderId?`, `ownerUserId`, `remoteUid?`, `messageIdHeader?`,
`threadKey?`, `from?`, `to?`, `subject?`, `sentAt?`, `flags[]`, `internalDate?`,
`bodyPreview?`, `rawRef?`, `dedupHash?`, `deleted` (bool), `createdAt`,
`updatedAt`.

### `ExternalSyncRun`
`id`, `accountId`, `ownerUserId`, `mode`, `folders[]`, `since?`, `status`,
`statsFetched`, `statsUpdated`, `statsDeleted`, `startedAt`, `endedAt?`,
`error?`.

### `AdminUserRecord` / `AdminUserActivity`
Cf. `entities.rs` — dashboards admin (sessions24h, actions7d, activity feed).

### `ChangeRequestItem` / `WorkflowStage` / `WorkflowEvent`
Modèle "change requests" (workflow multi-étapes, checklists, execution state).

## Index

Le code n'utilise pas `create_index` de manière visible ; les index sont
gérés hors code (opération MongoDB manuelle). Index recommandés :

- `users.email` unique
- `emails.{to,internal_date}`, `emails.uid`, `emails.id` unique
- `external_imap_messages.{accountId,remoteUid}` unique
- `external_imap_messages.dedupHash`
- `send_queue.{status,scheduledAt}`
- `mail_events.at`, `auth_events.at`
