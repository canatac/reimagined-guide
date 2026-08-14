# USAGE — misfits.ai Mail

## 1. Lancer les binaires

```bash
# 1) API HTTP (port 8000 par défaut)
API_SERVER_ADDR=0.0.0.0:8000 ./target/release/email_api

# 2) SMTP (plain 8025, TLS 8465)
./target/release/smtp_server

# 3) IMAP (port 143)
IMAP_SERVER=0.0.0.0:143 ./target/release/imap_server
```

Sous Docker, chaque binaire est démarré via `entrypoint.sh` + `command:` du
compose (`smtp_server`, `email_api`, `imap_server`).

## 2. SMTP — commandes supportées

Source : [`src/bin/smtp_server.rs`](../src/bin/smtp_server.rs).

Commandes reconnues :
- `HELO` / `EHLO`
- `STARTTLS` (obligatoire si `SMTP_REQUIRE_STARTTLS=true`)
- `AUTH PLAIN` (via `SessionManager`, session par connexion)
- `MAIL FROM:` — parsé insensible à la casse, cf. fix PR #243
- `RCPT TO:` — idem
- `DATA` … `.` (fin de corps)
- `RSET`, `NOOP`, `QUIT`

Routing entrant : à `QUIT`, si `from` et `to` sont non vides, le corps est
parsé (`extract_email_content`), puis stocké MongoDB (`emails`) et un événement
publié dans `mail_events` / `smtp_events`.

## 3. IMAP — capabilities

Bannière et CAPABILITY (cf. `src/imap_server/mod.rs:41,168`) :

```
* OK IMAP4rev1 Service Ready
* CAPABILITY IMAP4rev1 AUTH=PLAIN LOGIN IDLE UIDPLUS MULTIAPPEND
```

Commandes implémentées : `CAPABILITY`, `LOGIN`, `LOGOUT`, `LIST`, `SELECT`,
`FETCH`, `NOOP`. `SELECT` renvoie `FLAGS/EXISTS/RECENT/UNSEEN/UIDVALIDITY/UIDNEXT`
puis `OK [READ-WRITE] SELECT completed`.

## 4. Endpoints HTTP (email_api)

Extrait depuis la configuration `HttpServer::new(...)` (ligne 6489 de
[`src/bin/email_api.rs`](../src/bin/email_api.rs)). Auth = header
`x-user-id: <user>` sur les endpoints utilisateur (cf. ligne 2650) ; endpoints
`/api/admin/*` protégés par `admin_auth::require_admin` (cf. `src/bin/admin_auth.rs`).

### Docs / méta
| Méthode | Path                       | Handler                  |
|---------|----------------------------|--------------------------|
| GET     | `/api/openapi.json`        | `api_openapi_json`       |
| GET     | `/api/docs`                | `api_swagger_ui`         |
| GET     | `/api/external/openapi.json` | `api_external_openapi` |

### Auth / user
| Méthode | Path                                | Handler                       |
|---------|-------------------------------------|-------------------------------|
| POST    | `/api/auth/login`                   | `auth_login`                  |
| POST    | `/api/auth/register`                | `auth_register`               |
| POST    | `/api/auth/logout`                  | `auth_logout`                 |
| POST    | `/api/auth/refresh`                 | `auth_refresh`                |
| POST    | `/api/auth/2fa/verify`              | `api_2fa_verify`              |
| POST    | `/api/auth/password-reset/request`  | `api_password_reset_request`  |
| POST    | `/api/auth/password-reset/confirm`  | `api_password_reset_confirm`  |
| GET     | `/api/auth/oauth/{provider}/start`  | `auth_oauth_start`            |
| GET     | `/api/auth/oauth/{provider}/callback` | `auth_oauth_callback`       |
| PATCH   | `/api/user/locale`                  | `api_patch_user_locale`       |

### Emails (inbox / envoi / brouillons / templates)
| Méthode | Path                          | Handler                 |
|---------|-------------------------------|-------------------------|
| GET     | `/api/emails`                 | `api_emails`            |
| GET     | `/api/emails/{id}`            | `api_email_by_id`       |
| POST    | `/api/emails/{id}/action`     | `api_email_action`      |
| GET     | `/api/tags`                   | `api_tags`              |
| POST    | `/api/send`                   | `api_send`              |
| GET     | `/api/send/{id}/status`       | `api_send_status`       |
| POST    | `/api/send/undo`              | `api_send_undo`         |
| POST    | `/api/send/schedule`          | `api_send_schedule`     |
| GET     | `/api/drafts`                 | `api_drafts_list`       |
| POST    | `/api/drafts`                 | `api_drafts_upsert`     |
| DELETE  | `/api/drafts/{id}`            | `api_drafts_delete`     |
| GET     | `/api/templates`              | `api_templates`         |

### AI / Hermes
| Méthode | Path                                | Handler                  |
|---------|-------------------------------------|--------------------------|
| GET     | `/api/settings/ai`                  | `api_get_ai_settings`    |
| PUT     | `/api/settings/ai`                  | `api_put_ai_settings`    |
| POST    | `/api/hermes/chat`                  | `api_hermes_chat`        |
| GET     | `/api/hermes/runs`                  | `api_hermes_runs_list`   |
| POST    | `/api/hermes/runs`                  | `api_hermes_runs`        |
| GET     | `/api/hermes/runs/{id}/status`      | `api_hermes_run_status`  |
| GET     | `/api/hermes/runs/{id}/events`      | `api_hermes_run_events`  |

### Calendrier
| Méthode | Path                          | Handler                 |
|---------|-------------------------------|-------------------------|
| POST    | `/api/calendar/events`        | `calendar_create_event` |
| GET     | `/api/calendar/events`        | `calendar_list_events`  |
| GET     | `/api/calendar/events/{id}`   | `calendar_get_event`    |

### External IMAP (Gmail/Outlook connectés)
| Méthode | Path                                                        | Handler                            |
|---------|-------------------------------------------------------------|------------------------------------|
| GET     | `/api/external/accounts`                                    | `api_external_accounts_list`       |
| POST    | `/api/external/accounts`                                    | `api_external_accounts_create`     |
| GET     | `/api/external/accounts/{id}`                               | `api_external_account_get`         |
| PATCH   | `/api/external/accounts/{id}`                               | `api_external_account_patch`       |
| DELETE  | `/api/external/accounts/{id}`                               | `api_external_account_delete`      |
| POST    | `/api/external/accounts/{id}/test`                          | `api_external_account_test`        |
| GET     | `/api/external/accounts/{id}/folders`                       | `api_external_folders_list`        |
| POST    | `/api/external/accounts/{id}/folders/discover`              | `api_external_folders_discover`    |
| PUT     | `/api/external/accounts/{id}/folders/{folder_id}/mapping`   | `api_external_folder_mapping_put`  |
| POST    | `/api/external/accounts/{id}/sync/start`                    | `api_external_sync_start`          |
| GET     | `/api/external/accounts/{id}/sync/status`                   | `api_external_sync_status`         |
| POST    | `/api/external/accounts/{id}/sync/pause`                    | `api_external_sync_pause`          |
| POST    | `/api/external/accounts/{id}/sync/resume`                   | `api_external_sync_resume`         |
| GET     | `/api/external/sync/runs/{run_id}`                          | `api_external_sync_run_get`        |
| GET     | `/api/external/accounts/{id}/messages`                      | `api_external_messages_list`       |
| POST    | `/api/external/messages/{message_id}/action`                | `api_external_message_action`      |

### Admin (require_admin)
| Méthode | Path                          | Handler                     |
|---------|-------------------------------|-----------------------------|
| GET     | `/api/admin/whoami`           | `api_admin_whoami`          |
| GET     | `/api/admin/users`            | `api_admin_users_list`      |
| POST    | `/api/admin/users`            | `api_admin_user_create`     |
| GET     | `/api/admin/users/{id}`       | `api_admin_user_get`        |
| GET     | `/api/monitoring/live`        | `api_monitoring_live`       |
| GET     | `/api/security/live`          | `api_security_live`         |

### Events / SSE / mailing lists
| Méthode | Path                     | Handler                |
|---------|--------------------------|------------------------|
| GET     | `/api/events`            | `api_events`           |
| GET     | `/api/events/stream`     | `api_events_stream`    |
| POST    | `/send-email`            | `send_email_handler`   |
| POST    | `/create-mailing-list`   | `create_mailing_list`  |

## 5. Exemples curl

```bash
# Lister l'inbox
curl -H 'x-user-id: alice@misfits.ai' http://localhost:8000/api/emails

# Envoyer un email
curl -X POST http://localhost:8000/api/send \
  -H 'x-user-id: alice@misfits.ai' \
  -H 'Content-Type: application/json' \
  -d '{"to":"bob@example.com","subject":"hi","body":"hello"}'

# Register + login
curl -X POST http://localhost:8000/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@misfits.ai","password":"secret"}'

# Connecter un compte IMAP externe (Gmail)
curl -X POST http://localhost:8000/api/external/accounts \
  -H 'x-user-id: alice@misfits.ai' \
  -H 'Content-Type: application/json' \
  -d '{"provider":"gmail","email":"alice@gmail.com","imapHost":"imap.gmail.com","imapPort":993,"imapTls":true,"authType":"password","secretValue":"app-password"}'

# Test SMTP local via swaks (STARTTLS obligatoire en prod)
swaks --to alice@misfits.ai --from bob@example.com --server localhost:8025
```

## 6. OpenAPI

Deux specs servies :
- `/api/openapi.json` — API principale (fichier embarqué via `include_str!`
  depuis `ops/openapi/`).
- `/api/external/openapi.json` — sous-API "External IMAP".
UI Swagger : `/api/docs`.
