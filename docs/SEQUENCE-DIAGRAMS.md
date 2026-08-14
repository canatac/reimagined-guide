# SEQUENCE DIAGRAMS

Diagrammes tirés du code source (`src/bin/*.rs`, `src/imap_server/mod.rs`,
`src/logic/mod.rs`, `src/external_imap/mod.rs`).

## (a) Réception SMTP entrante → routing RCPT TO → MongoDB

```mermaid
sequenceDiagram
    autonumber
    participant MTA as MTA distant
    participant SMTP as smtp_server (0.0.0.0:8025/8465)
    participant SM as SessionManager (session courante)
    participant Mongo as MongoDB mailserver

    MTA->>SMTP: TCP connect
    SMTP-->>MTA: 220 mail.misfits.ai ESMTP
    MTA->>SMTP: EHLO client
    SMTP-->>MTA: 250-STARTTLS / 250 AUTH PLAIN
    MTA->>SMTP: STARTTLS
    SMTP-->>MTA: 220 Ready
    Note over SMTP,SM: Handshake TLS ; session par connexion (fix PR #243)
    MTA->>SMTP: MAIL FROM:<bob@ext.com>
    Note right of SMTP: match insensible à la casse (fix PR #243)
    SMTP-->>MTA: 250 OK
    MTA->>SMTP: RCPT TO:<alice@misfits.ai>
    SMTP-->>MTA: 250 OK
    MTA->>SMTP: DATA + corps + .
    SMTP->>SMTP: extract_email_content(body)
    SMTP->>Mongo: insertOne emails { from, to, subject, body, internal_date }
    SMTP->>Mongo: insertOne mail_events { kind:"inbound", at, from, to }
    SMTP->>Mongo: insertOne smtp_events { raw, status }
    SMTP-->>MTA: 250 OK: message queued
    MTA->>SMTP: QUIT
    SMTP-->>MTA: 221 Bye
```

## (b) Envoi SMTP sortant + service DKIM externe

```mermaid
sequenceDiagram
    autonumber
    participant Client as Client (API /api/send)
    participant API as email_api
    participant SQ as send_queue (Mongo)
    participant DKIM as dkim-service (canatac/studious-octo-rotary-phone)
    participant Relay as MTA sortant (port 25 ou SMTP_RELAY_*)
    participant Log as mail_events / smtp_events

    Client->>API: POST /api/send {to, subject, body} + x-user-id
    API->>SQ: insertOne send_queue { status:"pending" }
    API-->>Client: 202 { id }
    API->>DKIM: POST DKIM_SERVICE_URL {domain, from, headers, body}
    DKIM-->>API: 200 { dkim_signature }
    API->>Relay: MAIL FROM / RCPT TO / DATA (avec header DKIM-Signature)
    Relay-->>API: 250 OK
    API->>SQ: updateOne { status:"sent", sentAt }
    API->>Log: mail_events { kind:"outbound", to, subject }
    Client->>API: GET /api/send/{id}/status
    API-->>Client: { status:"sent" }
```

## (c) IMAP fetch inbox

```mermaid
sequenceDiagram
    autonumber
    participant C as Client IMAP (Thunderbird, ...)
    participant I as imap_server (:143)
    participant Mongo as MongoDB mailserver

    C->>I: connect
    I-->>C: * OK IMAP4rev1 Service Ready
    C->>I: a1 CAPABILITY
    I-->>C: * CAPABILITY IMAP4rev1 AUTH=PLAIN LOGIN IDLE UIDPLUS MULTIAPPEND
    C->>I: a2 LOGIN alice pass
    I->>Mongo: users.find({email:"alice"}) + bcrypt verify
    Mongo-->>I: ok
    I-->>C: a2 OK LOGIN completed
    C->>I: a3 LIST "" "*"
    I->>Mongo: mailboxes.find({owner:"alice"})
    Mongo-->>I: [INBOX, Sent, ...]
    I-->>C: * LIST (\HasNoChildren) "/" "INBOX" ...
    C->>I: a4 SELECT INBOX
    I->>Mongo: emails.count({to:"alice"}), maxUid, unseen
    I-->>C: * FLAGS / EXISTS / UIDVALIDITY / UIDNEXT + OK [READ-WRITE]
    C->>I: a5 UID FETCH 1:* (FLAGS ENVELOPE)
    I->>Mongo: emails.find({to:"alice"}).sort(uid)
    Mongo-->>I: docs
    I-->>C: * n FETCH (...) + a5 OK
```

## (d) API GET /api/emails (inbox client authentifié)

```mermaid
sequenceDiagram
    autonumber
    participant Web as misfits-web (front)
    participant Caddy as Caddy (TLS, mail.misfits.ai)
    participant API as email_api (127.0.0.1:8000)
    participant Mongo as MongoDB mailserver

    Web->>Caddy: GET /api/emails (Cookie session)
    Caddy->>API: proxy_pass /api/emails + x-user-id: alice@misfits.ai
    API->>API: read header "x-user-id" (email_api.rs:2650)
    API->>Mongo: emails.find({to: user}).sort({internal_date:-1})
    Mongo-->>API: [Email, ...]
    API-->>Caddy: 200 [{id, from, subject, ...}]
    Caddy-->>Web: 200 JSON
```

## (e) Auth flow — login + 2FA + OAuth GitHub

```mermaid
sequenceDiagram
    autonumber
    participant U as User (browser)
    participant API as email_api
    participant Mongo as MongoDB mailserver
    participant GH as GitHub OAuth

    Note over U,API: --- Password login ---
    U->>API: POST /api/auth/login {email, password}
    API->>Mongo: users.findOne({email})
    Mongo-->>API: user
    API->>API: bcrypt::verify(password, user.hash)
    alt 2FA activé
        API->>Mongo: two_factor_codes.insertOne
        API-->>U: 200 { need2fa: true }
        U->>API: POST /api/auth/2fa/verify {code}
        API->>Mongo: two_factor_codes.findOne + expire
    end
    API->>Mongo: auth_events.insertOne { kind:"login" }
    API-->>U: 200 { token / cookie }

    Note over U,GH: --- OAuth GitHub ---
    U->>API: GET /api/auth/oauth/github/start
    API-->>U: 302 redirect to GH authorize (GITHUB_CLIENT_ID)
    U->>GH: consent
    GH-->>U: 302 → /api/auth/oauth/github/callback?code=...
    U->>API: GET /api/auth/oauth/github/callback?code
    API->>GH: POST /login/oauth/access_token (client_id/secret)
    GH-->>API: access_token
    API->>GH: GET /user
    GH-->>API: profile
    API->>Mongo: users.upsert({email})
    API-->>U: 302 → FRONTEND_BASE_URL avec session
```
