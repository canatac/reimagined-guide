# INSTALL — misfits.ai Mail (reimagined-guide)

Ce document est extrait du code réel du dépôt. Chaque affirmation renvoie à un
fichier source.

## 1. Prérequis

- Rust stable (image builder = `rust:1.88`, cf. [`Dockerfile`](../Dockerfile) ligne 2).
- MongoDB 4+ (natif systemd sur la VM Scaleway — **pas** dans un container ;
  cf. commentaire d'en-tête de [`docker-compose.deploy.yml`](../docker-compose.deploy.yml)).
- Docker + Docker Compose v2 pour l'exécution en production.
- OpenSSL / `libssl-dev` en build (Dockerfile étape builder).

## 2. Binaires produits

Déclarés dans [`Cargo.toml`](../Cargo.toml) (`autobins = false`) :

| Binaire       | Chemin                        | Rôle                                  |
|---------------|-------------------------------|---------------------------------------|
| `smtp_server` | `src/bin/smtp_server.rs`      | Serveur SMTP entrant/sortant + STARTTLS |
| `email_api`   | `src/bin/email_api.rs`        | API HTTP (actix-web) : inbox, send, admin, external IMAP, calendar, OAuth, Hermes |
| `imap_server` | `src/bin/imap_server.rs`      | Serveur IMAP4rev1 minimal             |
| `client`      | `src/bin/client.rs`           | Client SMTP de test                   |

(Aussi présent : `admin_auth.rs`, `api.rs`, `imap_runner.rs` — modules utilitaires.)

## 3. Variables d'environnement

Source de vérité : [`env.example`](../env.example). Extrait par domaine :

### SMTP
- `SMTP_TLS_ADDR` (def. `0.0.0.0:8465`)
- `SMTP_PLAIN_ADDR` (def. `0.0.0.0:8025`)
- `SMTP_REQUIRE_STARTTLS` (`true`/`false`)
- `SMTP_HOSTNAME` (ex. `mail.misfits.ai`)
- `SMTP_USERNAME` / `SMTP_PASSWORD`
- `CERT_PATH` / `KEY_PATH` (en prod, injectés depuis le volume `caddy_data`, cf.
  `docker-compose.deploy.yml`)

### SMTP Relay (optionnel — port 25 sortant bloqué)
`SMTP_RELAY_HOST`, `SMTP_RELAY_PORT`, `SMTP_RELAY_USER`, `SMTP_RELAY_PASSWORD`.

### MongoDB
- `MONGODB_USERNAME`, `MONGODB_PASSWORD`
- `MONGODB_CLUSTER_URL` (prod = IP privée Scaleway VPC)
- `MONGODB_APP_NAME` (def. `mailserver`)
- `MONGODB_DATABASE` (def. `mailserver`)
- `MONGODB_URL` complet en prod (injecté via 1Password)
- `USE_MONGODB=true` (sinon fallback fichiers locaux)

### IMAP
- `IMAP_SERVER` (def. `0.0.0.0:143`) — lu par `src/bin/imap_server.rs:52`
- `IMAP_SERVER_API_PORT` (def. `8080`)

### API
- `API_SERVER_ADDR` (def. `0.0.0.0:8000`)
- `HERMES_BASE_URL` (adresse VPC privée), `HERMES_API_KEY`, `HERMES_MODEL`
- `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `OAUTH_CALLBACK_BASE_URL`, `FRONTEND_BASE_URL`

### DKIM
- `DKIM_SERVICE_URL` (def. `http://dkim-service:3000/generate-dkim`)
  → Service externe fourni par `canatac/studious-octo-rotary-phone`.

### Monitoring / Logs
- `SMTP_MONITORING_ENABLED=true`
- `RUST_LOG=info|debug`

### Domaine
- `DOMAIN_NAME=misfits.ai`

## 4. Build local

```bash
cp env.example .env
cargo check --lib --bins        # même vérif qu'en CI (cicd.yml job "test")
cargo build --release --bins
./target/release/smtp_server &
./target/release/email_api &
./target/release/imap_server &
```

## 5. Build Docker

```bash
docker build -t smtp-server:local .
```

Le [`Dockerfile`](../Dockerfile) est multi-stage :
- Stage 1 (`rust:1.88`) — cache-friendly : `Cargo.toml`+`Cargo.lock` copiés
  avant les sources pour cacher les 445 dépendances.
- Stage 2 (`debian:bookworm-slim`) — installe `openssl`, `ca-certificates`,
  `libssl3`, `netcat-openbsd`, `gosu` ; ajoute un utilisateur `default_user`
  (UID 10001) et copie les 3 binaires. Certs auto-signés générés à la volée.
- Healthcheck TCP : `nc -z 127.0.0.1 8025`.
- `EXPOSE 25 8025 8465 143 993 8000 8443`.

## 6. Déploiement VM Scaleway (workflow réel)

Pipeline : [`.github/workflows/cicd.yml`](../.github/workflows/cicd.yml).

Étapes :

1. **JOB `test`** — `cargo check --lib --bins` (Swatinem/rust-cache).
2. **JOB `build-push-smtp`** — Buildx → push vers Scaleway Registry :
   - `registry: ${SCW_REGISTRY_ENDPOINT}` (ex. `rg.fr-par.scw.cloud/smtp-rust-registry`)
   - `username: nologin`, `password: ${SCW_SECRET_KEY}`
   - tags : `smtp-server:latest` et `smtp-server:${{ github.sha }}`.
3. **JOB `deploy`** — SSH `debian@${VM_IP}` (VM Scaleway `51.158.114.182`) :
   - Charge les secrets via `1password/load-secrets-action@v4`
     (`op://hermes/ssh-hermes-smtp/private-key`, `op://hermes/scw-hermes-smtp/texte`).
   - `scp docker-compose.deploy.yml Caddyfile → /home/debian/`.
   - Injecte `GITHUB_CLIENT_ID/SECRET`, `SCW_REGISTRY_ENDPOINT`,
     `OAUTH_CALLBACK_BASE_URL`, `FRONTEND_BASE_URL` dans `/home/debian/.env.deploy`.
   - `docker login`, pull images (SMTP + DKIM), `docker compose -f docker-compose.deploy.yml --env-file .env.deploy up -d`.

Services déployés (cf. [`docker-compose.deploy.yml`](../docker-compose.deploy.yml)) :
`smtp-server`, `email-api`, `imap-server`, `dkim-service`, `misfits-web`.
Ports host mappés : `25→8025`, `587→8465`, `8025→8025`, `8465→8465`,
`email-api` sur `127.0.0.1:8000` (fronté par Caddy).

## 7. Secrets GitHub attendus

Lus par [`cicd.yml`](../.github/workflows/cicd.yml) :

| Secret                     | Rôle                                             |
|----------------------------|--------------------------------------------------|
| `SCW_REGISTRY_ENDPOINT`    | Endpoint du registry Scaleway                    |
| `SCW_SECRET_KEY`           | Password registry (username fixe = `nologin`)    |
| `VM_IP`                    | IP publique VM Scaleway                          |
| `VM_KNOWN_HOSTS`           | Fingerprint SSH                                  |
| `OP_SERVICE_ACCOUNT_TOKEN` | Jeton 1Password service-account                  |
| `OAUTH_GITHUB_CLIENT_ID`   | OAuth GitHub                                     |
| `OAUTH_GITHUB_CLIENT_SECRET` | OAuth GitHub                                   |

Secrets 1Password (vault `hermes`) chargés au runtime :
`ssh-hermes-smtp/private-key`, `scw-hermes-smtp/texte` (contenu `.env.deploy`).

## 8. MongoDB natif (VM)

- MongoDB tourne en systemd (`mongod`) sur la VM et écoute sur son IP privée
  Scaleway (variable `MONGODB_CLUSTER_URL`/`MONGODB_URL`).
- Base : `mailserver`, collections listées dans
  [`docs/DATA-DICTIONARY.md`](DATA-DICTIONARY.md).

## 9. DNS — SPF / DKIM / DMARC

Pointeurs (le code n'impose pas les valeurs — à publier côté zone DNS
`misfits.ai`) :

- **SPF** : `v=spf1 ip4:<IP publique VM> -all`
- **DKIM** : sélecteur généré par le service DKIM externe
  (`DKIM_SERVICE_URL`, cf. `canatac/studious-octo-rotary-phone`). La clé
  publique est publiée en TXT `<selector>._domainkey.misfits.ai`.
- **DMARC** : `v=DMARC1; p=quarantine; rua=mailto:postmaster@misfits.ai`

## 10. Note régression fix récent

PR #243 (master `6abd9a1b`) : le handler SMTP utilisait le `SessionManager`
global au lieu de la session courante, et le parsing `MAIL FROM:`/`RCPT TO:`
n'était pas insensible à la casse. Correction en place dans
[`src/bin/smtp_server.rs`](../src/bin/smtp_server.rs) (lignes ~738–744).
