# Stack Mail Rust — Déploiement sur Scaleway

Serveur SMTP/IMAP en Rust avec TLS automatique (Caddy + Let's Encrypt), MongoDB natif et frontend Next.js, déployé sur une VM Scaleway via GitHub Actions.

---

## Architecture

```
Internet
   │
   ├─ :25 / :587 → smtp-server (Rust)   ← emails entrants/sortants
   ├─ :143 / :993 → imap-server (Rust)  ← accès boîtes mail
   ├─ :80 / :443  → Caddy (host mode)   ← TLS Let's Encrypt + reverse proxy
   │                   ├─ /api/*  → email-api:8000 (Rust)
   │                   └─ /*      → misfits-web:3001 (Next.js)
   └─ :27017 (réseau privé seulement) → MongoDB 7 (natif sur VM)
```

### Composants

| Composant | Runtime | Description |
|-----------|---------|-------------|
| `smtp-server` | Container Docker | Serveur SMTP Rust (ports 25, 587) |
| `email-api` | Container Docker | API REST (port 8000, Caddy reverse proxy) |
| `imap-server` | Container Docker | Serveur IMAP Rust (ports 143, 993) |
| `dkim-service` | Container Docker | Signature DKIM (port 3000) |
| `misfits-web` | Container Docker | Frontend Next.js (port 3001) |
| `caddy` | Container Docker (host mode) | TLS + reverse proxy (ports 80, 443) |
| `mongod` | Natif sur VM | Base de données (port 27017, réseau privé) |

### Fichiers Docker Compose

| Fichier | Usage |
|---------|-------|
| `docker-compose.yml` | Développement local (MongoDB en container, build local) |
| `docker-compose.deploy.yml` | Production sur VM (images SCW Registry, MongoDB natif) |

---

## Prérequis

- Compte [Scaleway](https://console.scaleway.com) avec clés API
- Domaine DNS pointant vers l'IP publique de la VM (`mail.misfits.ai → <VM_IP>`)
- [1Password](https://1password.com) avec vault `hermes` pour les secrets
- GitHub Actions avec accès au vault 1Password
- Terraform ≥ 1.0 (`brew install terraform` ou `prepare-deploy-machine.sh`)
- Scaleway CLI (`scw`) et GitHub CLI (`gh`)

Pour installer les outils sur votre machine de développement :
```bash
sudo bash prepare-deploy-machine.sh
```

---

## 1. Provisionner l'infrastructure Scaleway (Terraform)

```bash
cd infra/
terraform init
terraform plan
terraform apply
```

Cela crée :
- VM DEV1-S (Debian 11 Bullseye)
- IP publique flexible
- Groupe de sécurité (ports 22, 80, 443, 25, 587, 143, 993)
- Container Registry Scaleway (pour les images Docker)

Récupérer l'IP publique :
```bash
terraform output vm_public_ip
```

---

## 2. Provisionnement initial de la VM

Exécuter **une seule fois** sur la nouvelle VM :

```bash
# Copier le script sur la VM
scp infra/init-vm.sh debian@<VM_PUBLIC_IP>:~

# Hermes gateway (server-to-server)
# Keep HERMES_BASE_URL on private VPC address only (no public 8642)
HERMES_BASE_URL=http://172.16.12.2:8642
HERMES_API_KEY=your_hermes_api_key
HERMES_MODEL=hermes-agent

# Logging
RUST_LOG=debug
# Exécuter (remplacer les valeurs)
ssh debian@<VM_PUBLIC_IP> "bash ~/init-vm.sh '<MONGODB_PASSWORD>' '<MONGODB_USERNAME>'"
```

Le script installe et configure :
1. **Docker Engine** (CE) + plugin compose
2. **MongoDB 7** (natif) avec authentification activée sur l'IP privée
3. **nftables** (pare-feu : INPUT drop sauf SSH/mail/HTTP, FORWARD pour Docker)
4. Sudoers pour que le CI/CD puisse lancer Docker sans mot de passe

À la fin du script, noter l'IP privée affichée (`172.16.x.x`).

### Initialiser les collections MongoDB

```bash
ssh debian@<VM_PUBLIC_IP> "mongosh mongodb://<MONGODB_USERNAME>:<MONGODB_PASSWORD>@127.0.0.1:27017/mailserver?authSource=admin < scripts/init-mongo.js"
```

---

## 3. Configurer les secrets

### 3.1 Vault 1Password (vault: `hermes`, item: `scw-hermes-smtp`)

Créer ou mettre à jour ces champs dans 1Password :

| Champ 1Password | Valeur |
|-----------------|--------|
| `SMTP_USERNAME` | Nom d'utilisateur SMTP |
| `SMTP_PASSWORD` | Mot de passe SMTP |
| `MONGODB_USERNAME` | Utilisateur MongoDB (ex: `adoremio`) |
| `MONGODB_PASSWORD` | Mot de passe MongoDB |
| `MONGODB_URL` | `mongodb://user:pass@172.16.x.x:27017/mailserver?authSource=admin` |
| `DOMAIN_NAME` | `misfits.ai` |
| `GITHUB_CLIENT_ID` | OAuth GitHub |
| `GITHUB_CLIENT_SECRET` | OAuth GitHub |
| `OPENROUTER_API_KEY` | Clé OpenRouter (frontend AI) |

### 3.2 Secrets GitHub Actions

Ces secrets sont définis dans `Settings → Secrets → Actions` du dépôt :

| Secret GitHub | Description |
|---------------|-------------|
| `SCW_REGISTRY_ENDPOINT` | `rg.fr-par.scw.cloud/<votre-registry>` |
| `SCW_SECRET_KEY` | Clé API Scaleway |
| `SCW_DEFAULT_PROJECT_ID` | ID projet Scaleway |
| `VM_IP` | IP publique de la VM |
| `VM_SSH_KEY` | Clé SSH privée (pour se connecter à la VM) |
| `VM_KNOWN_HOSTS` | Résultat de `ssh-keyscan <VM_IP>` |
| `OP_SERVICE_ACCOUNT_TOKEN` | Token 1Password service account |

Script helper pour configurer les secrets GitHub (première fois) :
```bash
bash setup-secrets.sh
```

---

## 4. Premier déploiement (CI/CD)

Pousser sur `main` déclenche le pipeline GitHub Actions (`.github/workflows/cicd.yml`) :

```
1. Build Rust (cargo build --release)
2. Build images Docker + push → Scaleway Registry
3. SSH sur la VM :
   a. Redémarrage Docker
   b. Pull des nouvelles images
   c. Démarrage Caddy seul (obtention cert Let's Encrypt)
   d. Démarrage du stack complet (docker-compose.deploy.yml)
   e. Smoke tests (SMTP :587, DKIM health)
```

Pour suivre un déploiement :
```bash
# Logs en temps réel sur la VM
ssh debian@<VM_IP> "sudo docker compose -f docker-compose.deploy.yml logs -f"

# Vérifier les certificats Caddy
ssh debian@<VM_IP> "sudo find /var/lib/docker/volumes/*/caddy/certificates -name '*.crt' 2>/dev/null"
```

---

## 5. Déployer une nouvelle VM (remplacement complet)

Procédure complète pour repartir de zéro :

```bash
# 1. Détruire l'ancienne infrastructure (ATTENTION : perte des données)
cd infra/ && terraform destroy

# 2. Recréer (prend ~2 minutes)
terraform apply

# 3. Récupérer la nouvelle IP
NEW_IP=$(terraform output -raw vm_public_ip)
echo "Nouvelle VM : $NEW_IP"

# 4. Provisionner la VM
scp infra/init-vm.sh debian@$NEW_IP:~
ssh debian@$NEW_IP "bash ~/init-vm.sh '<MONGODB_PASSWORD>' '<MONGODB_USERNAME>'"

# 5. Mettre à jour le secret GitHub VM_IP
gh secret set VM_IP --body "$NEW_IP"
gh secret set VM_KNOWN_HOSTS --body "$(ssh-keyscan $NEW_IP 2>/dev/null)"

# 6. Mettre à jour MONGODB_URL dans 1Password avec la nouvelle IP privée
#    (affichée à la fin de init-vm.sh)

# 7. Déclencher le CI/CD
git commit --allow-empty -m "ci: redeploy on new VM" && git push origin main
```

---

## 6. Opérations courantes

### Logs

```bash
ssh debian@<VM_IP> "sudo docker compose -f docker-compose.deploy.yml logs smtp-server -f"
ssh debian@<VM_IP> "sudo docker compose -f docker-compose.deploy.yml logs caddy -f"
```

### Redémarrer un service

```bash
ssh debian@<VM_IP> "sudo docker compose -f docker-compose.deploy.yml restart smtp-server"
```

### MongoDB

```bash
# Connexion en ligne de commande
ssh debian@<VM_IP> "mongosh 'mongodb://<user>:<pass>@127.0.0.1:27017/mailserver?authSource=admin'"

# Vérifier les utilisateurs
ssh debian@<VM_IP> "mongosh --eval 'db.getSiblingDB(\"admin\").getUsers()'"
```

### Renouvellement des certificats

Caddy renouvelle automatiquement les certificats Let's Encrypt tous les ~60 jours.
Le CI/CD re-applique les permissions (`chmod o+rX`) à chaque déploiement.

Pour forcer un renouvellement manuellement :
```bash
ssh debian@<VM_IP> "sudo docker exec caddy caddy reload --config /etc/caddy/Caddyfile"
```

### Pare-feu nftables

```bash
# Voir les règles actives
ssh debian@<VM_IP> "sudo nft list ruleset"

# Recharger depuis la config persistée
ssh debian@<VM_IP> "sudo nft -f /etc/nftables.conf"
```

---

## 7. Développement local

```bash
# Copier et éditer les variables
cp env.example .env
# Éditer .env : MONGODB_CLUSTER_URL=mongodb, CERT_PATH=localhost.crt, etc.

# Générer des certificats auto-signés pour le dev
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/localhost.key \
  -out certs/localhost.crt -days 365 -nodes -subj '/CN=localhost'

# Démarrer le stack de développement
docker compose up -d

# Logs
docker compose logs smtp-server -f
```

Le stack local inclut un container MongoDB (port 27017). Aucun Caddy en dev ; les services SMTP/IMAP exposent directement leurs ports TLS.

---

## 8. Structure du projet

```
.
├── src/                        # Code Rust (smtp_server, imap_server, email_api...)
├── Cargo.toml                  # Dépendances Rust
├── Dockerfile                  # Build multi-stage Rust → Debian slim (UID 10001)
├── Caddyfile                   # Config Caddy (reverse proxy + TLS auto)
├── docker-compose.yml          # Dev local (MongoDB container + build local)
├── docker-compose.deploy.yml   # Production VM (SCW Registry + MongoDB natif)
├── env.example                 # Template variables d'environnement
├── infra/
│   ├── main.tf                 # Infrastructure Scaleway (Terraform)
│   └── init-vm.sh              # Provisionnement VM (Docker, MongoDB, nftables)
├── scripts/
│   └── init-mongo.js           # Création collections/indexes MongoDB
├── prepare-deploy-machine.sh   # Setup machine de dev (Terraform, gh, scw CLI)
└── setup-secrets.sh            # Helper config secrets GitHub (première fois)
```

---

## Variables d'environnement

Voir [`env.example`](./env.example) pour la liste complète avec commentaires.

En production, toutes les variables sensibles sont lues depuis le vault 1Password `hermes`
(item `scw-hermes-smtp`) via `load-secrets-action` dans le CI/CD.
