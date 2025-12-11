# Guide Docker pour le Serveur SMTP Rust

## 🚀 Lancement de l'application avec Docker

### Prérequis
- Docker et Docker Compose installés
- Certificats SSL/TLS (optionnel pour les tests)

### 1. Configuration initiale

#### 1.1 Créer le fichier .env
```bash
cp env.example .env
```

#### 1.2 Modifier le fichier .env
Éditez le fichier `.env` avec vos paramètres :
```bash
# SMTP Server Configuration
SMTP_TLS_ADDR=0.0.0.0:8465
SMTP_PLAIN_ADDR=0.0.0.0:8025

# SSL/TLS Certificate Paths (optionnel pour les tests)
CERT_PATH=localhost.crt
KEY_PATH=localhost.key

# SMTP Authentication
SMTP_USERNAME=admin
SMTP_PASSWORD=password123

# MongoDB Configuration (optionnel pour les tests)
MONGODB_USERNAME=your_mongodb_username
MONGODB_PASSWORD=your_mongodb_password
MONGODB_CLUSTER_URL=your_cluster.mongodb.net
MONGODB_APP_NAME=mailserver

# IMAP Server Configuration
IMAP_SERVER=0.0.0.0:143
IMAP_SERVER_API_PORT=8080

# API Server Configuration
API_SERVER_ADDR=0.0.0.0:8000

# Logging
RUST_LOG=debug
```

#### 1.3 Créer les certificats SSL (optionnel)
Pour les tests, vous pouvez créer des certificats auto-signés :
```bash
mkdir -p certs
cd certs

# Générer une clé privée
openssl genrsa -out localhost.key 2048

# Générer un certificat auto-signé
openssl req -new -x509 -key localhost.key -out localhost.crt -days 365 -subj "/CN=localhost"

# Copier pour les autres services
cp localhost.crt fullchain.pem
cp localhost.key privkey.pem
```

### 2. Lancement avec Docker Compose

#### 2.1 Lancer tous les services
```bash
docker-compose up -d
```

#### 2.2 Lancer un service spécifique
```bash
# Seulement le serveur SMTP
docker-compose up -d smtp-server

# Seulement l'API email
docker-compose up -d email-api

# Seulement le serveur IMAP
docker-compose up -d imap-server
```

#### 2.3 Vérifier les logs
```bash
# Tous les services
docker-compose logs -f

# Service spécifique
docker-compose logs -f smtp-server
docker-compose logs -f email-api
docker-compose logs -f imap-server
```

### 3. Lancement avec Docker simple

#### 3.1 Construire l'image
```bash
docker build -t mailserver .
```

#### 3.2 Lancer le serveur SMTP
```bash
docker run -d \
  --name smtp-server \
  -p 25:25 \
  -p 8025:8025 \
  -p 8465:8465 \
  -v $(pwd)/emails:/app/emails \
  -v $(pwd)/certs:/app/certs \
  -e SMTP_TLS_ADDR=0.0.0.0:8465 \
  -e SMTP_PLAIN_ADDR=0.0.0.0:8025 \
  -e CERT_PATH=/app/certs/localhost.crt \
  -e KEY_PATH=/app/certs/localhost.key \
  -e SMTP_USERNAME=admin \
  -e SMTP_PASSWORD=password123 \
  -e RUST_LOG=debug \
  mailserver smtp_server
```

#### 3.3 Lancer l'API email
```bash
docker run -d \
  --name email-api \
  -p 8000:8000 \
  -p 8443:8443 \
  -v $(pwd)/certs:/app/certs \
  -e API_SERVER_ADDR=0.0.0.0:8000 \
  -e FULLCHAIN_PATH=/app/certs/fullchain.pem \
  -e PRIVKEY_PATH=/app/certs/privkey.pem \
  -e SMTP_USERNAME=admin \
  -e SMTP_PASSWORD=password123 \
  -e RUST_LOG=debug \
  mailserver email_api
```

## 🧪 Tests de l'application

### 1. Test du serveur SMTP

#### 1.1 Test de connexion SMTP
```bash
# Test de connexion sur le port plain (8025)
telnet localhost 8025

# Test de connexion sur le port TLS (8465)
openssl s_client -connect localhost:8465 -crlf
```

#### 1.2 Test d'envoi d'email avec telnet
```bash
telnet localhost 8025

# Dans telnet, tapez :
EHLO localhost
MAIL FROM: <test@example.com>
RCPT TO: <recipient@example.com>
DATA
Subject: Test Email
From: test@example.com
To: recipient@example.com

This is a test email.
.
QUIT
```

#### 1.3 Test avec swaks (si installé)
```bash
# Test simple
swaks --to recipient@example.com --from test@example.com --server localhost:8025

# Test avec authentification
swaks --to recipient@example.com --from test@example.com --server localhost:8025 --auth-user admin --auth-password password123

# Test TLS
swaks --to recipient@example.com --from test@example.com --server localhost:8465 --tls
```

### 2. Test de l'API email

#### 2.1 Test de l'endpoint d'envoi d'email
```bash
curl -X POST http://localhost:8000/send-email \
  -H "Content-Type: application/json" \
  -d '{
    "from": "test@example.com",
    "to": "recipient@example.com",
    "subject": "Test via API",
    "body": "This is a test email sent via the API."
  }'
```

#### 2.2 Test de création de liste de diffusion
```bash
curl -X POST http://localhost:8000/create-mailing-list \
  -H "Content-Type: application/json" \
  -d '{
    "label": "test-list",
    "emails": ["user1@example.com", "user2@example.com"]
  }'
```

#### 2.3 Test d'envoi à une liste de diffusion
```bash
curl -X POST http://localhost:8000/send-to-mailing-list \
  -H "Content-Type: application/json" \
  -d '{
    "label": "test-list",
    "from": "admin@example.com",
    "subject": "Newsletter",
    "body": "This is a newsletter sent to the mailing list."
  }'
```

### 3. Test du serveur IMAP

#### 3.1 Test de connexion IMAP
```bash
# Test de connexion IMAP
telnet localhost 143

# Dans telnet, tapez :
a001 LOGIN admin password123
a002 LIST "" "*"
a003 LOGOUT
```

#### 3.2 Test avec un client IMAP
Utilisez un client email comme Thunderbird ou Outlook pour vous connecter :
- Serveur : localhost
- Port : 143 (IMAP) ou 993 (IMAPS)
- Utilisateur : admin
- Mot de passe : password123

### 4. Vérification des emails reçus

#### 4.1 Vérifier les fichiers d'emails
```bash
# Lister les emails reçus
ls -la emails/

# Voir le contenu d'un email
cat emails/[nom_du_fichier].eml
```

#### 4.2 Vérifier les logs Docker
```bash
# Logs du serveur SMTP
docker-compose logs smtp-server

# Logs de l'API
docker-compose logs email-api

# Logs du serveur IMAP
docker-compose logs imap-server
```

### 5. Tests de charge et performance

#### 5.1 Test de charge simple avec curl
```bash
# Envoyer 10 emails en parallèle
for i in {1..10}; do
  curl -X POST http://localhost:8000/send-email \
    -H "Content-Type: application/json" \
    -d "{
      \"from\": \"test$i@example.com\",
      \"to\": \"recipient@example.com\",
      \"subject\": \"Test $i\",
      \"body\": \"This is test email number $i.\"
    }" &
done
wait
```

#### 5.2 Test de connectivité réseau
```bash
# Vérifier que les ports sont ouverts
netstat -tlnp | grep -E ':(25|8025|8465|8000|8443|143|993)'

# Ou avec nmap
nmap -p 25,8025,8465,8000,8443,143,993 localhost
```

## 🔧 Dépannage

### Problèmes courants

#### 1. Erreur de certificats SSL
```bash
# Vérifier que les certificats existent
ls -la certs/

# Régénérer les certificats si nécessaire
cd certs
openssl genrsa -out localhost.key 2048
openssl req -new -x509 -key localhost.key -out localhost.crt -days 365 -subj "/CN=localhost"
```

#### 2. Erreur de permissions
```bash
# Donner les bonnes permissions aux certificats
chmod 600 certs/*.key
chmod 644 certs/*.crt
```

#### 3. Ports déjà utilisés
```bash
# Vérifier les ports utilisés
sudo netstat -tlnp | grep -E ':(25|8025|8465|8000|8443|143|993)'

# Arrêter les services qui utilisent ces ports
sudo systemctl stop postfix  # si postfix utilise le port 25
```

#### 4. Problèmes de MongoDB
Si vous n'utilisez pas MongoDB, commentez les variables MongoDB dans le `.env` ou utilisez une base de données locale.

### Commandes utiles

```bash
# Arrêter tous les services
docker-compose down

# Redémarrer un service
docker-compose restart smtp-server

# Voir les conteneurs en cours
docker-compose ps

# Nettoyer les conteneurs et images
docker-compose down --rmi all --volumes --remove-orphans

# Reconstruire les images
docker-compose build --no-cache
```

## 📊 Monitoring

### Vérifier l'état des services
```bash
# État des conteneurs
docker-compose ps

# Utilisation des ressources
docker stats

# Logs en temps réel
docker-compose logs -f --tail=100
```

### Métriques importantes
- Nombre d'emails reçus : `ls emails/ | wc -l`
- Taille du répertoire emails : `du -sh emails/`
- Logs d'erreur : `docker-compose logs | grep ERROR` 