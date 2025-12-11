# Guide d'intégration des variables d'environnement dans Docker Compose

## 📋 Vue d'ensemble

Ce guide explique comment intégrer les variables d'environnement du fichier `.env` dans votre configuration Docker Compose pour votre serveur SMTP Rust.

## 🔧 Méthodes d'intégration

### 1. **Syntaxe `${VARIABLE}` (Recommandée)**

Docker Compose charge automatiquement le fichier `.env` et permet d'utiliser les variables avec la syntaxe `${VARIABLE}`.

**Exemple dans `docker-compose.yml` :**
```yaml
environment:
  - SMTP_USERNAME=${SMTP_USERNAME}
  - SMTP_PASSWORD=${SMTP_PASSWORD}
  - RUST_LOG=${RUST_LOG}
```

**Avantages :**
- ✅ Chargement automatique du fichier `.env`
- ✅ Valeurs par défaut possibles avec `${VARIABLE:-default}`
- ✅ Validation des variables manquantes
- ✅ Séparation claire entre code et configuration

### 2. **Fichier `.env` explicite**

Vous pouvez aussi spécifier explicitement le fichier d'environnement :
```bash
docker-compose --env-file .env up -d
```

### 3. **Variables d'environnement système**

Les variables d'environnement système sont automatiquement disponibles :
```bash
export SMTP_USERNAME=admin
export SMTP_PASSWORD=secret
docker-compose up -d
```

## 📁 Structure des fichiers

```
├── docker-compose.yml          # Configuration principale
├── docker-compose.override.yml # Surcharges pour le développement
├── docker-compose.prod.yml     # Configuration de production
├── .env                        # Variables d'environnement (à créer)
├── env.example                 # Exemple de variables
└── scripts/
    └── docker-env.sh          # Script de gestion des environnements
```

## 🚀 Utilisation pratique

### **Étape 1 : Créer le fichier .env**
```bash
cp env.example .env
```

### **Étape 2 : Configurer les variables**
Éditez le fichier `.env` :
```bash
# SMTP Server Configuration
SMTP_TLS_ADDR=0.0.0.0:8465
SMTP_PLAIN_ADDR=0.0.0.0:8025

# SSL/TLS Certificate Paths
CERT_PATH=localhost.crt
KEY_PATH=localhost.key
FULLCHAIN_PATH=fullchain.pem
PRIVKEY_PATH=privkey.pem

# SMTP Authentication
SMTP_USERNAME=admin
SMTP_PASSWORD=password123

# MongoDB Configuration
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

### **Étape 3 : Lancer avec le script (recommandé)**
```bash
# Mode développement (avec valeurs par défaut)
./scripts/docker-env.sh dev

# Mode production (validation stricte)
./scripts/docker-env.sh prod
```

### **Étape 4 : Lancer manuellement**
```bash
# Développement
docker-compose up -d

# Production
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

## 🔍 Validation et valeurs par défaut

### **Valeurs par défaut dans `docker-compose.override.yml`**
```yaml
environment:
  - SMTP_USERNAME=${SMTP_USERNAME:-admin}
  - SMTP_PASSWORD=${SMTP_PASSWORD:-password123}
  - RUST_LOG=${RUST_LOG:-debug}
```

### **Validation en production**
Le script `docker-env.sh` vérifie les variables critiques :
```bash
# Variables critiques pour la production
CRITICAL_VARS=(
    "SMTP_USERNAME"
    "SMTP_PASSWORD"
    "MONGODB_USERNAME"
    "MONGODB_PASSWORD"
    "MONGODB_CLUSTER_URL"
)
```

## 🛠️ Commandes utiles

### **Vérifier les variables chargées**
```bash
# Afficher les variables d'environnement d'un conteneur
docker-compose exec smtp-server env | grep SMTP

# Vérifier la configuration
docker-compose config
```

### **Tester avec des variables temporaires**
```bash
# Variables temporaires pour un test
SMTP_USERNAME=test SMTP_PASSWORD=test123 docker-compose up -d
```

### **Debug des variables**
```bash
# Voir quelles variables sont utilisées
docker-compose config | grep -A 10 environment
```

## 🔒 Sécurité

### **Bonnes pratiques**
1. **Ne jamais commiter le fichier `.env`**
   ```bash
   echo ".env" >> .gitignore
   ```

2. **Utiliser des secrets pour la production**
   ```yaml
   # docker-compose.prod.yml
   secrets:
     smtp_password:
       file: ./secrets/smtp_password.txt
   ```

3. **Validation des variables critiques**
   ```bash
   # Le script vérifie automatiquement
   ./scripts/docker-env.sh prod
   ```

### **Gestion des secrets**
```bash
# Créer un fichier de secrets
mkdir -p secrets
echo "votre_mot_de_passe_secret" > secrets/smtp_password.txt
chmod 600 secrets/smtp_password.txt
```

## 📊 Monitoring et debugging

### **Vérifier l'état des services**
```bash
# État des conteneurs
docker-compose ps

# Logs en temps réel
docker-compose logs -f

# Logs d'un service spécifique
docker-compose logs -f smtp-server
```

### **Debug des variables d'environnement**
```bash
# Voir les variables dans un conteneur
docker-compose exec smtp-server printenv | grep SMTP

# Vérifier la configuration résolue
docker-compose config
```

## 🔄 Gestion des environnements

### **Développement**
```bash
./scripts/docker-env.sh dev
# Utilise docker-compose.yml + docker-compose.override.yml
# Valeurs par défaut si .env manquant
```

### **Production**
```bash
./scripts/docker-env.sh prod
# Utilise docker-compose.yml + docker-compose.prod.yml
# Validation stricte des variables
```

### **Test**
```bash
./scripts/docker-env.sh test
# Utilise docker-compose.yml + docker-compose.test.yml
# Configuration isolée pour les tests
```

## 🚨 Dépannage

### **Problèmes courants**

#### 1. **Variable non définie**
```bash
# Erreur : Variable non définie
# Solution : Vérifier le fichier .env
cat .env | grep SMTP_USERNAME
```

#### 2. **Fichier .env non trouvé**
```bash
# Erreur : Fichier .env manquant
# Solution : Copier depuis l'exemple
cp env.example .env
```

#### 3. **Permissions de certificats**
```bash
# Erreur : Certificats non accessibles
# Solution : Vérifier les permissions
chmod 600 certs/*.key
chmod 644 certs/*.crt
```

#### 4. **Ports déjà utilisés**
```bash
# Erreur : Port déjà utilisé
# Solution : Vérifier les services
sudo netstat -tlnp | grep :8025
```

### **Commandes de debug**
```bash
# Vérifier la configuration
docker-compose config

# Tester la connexion
docker-compose exec smtp-server netstat -tlnp

# Vérifier les logs
docker-compose logs --tail=100 smtp-server
```

## 📝 Exemples complets

### **Configuration minimale**
```bash
# .env minimal
SMTP_USERNAME=admin
SMTP_PASSWORD=password123
RUST_LOG=debug

# Lancer
docker-compose up -d smtp-server
```

### **Configuration complète**
```bash
# .env complet
SMTP_TLS_ADDR=0.0.0.0:8465
SMTP_PLAIN_ADDR=0.0.0.0:8025
CERT_PATH=localhost.crt
KEY_PATH=localhost.key
FULLCHAIN_PATH=fullchain.pem
PRIVKEY_PATH=privkey.pem
SMTP_USERNAME=admin
SMTP_PASSWORD=password123
MONGODB_USERNAME=user
MONGODB_PASSWORD=pass
MONGODB_CLUSTER_URL=cluster.mongodb.net
MONGODB_APP_NAME=mailserver
IMAP_SERVER=0.0.0.0:143
IMAP_SERVER_API_PORT=8080
API_SERVER_ADDR=0.0.0.0:8000
RUST_LOG=debug

# Lancer tous les services
./scripts/docker-env.sh prod
```

Cette approche vous donne une gestion flexible et sécurisée de vos variables d'environnement dans Docker Compose ! 