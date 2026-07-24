#!/bin/bash
# setup-secrets.sh - Script pour configurer les secrets GitHub (Scaleway)

# Vérifier que gh CLI est installé
gh --version >/dev/null 2>&1 || { echo "GitHub CLI (gh) n'est pas installé. Installe-le avec : sudo apt install gh"; exit 1; }

# Se connecter à GitHub
gh auth status >/dev/null 2>&1 || gh auth login

# Demander les informations
read -p "Nom du dépôt GitHub (ex: canatac/reimagined-guide): " REPO
read -p "Nom du registre Scaleway (ex: smtp-rust-registry): " REGISTRY_NAME
read -p "IP publique de la VM: " VM_IP
read -p "Chemin vers ta clé SSH privée (ex: ~/.ssh/id_rsa): " SSH_KEY_PATH

# Lire la clé SSH
SSH_KEY=$(cat $SSH_KEY_PATH)

# Lire le known_hosts pour la VM
KNOWN_HOSTS=$(ssh-keyscan $VM_IP 2>/dev/null)

# Demander les credentials Scaleway
read -p "Scaleway Access Key: " SCW_ACCESS_KEY
read -p "Scaleway Secret Key: " SCW_SECRET_KEY
read -p "Scaleway Default Project ID: " SCW_DEFAULT_PROJECT_ID

# Configurer les secrets GitHub
echo "Configuration des secrets GitHub pour $REPO..."

echo $REGISTRY_NAME | gh secret set REGISTRY_NAME --repo $REPO --app actions
echo $VM_IP | gh secret set VM_IP --repo $REPO --app actions
echo "$SSH_KEY" | gh secret set VM_SSH_KEY --repo $REPO --app actions
echo "$KNOWN_HOSTS" | gh secret set VM_KNOWN_HOSTS --repo $REPO --app actions
echo $SCW_ACCESS_KEY | gh secret set SCW_ACCESS_KEY --repo $REPO --app actions
echo $SCW_SECRET_KEY | gh secret set SCW_SECRET_KEY --repo $REPO --app actions
echo $SCW_DEFAULT_PROJECT_ID | gh secret set SCW_DEFAULT_PROJECT_ID --repo $REPO --app actions

echo "✅ Secrets configurés avec succès !"