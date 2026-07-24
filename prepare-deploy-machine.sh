#!/bin/bash
# prepare-deploy-machine.sh - Préparation de la machine de déploiement
# Objectif : Installer TOUS les pré-requis pour déployer sur Scaleway
# Exécuter avec : sudo ./prepare-deploy-machine.sh

set -euo pipefail

LOG_FILE="/tmp/prepare-deploy-$(date +%s).log"
echo "=== Préparation de la machine de déploiement ===" | tee $LOG_FILE

# 1. Mettre à jour le système
sudo apt-get update && sudo apt-get upgrade -y

# 2. Installer les outils système
sudo apt-get install -y \
  curl \
  wget \
  git \
  jq \
  unzip \
  openssh-client \
  dnsutils \
  netcat-openbsd

# 3. Installer Terraform
if ! command -v terraform &> /dev/null; then
  echo "Installation de Terraform..." | tee -a $LOG_FILE
  wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor | sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg >/dev/null
  echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
  sudo apt-get update && sudo apt-get install -y terraform
fi

# 4. Installer GitHub CLI (gh)
if ! command -v gh &> /dev/null; then
  echo "Installation de GitHub CLI..." | tee -a $LOG_FILE
  curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo gpg --dearmor -o /usr/share/keyrings/githubcli-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
  sudo apt-get update && sudo apt-get install -y gh
fi

# 5. Installer Scaleway CLI (scw)
if ! command -v scw &> /dev/null; then
  echo "Installation de Scaleway CLI..." | tee -a $LOG_FILE
  curl -s https://raw.githubusercontent.com/scaleway/scaleway-cli/master/install.sh | bash
  export PATH=$PATH:$HOME/.scw/bin
  echo 'export PATH=$PATH:$HOME/.scw/bin' >> ~/.bashrc
fi

# 6. Configurer Terraform pour Scaleway
if [ ! -d ~/.terraform.d/plugins ]; then
  echo "Configuration de Terraform pour Scaleway..." | tee -a $LOG_FILE
  mkdir -p ~/.terraform.d/plugins
  wget https://github.com/scaleway/terraform-provider-scaleway/releases/download/v2.12.0/terraform-provider-scaleway_2.12.0_linux_amd64.zip
  unzip terraform-provider-scaleway_2.12.0_linux_amd64.zip
  mv terraform-provider-scaleway_v2.12.0 ~/.terraform.d/plugins/
  rm terraform-provider-scaleway_2.12.0_linux_amd64.zip
fi

# 7. Vérifier les installations
TERRAFORM_VERSION=$(terraform --version | head -n1)
GH_VERSION=$(gh --version | head -n1)
SCW_VERSION=$(scw version | head -n1 2>/dev/null || echo "Non configuré")

echo -e "\n=== Vérification des installations ===" | tee -a $LOG_FILE
echo "✅ Terraform : $TERRAFORM_VERSION" | tee -a $LOG_FILE
echo "✅ GitHub CLI : $GH_VERSION" | tee -a $LOG_FILE
echo "✅ Scaleway CLI : $SCW_VERSION" | tee -a $LOG_FILE

echo -e "\n=== Préparation terminée ===" | tee -a $LOG_FILE
echo "Log détaillé : $LOG_FILE"
echo -e "\n📌 Prochaines étapes :"
echo "1. Se connecter à GitHub : gh auth login"
echo "2. Se connecter à Scaleway : scw init"
echo "3. Exécuter terraform apply dans /home/canatac/reimagined-guide/infra/"
