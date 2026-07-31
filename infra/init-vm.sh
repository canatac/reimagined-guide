#!/bin/bash
# =============================================================================
# init-vm.sh — Provisionnement d'une VM Scaleway fraîche pour le stack mail
# =============================================================================
#
# À exécuter UNE SEULE FOIS sur une nouvelle VM Debian 11 (Bullseye).
# La VM doit être créée au préalable via Terraform (infra/main.tf).
#
# Usage depuis votre machine locale :
#   scp infra/init-vm.sh debian@<VM_PUBLIC_IP>:~
#   ssh debian@<VM_PUBLIC_IP> "bash ~/init-vm.sh <MONGODB_PASSWORD> <MONGODB_USERNAME>"
#
# Exemple :
#   ssh debian@51.158.114.182 "bash ~/init-vm.sh 'MonMotDePasse123' 'adoremio'"
#
# Ce script installe et configure :
#   1. Docker Engine (CE)
#   2. MongoDB 7 (natif, pas en container)
#   3. Pare-feu nftables (INPUT + FORWARD)
#   4. Permissions sudo pour l'utilisateur debian
#
# Après ce script, le CI/CD GitHub Actions déploie le stack via
# docker-compose.deploy.yml (smtp-server, email-api, imap-server, caddy...).
# =============================================================================

set -euo pipefail

MONGODB_PASSWORD="${1:?Usage: $0 <MONGODB_PASSWORD> <MONGODB_USERNAME>}"
MONGODB_USERNAME="${2:?Usage: $0 <MONGODB_PASSWORD> <MONGODB_USERNAME>}"
MONGODB_DATABASE="mailserver"

echo "=== Mise à jour système ==="
sudo apt-get update -qq
sudo apt-get upgrade -y -qq

echo "=== Installation des paquets de base ==="
sudo apt-get install -y -qq \
  curl wget gnupg ca-certificates lsb-release \
  nftables apt-transport-https

# =============================================================================
# 1. Docker Engine
# =============================================================================
echo "=== Installation de Docker ==="
if ! command -v docker &>/dev/null; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg \
    | sudo gpg --batch --yes --no-tty --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg

  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/debian \
    $(lsb_release -cs) stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

  sudo apt-get update -qq
  sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
  sudo systemctl enable --now docker
  echo "Docker installé : $(docker --version)"
else
  echo "Docker déjà installé : $(docker --version)"
fi

# Ajouter l'utilisateur courant au groupe docker
sudo usermod -aG docker "$USER"

# =============================================================================
# 2. MongoDB 7
# =============================================================================
echo "=== Installation de MongoDB ==="
DISTRO_CODENAME=$(lsb_release -cs)
MONGO_VERSION="8.0"
# Les paquets serveur MongoDB n'existent que pour bullseye et bookworm ;
# trixie+ → bookworm (cf. https://www.mongodb.com/docs/v8.0/tutorial/install-mongodb-on-debian/)
case "$DISTRO_CODENAME" in
  bullseye) MONGO_DISTRO="bullseye" ;;
  *)        MONGO_DISTRO="bookworm" ;;
esac
# Supprimer tout ancien .list MongoDB malformé avant d'en écrire un nouveau
sudo rm -f /etc/apt/sources.list.d/mongodb-org-*.list
if ! command -v mongod &>/dev/null; then
  curl -fsSL "https://www.mongodb.org/static/pgp/server-${MONGO_VERSION}.asc" \
    | sudo gpg --batch --yes --no-tty --dearmor \
      -o "/usr/share/keyrings/mongodb-server-${MONGO_VERSION}.gpg"
  sudo chmod a+r "/usr/share/keyrings/mongodb-server-${MONGO_VERSION}.gpg"
  echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-${MONGO_VERSION}.gpg ] https://repo.mongodb.org/apt/debian ${MONGO_DISTRO}/mongodb-org/${MONGO_VERSION} main" \
    | sudo tee "/etc/apt/sources.list.d/mongodb-org-${MONGO_VERSION}.list"

  sudo apt-get update
  sudo apt-get install -y mongodb-org
  sudo systemctl enable --now mongod
  echo "MongoDB installé : $(mongod --version | head -1)"
else
  echo "MongoDB déjà installé : $(mongod --version | head -1)"
fi

# Configurer MongoDB : bind sur localhost + IP privée Scaleway (172.16.x.x)
PRIVATE_IP=$(ip route get 8.8.8.8 | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1); exit}')
echo "IP privée détectée : $PRIVATE_IP"

sudo sed -i "s|bindIp: 127.0.0.1|bindIp: 127.0.0.1,$PRIVATE_IP|g" /etc/mongod.conf

# Activer l'authentification MongoDB
if ! grep -q "^security:" /etc/mongod.conf; then
  printf '\nsecurity:\n  authorization: enabled\n' | sudo tee -a /etc/mongod.conf
fi

# Créer l'utilisateur applicatif (nécessite mongod sans auth pour la première fois)
echo "Création de l'utilisateur MongoDB '$MONGODB_USERNAME'..."
# Démarrer sans auth pour créer l'admin d'abord
sudo mongosh --quiet --eval "
  db = db.getSiblingDB('admin');
  if (db.getUser('$MONGODB_USERNAME') == null) {
    db.createUser({
      user: '$MONGODB_USERNAME',
      pwd: '$MONGODB_PASSWORD',
      roles: [
        { role: 'readWrite', db: '$MONGODB_DATABASE' },
        { role: 'dbAdmin',   db: '$MONGODB_DATABASE' }
      ]
    });
    print('Utilisateur créé.');
  } else {
    print('Utilisateur déjà existant.');
  }
" || echo "AVERTISSEMENT : mongosh a échoué (l'utilisateur existe peut-être déjà)"

# Redémarrer avec auth activée
sudo systemctl restart mongod
sleep 2
echo "MongoDB prêt avec authentification sur $PRIVATE_IP:27017"

# =============================================================================
# 3. Pare-feu nftables
# =============================================================================
echo "=== Configuration nftables ==="

sudo tee /etc/nftables.conf > /dev/null << 'NFTEOF'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;

    # Trafic loopback
    iif lo accept

    # Connexions établies
    ct state established,related accept

    # SSH
    tcp dport 22 accept

    # HTTP/HTTPS (pour Caddy + ACME)
    tcp dport { 80, 443 } accept

    # SMTP
    tcp dport { 25, 465, 587 } accept

    # IMAP
    tcp dport { 143, 993 } accept

    # MongoDB depuis le réseau privé Scaleway uniquement
    ip saddr 172.16.0.0/12 tcp dport 27017 accept

    # ICMP
    icmp type echo-request accept
    icmpv6 type echo-request accept
  }

  chain forward {
    type filter hook forward priority 0; policy drop;

    # Trafic DNAT (Caddy host mode → containers)
    ct status dnat accept

    # Trafic établi
    ct state established,related accept

    # Containers → internet (réseau Docker bridge)
    ip saddr 172.16.0.0/12 accept
    ip saddr 172.17.0.0/16 accept
  }

  chain output {
    type filter hook output priority 0; policy accept;
  }
}
NFTEOF

sudo systemctl enable --now nftables
sudo nft -f /etc/nftables.conf
echo "nftables configuré."

# =============================================================================
# 4. Sudo passwordless pour les commandes Docker (CI/CD GitHub Actions)
# =============================================================================
echo "=== Configuration sudo pour CI/CD ==="
cat << 'SUDOEOF' | sudo tee /etc/sudoers.d/docker-cicd
debian ALL=(ALL) NOPASSWD: /usr/bin/docker, /usr/bin/nft, /usr/sbin/nft, /usr/bin/systemctl restart docker, /usr/bin/systemctl restart mongod, /bin/cp, /bin/chmod, /bin/chown, /usr/bin/tee
SUDOEOF
sudo chmod 0440 /etc/sudoers.d/docker-cicd

# =============================================================================
# Résumé
# =============================================================================
echo ""
echo "=== ✅ Provisionnement terminé ==="
echo ""
echo "  IP privée MongoDB   : $PRIVATE_IP:27017"
echo "  Utilisateur MongoDB : $MONGODB_USERNAME (DB: $MONGODB_DATABASE)"
echo ""
echo "Prochaines étapes :"
echo "  1. Mettre à jour MONGODB_URL dans 1Password : mongodb://$MONGODB_USERNAME:<pass>@$PRIVATE_IP:27017/$MONGODB_DATABASE?authSource=admin"
echo "  2. Pousser sur main pour déclencher le CI/CD GitHub Actions"
echo "  3. Vérifier les logs : ssh debian@<VM_IP> 'sudo docker compose -f docker-compose.deploy.yml logs'"
