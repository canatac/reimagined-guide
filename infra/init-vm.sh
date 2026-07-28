#!/bin/bash
# init-vm.sh - Initialisation de la VM pour SMTP Rust

# Installer Docker
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io

# Ajouter l'utilisateur au groupe docker
sudo usermod -aG docker $USER

# Installer Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.23.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Configurer le login Scaleway Container Registry
SCW_REGISTRY_ENDPOINT="${SCW_REGISTRY_ENDPOINT}"
SCW_ACCESS_KEY="${SCW_ACCESS_KEY}"
SCW_SECRET_KEY="${SCW_SECRET_KEY}"

echo "Logging into Scaleway Container Registry $SCW_REGISTRY_ENDPOINT..."
echo $SCW_SECRET_KEY | docker login $SCW_REGISTRY_ENDPOINT -u $SCW_ACCESS_KEY --password-stdin

# Créer le répertoire pour les configs
mkdir -p /home/smtpadmin/smtp-config

# Créer le service systemd pour le conteneur SMTP
cat <<EOF | sudo tee /etc/systemd/system/smtp.service
[Unit]
Description=SMTP Rust Container
After=network.target

[Service]
Restart=always
User=smtpadmin
ExecStart=/usr/bin/docker run --rm -p 25:25 -p 587:587 -p 143:143 -p 8080:8080 -v /home/smtpadmin/smtp-config:/config $SCW_REGISTRY_ENDPOINT/smtp-server:latest
WorkingDirectory=/home/smtpadmin

[Install]
WantedBy=multi-user.target
EOF

# Recharger systemd et démarrer le service
sudo systemctl daemon-reload
sudo systemctl enable smtp.service
sudo systemctl start smtp.service

# Vérifier que le conteneur tourne
docker ps
