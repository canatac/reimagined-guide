# main.tf - Infrastructure Scaleway pour SMTP Rust

terraform {
  required_providers {
    scaleway = {
      source  = "scaleway/scaleway"
      version = "~> 2.0"
    }
  }
  required_version = ">= 0.13"
}

provider "scaleway" {
  zone   = "fr-par-1"
  region = "fr-par"
}

# Groupe de sécurité
resource "scaleway_instance_security_group" "smtp_sg" {
  name        = "smtp-security-group"
  description = "Allow SMTP, IMAP, API, SSH, and HTTPS web traffic"
  inbound_rule {
    action   = "accept"
    port     = 22
    ip_range = "0.0.0.0/0"
  }
  inbound_rule {
    action   = "accept"
    port     = 80
    ip_range = "0.0.0.0/0"
  }
  inbound_rule {
    action   = "accept"
    port     = 443
    ip_range = "0.0.0.0/0"
  }
  inbound_rule {
    action   = "accept"
    port     = 25
    ip_range = "0.0.0.0/0"
  }
  inbound_rule {
    action   = "accept"
    port     = 587
    ip_range = "0.0.0.0/0"
  }
  inbound_rule {
    action   = "accept"
    port     = 143
    ip_range = "0.0.0.0/0"
  }
  inbound_rule {
    action   = "accept"
    port     = 8080
    ip_range = "0.0.0.0/0"
  }
  outbound_rule {
    action   = "accept"
    port     = 443
    ip_range = "0.0.0.0/0"
  }
}

# Registre de conteneurs
resource "scaleway_registry_namespace" "smtp_registry" {
  name        = "smtp-rust-registry"
  description = "Registry for SMTP Rust images"
  is_public   = false
}

# IP publique
resource "scaleway_instance_ip" "smtp_ip" {
  # L'IP est créée automatiquement
}

# VM Ubuntu 22.04 LTS
resource "scaleway_instance_server" "smtp_vm" {
  name              = "smtp-vm"
  type              = "DEV1-S"  # 2 vCPUs, 2GB RAM
  image             = "ubuntu_jammy"
  security_group_id = scaleway_instance_security_group.smtp_sg.id
  ip_id             = scaleway_instance_ip.smtp_ip.id  # Attacher l'IP ici

  user_data = {
    cloud-init = <<-EOT
      #cloud-config
      package_update: true
      package_upgrade: true
      packages:
        - docker.io
        - docker-compose
      ssh_authorized_keys:
        - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0u6jSIq3HSixMdiqkiTYM3BhQGNi/sjq88rZ9MyHfl github-login
      runcmd:
        - [ systemctl, enable, docker ]
        - [ systemctl, start, docker ]
        - [ usermod, -aG, docker, ubuntu ]
    EOT
  }
}

# Outputs
output "registry_endpoint" {
  value = scaleway_registry_namespace.smtp_registry.endpoint
}

output "vm_public_ip" {
  value = scaleway_instance_ip.smtp_ip.address
}

output "registry_username" {
  value = scaleway_registry_namespace.smtp_registry.organization_id
}

output "registry_note" {
  value = "⚠️ Pour obtenir un mot de passe : scw registry namespace get-access-key ${scaleway_registry_namespace.smtp_registry.id}"
}