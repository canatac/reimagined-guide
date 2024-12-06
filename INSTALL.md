# Installation and Operation Guide for an SMTP Mail Server with DKIM Management

## Introduction
This guide describes the steps to install, configure, and operate an SMTP mail server on a Linux machine. It includes TLS management, DKIM integration for email signing, and related service operations.

---

## 1. Prerequisites
- Access to a Linux machine with root privileges.
- **Certbot** to manage SSL/TLS certificates.
- **OpenDKIM** for DKIM signatures.
- **Rust** and **Cargo** to run your SMTP server binaries.
- Testing tools such as `telnet`, `swaks`, and `openssl`.

---

## 2. Installing Dependencies
### Update and install essential packages
```bash
sudo apt-get update
sudo apt-get upgrade
sudo apt-get install -y telnet net-tools swaks openssl certbot opendkim opendkim-tools
```

---

## 3. SMTP Server Configuration

### 3.1 Generate TLS Certificates
Generate a self-signed certificate or use Let’s Encrypt:

#### Self-signed Certificate
```bash
openssl genrsa -out tls_key.pem 2048
openssl req -new -key tls_key.pem -out tls_csr.pem
openssl x509 -req -days 365 -in tls_csr.pem -signkey tls_key.pem -out tls_cert.pem
chmod 600 tls_key.pem
```

#### Let’s Encrypt with Certbot
```bash
sudo certbot certonly --standalone -d mail.misfits.ai
```

### 3.2 Manage Certificate Permissions
Ensure your server can access the Let’s Encrypt certificates:
```bash
sudo chown root:cert-access /etc/letsencrypt/live/mail.misfits.ai/
sudo chmod 750 /etc/letsencrypt/live/mail.misfits.ai/
```

---

## 4. DKIM Configuration

### 4.1 Generate DKIM Keys
```bash
sudo -u opendkim opendkim-genkey -D /etc/dkimkeys -d misfits.ai -s haydi
sudo chmod 600 /etc/dkimkeys/haydi.private
```
Publish the DKIM public key in a DNS TXT record:
```
haydi._domainkey.misfits.ai IN TXT "v=DKIM1; k=rsa; p=<public_key>"
```

### 4.2 Test DKIM Key
```bash
sudo opendkim-testkey -d misfits.ai -s haydi -vvv
```

### 4.3 Validate DKIM on Messages
Use `opendkim-testmsg` to validate DKIM signatures on sent emails.

---

## 5. Deployment and Server Execution

### 5.1 Install Rust Services
Compile and run the SMTP server:
```bash
cd /path/to/MAILSERVER/reimagined-guide
cargo run --bin smtp_server
```

### 5.2 Create a systemd Service
Create a service file to automatically start your server:

#### Example: `/etc/systemd/system/smtp_server.service`
```ini
[Unit]
Description=SMTP Server
After=network.target

[Service]
User=azureuser
WorkingDirectory=/home/azureuser/MAILSERVER/reimagined-guide
ExecStart=/usr/bin/cargo run --bin smtp_server
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable smtp_server.service
sudo systemctl start smtp_server.service
sudo systemctl status smtp_server.service
```

---

## 6. Testing and Debugging

### 6.1 Test SMTP Connectivity
```bash
telnet localhost 25
```

### 6.2 Send Test Emails
Use `swaks` to test email sending:
```bash
swaks --to user@example.com --from test@misfits.ai --server localhost:25
```

### 6.3 Validate Logs
Check logs for debugging:
```bash
sudo journalctl -u smtp_server.service -f
```

---

## 7. Maintenance and Certificate Renewal

### 7.1 Renew Let’s Encrypt Certificates
```bash
sudo certbot renew
```
Restart the SMTP service after each renewal:
```bash
sudo systemctl restart smtp_server.service
```

### 7.2 Manage Logs
Clear system logs to optimize disk space:
```bash
sudo journalctl --vacuum-time=30d
```

---

## 8. Future Optimizations
- Automate DKIM testing for each email.
- Integrate SPF and DMARC.
- Add alerts for critical errors in logs.

---

## Conclusion
This guide provides the foundation for deploying and operating a secure SMTP server with DKIM management. Adjust configurations as needed to ensure optimal availability.

