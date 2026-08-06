# Phase A — Gmail deliverability bootstrap (100% autonome, sans relay tiers)

Objectif: sortir du `550-5.7.1 NotAuthorizedError` Gmail en alignant identité DNS + MTA + preuves de conformité.

## 0) Hypothèses
- IP sortante SMTP: `51.158.114.182`
- FQDN SMTP: `mail.misfits.ai`
- Domaine From principal: `misfits.ai`
- API envoi: `https://mail.misfits.ai/api/send`

## 1) DNS/identité (bloquant)
1. PTR/rDNS (chez provider IP):
   - `51.158.114.182 -> mail.misfits.ai`
2. A record (Azure DNS):
   - `mail.misfits.ai -> 51.158.114.182`
3. SPF (zone `misfits.ai`):
   - `v=spf1 ip4:51.158.114.182 -all`
4. DKIM 2048 bits (selector actif) aligné `d=misfits.ai`
5. DMARC (phase initiale):
   - `_dmarc.misfits.ai TXT "v=DMARC1; p=none; adkim=s; aspf=s; rua=mailto:dmarc@misfits.ai; pct=100"`

## 2) MTA runtime (smtp-vm)
1. EHLO/HELO = `mail.misfits.ai`
2. STARTTLS fonctionnel (chaîne cert valide)
3. Queue + retry:
   - 4xx: retry exponentiel
   - 5xx policy (ex 5.7.1): no immediate retry flood
4. Throttle Gmail:
   - limiter concurrence + débit vers `gmail.com` et `googlemail.com`
5. Observabilité obligatoire par tentative:
   - `message_id`, `mx_host`, `remote_ip`, `smtp_code`, `smtp_reply`, `attempt`

## 3) Vérifications ad-hoc (commandes)

### 3.1 DNS identity
Depuis n'importe quelle machine avec dig:

```bash
dig +short A mail.misfits.ai
dig +short -x 51.158.114.182
dig +short TXT misfits.ai
dig +short TXT selector1._domainkey.misfits.ai
dig +short TXT _dmarc.misfits.ai
```

Attendu:
- A = `51.158.114.182`
- PTR = `mail.misfits.ai`
- SPF contient `ip4:51.158.114.182`
- DKIM record présent
- DMARC record présent

### 3.2 SMTP/TLS identité sortante
Depuis smtp-vm:

```bash
openssl s_client -starttls smtp -connect mail.protonmail.ch:25 -servername mail.protonmail.ch < /dev/null
```

Attendu:
- handshake TLS réussi (pas d'erreur cert critique côté client)

### 3.3 Test envoi API (Gmail)
Depuis smtp-vm:

```bash
curl -sS -X POST 'http://127.0.0.1:8000/api/send' \
  -H 'content-type: application/json' \
  -H 'x-user-id: admin' \
  -H 'x-user-email: admin@misfits.ai' \
  -d '{
    "from":"joey.starr@misfits.ai",
    "to":[{"email":"can.atac@gmail.com","name":"Can"}],
    "subject":"phase-a gmail bootstrap",
    "body":"<p>phase-a verification</p>"
  }'
```

Puis vérifier:
1) `/api/send/{id}/status`
2) `/api/monitoring/messages/{message_id}/trace`

Attendu minimal:
- si acceptation Gmail: `acceptedByRemoteMx=true`, `latestSmtpReply` en `250 ...`, `handoffOnly=false`
- si blocage réputation: `smtp_code=550`, `smtp_reply` contenant `5.7.1 NotAuthorizedError`

## 4) Critères de sortie Phase A
- [ ] DNS identity complète (A/PTR/SPF/DKIM/DMARC)
- [ ] EHLO aligné `mail.misfits.ai`
- [ ] traces API complètes et exploitables
- [ ] au moins 1 tentative Gmail avec preuve catégorisée (accept ou policy block) via trace API

## 5) Interprétation résultat
- `550-5.7.1 NotAuthorizedError` après identité correcte = réputation IP insuffisante (pas bug applicatif)
- `250` remote MX + trace publique = chemin technique OK; inbox placement dépend réputation/contenu/engagement

## 6) Warm-up (sans relay externe)
- Démarrer bas volume réel (utilisateurs engagés), montée progressive quotidienne
- Monitorer taux 2xx/4xx/5xx par provider
- Activer Google Postmaster Tools et suivre réputation domaine/IP

## 7) Références
- Google help: NotAuthorizedError
  - https://support.google.com/mail/?p=NotAuthorizedError
- Google Postmaster Tools
  - https://postmaster.google.com/
- RFC 5321 (SMTP)
  - https://www.rfc-editor.org/rfc/rfc5321
- RFC 7208 (SPF)
  - https://www.rfc-editor.org/rfc/rfc7208
- RFC 6376 (DKIM)
  - https://www.rfc-editor.org/rfc/rfc6376
- RFC 7489 (DMARC)
  - https://www.rfc-editor.org/rfc/rfc7489
