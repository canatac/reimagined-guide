# 📋 Issues — UI End-User pour misfits.ai Mail

> **Contexte:** Plateforme email misfits.ai (backend Rust SMTP/IMAP + DKIM Node.js).
> **Objectif:** Construire une UI web + mobile innovante, IA-first, pour les utilisateurs finaux.
> **Format:** Issues prêtes à importer sur GitHub (ciblant `canatac/reimagined-guide`).
> **Auteur:** Hermes Agent (PM) — en attente des droits GitHub pour upload.
> **Date:** 2026-07-27

---

## 🏗️ Épic 1 — Fondations UI & Design System

### Issue #1 — Setup du projet frontend (monorepo)

**Labels:** `frontend`, `infra`, `P0`, `Epic-1`
**Estimate:** 3

**Description:**
Initialiser le projet frontend dans le monorepo `canatac/reimagined-guide` sous `/web`. Stack recommandée :

- **Framework:** Next.js 15 (App Router, RSC) ou SvelteKit 2
- **Langage:** TypeScript strict
- **Styling:** Tailwind CSS 4 + design tokens
- **State:** Zustand ou Svelte stores
- **Build:** Turbopack / Vite
- **Tests:** Vitest + Playwright (E2E)
- **CI:** Intégration dans le pipeline existant (Azure ACR build)

**Critères d'acceptation:**
- [ ] `/web` initialisé avec la stack choisie
- [ ] `pnpm dev` lance le serveur de dev sur `localhost:3000`
- [ ] `pnpm build` produit un build de production
- [ ] `pnpm test` lance les tests unitaires
- [ ] CI pipeline build le frontend et publie l'image
- [ ] README avec instructions de démarrage

---

### Issue #2 — Design System & Design Tokens

**Labels:** `frontend`, `design`, `P0`, `Epic-1`
**Estimate:** 5

**Description:**
Créer un design system complet avec tokens, composants de base et guidelines. Le design doit être :

- **Moderne et épuré** — inspiré par Linear, Vercel, Superhuman
- **Thèmes:** Light, Dark, et auto (system preference)
- **Accessibilité:** WCAG 2.2 AA minimum, AAA quand possible
- **Internationalisation:** i18n ready (fr/en par défaut, extensible)
- **Responsive:** Mobile-first, tablet, desktop, ultra-wide

**Tokens à définir:**
- Couleurs (primary, secondary, semantic, surface, background)
- Typographie (font families, sizes, weights, line-heights)
- Espacements (scale 4px-based)
- Border-radius
- Shadows (elevation levels)
- Animations (durations, easings, keyframes)
- Z-index scale

**Composants de base (Design System):**
- Button (variants: primary, secondary, ghost, danger, icon)
- Input / Textarea / Select / Combobox
- Checkbox / Radio / Toggle / Slider
- Badge / Chip / Tag
- Avatar
- Card
- Modal / Dialog / Sheet
- Tooltip / Popover
- Toast / Notification
- Tabs / Accordion
- Table / DataGrid
- Skeleton loaders
- Empty states
- Error boundaries
- Command palette (Cmd+K)

**Critères d'acceptation:**
- [ ] Tokens définis en CSS variables + config Tailwind
- [ ] Storybook configuré avec tous les composants
- [ ] Tests visuels (Chromatic ou Percy)
- [ ] Documentation des guidelines d'usage
- [ ] Thèmes light/dark fonctionnels
- [ ] Score Lighthouse accessibilité ≥ 95

---

### Issue #3 — Authentification & Session Management

**Labels:** `frontend`, `auth`, `P0`, `Epic-1`
**Estimate:** 5

**Description:**
Système d'authentification sécurisé pour les utilisateurs finaux de misfits.ai Mail.

**Fonctionnalités:**
- Login (email + password)
- Logout
- Session persistante (httpOnly cookies, refresh tokens)
- Password reset flow (email link)
- Rate limiting sur les tentatives de login
- 2FA / TOTP (option, désactivable par admin)
- Passkeys / WebAuthn (support moderne)
- "Se souvenir de moi" (device trust)
- Détection de session concurrente
- Audit log des connexions

**UI:**
- Page de login épurée avec branding misfits.ai
- Indicateur visuel de force du mot de passe
- États d'erreur clairs et accessibles
- Redirect après login vers inbox
- Lock screen après inactivité (configurable)

**Critères d'acceptation:**
- [ ] Login/logout fonctionnels
- [ ] Session persistante avec refresh automatique
- [ ] Password reset complet (email → reset → confirmation)
- [ ] 2FA TOTP fonctionnel
- [ ] Passkeys supportés sur navigateurs compatibles
- [ ] Tests E2E pour tous les flows
- [ ] Audit log consultable

---

## 📬 Épic 2 — Inbox & Email Management

### Issue #4 — Vue Inbox principale

**Labels:** `frontend`, `feature`, `P0`, `Epic-2`
**Estimate:** 8

**Description:**
Vue inbox principale — le cœur de l'application. Doit être rapide, fluide, et offrir une expérience premium (type Superhuman / Shortwave).

**Layout:**
- **Sidebar gauche:** Dossiers (Inbox, Sent, Drafts, Archive, Trash, Spam), labels, comptes multiples
- **Liste centrale:** Liste des emails avec preview, tri, filtre, recherche rapide
- **Panneau de lecture droit:** Email sélectionné avec rendu HTML sécurisé, pièces jointes, headers
- **Layout adaptatif:** 3 colonnes (desktop large), 2 colonnes (desktop), 1 colonne (mobile/tablet)

**Fonctionnalités de base:**
- Liste des emails avec: expéditeur, sujet, preview, date, flags (unread, starred, important, attachments)
- Tri par date, expéditeur, sujet, taille, non-lus d'abord
- Filtres rapides: Tous, Non-lus, Suivis, Avec pièces jointes
- Sélection multiple avec actions bulk (marquer lu, archiver, supprimer, déplacer, label)
- Pagination infinie ou virtualisation (performance pour gros volumes)
- Raccourcis clavier (j/k navigation, e archiver, # supprimer, etc.)
- Pull-to-refresh sur mobile
- Indicateur de chargement et états vides

**Rendu des emails:**
- HTML sanitization (DOMPurify ou équivalent)
- Prévention des tracking pixels (bloquer images externes par défaut)
- Affichage des pièces jointes avec icônes par type
- Preview des images inline
- Collapse des citations longues
- Affichage "Show quoted text" pour les threads
- Support multipart/alternative (HTML + plaintext fallback)

**Critères d'acceptation:**
- [ ] Inbox charge en < 1s avec 1000 emails
- [ ] Navigation clavier complète documentée
- [ ] HTML emails rendus de façon sécurisée
- [ ] Actions bulk fonctionnelles
- [ ] Responsive sur tous breakpoints
- [ ] Tests E2E des flows principaux

---

### Issue #5 — Composition d'email (Composer)

**Labels:** `frontend`, `feature`, `P0`, `Epic-2`
**Estimate:** 8

**Description:**
Éditeur d'email riche avec formatage, pièces jointes, et intégration IA.

**Fonctionnalités:**
- Éditeur WYSIWYG (Tiptap, Lexical, ou ProseMirror)
- Formatage: gras, italique, souligné, listes, liens, citations, code
- Destinataires: To, Cc, Bcc avec autocomplétion depuis contacts
- Pièces jointes: drag & drop, upload, preview
- Images inline (paste ou upload)
- Signatures personnalisables (par compte)
- Drafts automatiques (sauvegarde toutes les 10s)
- Templates d'email
- Programmation d'envoi (send later)
- Annuler l'envoi (undo send — fenêtre de 5-30s configurable)
- Vérification des destinataires (avertissement si destinataire externe)
- Mode plein écran et mode compact (fenêtre flottante)
- Raccourcis clavier (Cmd+Enter pour envoyer, Cmd+Shift+C pour Cc, etc.)
- Drag des fichiers depuis le système
- Support markdown en input (converti en HTML)

**Validation avant envoi:**
- Vérification des adresses (format + domaine valide)
- Avertissement si pas de pièce jointe mais "pièce jointe" mentionné dans le texte
- Avertissement si destinataire externe (domaine hors misfits.ai)
- Vérification des liens (pas de liens suspects)

**Critères d'acceptation:**
- [ ] Composer fonctionne avec formatage riche
- [ ] Drafts auto sauvegardés et restaurables
- [ ] Pièces jointes upload et preview
- [ ] Send later programmable
- [ ] Undo send fonctionnel
- [ ] Tests E2E complets

---

### Issue #6 — Recherche d'emails

**Labels:** `frontend`, `feature`, `P1`, `Epic-2`
**Estimate:** 5

**Description:**
Recherche puissante et rapide dans tous les emails.

**Types de recherche:**
- **Recherche textuelle:** full-text search sur sujet, corps, expéditeur, destinataire
- **Recherche sémantique (IA):** recherche par concept/intent ("emails about the Q4 budget")
- **Filtres avancés:** par date range, taille, has attachment, from, to, subject, label, folder
- **Opérateurs de recherche:** from:, to:, subject:, has:attachment, before:, after:, is:unread, is:starred, label:, filename:, larger:, smaller:
- **Recherche dans les pièces jointes** (PDF, images via OCR)
- **Sauvegarde des recherches** favorites
- **Historique de recherche**
- **Raccourci:** Cmd+/ ou Ctrl+/ pour focus sur la barre de recherche

**UI:**
- Barre de recherche globale (header)
- Filtres dépliables (faceted search)
- Surlignage des termes trouvés
- Tri des résultats par pertinence ou date
- Vue résultats groupés par thread

**Critères d'acceptation:**
- [ ] Recherche textuelle rapide (< 200ms sur 10k emails)
- [ ] Opérateurs de recherche fonctionnels
- [ ] Filtres faceted fonctionnels
- [ ] Recherches sauvegardables
- [ ] Recherche sémantique IA (voir Epic 4)

---

### Issue #7 — Threads & Conversations

**Labels:** `frontend`, `feature`, `P1`, `Epic-2`
**Estimate:** 5

**Description:**
Affichage des emails en threads de conversation (groupés par sujet/participants).

**Fonctionnalités:**
- Vue threadée: emails groupés par conversation
- Affichage chronologique des messages du thread
- Collapse/expand des messages individuels
- Indicateur visuel du nombre de messages
- Mise en évidence du dernier message non lu
- Quick-reply inline dans le thread
- Forward d'un thread complet (as mbox ou forwarded emails)
- Vue "timeline" alternative (visuelle)
- Détachement d'un email d'un thread (re-threading)

**Critères d'acceptation:**
- [ ] Threads correctement groupés (References + Subject heuristics)
- [ ] Collapse/expand fluide
- [ ] Quick-reply fonctionnel
- [ ] Forward de thread complet
- [ ] Tests E2E

---

### Issue #8 — Labels, Filtres & Organisation

**Labels:** `frontend`, `feature`, `P1`, `Epic-2`
**Estimate:** 5

**Description:**
Système d'organisation flexible pour les emails.

**Labels:**
- Création de labels personnalisés (nom + couleur + icône)
- Labels multiples par email
- Vue filtrée par label
- Labels hiérarchiques (nested)
- Application automatique via règles

**Filtres / Règles:**
- Création de règles: SI condition ALORS action
- Conditions: from, to, subject, contains, has attachment, size
- Actions: marquer lu, archiver, label, déplacer, forward, supprimer
- Éditeur visuel de règles (no-code)
- Test d'une règle sur les emails existants
- Import/export de filtres

**Autres:**
- Archive (et unarchive)
- Snooze (rappeler plus tard — demain matin, ce soir, weekend, custom)
- Pin / Follow-up (voir Epic 4 pour AI follow-up)
- Bulk operations

**Critères d'acceptation:**
- [ ] CRUD labels complet
- [ ] Règles visuelles fonctionnelles
- [ ] Snooze avec rappel à la date choisie
- [ ] Archive/unarchive
- [ ] Tests E2E

---

## 🤖 Épic 3 — IA & Smart Features

### Issue #9 — Assistant IA de composition (AI Composer)

**Labels:** `frontend`, `ai`, `feature`, `P0`, `Epic-3`
**Estimate:** 8

**Description:**
Intégration d'un assistant IA directement dans le composer pour aider à écrire, reformuler, et optimiser les emails.

**Fonctionnalités:**

**Génération & rédaction:**
- "Écris cet email pour moi" — à partir d'un prompt en langage naturel ("Dis à Marc que le rapport sera en retard")
- Choix du ton: professionnel, amical, direct, formel, décontracté
- Choix de la longueur: concis, standard, détaillé
- Traduction en temps réel (fr ↔ en ↔ es ↔ de ↔ …)
- Génération de sujet optimisé
- Suggestions auto-completion pendant la frappe (type Gmail Smart Compose)

**Reformulation & amélioration:**
- "Rendre plus professionnel / plus amical / plus direct"
- "Raccourcir" ou "Développer"
- "Corriger la grammaire et l'orthographe"
- "Changer le ton"
- "Réécrire plus clairement"
- Résumé automatique d'un long email

**Analyse pré-envoi:**
- Score de ton (trop agressif ? trop familier ?)
- Détection de ton sarcastique ou passif-agressif
- Suggestions d'amélioration (clarté, concision, politesse)
- Détection de mentions de dates/échéances → proposer ajout au calendrier
- Vérification de cohérence (ex: "demain" mais pas de date précise)

**UI:**
- Panneau IA latéral dans le composer (toggle)
- Command palette IA: Cmd+I pour invoquer
- Inline suggestions (ghost text)
- Quick actions en sélection de texte (reformuler, traduire, résumer)
- Streaming de la réponse (typewriter effect)
- Historique des prompts IA dans la session

**Confidentialité:**
- Option "IA locale" (modèle on-device pour sensibilité)
- Option "IA cloud" (modèle plus puissant)
- Chiffrement du contenu envoyé au modèle
- Pas de stockage des prompts côté provider
- Mode "no-AI" pour utilisateurs qui le souhaitent

**Critères d'acceptation:**
- [ ] Génération d'email depuis un prompt
- [ ] Reformulation (ton, longueur, correction)
- [ ] Traduction bidirectionnelle
- [ ] Auto-completion inline
- [ ] Analyse pré-envoi (ton, clarté)
- [ ] Streaming des réponses
- [ ] Mode IA locale + cloud
- [ ] Tests E2E

---

### Issue #10 — Triage & Résumé automatiques par IA

**Labels:** `frontend`, `ai`, `feature`, `P0`, `Epic-3`
**Estimate:** 8

**Description:**
L'IA analyse, trie, et résume automatiquement les emails entrants pour réduire la charge cognitive de l'utilisateur.

**Triage intelligent:**
- Catégorisation auto: Important, Newsletter, Notification, Promo, Social, Personal, Work
- Score de priorité (0-100) basé sur: expéditeur, contenu, urgence, relation
- Détection d'emails nécessitant une réponse urgente
- Détection d'emails actionables vs informatifs
- Suggestions d'actions: "Répondre", "Archiver", "Suivre plus tard", "Déléguer"
- Auto-labeling (catégorie + tags personnalisés)
- Auto-archivage des newsletters après 7 jours (configurable)
- Regroupement d'emails similaires (digest de notifications)

**Résumés par IA:**
- Résumé d'un email long en 1-3 phrases
- Résumé d'un thread complet
- Résumé de la journée ("Voici ce qui s'est passé pendant votre absence")
- Résumé hebdomadaire (digest du lundi matin)
- Points d'action extraits ("Tu dois: répondre à Marc, valider le budget, confirmer la réunion")

**Smart Inbox:**
- Vue "Important uniquement" (tri IA)
- Vue "Action requise" (emails qui demandent une action de ta part)
- Vue "Newsletters & Promo" (groupés et archivables en un clic)
- Vue "En attente de réponse" (emails envoyés sans réponse)
- Score de "boîte propre" (% d'emails triés)

**UI:**
- Badges de catégorie sur chaque email
- Panneau de résumé en haut de l'inbox (daily briefing)
- Suggestions d'actions inline
- Animations subtiles pour le tri automatique
- Toggle "Auto-tri IA" dans les settings

**Critères d'acceptation:**
- [ ] Catégorisation auto fonctionnelle (> 85% accuracy)
- [ ] Score de priorité visible
- [ ] Smart Inbox views fonctionnelles
- [ ] Résumé d'email en 1-3 phrases
- [ ] Résumé de thread
- [ ] Daily briefing
- [ ] Weekly digest
- [ ] Auto-archivage configurable
- [ ] Tests E2E

---

### Issue #11 — Assistant IA conversationnel (Chat Mail Assistant)

**Labels:** `frontend`, `ai`, `feature`, `P1`, `Epic-3`
**Estimate:** 8

**Description:**
Un assistant IA conversationnel (type ChatGPT) spécialisé pour la gestion email, accessible depuis l'app.

**Capacités de l'assistant:**
- "Quels emails importants ai-je reçus aujourd'hui ?"
- "Résume la conversation avec Marc sur le projet X"
- "Trouve tous les emails qui mentionnent le budget Q4"
- "Rédige une réponse à ce thread"
- "Programme un rappel pour suivre cet email si pas de réponse d'ici 3 jours"
- "Combien d'emails non lus ai-je ?"
- "Archive tous les newsletters de cette semaine"
- "Montre-moi les emails où on parle de déploiement"
- "Crée un filtre pour les emails de Stripe"
- "Quelle est la prochaine étape pour le projet SMTP ?"

**UI:**
- Panneau de chat latéral (toggle, Cmd+J)
- Vue plein écran possible
- Réponses avec citations et liens vers les emails concernés
- Actions directes depuis le chat ("Archive cet email" → l'IA exécute)
- Suggestions de questions rapides
- Contexte: l'IA connaît l'état de l'inbox, les emails ouverts, les threads
- Streaming des réponses
- Historique de conversation persistant

**Sécurité:**
- L'IA ne peut pas envoyer d'emails sans confirmation explicite
- L'IA ne peut pas supprimer définitivement (archive uniquement)
- Audit log des actions IA
- Mode "lecture seule" configurable

**Critères d'acceptation:**
- [ ] Chat fonctionnel avec streaming
- [ ] Recherche et résumé via chat
- [ ] Actions depuis le chat (archive, label, mark read)
- [ ] Citations et liens vers emails
- [ ] Confirmation avant actions destructives
- [ ] Tests E2E

---

### Issue #12 — Détection de phishing & sécurité IA

**Labels:** `frontend`, `ai`, `security`, `P0`, `Epic-3`
**Estimate:** 5

**Description:**
L'IA analyse en temps réel chaque email entrant pour détecter le phishing, le spam, et les tentatives de fraudes.

**Détections:**
- Phishing (usurpation d'identité, liens suspects, urgency scams)
- Spam scoring (amélioré vs filtres traditionnels)
- Détection de domaines suspects (typosquatting, homoglyph)
- Analyse des headers (SPF, DKIM, DMARC — corrélation avec backend DKIM)
- Détection de malware (pièces jointes suspectes — via intégration antivirus)
- Détection de BEC (Business Email Compromise)
- Détection de deepfake audio/vidéo dans pièces jointes (futur)

**UI:**
- Warning banner sur emails suspects
- Score de confiance (0-100)
- Détails des détections (explications)
- Bouton "Signaler comme phishing"
- Auto-déplacement vers Spam (configurable)
- Quarantaine pour emails très suspects
- Notification de sécurité (digest des emails bloqués)

**Critères d'acceptation:**
- [ ] Détection phishing en temps réel
- [ ] Warning banner visible
- [ ] Auto-quarantaine configurable
- [ ] Score de confiance
- [ ] Reporting utilisateur
- [ ] Tests E2E

---

### Issue #13 — Suivi intelligent & Rappels IA

**Labels:** `frontend`, `ai`, `feature`, `P1`, `Epic-3`
**Estimate:** 5

**Description:**
L'IA suit automatiquement les emails qui nécessitent un suivi et rappelle l'utilisateur au bon moment.

**Détection automatique:**
- Détection d'emails nécessitant une réponse (question explicite, demande, etc.)
- Détection d'emails envoyés en attente de réponse
- Estimation du délai de réponse attendu (par expéditeur/contexte)
- Suivi de promises ("Je te renvoie ça d'ici vendredi" → rappel vendredi)

**Rappels intelligents:**
- "Tu n'as pas répondu à Marc depuis 3 jours"
- "Tu as promis de renvoyer le rapport aujourd'hui"
- "Cet email semble urgent et n'a pas de réponse"
- Rappel avant une échéance mentionnée dans un email
- Rappel si pas de réponse à un email envoyé (configurable: 3 jours, 1 semaine, etc.)

**UI:**
- Section "En attente de réponse" dans la sidebar
- Section "En attente de leur réponse" (suivi)
- Badges de rappel sur les emails
- Notifications push (mobile + desktop)
- Vue "Tâches email" (emails transformés en TODO par IA)
- Intégration possible avec todo lists externes (Notion, Linear, etc.)

**Critères d'acceptation:**
- [ ] Détection automatique des emails à suivre
- [ ] Rappels contextuels
- [ ] Notifications push
- [ ] Vue "Tâches email"
- [ ] Tests E2E

---

## 📅 Épic 4 — Calendar, Contacts & Collaboration

### Issue #14 — Carnet d'adresses intelligent

**Labels:** `frontend`, `feature`, `P1`, `Epic-4`
**Estimate:** 5

**Description:**
Carnet d'adresses enrichi automatiquement par l'IA.

**Fonctionnalités:**
- Auto-enrichissement: à chaque email, extraction et ajout des contacts
- Profil de contact: nom, emails, téléphones, entreprise, fonction, dernier contact, fréquence
- Photo de profil (gravatar, ou IA depuis les signatures)
- Notes sur le contact
- Historique des échanges (timeline)
- Tags de contact (VIP, client, partenaire, famille…)
- Recherche de contacts
- Import/export (vCard, CSV, Google Contacts)
- Groupes de contacts (listes de diffusion)
- Suggestion de contacts pour Cc ("Tu as oublié Sarah qui était dans le thread précédent")
- Déduplication automatique
- Merge de contacts en conflit

**IA enrichment:**
- Extraction auto des signatures email
- Détection de changements (nouveau job, nouvelle entreprise)
- Score de relation (fréquence + récence des échanges)
- Suggestion de contacts à recontacter ("Tu n'as pas écrit à Pierre depuis 6 mois")

**Critères d'acceptation:**
- [ ] Auto-enrichissement fonctionnel
- [ ] Profil contact complet
- [ ] Recherche rapide
- [ ] Import/export
- [ ] Déduplication
- [ ] Suggestions IA
- [ ] Tests E2E

---

### Issue #15 — Calendrier intégré

**Labels:** `frontend`, `feature`, `P2`, `Epic-4`
**Estimate:** 8

**Description:**
Calendrier intégré à l'app email, avec détection IA des événements mentionnés dans les emails.

**Fonctionnalités:**
- Vue jour/semaine/mois
- Création d'événements manuels
- Détection IA: "Réunion jeudi 14h" → proposition d'ajout au calendrier
- Extraction des dates/heures depuis les emails
- Invitations par email (iCal/ICS)
- Rappels et notifications
- Vue agenda + vue planning
- Color coding par type d'événement
- Disponibilité (free/busy) — si participants internes
- Synchronisation CalDAV (extensible)
- Import/export ICS

**UI:**
- Vue calendrier en onglet ou panneau latéral
- Drag & drop pour rescheduler
- Mini-calendrier dans la sidebar
- Badges de dates détectées dans les emails
- Quick-add depuis un email ("Ajouter au calendrier")

**Critères d'acceptation:**
- [ ] Vue jour/semaine/mois
- [ ] Détection IA des dates dans emails
- [ ] Création d'événements
- [ ] Rappels
- [ ] Import/export ICS
- [ ] Tests E2E

---

### Issue #16 — Multi-comptes & Unified Inbox

**Labels:** `frontend`, `feature`, `P1`, `Epic-4`
**Estimate:** 5

**Description:**
Support de multiple comptes email dans une seule interface.

**Fonctionnalités:**
- Ajout de comptes externes (via IMAP/SMTP — Gmail, Outlook, ProtonMail Bridge, etc.)
- Unified inbox (tous les comptes en un seul vue)
- Vue par compte (switch)
- Compte par défaut configurable
- Signatures par compte
- Aliases (plusieurs adresses pour un compte)
- Identité visuelle par compte (couleur/avatar)
- Sync IMAP bidirectionnelle
- Notifications par compte (configurables)

**UI:**
- Sélecteur de compte dans la sidebar
- Badge par compte (non lus)
- Filtre par compte dans l'inbox
- Indicateur visuel du compte sur chaque email

**Critères d'acceptation:**
- [ ] Ajout/suppression de comptes externes
- [ ] Unified inbox fonctionnelle
- [ ] Vue par compte
- [ ] Signatures par compte
- [ ] Sync bidirectionnelle IMAP
- [ ] Tests E2E

---

## 📱 Épic 5 — Mobile, PWA & Notifications

### Issue #17 — PWA & Offline Mode

**Labels:** `frontend`, `pwa`, `P0`, `Epic-5`
**Estimate:** 5

**Description:**
Transformer l'app web en PWA installable avec support offline.

**Fonctionnalités:**
- Service worker avec cache stratégies (cache-first pour assets, network-first pour emails)
- Installable (Add to Home Screen) sur iOS et Android
- Offline mode: lecture des emails déjà téléchargés, composition en draft
- Sync au retour de connexion
- Push notifications (web push)
- Background sync (envoi des drafts en attente)
- App shortcuts (quick actions depuis l'icône)
- Splash screen personnalisé
- Thème adapté au système (status bar color)

**Critères d'acceptation:**
- [ ] Installable sur iOS et Android
- [ ] Offline reading
- [ ] Offline composition (drafts)
- [ ] Sync au retour connexion
- [ ] Push notifications web
- [ ] Lighthouse PWA score ≥ 90

---

### Issue #18 — Notifications push intelligentes

**Labels:** `frontend`, `feature`, `P1`, `Epic-5`
**Estimate:** 5

**Description:**
Système de notifications push intelligent, filtré par IA pour éviter le bruit.

**Règles de notification:**
- Notification uniquement pour les emails "importants" (tri IA)
- Pas de notification pour newsletters/promos (sauf whitelist)
- Notification de résumé quotidien (matin, configurable)
- Mode "Ne pas déranger" (heurées, focus mode)
- Notifications groupées (digest au lieu de notification par email)
- Notifications prioritaires pour réponses à mes emails
- Custom rules de notification (par expéditeur, label, etc.)

**UI:**
- Centre de notifications dans l'app
- Settings de notifications granulaires
- Badge de compteur sur l'icône (non lus importants uniquement)
- Notifications avec actions (Répondre, Archiver, Marquer lu)

**Critères d'acceptation:**
- [ ] Push notifications web fonctionnelles
- [ ] Filtre IA des notifications
- [ ] Ne pas déranger
- [ ] Actions dans les notifications
- [ ] Centre de notifications
- [ ] Tests E2E

---

## ⚙️ Épic 6 — Settings, Privacy & Administration

### Issue #19 — Settings & Préférences utilisateur

**Labels:** `frontend`, `feature`, `P1`, `Epic-6`
**Estimate:** 5

**Description:**
Panneau de paramètres complet et ergonomique.

**Sections:**
- **Général:** Langue, fuseau horaire, thème, densité d'affichage, image par défaut
- **Compte:** Email, nom affiché, signature, réponse auto (vacances), forwarding
- **IA:** Activation IA, modèle (local/cloud), niveau d'assistance, entraînement opt-out
- **Notifications:** Push, email, digest, DND
- **Filtres & Règles:** Gestion des règles
- **Labels:** Gestion des labels
- **Sécurité:** Mot de passe, 2FA, sessions actives, audit log
- **Import/Export:** Import emails (Mbox, PST, EML), export (Mbox, EML)
- **Raccourcis clavier:** Personnalisation
- **Accessibilité:** Contraste, taille police, lecteur d'écran, navigation clavier
- **Beta features:** Feature flags

**UI:**
- Layout settings type macOS System Preferences
- Recherche dans les settings
- Indicateurs de changements non sauvegardés
- Preview des changements en temps réel

**Critères d'acceptation:**
- [ ] Toutes les sections implémentées
- [ ] Recherche dans settings
- [ ] Import/Export emails
- [ ] Tests E2E

---

### Issue #20 — Privacy, Security & Chiffrement E2E

**Labels:** `frontend`, `security`, `P0`, `Epic-6`
**Estimate:** 8

**Description:**
Privacy-first: chiffrement, transparence, contrôle utilisateur.

**Chiffrement:**
- PGP encryption intégrée (envoi de emails chiffrés)
- PGP signing (signature des emails sortants)
- Gestion des clés PGP (génération, import, export, publication sur keyserver)
- Chiffrement at-rest côté client (IndexedDB chiffré)
- Support WKD (Web Key Directory) pour découverte auto des clés

**Privacy:**
- Bloqueur de tracking pixels (activé par défaut)
- Bloqueur de pixels espions dans les emails
- Proxy de images (chargement via proxy, pas de connexion directe)
- No telemetry par défaut (opt-in explicite)
- Mode "Paranoid" (bloque tout contenu externe)
- Clear data cache (option: tout effacer, ou selective)
- Cookie management

**Sécurité:**
- CSP strict
- Audit log (connexions, actions sensibles)
- Détection de breach (HaveIBeenPwned integration)
- Alertes de sécurité (nouveau device, login inhabituel)
- Lock screen (PIN/biometric après inactivité)

**UI:**
- Centre de sécurité (dashboard)
- Score de sécurité
- Recommandations de durcissement
- Gestion PGP dans settings
- Indicateurs visuels (emails chiffrés, signés, tracking bloqués)

**Critères d'acceptation:**
- [ ] PGP encryption/signing
- [ ] Tracking pixel blocker
- [ ] Image proxy
- [ ] No telemetry par défaut
- [ ] Audit log
- [ ] Centre de sécurité
- [ ] Tests E2E

---

### Issue #21 — Administration (interface admin)

**Labels:** `frontend`, `admin`, `P2`, `Epic-6`
**Estimate:** 5

**Description:**
Interface d'administration pour la plateforme misfits.ai Mail (admin système, pas user).

**Fonctionnalités:**
- Gestion des utilisateurs (création, suspension, suppression)
- Gestion des domaines (ajout, vérification DNS, DKIM/SPF/DMARC status)
- Monitoring système (queue SMTP, deliveries, bounces, spam score)
- Gestion des alias et forwarding
- Quotas et stockage par utilisateur
- Logs système (consultation, filtre, export)
- Health checks (SMTP, IMAP, DKIM service, MongoDB)
- Backup/restore management
- Feature flags (activation/désactivation de fonctionnalités)
- Announcements (message global aux utilisateurs)

**UI:**
- Dashboard admin (vue d'ensemble)
- Tables de gestion avec filtres
- Graphes de monitoring (charts)
- Alertes et notifications admin
- Mode "maintenance"

**Critères d'acceptation:**
- [ ] Gestion utilisateurs
- [ ] Monitoring système
- [ ] Health checks
- [ ] Logs consultables
- [ ] Tests E2E

---

## 🎯 Épic 7 — Innovation & Différenciation

### Issue #22 — Command Palette (Cmd+K) universelle

**Labels:** `frontend`, `feature`, `P1`, `Epic-7`
**Estimate:** 5

**Description:**
Command palette type Linear/Raycast accessible partout dans l'app.

**Actions disponibles:**
- Navigation (Inbox, Sent, Drafts, labels, dossiers)
- Recherche d'emails
- Composer un nouvel email
- Actions sur email sélectionné (archiver, supprimer, label, forward)
- Quick actions IA ("Résume cet email", "Trouve les emails de Marc")
- Settings
- Changement de thème
- Raccourcis clavier help
- Toggle features (IA, tracking blocker, etc.)

**UI:**
- Overlay centré, backdrop blur
- Recherche fuzzy
- Navigation clavier complète
- Historique des commandes récentes
- Extensions (plugins futures)

**Critères d'acceptation:**
- [ ] Cmd+K ouvre la palette
- [ ] Toutes les actions accessibles
- [ ] Recherche rapide (< 50ms)
- [ ] Navigation clavier
- [ ] Tests E2E

---

### Issue #23 — Analytics personnels & Insights

**Labels:** `frontend`, `ai`, `feature`, `P2`, `Epic-7`
**Estimate:** 5

**Description:**
Dashboard d'analytics personnels sur son usage email, généré par IA.

**Métriques:**
- Volume d'emails reçus/envoyés (par jour/semaine/mois)
- Temps de réponse moyen (par contact, global)
- Top contacts (fréquence)
- Répartition par catégorie (IA)
- Heures de plus grande activité
- "Email debt" (emails non répondus importants)
- Patterns de communication (réponse rapide vs lente)
- Score de "boîte propre" (tendance)
- Heatmap d'activité

**Insights IA:**
- "Tu réponds plus vite à Marc qu'à Sarah"
- "Ton volume d'emails a augmenté de 30% ce mois"
- "Tu es le plus actif le mardi matin"
- "Tu as 12 emails importants sans réponse"
- Recommandations ("Considère archiver les newsletters le vendredi")

**UI:**
- Dashboard dédié
- Graphes interactifs (Recharts ou visx)
- Vue hebdomadaire, mensuelle, annuelle
- Comparaison entre périodes
- Export des données

**Critères d'acceptation:**
- [ ] Dashboard analytics
- [ ] Métriques calculées
- [ ] Insights IA
- [ ] Graphes interactifs
- [ ] Tests E2E

---

### Issue #24 — Spaces & Collaboration (teams)

**Labels:** `frontend`, `feature`, `P2`, `Epic-7`
**Estimate:** 8

**Description:**
Espaces collaboratifs pour équipes — boîte mail partagée, notes partagées, assignation d'emails.

**Fonctionnalités:**
- Boîte mail partagée (team@misfits.ai)
- Assignation d'emails à des membres
- Notes partagées sur un email/thread
- Statuts: Nouveau, En cours, En attente, Résolu
- Vue "Team inbox" (emails assignés à moi, non assignés, tous)
- @mentions internes dans les notes
- Partage de thread (lien interne)
- Templates d'équipe
- Rôles: Admin, Member, Viewer
- Stats par membre (temps de réponse, volume traité)

**UI:**
- Vue "Team" dans la sidebar
- Avatars des assignés sur les emails
- Panneau de notes partagées
- Workflow board (type Trello: colonnes par statut)

**Critères d'acceptation:**
- [ ] Boîte partagée fonctionnelle
- [ ] Assignation d'emails
- [ ] Notes partagées
- [ ] Vue Team inbox
- [ ] Workflow board
- [ ] Tests E2E

---

### Issue #25 — Extensions & API publique

**Labels:** `frontend`, `api`, `P2`, `Epic-7`
**Estimate:** 8

**Description:**
Système d'extensions et API publique pour étendre l'app.

**Extensions:**
- Système de plugins (type VS Code extensions)
- Marketplace d'extensions (futur)
- API JavaScript pour interagir avec l'app (read emails, send, label)
- Webhooks pour événements email (nouveau email, réponse, etc.)
- Integrations: Zapier, n8n, Slack, Notion, Linear, Trello

**API publique:**
- REST API (CRUD emails, labels, contacts)
- GraphQL API (flexibilité)
- Webhooks
- OAuth2 pour apps tierces
- Rate limiting
- Documentation interactive (Swagger/Stoplight)

**SDK:**
- JavaScript SDK (browser)
- Python SDK (server-side)
- CLI tool

**Critères d'acceptation:**
- [ ] Système d'extensions documenté
- [ ] REST API documentée
- [ ] GraphQL API
- [ ] Webhooks
- [ ] OAuth2
- [ ] SDK JS + Python
- [ ] Tests E2E

---

## 📊 Roadmap & Priorités

| Epic | Issues | Priorité | Sprint suggéré |
|------|--------|----------|----------------|
| Epic 1 — Fondations | #1, #2, #3 | P0 | Sprint 1-2 |
| Epic 2 — Inbox | #4, #5, #6, #7, #8 | P0-P1 | Sprint 2-4 |
| Epic 3 — IA | #9, #10, #11, #12, #13 | P0-P1 | Sprint 3-5 |
| Epic 4 — Cal/Contacts | #14, #15, #16 | P1-P2 | Sprint 5-6 |
| Epic 5 — PWA & Mobile | #17, #18 | P0-P1 | Sprint 4-5 |
| Epic 6 — Settings & Security | #19, #20, #21 | P0-P2 | Sprint 3-6 |
| Epic 7 — Innovation | #22, #23, #24, #25 | P1-P2 | Sprint 6-8 |

**Total:** 25 issues | **Estimation totale:** ~140 story points

---

## 🏛️ Principes directeurs

1. **IA-first** — L'IA n'est pas une feature, c'est un layer transversal qui améliore chaque interaction
2. **Privacy by default** — Tracking blocker, no telemetry, chiffrement opt-in simple
3. **Performance obsession** — < 1s load time, 60fps animations, virtualization pour gros volumes
4. **Keyboard-first** — Tout est faisable au clavier, la souris est un bonus
5. **Accessibilité native** — WCAG 2.2 AA minimum, screen reader support
6. **Mobile-grade** — PWA installable, offline, push notifications
7. **Extensible** — API publique, extensions, webhooks
8. **Open source friendly** — Code ouvert, contributions welcome

---

_Dernière mise à jour: 2026-07-27 par Hermes Agent (PM)_
_En attente des droits GitHub sur `canatac/reimagined-guide` pour upload des issues._