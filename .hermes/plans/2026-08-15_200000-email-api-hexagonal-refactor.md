# Refactor `email_api_dir/main.rs` — Plan Ultime (Hexagonal, Clean Code)

> **Pour Hermes / implémenteur :** utiliser `subagent-driven-development` : 1 tâche = 1 subagent = 1 PR = CI verte avant la suivante. **JAMAIS** de suppression d'un bloc par range calculée (bug off-by-one récurrent) — **toujours** faire du copier/lire, puis remplacer par un stub explicite, puis vérifier compilation avant purge.

**Goal :** Ramener `src/bin/email_api_dir/main.rs` de **1445 LOC → ~150 LOC** (setup + wiring + `HttpServer::new` uniquement), en distribuant la logique métier dans des modules ciblés respectant l'architecture hexagonale : **domaine pur** (crates/domain) ← **ports** (traits) ← **adaptateurs** (mongo, actix, smtp) ← **binaire** (composition root).

**Architecture cible :**
- `main.rs` = composition root (env, DI, `HttpServer::new`, routes wiring)
- `bootstrap/` = construction Mongo, TLS, event bus, workers de fond
- `routes/` = tables de routes actix découpées par domaine (mail, admin, monitoring, security, hermes, auth, external, docs)
- `handlers/` = les handlers actix eux-mêmes (déjà extraits pour la moitié)
- `types/` = DTOs partagés (`EmailRequest`, `MailEvent`, `MailingList*`, `Auth*`, etc.)
- `events/` = bus SSE + `persist_event` + `emit_event` + endpoints `api_events*`
- `dkim/` = trait `DkimService` + `RealDkimService`

**Tech Stack :** Rust 1.80+, actix-web 4, MongoDB, rustls, mockall (tests). **Zéro build local** (validation via CI GitHub Actions uniquement).

---

## État initial (audit)

**Fichier :** `src/bin/email_api_dir/main.rs` — 1445 LOC.

**Découpage constaté :**
| Section | Lignes | LOC | Cible |
|---|---|---|---|
| Imports + `mod` decls | 1–95 | 95 | reste dans `main.rs` |
| `MailEvent*` enum + struct + `EventBus` type | 97–128 | 32 | → `events/types.rs` |
| DTOs Undo/Schedule/Github/Auth/User/Session | 130–210 | 81 | → `types/mod.rs` |
| `persist_event`, `emit_event`, `api_events*` | 214–309 | 96 | → `events/mod.rs` |
| DTOs Deliverability | 311–340 | 30 | → `types/deliverability.rs` (ou déjà dans admin_ops) |
| `EmailRequest`, `MailingList*` | 341–361 | 21 | → `types/mail.rs` |
| `create_mailing_list`, `send_to_mailing_list` | 363–475 | 113 | → `mailing_list_handlers.rs` |
| `send_email_handler` | 477–552 | 76 | → `mailbox/send_handlers.rs` (déjà module) |
| `#[actix_web::main] async fn main` | 554–983 | 430 | découpé en `bootstrap/` + `routes/` |
| `#[cfg(test)] mod tests` | 984–1400 | 417 | reste en tests (ou → `tests/integration/`) |
| `RealDkimService` impl | 1401–1445 | 45 | → `dkim.rs` |

**Sous-modules existants :** `admin_auth`, `auth_handlers`, `monitoring_handlers`, `mailbox/{send,read,drafts,single}_handlers`, `admin_ops`, `external_handlers`, `external_probe_handlers`, `helpers`.

**Contraintes architecturales :**
- Le crate `simple_smtp_domain` (crates/domain) reste pur (chrono, mongodb::bson, serde, uuid seulement) — aucune dépendance actix.
- `src/logic/` est le port applicatif (traits + impl Mongo). Il n'a AUCUNE dépendance actix. À conserver tel quel.
- Les handlers actix restent dans `src/bin/email_api_dir/**` (adaptateur HTTP).
- **Cette refacto ne bouge PAS de logique métier** — c'est du **découpage de fichier**. Aucun changement de comportement, aucun ajout de trait.

**Tests :** le `mod tests` en fin de fichier utilise `mockall::mock!` pour `DkimService`. Il doit continuer à compiler après le déplacement.

---

## Principes de sécurité (leçons des PR #284/#285)

1. **JAMAIS** utiliser un script Python qui supprime des ranges de lignes calculées : les bornes shiftent, on perd des signatures adjacentes (bug reproduit 3 fois).
2. **Toujours** procéder par :
   - a) `git show master:file` → copier le bloc source vers le fichier cible
   - b) compiler CI (module cible seul, sans toucher au source)
   - c) `patch mode=replace` : remplacer le bloc dans le source par un commentaire `// moved to <module>` en gardant la ligne de démarcation
   - d) commit + push, wait CI verte
3. **Un commit = une fonction / un groupe de types cohérent.** Pas de "big bang".
4. **Une PR = une étape du plan** (Task N). Merger avant la suivante.
5. Après CHAQUE extraction : `bash scripts/arch_guard.sh` en pré-commit.
6. Pour chaque suppression, vérifier grep du symbole dans tout le repo (`grep -rn "symbol_name" src/`) : si utilisé ailleurs, marquer `pub(crate)` et exporter via `pub use`.

---

## Plan d'exécution — 11 tâches séquentielles

### Task 1 — Extraire les DTOs mail vers `types/mail.rs`

**Objectif :** Sortir `EmailRequest`, `MailingListRequest`, `MailingListEmailRequest` de `main.rs`.

**Fichiers :**
- Créer : `src/bin/email_api_dir/types/mod.rs`
- Créer : `src/bin/email_api_dir/types/mail.rs`
- Modifier : `src/bin/email_api_dir/main.rs` (retirer structs 341–361, ajouter `mod types;` + `use types::mail::*;`)

**Étape 1 :** créer `types/mod.rs` :
```rust
pub(crate) mod mail;
```

**Étape 2 :** créer `types/mail.rs` avec le contenu VERBATIM de `main.rs:341–361` (les 3 structs), imports `serde::{Deserialize, Serialize}`.

**Étape 3 :** dans `main.rs`, remplacer les 3 struct blocks par le commentaire `// DTOs mail → types::mail`, ajouter `mod types;` près des autres `mod` decls, ajouter `use types::mail::{EmailRequest, MailingListRequest, MailingListEmailRequest};`.

**Étape 4 :** vérifier grep externe :
```bash
grep -rn "EmailRequest\|MailingListRequest\|MailingListEmailRequest" src/ | grep -v email_api_dir/main.rs
```
Si résultat → adapter les imports concernés (ex : dans tests utilisant `use super::*;` il faut aussi importer via `types::mail::*`).

**Étape 5 :** CI verte + `gh pr merge`.

**Métrique :** main.rs 1445 → ~1424 (−21).

---

### Task 2 — Extraire les DTOs auth vers `types/auth.rs`

**Objectif :** Sortir `GithubTokenResponse`, `GithubUser`, `GithubEmail`, `UserResponse`, `SessionResponse`, `AuthResponse`, `UndoSendRequest`, `ScheduleSendBody` (main.rs:130–210).

**Fichiers :**
- Créer : `src/bin/email_api_dir/types/auth.rs`
- Modifier : `src/bin/email_api_dir/types/mod.rs` (ajouter `pub(crate) mod auth;`)
- Modifier : `src/bin/email_api_dir/main.rs`

**Étapes :** identiques à Task 1. Attention : ces DTOs sont utilisés par `auth_handlers.rs` → grep obligatoire, `pub(crate)` sur tout.

**Étape 4 (vérif spéciale) :**
```bash
grep -rn "UserResponse\|SessionResponse\|AuthResponse\|GithubUser\|GithubEmail\|GithubTokenResponse\|UndoSendRequest\|ScheduleSendBody" src/ | grep -v types/auth.rs
```

**Métrique :** main.rs ~1424 → ~1343 (−81).

---

### Task 3 — Extraire l'event bus vers `events/`

**Objectif :** Sortir `MailEventKind`, `MailEvent`, `EventBus` (type alias), `persist_event`, `emit_event`, `api_events`, `api_events_stream`.

**Fichiers :**
- Créer : `src/bin/email_api_dir/events/mod.rs`
- Créer : `src/bin/email_api_dir/events/types.rs` (enum + struct + type alias `EventBus = broadcast::Sender<MailEvent>`)
- Créer : `src/bin/email_api_dir/events/handlers.rs` (les 2 handlers actix)
- Créer : `src/bin/email_api_dir/events/emit.rs` (`persist_event` + `emit_event`)
- Modifier : `main.rs` (retirer 97–128 + 214–309, ajouter `mod events; use events::{...};`)

**Étape 1 :** `events/mod.rs` :
```rust
pub(crate) mod emit;
pub(crate) mod handlers;
pub(crate) mod types;

pub(crate) use emit::{emit_event, persist_event};
pub(crate) use handlers::{api_events, api_events_stream};
pub(crate) use types::{EventBus, MailEvent, MailEventKind};
```

**Étape 2 :** copier les blocs verbatim, ajuster imports (chaque fichier a besoin de `use tokio::sync::broadcast; use mongodb::Client;` etc.).

**Étape 3 :** dans `main.rs`, remplacer par `mod events;` + `use events::{MailEvent, EventBus, api_events, api_events_stream, emit_event, persist_event};`.

**Étape 4 :** vérifier grep de chaque symbole. `emit_event` est appelé dans presque tous les handlers → ils utilisent probablement déjà `use super::emit_event;` ou `use crate::...`. À adapter.

**Étape 5 :** CI + merge.

**Métrique :** main.rs ~1343 → ~1215 (−128).

---

### Task 4 — Extraire les mailing lists vers leur propre handler module

**Objectif :** Sortir `create_mailing_list` (363–398) et `send_to_mailing_list` (400–475).

**Fichiers :**
- Créer : `src/bin/email_api_dir/mailing_list_handlers.rs`
- Modifier : `main.rs`

**Étapes :** copy → remplace par `// moved` → import via `mod mailing_list_handlers; use mailing_list_handlers::{create_mailing_list, send_to_mailing_list};`.

**Attention imports :** ces fns utilisent `web::Json`, `Responder`, `std::fs::create_dir_all`, `std::path::Path`, `Utc`, `smtp_client::send_smtp_email` (à vérifier).

**Métrique :** main.rs ~1215 → ~1102 (−113).

---

### Task 5 — Extraire `send_email_handler` vers `mailbox/send_handlers.rs`

**Objectif :** Le module cible existe déjà, y déplacer la fn 477–552.

**Fichiers :**
- Modifier : `src/bin/email_api_dir/mailbox/send_handlers.rs` (ajouter la fn)
- Modifier : `src/bin/email_api_dir/mailbox/mod.rs` (`pub use send_handlers::send_email_handler;`)
- Modifier : `main.rs`

**Vérif :** `send_email_handler` utilise `EmailRequest` (extrait en Task 1) → import `use super::super::types::mail::EmailRequest;`. Il utilise aussi `DkimService` trait (à extraire en Task 6, ATTENTION à l'ordre).

**Décision :** **inverser Task 5 et Task 6** — faire Task 6 (DkimService) AVANT, puis Task 5 avec l'import propre.

**Métrique post-inversion :** main.rs ~1102 → ~1026 (−76).

---

### Task 6 — Extraire `DkimService` trait + `RealDkimService` vers `dkim.rs`

**Objectif :** Sortir le trait `DkimService` (défini quelque part avant tests) et `RealDkimService` (1401–1445).

**Prérequis :** repérer où le trait est défini :
```bash
grep -n "trait DkimService" src/bin/email_api_dir/main.rs
```

**Fichiers :**
- Créer : `src/bin/email_api_dir/dkim.rs` (trait + impl `RealDkimService`)
- Modifier : `main.rs`

**Étape 1 :** copier trait + impl verbatim, ajouter `use async_trait::async_trait;` + `use serde_json;` + `use super::types::mail::EmailRequest;`.

**Étape 2 :** dans `main.rs` : `mod dkim; use dkim::{DkimService, RealDkimService};`.

**Étape 3 :** vérifier que le `mod tests` peut toujours mocker `DkimService` — `use super::dkim::DkimService;` dans le tests block.

**Métrique :** main.rs −45 environ. Cumul après Task 5+6 : ~1102 → ~981.

---

### Task 7 — Extraire le bootstrap Mongo vers `bootstrap/mongo.rs`

**Objectif :** Sortir la construction de `client_uri`, `mongo_client`, `fallback_client`, `shared_mongo` (~lignes 565–630 dans `main.rs` original).

**Fichiers :**
- Créer : `src/bin/email_api_dir/bootstrap/mod.rs` (`pub(crate) mod mongo;`)
- Créer : `src/bin/email_api_dir/bootstrap/mongo.rs`
- Modifier : `main.rs`

**API cible :**
```rust
// bootstrap/mongo.rs
pub(crate) struct MongoBundle {
    pub shared: Arc<mongodb::Client>,
    pub optional: Option<Arc<mongodb::Client>>,
}

pub(crate) async fn init_mongo() -> MongoBundle { ... }
```

Dans `main.rs` :
```rust
let mongo = bootstrap::mongo::init_mongo().await;
let shared_mongo = mongo.shared.clone();
```

**Vérif :** log de connexion doit rester identique (`println!("MongoDB connection ready.")` etc.) — comportement inchangé.

**Métrique :** main.rs −66. Cumul : ~981 → ~915.

---

### Task 8 — Extraire le bootstrap TLS / monitoring / security / workers

**Objectif :** Sortir tout ce qui suit la connexion Mongo et précède le `HttpServer::new` : TLS builder, `monitoring::init_bus`, `security::init_bus`, `send_queue_worker` spawn (~lignes 650–675).

**Fichiers :**
- Créer : `src/bin/email_api_dir/bootstrap/tls.rs`
- Créer : `src/bin/email_api_dir/bootstrap/background.rs`
- Modifier : `bootstrap/mod.rs`, `main.rs`

**API cible :**
```rust
// bootstrap/tls.rs
pub(crate) fn build_ssl_acceptor() -> SslAcceptorBuilder { ... }

// bootstrap/background.rs
pub(crate) fn spawn_all(shared_mongo: Arc<mongodb::Client>) { 
    // init_bus monitoring, security, workers 
}
```

**Métrique :** main.rs −30. Cumul : ~915 → ~885.

---

### Task 9 — Extraire les routes HTTP (proxy 8000) vers `routes/http_api.rs`

**Objectif :** Le PLUS GROS morceau. Le `HttpServer::new` des lignes 673–957 (proxy HTTP 8000, ~280 LOC de `.service`/`.route`).

**Fichiers :**
- Créer : `src/bin/email_api_dir/routes/mod.rs`
- Créer : `src/bin/email_api_dir/routes/http_api.rs`
- Modifier : `main.rs`

**API cible :**
```rust
// routes/http_api.rs
pub(crate) fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        .route("/health", web::get().to(super::super::health_check))
        .route("/api/send", web::post().to(super::super::send_email_handler))
        // ... 107 routes ici
        ;
}
```

Dans `main.rs` :
```rust
let http_server = actix_web::rt::spawn(async move {
    HttpServer::new(move || {
        let cors = Cors::permissive();
        App::new()
            .wrap(cors)
            .app_data(http_logic.clone())
            .app_data(http_mongo.clone())
            // ... .app_data uniquement
            .configure(routes::http_api::configure)
    })
    .bind(&http_addr)?
    .run()
    .await
});
```

**⚠️ Difficulté :** les routes utilisent parfois `web::scope("/api/...")` ou `.service(...)` avec des scopes imbriqués. Utiliser `cfg.service(web::scope("/api/admin").route(...))` conserve la structure.

**Approche par sous-batch :** DÉCOUPER cette task en 5 sous-PRs :
- 9a : `routes/mail.rs` (endpoints `/api/send`, `/api/emails`, `/api/drafts`) — ~30 routes
- 9b : `routes/admin.rs` (`/api/admin/*`) — ~25 routes
- 9c : `routes/monitoring.rs` + `routes/security.rs` — ~15 routes
- 9d : `routes/external.rs` (`/api/external-*`) — ~10 routes
- 9e : `routes/misc.rs` (auth, calendar, tags, templates, docs, hermes, openapi) — ~27 routes

Chaque sous-batch = une PR indépendante, mergée avant la suivante. Compilation vérifiée à chaque étape.

**Métrique :** main.rs −280 (cumul par batches). Cumul final : ~885 → ~605.

---

### Task 10 — Extraire les 10 autres `App::new()` (test/debug servers) vers `routes/dev_servers.rs`

**Objectif :** Les 10 autres `App::new()` (lignes 959–1400) sont probablement des serveurs de test ou des configs cfg(debug). Les analyser d'abord :

**Étape 1 :** grep du contexte de chaque `App::new()` restant :
```bash
grep -B5 "App::new" src/bin/email_api_dir/main.rs | less
```

**Décision selon analyse :**
- Si ce sont des **serveurs alternatifs conditionnels** (features/env vars) → extraire dans `routes/alt_servers.rs`.
- Si ce sont des **restes de tests inline** → déplacer dans `#[cfg(test)] mod tests` ou vers `tests/integration/`.

**Métrique estimée :** main.rs −250. Cumul : ~605 → ~355.

---

### Task 11 — Nettoyer les imports morts + finaliser `main.rs` minimal

**Objectif :** État final : `main.rs` = imports + `mod` decls + `#[actix_web::main] async fn main` avec juste :
1. `dotenv().ok()`
2. `install_default() rustls`
3. `bootstrap::mongo::init_mongo().await`
4. `bootstrap::background::spawn_all(...)`
5. `bootstrap::tls::build_ssl_acceptor()`
6. `let http_server = actix_web::rt::spawn(async move { HttpServer::new(...).configure(routes::http_api::configure) ... });`
7. `let https_server = ...`
8. `tokio::try_join!(http_server, https_server)`

**Étape 1 :** `cargo fix --allow-dirty` (via CI, pas local) pour retirer imports non utilisés.

**Étape 2 :** vérifier que le `mod tests` compile toujours ; sinon, ajuster les `use super::*` en `use super::types::mail::*; use super::dkim::*; use super::mailing_list_handlers::*;` etc.

**Étape 3 :** vérifier arch guard + wc final.

**Métrique cible :** `main.rs` ≤ **200 LOC** hors tests (~150 sans le test module + 400 avec).

---

## Arborescence finale

```
src/bin/email_api_dir/
├── main.rs                          # 150 LOC — composition root uniquement
├── helpers.rs                       # (existant, 113 LOC)
├── admin_auth.rs                    # (existant, 239 LOC)
├── auth_handlers.rs                 # (existant, 536 LOC)
├── monitoring_handlers.rs           # (existant, 486 LOC)
├── external_handlers.rs             # (existant, 663 LOC → à découper en Task 12 futur)
├── external_probe_handlers.rs       # (existant, 77 LOC)
├── mailing_list_handlers.rs         # NOUVEAU (Task 4) — 113 LOC
├── dkim.rs                          # NOUVEAU (Task 6) — 50 LOC
├── types/
│   ├── mod.rs                       # NOUVEAU — 3 lignes
│   ├── mail.rs                      # NOUVEAU (Task 1) — 25 LOC
│   └── auth.rs                      # NOUVEAU (Task 2) — 85 LOC
├── events/
│   ├── mod.rs                       # NOUVEAU (Task 3) — 10 LOC
│   ├── types.rs                     # NOUVEAU — 35 LOC
│   ├── emit.rs                      # NOUVEAU — 25 LOC
│   └── handlers.rs                  # NOUVEAU — 90 LOC
├── bootstrap/
│   ├── mod.rs                       # NOUVEAU (Task 7) — 3 lignes
│   ├── mongo.rs                     # NOUVEAU (Task 7) — 70 LOC
│   ├── tls.rs                       # NOUVEAU (Task 8) — 20 LOC
│   └── background.rs                # NOUVEAU (Task 8) — 35 LOC
├── routes/
│   ├── mod.rs                       # NOUVEAU — 10 lignes
│   ├── mail.rs                      # NOUVEAU (Task 9a) — 50 LOC
│   ├── admin.rs                     # NOUVEAU (Task 9b) — 45 LOC
│   ├── monitoring.rs                # NOUVEAU (Task 9c) — 25 LOC
│   ├── security.rs                  # NOUVEAU (Task 9c) — 15 LOC
│   ├── external.rs                  # NOUVEAU (Task 9d) — 20 LOC
│   └── misc.rs                      # NOUVEAU (Task 9e) — 45 LOC
├── admin_ops/                       # (existant, dossier)
└── mailbox/                         # (existant)
    ├── mod.rs
    ├── send_handlers.rs             # + send_email_handler (Task 5)
    ├── read_handlers.rs
    ├── drafts_handlers.rs
    └── single_handlers.rs
```

**Cumul LOC estimé :** ~2400 LOC répartis sur 25 fichiers, aucun >150 LOC pour les nouveaux, `main.rs` = 150 LOC. **Réduction de main.rs : 1445 → 150 = −90%.**

---

## Validation par PR

Chaque PR doit :
1. Passer le `Compile & Check` job CI.
2. Passer `arch_guard.sh` (pas de dépendance nouvelle inter-couches).
3. Ne modifier QUE `src/bin/email_api_dir/**`.
4. Ne PAS changer le comportement fonctionnel : mêmes routes, mêmes DTOs, mêmes messages.
5. Être squash-mergée avec un titre `refactor(email_api): <task N> — <description courte>`.

**Aucun test métier ajouté dans ce plan** — c'est du pur découpage. Si des tests d'unité pertinents surgissent (ex : `bootstrap::mongo::init_mongo` avec URI custom), ils font l'objet d'une PR séparée post-refacto.

---

## Risques & mitigations

| Risque | Mitigation |
|---|---|
| Perte de signature de fonction adjacente (bug PR #283, #284) | JAMAIS de `del lines[start:end]` calculé. Toujours `patch mode=replace` avec old_string incluant la signature complète. |
| Imports circulaires entre `types/` et `handlers/` | `types/` ne dépend de RIEN (juste serde). Les handlers importent depuis `types/`, pas l'inverse. |
| Test `mockall::mock!` cassé après extraction DkimService | Task 6 inclut la vérif du `mod tests` avec `use super::dkim::DkimService;`. |
| `.configure(fn)` actix ne supporte pas les `.app_data` mutuels | Tous les `.app_data` restent dans `main.rs` avant `.configure(routes::...)`. `configure` ne fait QUE des `.route`/`.service`. |
| Grosse PR Task 9 (routes) refusée par revue | Découpée en 5 sous-PRs 9a–9e, chacune ~30 lignes bougées. |
| Doublon inaperçu (fn copiée mais pas supprimée en source) | Après chaque commit, `grep -c "fn <name>" src/bin/email_api_dir/` doit retourner exactement 1. Ajouter comme check systématique. |

---

## Questions ouvertes

1. **Le `mod tests` (417 LOC) doit-il migrer vers `tests/integration/` ?** — Décision différée post-refacto : d'abord découper le code, puis évaluer.
2. **Faut-il extraire un vrai port `EmailSender` trait ?** — Non dans ce plan (YAGNI) : `send_smtp_email` reste appelé directement. À faire dans une refacto hexagonale ultérieure si le besoin apparaît (test isolation, retry, alternate backend).
3. **`external_handlers.rs` (663 LOC) mérite-t-il une passe similaire ?** — Oui, mais après ce plan. Task 12 futur.

---

## Checklist finale (à cocher pendant l'exécution)

- [ ] Task 1 — DTOs mail extraits (PR mergée)
- [ ] Task 2 — DTOs auth extraits
- [ ] Task 3 — Events bus extrait
- [ ] Task 4 — Mailing list handlers extraits
- [ ] Task 6 — DkimService extrait (AVANT Task 5)
- [ ] Task 5 — `send_email_handler` migré vers `mailbox/`
- [ ] Task 7 — bootstrap Mongo extrait
- [ ] Task 8 — bootstrap TLS + background workers extraits
- [ ] Task 9a–9e — routes extraites (5 sous-PRs)
- [ ] Task 10 — Alt servers extraits ou supprimés
- [ ] Task 11 — main.rs nettoyé, ≤200 LOC hors tests
- [ ] `wc -l src/bin/email_api_dir/main.rs` retourne ≤ 600 (avec tests) ou ≤ 200 (sans)
- [ ] Aucun fichier neuf > 150 LOC
- [ ] `bash scripts/arch_guard.sh` vert
- [ ] Merge dans master avec CI verte
