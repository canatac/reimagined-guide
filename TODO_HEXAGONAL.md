# TODO Hexagonal — Reste à faire (post cycle 18)

## Contexte cycle 18
Ce cycle a livré :
- ✅ Script `scripts/domain_purity_audit.sh` (détecte imports EXT dans `crates/domain/`).
- ✅ Step CI soft (non bloquant) exécutant l'audit.
- ⏸️ **Purge `mongodb::bson`** : reportée (voir §1).
- ⏸️ **Migration ports vers `crates/domain`** : reportée (voir §2).

Baseline audit : **1 import EXT** dans `crates/domain/src/lib.rs` (`use mongodb::bson;`).

---

## §1 — Purger `mongodb::bson` de `crates/domain/`

### État
- `crates/domain/src/lib.rs` : **21 occurrences** de `bson::DateTime` (champs de structs `Mailbox`, `Email`, `SyncSession`, `CalendarEvent`, `EmailDto`, etc.).
- Consommateurs impactés (call-sites hors domaine) : **≥ 18 fichiers** dans `src/bin/` et `src/logic/mongo_adapter/` construisent ces types en passant `bson::DateTime::from_millis(...)`.

### Blocage
Remplacer `bson::DateTime` par `chrono::DateTime<chrono::Utc>` dans les DTOs impose :
1. Réécrire chaque construction call-site (`bson::DateTime::from_millis(Utc::now().timestamp_millis())` → `Utc::now()`).
2. Ajouter des `impl From<chrono::DateTime<Utc>> for bson::DateTime` (ou `.into()`) partout où le DTO est inséré via `bson::to_document`.
3. Vérifier les requêtes Mongo qui comparent `expires_at`, `send_after`, etc. (elles utilisent `bson::DateTime::from_millis` dans les `doc!` — inchangé côté adapter, mais tests d'intégration à revalider).

Estimation : ~50 sites à toucher, risque non nul de changement comportemental (sérialisation Mongo). **Non conforme à la règle "aucun changement comportemental" du cycle 18.**

### Plan cycle 19 proposé
- Étape A : introduire `type DomainDateTime = chrono::DateTime<chrono::Utc>` dans `crates/domain`, garder `bson::DateTime` en interne (facade).
- Étape B : DTOs domaine passent à `DomainDateTime`, adapters Mongo font la conversion via `impl From`.
- Étape C : retirer `mongodb` de `crates/domain/Cargo.toml`, audit passe à 0.

---

## §2 — Migration ports (`DatabaseInterface`, `LogicTrait`) vers `crates/domain/src/ports.rs`

### État
- `src/logic/traits.rs` (182 LOC) définit `DatabaseInterface` (~40 méthodes) + `LogicTrait`.
- Dépendances non-domaine dans les signatures :
  - `mongodb::bson` (paramètres `Document`, filtres)
  - `mongodb::error::Result` (type de retour de **toutes** les méthodes)
  - `mockall::automock` (test only, OK)

### Blocage
Déplacer tel quel violerait la pureté (le port trainerait `mongodb::error::Result`). Il faut d'abord :
1. Définir un `DomainError` dans `crates/domain` + `type DomainResult<T> = Result<T, DomainError>`.
2. Réécrire les signatures des ports pour retourner `DomainResult`.
3. Adapter chaque impl (Mongo, mocks) pour convertir `mongodb::error::Error → DomainError`.

Estimation : ~40 méthodes × 2 (trait + impl) = ~80 modifications ; risque de changement comportemental sur la propagation d'erreurs.

### Plan cycle 19/20 proposé
- Cycle 19 : introduire `DomainError` + `DomainResult` (alias transparents).
- Cycle 20 : migrer traits vers `crates/domain/src/ports.rs`, adapter Mongo implémente en convertissant les erreurs.

---

## Suivi
- Métrique clé : `bash scripts/domain_purity_audit.sh` → compteur = 0.
- LOC `crates/domain/src/` cible : ≤ 400 LOC après extraction ports.

## KPI baseline post-cycle 21

Garde-fous soft CI branchés (mode warning, non bloquants) :

- **CCN (lizard, seuil 8)** : baseline mesurée en CI — voir logs step "KPI - Complexity CCN audit"
- **Coverage domain (cargo-llvm-cov, seuil 90%)** : baseline mesurée — actuellement pas de tests → 0% attendu, target 90%
- **Ports migration** : baseline locale = 0 ports dans `crates/domain/`, **5 ports** encore dans `src/logic/traits.rs` → objectif 0.

Scripts : `scripts/complexity_audit.sh`, `scripts/domain_coverage_audit.sh`, `scripts/ports_migration_audit.sh`.
