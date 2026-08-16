//! Ports du domaine — interfaces d'inversion pures (aucun import externe).
//!
//! Cycle 22 : premier port migré depuis `src/logic/traits.rs`.
//! Objectif : que les use-cases dépendent uniquement de ces traits, pas de
//! `mongodb::error::Result` ni d'autres détails d'infrastructure.

use crate::errors::DomainResult;
use async_trait::async_trait;

/// Port applicatif — orchestration de haut niveau (use-cases).
///
/// Correspond à l'ancien `LogicTrait` de `src/logic/traits.rs`, mais
/// s'exprime en termes de `DomainResult` pour rester indépendant de
/// l'infrastructure. Les adapters (ex. `Logic` côté crate racine)
/// implémentent ce port en convertissant leurs erreurs concrètes via
/// `From<mongodb::Error> for DomainError`.
#[async_trait]
pub trait LogicPort: Send + Sync {
    async fn create_user(
        &self,
        username: &str,
        password: &str,
        mailbox: &str,
    ) -> DomainResult<()>;
}
