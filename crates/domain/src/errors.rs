use thiserror::Error;

/// DomainError — erreur pure du domaine, sans dépendance externe (mongodb, etc.).
/// Les adapters convertissent leurs erreurs concrètes vers ce type via `From`.
#[derive(Debug, Error)]
pub enum DomainError {
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("internal error: {0}")]
    Internal(String),
}

pub type DomainResult<T> = Result<T, DomainError>;
