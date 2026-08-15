// entities.rs — Boucle 13 : Re-export depuis la crate simple-smtp-domain.
// Le code métier vit désormais dans crates/domain/. Cette façade préserve
// tous les call-sites existants (`use crate::entities::X`) sans réécriture.

pub use simple_smtp_domain::*;
