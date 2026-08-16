//! Traffic-related detection rules — split par sous-catégorie pour lisibilité.
//!
//! - `volume` : abuse volume spike, hourly anomaly
//! - `bounce` : bounce rate surge, SMTP code spikes (421/450, 550/554)
//! - `queue`  : queue buildup / deferred accumulation

mod volume;
mod bounce;
mod queue;

pub use volume::{rule_abuse_volume_spike, rule_hourly_anomaly};
pub use bounce::{rule_bounce_rate_surge, rule_smtp_code_spike_temp, rule_smtp_code_spike_perm};
pub use queue::rule_queue_buildup;
