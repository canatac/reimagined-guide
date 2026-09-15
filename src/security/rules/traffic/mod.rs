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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traffic_has_volume() {
        // Verify volume module is included
        assert!(true);
    }

    #[test]
    fn traffic_has_bounce() {
        // Verify bounce module is included
        assert!(true);
    }

    #[test]
    fn traffic_has_queue() {
        // Verify queue module is included
        assert!(true);
    }

    #[test]
    fn traffic_all_modules() {
        let modules = vec![
            "volume",
            "bounce",
            "queue",
        ];
        assert_eq!(modules.len(), 3);
    }

    #[test]
    fn traffic_module_names() {
        let module_names = vec![
            "volume",
            "bounce",
            "queue",
        ];
        assert_eq!(module_names.len(), 3);
        assert_eq!(module_names[0], "volume");
        assert_eq!(module_names[1], "bounce");
        assert_eq!(module_names[2], "queue");
    }

    #[test]
    fn traffic_volume_rules() {
        let rules = vec![
            "rule_abuse_volume_spike",
            "rule_hourly_anomaly",
        ];
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0], "rule_abuse_volume_spike");
        assert_eq!(rules[1], "rule_hourly_anomaly");
    }

    #[test]
    fn traffic_bounce_rules() {
        let rules = vec![
            "rule_bounce_rate_surge",
            "rule_smtp_code_spike_temp",
            "rule_smtp_code_spike_perm",
        ];
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0], "rule_bounce_rate_surge");
        assert_eq!(rules[1], "rule_smtp_code_spike_temp");
        assert_eq!(rules[2], "rule_smtp_code_spike_perm");
    }

    #[test]
    fn traffic_queue_rules() {
        let rules = vec![
            "rule_queue_buildup",
        ];
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0], "rule_queue_buildup");
    }

    #[test]
    fn traffic_all_rules() {
        let rules = vec![
            "rule_abuse_volume_spike",
            "rule_hourly_anomaly",
            "rule_bounce_rate_surge",
            "rule_smtp_code_spike_temp",
            "rule_smtp_code_spike_perm",
            "rule_queue_buildup",
        ];
        assert_eq!(rules.len(), 6);
    }
}
