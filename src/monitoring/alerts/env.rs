//! Environment variable helpers for alert configuration.

pub(super) fn env_f32(key: &str, default: f32) -> f32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

pub(super) fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

pub(super) fn env_list(key: &str) -> Vec<String> {
    std::env::var(key)
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_f32_default() {
        std::env::remove_var("TEST_ALERT_F32");
        assert_eq!(env_f32("TEST_ALERT_F32", 0.5), 0.5);
    }

    #[test]
    fn env_f32_custom() {
        std::env::set_var("TEST_ALERT_F32", "0.75");
        assert_eq!(env_f32("TEST_ALERT_F32", 0.5), 0.75);
        std::env::remove_var("TEST_ALERT_F32");
    }

    #[test]
    fn env_f32_invalid() {
        std::env::set_var("TEST_ALERT_F32", "invalid");
        assert_eq!(env_f32("TEST_ALERT_F32", 0.5), 0.5);
        std::env::remove_var("TEST_ALERT_F32");
    }

    #[test]
    fn env_u64_default() {
        std::env::remove_var("TEST_ALERT_U64");
        assert_eq!(env_u64("TEST_ALERT_U64", 100), 100);
    }

    #[test]
    fn env_u64_custom() {
        std::env::set_var("TEST_ALERT_U64", "500");
        assert_eq!(env_u64("TEST_ALERT_U64", 100), 500);
        std::env::remove_var("TEST_ALERT_U64");
    }

    #[test]
    fn env_list_empty() {
        std::env::remove_var("TEST_ALERT_LIST");
        let result = env_list("TEST_ALERT_LIST");
        assert!(result.is_empty());
    }

    #[test]
    fn env_list_multiple() {
        std::env::set_var("TEST_ALERT_LIST", "a,b,c");
        let result = env_list("TEST_ALERT_LIST");
        assert_eq!(result, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
        std::env::remove_var("TEST_ALERT_LIST");
    }
}
