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
        std::env::remove_var("TEST_F32_MISSING");
        assert_eq!(env_f32("TEST_F32_MISSING", 42.5), 42.5);
    }

    #[test]
    fn env_f32_from_env() {
        std::env::set_var("TEST_F32_VAL", "3.14");
        assert_eq!(env_f32("TEST_F32_VAL", 0.0), 3.14);
        std::env::remove_var("TEST_F32_VAL");
    }

    #[test]
    fn env_f32_invalid_falls_back() {
        std::env::set_var("TEST_F32_BAD", "not-a-number");
        assert_eq!(env_f32("TEST_F32_BAD", 99.9), 99.9);
        std::env::remove_var("TEST_F32_BAD");
    }

    #[test]
    fn env_u64_default() {
        std::env::remove_var("TEST_U64_MISSING");
        assert_eq!(env_u64("TEST_U64_MISSING", 100), 100);
    }

    #[test]
    fn env_u64_from_env() {
        std::env::set_var("TEST_U64_VAL", "42");
        assert_eq!(env_u64("TEST_U64_VAL", 0), 42);
        std::env::remove_var("TEST_U64_VAL");
    }

    #[test]
    fn env_u64_invalid_falls_back() {
        std::env::set_var("TEST_U64_BAD", "abc");
        assert_eq!(env_u64("TEST_U64_BAD", 77), 77);
        std::env::remove_var("TEST_U64_BAD");
    }

    #[test]
    fn env_list_default_empty() {
        std::env::remove_var("TEST_LIST_MISSING");
        assert!(env_list("TEST_LIST_MISSING").is_empty());
    }

    #[test]
    fn env_list_from_env() {
        std::env::set_var("TEST_LIST_VAL", "a,b,c");
        assert_eq!(env_list("TEST_LIST_VAL"), vec!["a", "b", "c"]);
        std::env::remove_var("TEST_LIST_VAL");
    }

    #[test]
    fn env_list_filters_empty() {
        std::env::set_var("TEST_LIST_EMPTY", "a,,b, ,c,");
        assert_eq!(env_list("TEST_LIST_EMPTY"), vec!["a", "b", "c"]);
        std::env::remove_var("TEST_LIST_EMPTY");
    }
}
