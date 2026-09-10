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
    fn env_f32_returns_default_when_unset() {
        std::env::remove_var("TEST_F32_VAR");
        assert_eq!(env_f32("TEST_F32_VAR", 3.14), 3.14);
    }

    #[test]
    fn env_f32_reads_env_value() {
        std::env::set_var("TEST_F32_VAR", "2.71");
        assert_eq!(env_f32("TEST_F32_VAR", 0.0), 2.71);
        std::env::remove_var("TEST_F32_VAR");
    }

    #[test]
    fn env_f33_falls_back_on_invalid() {
        std::env::set_var("TEST_F32_VAR", "not-a-number");
        assert_eq!(env_f32("TEST_F32_VAR", 1.5), 1.5);
        std::env::remove_var("TEST_F32_VAR");
    }

    #[test]
    fn env_u64_returns_default_when_unset() {
        std::env::remove_var("TEST_U64_VAR");
        assert_eq!(env_u64("TEST_U64_VAR", 42), 42);
    }

    #[test]
    fn env_u64_reads_env_value() {
        std::env::set_var("TEST_U64_VAR", "100");
        assert_eq!(env_u64("TEST_U64_VAR", 0), 100);
        std::env::remove_var("TEST_U64_VAR");
    }

    #[test]
    fn env_u64_falls_back_on_invalid() {
        std::env::set_var("TEST_U64_VAR", "abc");
        assert_eq!(env_u64("TEST_U64_VAR", 99), 99);
        std::env::remove_var("TEST_U64_VAR");
    }

    #[test]
    fn env_list_returns_empty_when_unset() {
        std::env::remove_var("TEST_LIST_VAR");
        assert!(env_list("TEST_LIST_VAR").is_empty());
    }

    #[test]
    fn env_list_splits_comma_separated() {
        std::env::set_var("TEST_LIST_VAR", "a,b,c");
        assert_eq!(env_list("TEST_LIST_VAR"), vec!["a", "b", "c"]);
        std::env::remove_var("TEST_LIST_VAR");
    }

    #[test]
    fn env_list_trims_whitespace() {
        std::env::set_var("TEST_LIST_VAR", "  a , b ,  c  ");
        assert_eq!(env_list("TEST_LIST_VAR"), vec!["a", "b", "c"]);
        std::env::remove_var("TEST_LIST_VAR");
    }

    #[test]
    fn env_list_skips_empty_entries() {
        std::env::set_var("TEST_LIST_VAR", "a,,b,");
        assert_eq!(env_list("TEST_LIST_VAR"), vec!["a", "b"]);
        std::env::remove_var("TEST_LIST_VAR");
    }
}
