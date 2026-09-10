use fluent::{FluentArgs, FluentResource};
use fluent_bundle::concurrent::FluentBundle;
use fluent_langneg::{negotiate_languages, NegotiationStrategy};
use std::collections::HashMap;
use std::sync::OnceLock;
use unic_langid::LanguageIdentifier;

pub const SUPPORTED_LOCALES: &[&str] = &["fr", "en", "ar", "he", "fa", "es", "de", "pt", "it"];
const RTL_LOCALES: &[&str] = &["ar", "he", "fa"];
pub const DEFAULT_LOCALE: &str = "fr";

type Bundles = HashMap<String, FluentBundle<FluentResource>>;

static BUNDLES: OnceLock<Bundles> = OnceLock::new();

fn make_bundle(locale: &str, sources: &[&str]) -> FluentBundle<FluentResource> {
    let langid: LanguageIdentifier = locale.parse().expect("valid locale identifier");
    let mut bundle = FluentBundle::new_concurrent(vec![langid]);
    for src in sources {
        match FluentResource::try_new(src.to_string()) {
            Ok(res) => {
                bundle.add_resource(res).ok();
            }
            Err((res, _errors)) => {
                bundle.add_resource(res).ok();
            }
        }
    }
    bundle
}

fn init_bundles() -> Bundles {
    let mut map = HashMap::new();
    map.insert("fr".into(), make_bundle("fr", &[
        include_str!("../../i18n/fr/errors.ftl"),
        include_str!("../../i18n/fr/emails.ftl"),
    ]));
    map.insert("en".into(), make_bundle("en", &[
        include_str!("../../i18n/en/errors.ftl"),
        include_str!("../../i18n/en/emails.ftl"),
    ]));
    map.insert("ar".into(), make_bundle("ar", &[
        include_str!("../../i18n/ar/errors.ftl"),
        include_str!("../../i18n/ar/emails.ftl"),
    ]));
    map.insert("he".into(), make_bundle("he", &[
        include_str!("../../i18n/he/errors.ftl"),
        include_str!("../../i18n/he/emails.ftl"),
    ]));
    map.insert("fa".into(), make_bundle("fa", &[
        include_str!("../../i18n/fa/errors.ftl"),
        include_str!("../../i18n/fa/emails.ftl"),
    ]));
    map.insert("es".into(), make_bundle("es", &[
        include_str!("../../i18n/es/errors.ftl"),
        include_str!("../../i18n/es/emails.ftl"),
    ]));
    map.insert("de".into(), make_bundle("de", &[
        include_str!("../../i18n/de/errors.ftl"),
        include_str!("../../i18n/de/emails.ftl"),
    ]));
    map.insert("pt".into(), make_bundle("pt", &[
        include_str!("../../i18n/pt/errors.ftl"),
        include_str!("../../i18n/pt/emails.ftl"),
    ]));
    map.insert("it".into(), make_bundle("it", &[
        include_str!("../../i18n/it/errors.ftl"),
        include_str!("../../i18n/it/emails.ftl"),
    ]));
    map
}

fn bundles() -> &'static Bundles {
    BUNDLES.get_or_init(init_bundles)
}

/// Resolve the best locale from a user preference and/or an Accept-Language header.
/// User preference takes priority; falls back to Accept-Language negotiation, then DEFAULT_LOCALE.
pub fn resolve_locale(accept_lang: &str, user_locale: Option<&str>) -> String {
    if let Some(ul) = user_locale.map(str::trim).filter(|s| !s.is_empty()) {
        if SUPPORTED_LOCALES.contains(&ul) {
            return ul.to_string();
        }
    }

    if !accept_lang.is_empty() {
        let requested: Vec<LanguageIdentifier> = accept_lang
            .split(',')
            .filter_map(|s| s.split(';').next()?.trim().parse().ok())
            .collect();

        let available: Vec<LanguageIdentifier> = SUPPORTED_LOCALES
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        let default: LanguageIdentifier = DEFAULT_LOCALE.parse().unwrap();
        let resolved = negotiate_languages(
            &requested,
            &available,
            Some(&default),
            NegotiationStrategy::Filtering,
        );

        if let Some(lang) = resolved.first() {
            let s = lang.to_string();
            if SUPPORTED_LOCALES.contains(&s.as_str()) {
                return s;
            }
            // Region prefix fallback: "fr-CA" → "fr"
            let prefix = s.split('-').next().unwrap_or(&s).to_string();
            if SUPPORTED_LOCALES.contains(&prefix.as_str()) {
                return prefix;
            }
        }
    }

    DEFAULT_LOCALE.to_string()
}

/// Returns true for RTL locales (Arabic, Hebrew, Persian).
pub fn is_rtl(locale: &str) -> bool {
    RTL_LOCALES.contains(&locale)
}

/// Look up a translated message by key, with optional variable substitution.
/// Falls back to DEFAULT_LOCALE if the key is missing in the requested locale.
pub fn t(locale: &str, key: &str, args: &[(&str, &str)]) -> String {
    let bs = bundles();
    let effective = if bs.contains_key(locale) { locale } else { DEFAULT_LOCALE };

    if let Some(result) = format_msg(bs, effective, key, args) {
        return result;
    }
    if effective != DEFAULT_LOCALE {
        if let Some(result) = format_msg(bs, DEFAULT_LOCALE, key, args) {
            return result;
        }
    }
    key.to_string()
}

fn format_msg(bs: &Bundles, locale: &str, key: &str, args: &[(&str, &str)]) -> Option<String> {
    let bundle = bs.get(locale)?;
    let msg = bundle.get_message(key)?;
    let pattern = msg.value()?;
    let mut errors = vec![];

    let value = if args.is_empty() {
        bundle.format_pattern(pattern, None, &mut errors)
    } else {
        let mut args_map = FluentArgs::new();
        for (k, v) in args {
            args_map.set(*k, v.to_string());
        }
        bundle.format_pattern(pattern, Some(&args_map), &mut errors)
    };

    Some(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_rtl_arabic() {
        assert!(is_rtl("ar"));
    }

    #[test]
    fn is_rtl_hebrew() {
        assert!(is_rtl("he"));
    }

    #[test]
    fn is_rtl_persian() {
        assert!(is_rtl("fa"));
    }

    #[test]
    fn is_rtl_ltr_locales() {
        assert!(!is_rtl("fr"));
        assert!(!is_rtl("en"));
        assert!(!is_rtl("es"));
        assert!(!is_rtl("de"));
        assert!(!is_rtl("pt"));
        assert!(!is_rtl("it"));
    }

    #[test]
    fn resolve_locale_empty_accept_lang() {
        assert_eq!(resolve_locale("", None), "fr");
    }

    #[test]
    fn resolve_locale_user_preference_wins() {
        assert_eq!(resolve_locale("en-US,en;q=0.9", Some("de")), "de");
    }

    #[test]
    fn resolve_locale_unsupported_user_preference_falls_back() {
        // "xx" is not supported, falls back to accept-language negotiation
        assert_eq!(resolve_locale("en-US,en;q=0.9", Some("xx")), "en");
    }

    #[test]
    fn resolve_locale_accept_lang_en() {
        assert_eq!(resolve_locale("en-US,en;q=0.9", None), "en");
    }

    #[test]
    fn resolve_locale_accept_lang_fr() {
        assert_eq!(resolve_locale("fr-FR,fr;q=0.9", None), "fr");
    }

    #[test]
    fn resolve_locale_accept_lang_es() {
        assert_eq!(resolve_locale("es-ES,es;q=0.9", None), "es");
    }

    #[test]
    fn resolve_locale_accept_lang_de() {
        assert_eq!(resolve_locale("de-DE,de;q=0.9", None), "de");
    }

    #[test]
    fn resolve_locale_region_prefix_fallback() {
        // "fr-CA" → should fallback to "fr"
        assert_eq!(resolve_locale("fr-CA,fr;q=0.9", None), "fr");
    }

    #[test]
    fn resolve_locale_unsupported_language_falls_back_to_default() {
        // "zh" (Chinese) is not supported, falls back to default "fr"
        assert_eq!(resolve_locale("zh-CN,zh;q=0.9", None), "fr");
    }

    #[test]
    fn resolve_locale_multiple_languages() {
        // "en" is supported, should win over unsupported "zh"
        assert_eq!(resolve_locale("zh-CN,zh;q=0.8,en-US;q=0.9", None), "en");
    }

    #[test]
    fn supported_locales_contains_fr() {
        assert!(SUPPORTED_LOCALES.contains(&"fr"));
    }

    #[test]
    fn supported_locales_contains_en() {
        assert!(SUPPORTED_LOCALES.contains(&"en"));
    }

    #[test]
    fn supported_locales_contains_rtl() {
        assert!(SUPPORTED_LOCALES.contains(&"ar"));
        assert!(SUPPORTED_LOCALES.contains(&"he"));
        assert!(SUPPORTED_LOCALES.contains(&"fa"));
    }

    #[test]
    fn default_locale_is_fr() {
        assert_eq!(DEFAULT_LOCALE, "fr");
    }

    #[test]
    fn rtl_locales_count() {
        assert_eq!(RTL_LOCALES.len(), 3);
    }

    #[test]
    fn t_missing_key_returns_key() {
        // Key not found in any bundle returns the key itself
        let result = t("fr", "totally_missing_key_xyz123", &[]);
        assert_eq!(result, "totally_missing_key_xyz123");
    }

    #[test]
    fn t_unsupported_locale_falls_back_to_default() {
        // "xx" locale not supported, falls back to "fr"
        let result = t("xx", "totally_missing_key_xyz123", &[]);
        assert_eq!(result, "totally_missing_key_xyz123");
    }

    #[test]
    fn supported_locales_count() {
        assert_eq!(SUPPORTED_LOCALES.len(), 9);
    }

    #[test]
    fn bundles_initialization_succeeds() {
        // Verify that init_bundles() doesn't panic
        let b = bundles();
        assert!(!b.is_empty());
        assert!(b.contains_key("fr"));
        assert!(b.contains_key("en"));
    }
}
