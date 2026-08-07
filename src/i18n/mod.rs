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
        let mut fa = FluentArgs::new();
        for (k, v) in args {
            fa.set(k.to_string(), v.to_string());
        }
        bundle.format_pattern(pattern, Some(&fa), &mut errors)
    };

    Some(value.into_owned())
}
