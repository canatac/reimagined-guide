use super::*;

pub(crate) fn normalize_topic(raw: Option<&str>) -> String {
    let t = raw.unwrap_or("Tech").trim();
    if t.is_empty() {
        return "Tech".to_string();
    }
    t.to_string()
}

pub(crate) fn normalize_url(raw: Option<&str>) -> Option<String> {
    let trimmed = raw.unwrap_or("").trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return Some(trimmed.to_string());
    }
    Some(format!("https://{}", trimmed))
}

pub(crate) fn compute_signal(summary: &str, requested: Option<i32>) -> i32 {
    if let Some(v) = requested {
        return v.clamp(0, 100);
    }
    let boost = (summary.trim().chars().count() / 20) as i32;
    (65 + boost).clamp(50, 98)
}

pub(crate) fn extract_domain(raw: &str) -> Option<String> {
    let value = raw.trim().to_lowercase();
    if value.is_empty() {
        return None;
    }
    let without_scheme = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .unwrap_or(value.as_str());
    let host = without_scheme
        .split('/')
        .next()
        .unwrap_or("")
        .trim_start_matches("www.")
        .trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

pub(crate) fn bump_interest(weights: &mut std::collections::HashMap<String, i32>, key: &str, delta: i32) {
    let entry = weights.entry(key.to_string()).or_insert(0);
    *entry += delta;
}

fn bump_for_matches(
    weights: &mut std::collections::HashMap<String, i32>,
    corpus: &str,
    rules: &[(&str, &[&str], i32)],
) {
    for (key, terms, delta) in rules {
        if terms.iter().any(|term| corpus.contains(term)) {
            bump_interest(weights, key, *delta);
        }
    }
}

fn bump_for_topic(
    weights: &mut std::collections::HashMap<String, i32>,
    topic: &str,
) {
    const TOPIC_RULES: &[(&str, &str)] = &[
        ("tech", "tech"),
        ("finance", "finance"),
        ("science", "science"),
        ("design", "design"),
        ("lifestyle", "lifestyle"),
    ];

    if let Some((key, _)) = TOPIC_RULES.iter().find(|(_, candidate)| *candidate == topic) {
        bump_interest(weights, key, 4);
    }
}

fn item_text(item: &bson::Document) -> String {
    let mut corpus = String::new();
    if let Ok(title) = item.get_str("title") {
        corpus.push_str(title);
        corpus.push(' ');
    }
    if let Ok(summary) = item.get_str("summary") {
        corpus.push_str(summary);
    }
    corpus.to_lowercase()
}

fn source_text(source: &bson::Document) -> String {
    let name = source
        .get_str("name")
        .ok()
        .map(str::to_lowercase)
        .unwrap_or_default();
    let url = source
        .get_str("url")
        .ok()
        .map(str::to_lowercase)
        .unwrap_or_default();
    format!("{} {}", name, url)
}

pub(crate) fn infer_interest_weights(
    sources: &[bson::Document],
    items: &[bson::Document],
) -> std::collections::HashMap<String, i32> {
    let mut weights: std::collections::HashMap<String, i32> = std::collections::HashMap::new();

    const ITEM_RULES: &[(&str, &[&str], i32)] = &[
        ("ai", &["ai", "llm", "machine learning"], 3),
        ("engineering", &["rust", "engineering", "dev"], 2),
        ("devops", &["cloud", "kubernetes", "devops"], 2),
        ("security", &["security", "privacy", "auth"], 2),
        ("startup", &["startup", "product", "saas"], 2),
    ];

    const SOURCE_RULES: &[(&str, &[&str], i32)] = &[
        ("tech", &["tech"], 2),
        ("ai", &["ai", "openai", "qwen"], 2),
        ("finance", &["finance", "market"], 2),
        ("security", &["security"], 2),
        ("science", &["science"], 2),
        ("design", &["design", "ux"], 2),
    ];

    for item in items {
        if let Ok(topic) = item.get_str("topic") {
            bump_for_topic(&mut weights, topic.trim().to_lowercase().as_str());
        }

        let text = item_text(item);
        bump_for_matches(&mut weights, &text, ITEM_RULES);
    }

    for source in sources {
        let corpus = source_text(source);
        bump_for_matches(&mut weights, &corpus, SOURCE_RULES);
    }

    if weights.is_empty() {
        bump_interest(&mut weights, "tech", 1);
    }

    weights
}

pub(crate) fn suggestion_catalog() -> Vec<(&'static str, &'static str, &'static str, &'static str, &'static [&'static str])> {
    vec![
        (
            "Hacker News",
            "https://news.ycombinator.com/rss",
            "rss",
            "Veille tech généraliste à fort signal (startups, infra, produits).",
            &["tech", "startup", "engineering"],
        ),
        (
            "TechCrunch",
            "https://techcrunch.com/feed/",
            "rss",
            "Actualité startups, levées et nouveaux produits.",
            &["tech", "startup", "finance"],
        ),
        (
            "The Pragmatic Engineer",
            "https://newsletter.pragmaticengineer.com/feed",
            "rss",
            "Analyses engineering management et architecture logicielle.",
            &["engineering", "tech"],
        ),
        (
            "InfoQ",
            "https://www.infoq.com/feed/",
            "rss",
            "Articles techniques profonds sur architecture, cloud et dev.",
            &["engineering", "devops", "tech"],
        ),
        (
            "Cloudflare Blog",
            "https://blog.cloudflare.com/rss/",
            "rss",
            "Réseau, sécurité, performance et incident reports détaillés.",
            &["security", "devops", "engineering"],
        ),
        (
            "Google Security Blog",
            "https://security.googleblog.com/atom.xml",
            "rss",
            "Veille sécurité opérationnelle et vulnérabilités majeures.",
            &["security", "tech"],
        ),
        (
            "OpenAI News",
            "https://openai.com/news/rss.xml",
            "rss",
            "Mises à jour IA produits et recherche appliquée.",
            &["ai", "tech", "science"],
        ),
        (
            "Simon Willison Blog",
            "https://simonwillison.net/atom/everything/",
            "rss",
            "Observabilité IA, LLM tools et retours terrain développeur.",
            &["ai", "engineering", "tech"],
        ),
        (
            "Stratechery",
            "https://stratechery.com",
            "site",
            "Analyses business tech (stratégie produit, marché, distribution).",
            &["finance", "startup", "tech"],
        ),
        (
            "MIT Technology Review (AI)",
            "https://www.technologyreview.com/topic/artificial-intelligence/",
            "site",
            "Perspective business + sociétale sur l'IA en production.",
            &["ai", "science", "tech"],
        ),
        (
            "McKinsey Tech Trends",
            "https://www.mckinsey.com/capabilities/mckinsey-digital/our-insights",
            "site",
            "Tendances stratégiques et impacts business des technologies.",
            &["finance", "tech", "startup"],
        ),
        (
            "A16Z AI Canon",
            "https://a16z.com/ai-canon/",
            "article",
            "Collection d'articles de référence IA produit/market fit.",
            &["ai", "startup", "finance"],
        ),
    ]
}

