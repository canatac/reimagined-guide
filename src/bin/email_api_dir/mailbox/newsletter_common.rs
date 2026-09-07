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

pub(crate) fn infer_interest_weights(
    sources: &[bson::Document],
    items: &[bson::Document],
) -> std::collections::HashMap<String, i32> {
    let mut weights: std::collections::HashMap<String, i32> = std::collections::HashMap::new();

    for item in items {
        if let Ok(topic) = item.get_str("topic") {
            match topic.trim().to_lowercase().as_str() {
                "tech" => bump_interest(&mut weights, "tech", 4),
                "finance" => bump_interest(&mut weights, "finance", 4),
                "science" => bump_interest(&mut weights, "science", 4),
                "design" => bump_interest(&mut weights, "design", 4),
                "lifestyle" => bump_interest(&mut weights, "lifestyle", 4),
                _ => {}
            }
        }

        let mut corpus = String::new();
        if let Ok(title) = item.get_str("title") {
            corpus.push_str(title);
            corpus.push(' ');
        }
        if let Ok(summary) = item.get_str("summary") {
            corpus.push_str(summary);
        }
        let text = corpus.to_lowercase();

        if text.contains("ai") || text.contains("llm") || text.contains("machine learning") {
            bump_interest(&mut weights, "ai", 3);
        }
        if text.contains("rust") || text.contains("engineering") || text.contains("dev") {
            bump_interest(&mut weights, "engineering", 2);
        }
        if text.contains("cloud") || text.contains("kubernetes") || text.contains("devops") {
            bump_interest(&mut weights, "devops", 2);
        }
        if text.contains("security") || text.contains("privacy") || text.contains("auth") {
            bump_interest(&mut weights, "security", 2);
        }
        if text.contains("startup") || text.contains("product") || text.contains("saas") {
            bump_interest(&mut weights, "startup", 2);
        }
    }

    for source in sources {
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
        let corpus = format!("{} {}", name, url);

        if corpus.contains("tech") {
            bump_interest(&mut weights, "tech", 2);
        }
        if corpus.contains("ai") || corpus.contains("openai") || corpus.contains("qwen") {
            bump_interest(&mut weights, "ai", 2);
        }
        if corpus.contains("finance") || corpus.contains("market") {
            bump_interest(&mut weights, "finance", 2);
        }
        if corpus.contains("security") {
            bump_interest(&mut weights, "security", 2);
        }
        if corpus.contains("science") {
            bump_interest(&mut weights, "science", 2);
        }
        if corpus.contains("design") || corpus.contains("ux") {
            bump_interest(&mut weights, "design", 2);
        }
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

