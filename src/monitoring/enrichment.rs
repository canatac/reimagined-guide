use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoInfo {
    pub ip: Option<String>,
    pub country: String,
    pub city: String,
    pub asn: String,
    pub company: String,
    pub datacenter: Option<String>,
}

impl Default for GeoInfo {
    fn default() -> Self {
        GeoInfo {
            ip: None,
            country: "unknown".into(),
            city: "unknown".into(),
            asn: "unknown".into(),
            company: "unknown".into(),
            datacenter: None,
        }
    }
}

#[derive(Deserialize)]
struct IpApiResponse {
    #[serde(default)]
    country_name: String,
    #[serde(default)]
    city: String,
    #[serde(default)]
    asn: String,
    #[serde(default)]
    org: String,
}

struct CacheEntry {
    geo: GeoInfo,
    fetched_at: Instant,
}

static CACHE: OnceLock<Mutex<HashMap<String, CacheEntry>>> = OnceLock::new();
static HTTP: OnceLock<reqwest::Client> = OnceLock::new();

const CACHE_TTL: Duration = Duration::from_secs(86_400);

fn cache() -> &'static Mutex<HashMap<String, CacheEntry>> {
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn http() -> &'static reqwest::Client {
    HTTP.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .user_agent("misfits-monitoring/1.0")
            .build()
            .unwrap_or_default()
    })
}

pub async fn enrich_ip(ip: &str) -> GeoInfo {
    if ip.is_empty() || is_private(ip) {
        return private_geo(ip);
    }

    if let Some(geo) = cached_geo(ip) {
        return geo;
    }

    let url = format!("https://ipapi.co/{}/json/", ip);
    let geo = match http().get(&url).send().await {
        Ok(resp) => match resp.json::<IpApiResponse>().await {
            Ok(data) => GeoInfo {
                ip: Some(ip.to_string()),
                country: non_empty(data.country_name),
                city: non_empty(data.city),
                asn: non_empty(data.asn),
                company: non_empty(data.org.clone()),
                datacenter: infer_datacenter(&data.org),
            },
            Err(_) => GeoInfo { ip: Some(ip.to_string()), ..Default::default() },
        },
        Err(_) => GeoInfo { ip: Some(ip.to_string()), ..Default::default() },
    };

    if let Ok(mut c) = cache().lock() {
        c.insert(ip.to_string(), CacheEntry { geo: geo.clone(), fetched_at: Instant::now() });
    }

    geo
}

fn private_geo(ip: &str) -> GeoInfo {
    GeoInfo {
        ip: Some(ip.to_string()),
        country: "private".into(),
        city: "private".into(),
        asn: "private".into(),
        company: "private".into(),
        datacenter: None,
    }
}

fn cached_geo(ip: &str) -> Option<GeoInfo> {
    let Ok(cache) = cache().lock() else {
        return None;
    };
    let entry = cache.get(ip)?;
    (entry.fetched_at.elapsed() < CACHE_TTL).then(|| entry.geo.clone())
}

fn non_empty(s: String) -> String {
    if s.is_empty() { "unknown".into() } else { s }
}

fn infer_datacenter(org: &str) -> Option<String> {
    let o = org.to_lowercase();
    const RULES: &[(&[&str], &str)] = &[
        (&["amazon", "aws"], "AWS"),
        (&["google"], "GCP"),
        (&["microsoft", "azure"], "Azure"),
        (&["cloudflare"], "Cloudflare"),
        (&["ovh"], "OVH"),
        (&["hetzner"], "Hetzner"),
        (&["digitalocean"], "DigitalOcean"),
        (&["linode", "akamai"], "Akamai/Linode"),
        (&["vultr"], "Vultr"),
    ];

    RULES
        .iter()
        .find_map(|(needles, provider)| needles.iter().any(|needle| o.contains(needle)).then(|| (*provider).to_string()))
}

fn is_private(ip: &str) -> bool {
    const PREFIXES: &[&str] = &["127.", "10.", "192.168.", "172.1", "172.2", "172.3"];
    const EXACT_VALUES: &[&str] = &["::1", "localhost", "0.0.0.0"];

    PREFIXES.iter().any(|prefix| ip.starts_with(prefix)) || EXACT_VALUES.contains(&ip)
}
