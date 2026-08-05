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
        return GeoInfo {
            ip: Some(ip.to_string()),
            country: "private".into(),
            city: "private".into(),
            asn: "private".into(),
            company: "private".into(),
            datacenter: None,
        };
    }

    // Serve from cache if fresh
    {
        if let Ok(c) = cache().lock() {
            if let Some(entry) = c.get(ip) {
                if entry.fetched_at.elapsed() < CACHE_TTL {
                    return entry.geo.clone();
                }
            }
        }
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

fn non_empty(s: String) -> String {
    if s.is_empty() { "unknown".into() } else { s }
}

fn infer_datacenter(org: &str) -> Option<String> {
    let o = org.to_lowercase();
    if o.contains("amazon") || o.contains("aws") { Some("AWS".into()) }
    else if o.contains("google") { Some("GCP".into()) }
    else if o.contains("microsoft") || o.contains("azure") { Some("Azure".into()) }
    else if o.contains("cloudflare") { Some("Cloudflare".into()) }
    else if o.contains("ovh") { Some("OVH".into()) }
    else if o.contains("hetzner") { Some("Hetzner".into()) }
    else if o.contains("digitalocean") { Some("DigitalOcean".into()) }
    else if o.contains("linode") || o.contains("akamai") { Some("Akamai/Linode".into()) }
    else if o.contains("vultr") { Some("Vultr".into()) }
    else { None }
}

fn is_private(ip: &str) -> bool {
    ip.starts_with("127.")
        || ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip.starts_with("172.1") // 172.16–31
        || ip.starts_with("172.2")
        || ip.starts_with("172.3")
        || ip == "::1"
        || ip == "localhost"
        || ip == "0.0.0.0"
}
