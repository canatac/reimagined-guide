use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::hash::MessageDigest;
use base64::{encode, decode};
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;

pub struct EmailAuthenticator {
    dkim_private_key: Rsa<openssl::pkey::Private>,
    dkim_selector: String,
    dkim_domain: String,
}

impl EmailAuthenticator {
    pub fn new(dkim_private_key_pem: &str, dkim_selector: &str, dkim_domain: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let dkim_private_key = Rsa::private_key_from_pem(dkim_private_key_pem.as_bytes())?;
        Ok(Self {
            dkim_private_key,
            dkim_selector: dkim_selector.to_string(),
            dkim_domain: dkim_domain.to_string(),
        })
    }

    pub fn sign_with_dkim(&self, email_content: &str) -> Result<String, Box<dyn std::error::Error>> {
        let headers_to_sign = "from:to:subject:date";
        let canonicalized_headers = self.canonicalize_headers(email_content);
        let body_hash = self.compute_body_hash(email_content);

        let dkim_header = format!(
            "v=1; a=rsa-sha256; c=relaxed/simple; d={}; s={};\r\n\tt={}; bh={};\r\n\th={}",
            self.dkim_domain, self.dkim_selector, 
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
            body_hash, headers_to_sign
        );

        let signature_base = format!("{}{}", dkim_header, canonicalized_headers);
        let signature = self.sign_rsa(&signature_base)?;

        Ok(format!("{}; b={}", dkim_header, signature))
    }
//relaxed canonicalization method as specified in the DKIM standard (RFC 6376)
    fn canonicalize_headers(&self, email_content: &str) -> String {
        email_content
            .lines()
            .take_while(|line| !line.is_empty())
            .map(|line| {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() == 2 {
                    // Convert header name to lowercase and remove leading/trailing whitespace
                    let header_name = parts[0].trim().to_lowercase();
                    // Remove leading/trailing whitespace from header value and collapse internal whitespace
                    let header_value = parts[1].trim().split_whitespace().collect::<Vec<&str>>().join(" ");
                    format!("{}:{}\r\n", header_name, header_value)
                } else {
                    // If the line doesn't contain a colon, just trim it
                    format!("{}\r\n", line.trim())
                }
            })
            .collect()
    }

    fn compute_body_hash(&self, email_content: &str) -> String {
        let body = email_content.split("\r\n\r\n").nth(1).unwrap_or("");
        let digest = openssl::hash::hash(MessageDigest::sha256(), body.as_bytes()).unwrap();
        base64::encode(digest)
    }

    fn sign_rsa(&self, data: &str) -> Result<String, Box<dyn std::error::Error>> {
        let pkey = openssl::pkey::PKey::from_rsa(self.dkim_private_key.clone())?;
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
        signer.update(data.as_bytes())?;
        let signature = signer.sign_to_vec()?;
        Ok(encode(signature))
    }

    pub fn verify_spf(&self, sender_ip: &str, sender_domain: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
        let txt_records = resolver.txt_lookup(format!("{}.", sender_domain))?;

        for record in txt_records {
            for txt in record.iter() {
                let spf_record = std::str::from_utf8(txt)?;
                if spf_record.starts_with("v=spf1") {
                    // Implement SPF verification logic here
                    // This is a simplified check and should be expanded for production use
                    if spf_record.contains(&format!("ip4:{}", sender_ip)) {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    pub fn verify_dmarc(&self, sender_domain: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
        let dmarc_domain = format!("_dmarc.{}.", sender_domain);
        let txt_records = resolver.txt_lookup(dmarc_domain)?;

        for record in txt_records {
            for txt in record.iter() {
                let dmarc_record = std::str::from_utf8(txt)?;
                if dmarc_record.starts_with("v=DMARC1") {
                    // DMARC record found, implement full DMARC policy checking here
                    // This is a simplified check and should be expanded for production use
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}