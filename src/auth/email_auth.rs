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
        let headers_to_sign = self.determine_headers_to_sign(email_content);
        let canonicalized_headers = self.canonicalize_headers(email_content, &headers_to_sign);

        let body_hash = self.compute_body_hash(email_content);

        let dkim_header = format!(
            "v=1; a=rsa-sha256; c=relaxed/simple; d={}; s={}; t={}; bh={}; h={}",
            self.dkim_domain, 
            self.dkim_selector, 
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
            body_hash, 
            headers_to_sign.join(":")
        );

        let signature_base = format!("{}{}", dkim_header, canonicalized_headers.trim_end());
        // Debug print
        println!("String to be signed:\n{}", signature_base);

        let signature = self.sign_rsa(&signature_base)?;
        // Debug print
        println!("Raw signature (base64):\n{}", signature);

        Ok(format!("{}; b={}", dkim_header, signature))
    
    }
//
fn determine_headers_to_sign(&self, email_content: &str) -> Vec<String> {
    let headers = email_content.split("\r\n\r\n").next().unwrap_or("").lines();
    let mut headers_to_sign = vec![];
    let required_headers = ["from", "to", "subject", "date"];
    
    for header in headers {
        let header_name = header.split(':').next().unwrap_or("").trim().to_lowercase();
        if required_headers.contains(&header_name.as_str()) && !headers_to_sign.contains(&header_name) {
            headers_to_sign.push(header_name);
        }
    }

    // Ensure all required headers are included, even if they're not in the email
    for &required in required_headers.iter() {
        if !headers_to_sign.contains(&required.to_string()) {
            headers_to_sign.push(required.to_string());
        }
    }

    headers_to_sign
}
    fn canonicalize_headers(&self, email_content: &str, headers_to_sign: &[String]) -> String {
        let headers = email_content.split("\r\n\r\n").next().unwrap_or("");
        let mut canonicalized = String::new();
        let mut seen_headers = std::collections::HashSet::new();
    
        for line in headers.lines() {
            if line.is_empty() {
                break;
            }
            let (header_name, header_value) = match line.split_once(':') {
                Some((name, value)) => (name.trim(), value.trim()),
                None => continue,
            };
            let lowercase_name = header_name.to_lowercase();
            if headers_to_sign.contains(&lowercase_name) && !seen_headers.contains(&lowercase_name) {
                seen_headers.insert(lowercase_name);
                let canonical_value = header_value.split_whitespace().collect::<Vec<&str>>().join(" ");
                canonicalized.push_str(&format!("{}:{}\r\n", header_name, canonical_value));
            }
        }
    
        canonicalized

}
    

    fn compute_body_hash(&self, email_content: &str) -> String {
        let parts: Vec<&str> = email_content.split("\r\n\r\n").collect();
        let body = if parts.len() > 1 { parts[1] } else { "" };
        let digest = openssl::hash::hash(MessageDigest::sha256(), body.as_bytes()).unwrap();
        base64::encode(digest)
    }

    fn sign_rsa(&self, data: &str) -> Result<String, Box<dyn std::error::Error>> {
        let pkey = openssl::pkey::PKey::from_rsa(self.dkim_private_key.clone())?;
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
        signer.update(data.as_bytes())?;
        let signature = signer.sign_to_vec()?;

        // Debug print
        println!("Raw signature bytes: {:?}", signature);

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