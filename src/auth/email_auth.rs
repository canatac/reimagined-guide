use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::pkey::Public;
use base64::{encode, decode};
use trust_dns_resolver::{AsyncResolver, Resolver};
use trust_dns_resolver::config::*;
use base64;
use pem::Pem;

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
        println!("sign_with_dkim - INPUT - email_content: {}", email_content);
        let headers_to_sign = self.determine_headers_to_sign(email_content);
        let canonicalized_headers = self.canonicalize_headers(email_content, &headers_to_sign);

        let body_hash = self.compute_body_hash(email_content);

        let dkim_header = format!(
            "v=1;a=rsa-sha256;c=relaxed/simple;d={};s={};t={};bh={};h={};b=;",
            self.dkim_domain, 
            self.dkim_selector, 
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
            body_hash, 
            headers_to_sign.join(":")
        );

        let signature_base = format!("{}\r\n{}", dkim_header, canonicalized_headers);
        // Debug print
        println!("sign_with_dkim - OUTPUT - signature_base to be signed :\n{}", signature_base);
        println!("sign_with_dkim - OUTPUT - signature_base as bytes: {:?}", signature_base.as_bytes());
               
        let signature = self.sign_rsa(&signature_base)?;
        // Debug print
        println!("sign_rsa - OUTPUT - Raw signature_base (base64):\n{}", signature);

        let result = format!("{}{};", dkim_header.trim_end_matches(';'), signature);
        
        // Print the result before returning
        println!("sign_with_dkim - OUTPUT - DKIM Signature:\n{}", result);

        Ok(result)
    
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

    for header_name in headers_to_sign {
        let lowercase_name = header_name.to_lowercase();
        if !seen_headers.contains(&lowercase_name) {
            if let Some(header_value) = self.get_header_value(headers, header_name) {
                seen_headers.insert(lowercase_name.clone());
                let canonical_header = self.relaxed_canonicalization(header_name, header_value);
                canonicalized.push_str(&canonical_header);
                canonicalized.push_str("\r\n");
            }
        }
    }

    canonicalized
}
fn get_header_value<'a>(&self, headers: &'a str, header_name: &str) -> Option<&'a str> {
    headers.lines()
        .find(|line| line.to_lowercase().starts_with(&format!("{}:", header_name.to_lowercase())))
        .and_then(|line| line.splitn(2, ':').nth(1))
        .map(|value| value.trim())
}

fn relaxed_canonicalization(&self, name: &str, value: &str) -> String {
    let name = name.to_lowercase();
    let value = value.split_whitespace().collect::<Vec<&str>>().join(" ");
    format!("{}:{}", name, value.trim())
}

    fn compute_body_hash(&self, email_content: &str) -> String {
        let parts: Vec<&str> = email_content.split("\r\n\r\n").collect();
        let body = if parts.len() > 1 { parts[1] } else { "" };
        let digest = openssl::hash::hash(MessageDigest::sha256(), body.as_bytes()).unwrap();
        base64::encode(digest)
    }

    fn sign_rsa(&self, data: &str) -> Result<String, Box<dyn std::error::Error>> {
        println!("sign_rsa - INPUT - data: {}", data);
        let pkey = openssl::pkey::PKey::from_rsa(self.dkim_private_key.clone())?;

        let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;

        signer.update(data.as_bytes())?;
        let signature = signer.sign_to_vec()?;

        // Debug print raw signature bytes
        println!("sign_rsa - OUTPUT - Raw signature bytes: {:?}", signature);

        let encoded_signature = encode(signature);
        
        // Debug print encoded signature
        println!("sign_rsa - OUTPUT - Encoded signature: {}", encoded_signature);

        Ok(encoded_signature)
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

    pub async fn get_dkim_public_key(&self) -> Result<PKey<Public>, Box<dyn std::error::Error>> {
        let resolver = AsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    
        let dkim_record_name = format!("{}._domainkey.{}", self.dkim_selector, self.dkim_domain);
        
        println!("Querying DNS for DKIM record: {}", dkim_record_name);
    
        let txt_records = resolver.txt_lookup(dkim_record_name).await?;
        
        let mut full_record = String::new();
        for record in txt_records.iter() {
            for txt in record.iter() {
                full_record.push_str(std::str::from_utf8(txt)?);
            }
        }
        
        println!("Found DKIM record: {}", full_record);
    
        if full_record.starts_with("v=DKIM1;") {
            // Parse the DKIM record
            let mut public_key_base64 = String::new();
            for part in full_record.split(';') {
                let part = part.trim();
                if part.starts_with("p=") {
                    public_key_base64 = part.trim_start_matches("p=").to_string();
                    break;
                }
            }
            
            if public_key_base64.is_empty() {
                return Err("Public key not found in DKIM record".into());
            }
    
            println!("Extracted base64 public key: {}", public_key_base64);
    
            // Decode the base64 public key
            let public_key_der = base64::decode(public_key_base64)?;
    
            // Convert DER to RSA public key
            let rsa = Rsa::public_key_from_der(&public_key_der)?;
            
            // Convert RSA to PKey
            let pkey = PKey::from_rsa(rsa)?;
    
            println!("Converted public key to PKey format");
            Ok(pkey)
        } else {
            Err("Invalid DKIM record format".into())
        }
    }
}