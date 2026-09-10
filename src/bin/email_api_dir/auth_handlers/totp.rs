// totp.rs — Helpers HOTP/TOTP + endpoint api_2fa_verify. Extraits de auth_handlers.rs.
#![allow(unused_imports, dead_code)]
use super::super::*;
use super::login::make_session;

pub(crate) fn default_2fa_method() -> String { "email".to_string() }

#[derive(Deserialize)]
pub(crate) struct TwoFactorVerifyRequest {
    pub email: String,
    pub code: String,
    #[serde(default = "default_2fa_method")]
    pub method: String,
}

pub(crate) fn compute_hotp(key: &[u8], counter: u64) -> u32 {
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 0x0f) as usize;
    let code = ((result[offset] as u32 & 0x7f) << 24)
        | ((result[offset + 1] as u32) << 16)
        | ((result[offset + 2] as u32) << 8)
        | (result[offset + 3] as u32);
    code % 1_000_000
}

pub(crate) fn verify_totp(secret_b32: &str, code: &str) -> bool {
    use constant_time_eq::constant_time_eq;
    let s = secret_b32.to_uppercase();
    let pad = s.len() % 8;
    let padded = if pad == 0 { s } else { format!("{}{}", s, "=".repeat(8 - pad)) };
    let key = match BASE32.decode(padded.as_bytes()) { Ok(k) => k, Err(_) => return false };
    let t = Utc::now().timestamp() / 30;
    for delta in [-1i64, 0, 1] {
        let counter = (t + delta).max(0) as u64;
        let candidate = format!("{:06}", compute_hotp(&key, counter));
        if constant_time_eq(candidate.as_bytes(), code.as_bytes()) { return true; }
    }
    false
}

pub(crate) fn generate_totp_secret() -> String {
    BASE32.encode(Uuid::new_v4().as_bytes())
}

pub(crate) fn generate_otp_code() -> String {
    let b = Uuid::new_v4();
    let n = u32::from_be_bytes([b.as_bytes()[0], b.as_bytes()[1], b.as_bytes()[2], b.as_bytes()[3]]);
    format!("{:06}", n % 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_hotp_returns_6_digits() {
        let key = b"secret";
        let code = compute_hotp(key, 0);
        assert!(code < 1_000_000);
        assert!(code <= 999_999);
    }

    #[test]
    fn compute_hotp_same_key_same_counter() {
        let key = b"mysecret";
        let c1 = compute_hotp(key, 5);
        let c2 = compute_hotp(key, 5);
        assert_eq!(c1, c2);
    }

    #[test]
    fn compute_hotp_different_counters_differ() {
        let key = b"mysecret";
        let c1 = compute_hotp(key, 1);
        let c2 = compute_hotp(key, 2);
        assert_ne!(c1, c2);
    }

    #[test]
    fn verify_totp_valid_code_now() {
        // Generate secret, get current code, verify it matches
        let secret = generate_totp_secret();
        let t = chrono::Utc::now().timestamp() / 30;
        let code = format!("{:06}", compute_hotp(&BASE32.decode(secret.to_uppercase().as_bytes()).unwrap_or_else(|_| BASE32.decode(b"MFRGGZDFMZTWQ2LK").unwrap()), t));
        assert!(verify_totp(&secret, &code));
    }

    #[test]
    fn verify_totp_rejects_invalid_code() {
        let secret = generate_totp_secret();
        assert!(!verify_totp(&secret, "000000"));
        assert!(!verify_totp(&secret, "999999"));
    }

    #[test]
    fn verify_totp_rejects_empty_code() {
        let secret = generate_totp_secret();
        assert!(!verify_totp(&secret, ""));
    }

    #[test]
    fn generate_totp_secret_is_base32() {
        let secret = generate_totp_secret();
        assert!(!secret.is_empty());
        // All characters should be valid base32
        for c in secret.chars() {
            assert!(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '=');
        }
    }

    #[test]
    fn generate_otp_code_is_6_digits() {
        let code = generate_otp_code();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn generate_totp_secret_produces_unique() {
        let s1 = generate_totp_secret();
        let s2 = generate_totp_secret();
        assert_ne!(s1, s2);
    }
}

pub(crate) async fn api_2fa_verify(
    body: web::Json<TwoFactorVerifyRequest>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let db = mongo_db_name();
    if body.method == "totp" {
        let coll = mongo.database(&db).collection::<bson::Document>("users");
        let local = body.email.split('@').next().unwrap_or(&body.email);
        let user_doc = match coll.find_one(doc! { "$or": [{ "username": local }, { "username": &body.email }] }).await {
            Ok(Some(d)) => d,
            Ok(None) => return HttpResponse::Unauthorized().json(serde_json::json!({ "verified": false, "error": "User not found" })),
            Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e.to_string() })),
        };
        let totp_secret = match user_doc.get_str("totp_secret").ok().filter(|s| !s.is_empty()) {
            Some(s) => s.to_string(),
            None => return HttpResponse::BadRequest().json(serde_json::json!({ "verified": false, "error": "TOTP not configured for this user" })),
        };
        if !verify_totp(&totp_secret, &body.code) {
            return HttpResponse::Unauthorized().json(serde_json::json!({ "verified": false, "error": "Invalid TOTP code" }));
        }
    } else {
        let coll = mongo.database(&db).collection::<bson::Document>("two_factor_codes");
        let now_ms = Utc::now().timestamp_millis();
        match coll.find_one(doc! { "email": &body.email, "code": &body.code, "used": false, "expires_at": { "$gt": bson::DateTime::from_millis(now_ms) } }).await {
            Ok(Some(d)) => { if let Ok(oid) = d.get_object_id("_id") { let _ = coll.update_one(doc! { "_id": oid }, doc! { "$set": { "used": true } }).await; } }
            Ok(None) => return HttpResponse::Unauthorized().json(serde_json::json!({ "verified": false, "error": "Invalid or expired code" })),
            Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": e.to_string() })),
        }
    }
    let display = body.email.split('@').next().unwrap_or(&body.email).to_string();
    let session = make_session(&body.email, &display);
    HttpResponse::Ok().json(serde_json::json!({ "verified": true, "session": session.session }))
}
