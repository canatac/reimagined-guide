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
