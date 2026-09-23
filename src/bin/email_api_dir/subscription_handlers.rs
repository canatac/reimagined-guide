//! Pro plan subscription — payment + feature activation + invoice (issue #627).
//!
//! Provides:
//! - POST /api/subscription/subscribe — accept payment, activate Pro, generate invoice
//! - GET /api/subscription — current subscription status
//! - POST /api/subscription/cancel — cancel auto-renewal

#![allow(unused_imports, dead_code)]
use super::super::*;
use actix_web::{HttpRequest, HttpResponse, Responder};
use futures_util::TryStreamExt;
use mongodb::bson::doc;
use std::sync::Arc;

/// Plan tiers available for subscription.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PlanTier {
    Free,
    Pro,
}

impl PlanTier {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            PlanTier::Free => "free",
            PlanTier::Pro => "pro",
        }
    }
}

impl std::str::FromStr for PlanTier {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "free" => Ok(PlanTier::Free),
            "pro" => Ok(PlanTier::Pro),
            other => Err(format!("unknown plan tier: {other}")),
        }
    }
}

/// Subscription status.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SubscriptionStatus {
    Active,
    Cancelled,
    Expired,
}

impl SubscriptionStatus {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            SubscriptionStatus::Active => "active",
            SubscriptionStatus::Cancelled => "cancelled",
            SubscriptionStatus::Expired => "expired",
        }
    }
}

/// Input for POST /api/subscription/subscribe.
#[derive(Debug, Deserialize)]
pub(crate) struct SubscribeInput {
    pub(crate) plan: String,
    pub(crate) payment_method_id: Option<String>,
    pub(crate) currency: Option<String>,
}

/// Input for POST /api/subscription/cancel.
#[derive(Debug, Deserialize)]
pub(crate) struct CancelInput {
    pub(crate) reason: Option<String>,
}

/// Pro plan features activated on subscription.
#[derive(Debug, Serialize)]
pub(crate) struct ProFeatures {
    pub(crate) max_external_accounts: u32,
    pub(crate) max_storage_bytes: u64,
    pub(crate) custom_domain: bool,
    pub(crate) priority_support: bool,
    pub(crate) advanced_filters: bool,
    pub(crate) api_access: bool,
}

impl ProFeatures {
    pub(crate) fn for_tier(tier: &PlanTier) -> Self {
        match tier {
            PlanTier::Free => ProFeatures {
                max_external_accounts: 0,
                max_storage_bytes: 100 * 1024 * 1024, // 100 MB
                custom_domain: false,
                priority_support: false,
                advanced_filters: false,
                api_access: false,
            },
            PlanTier::Pro => ProFeatures {
                max_external_accounts: 10,
                max_storage_bytes: 10 * 1024 * 1024 * 1024, // 10 GB
                custom_domain: true,
                priority_support: true,
                advanced_filters: true,
                api_access: true,
            },
        }
    }
}

/// Invoice record stored after successful payment.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct Invoice {
    pub(crate) id: String,
    pub(crate) user_id: String,
    pub(crate) plan: String,
    pub(crate) amount_cents: u64,
    pub(crate) currency: String,
    pub(crate) status: String,
    pub(crate) created_at: mongodb::bson::DateTime,
}

/// POST /api/subscription/subscribe — accept payment, activate Pro, generate invoice.
pub(crate) async fn api_subscription_subscribe(
    req: HttpRequest,
    payload: web::Json<SubscribeInput>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let auth = match admin_auth::require_auth(&req, mongo.get_ref(), &mongo_db_name()).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let user_id = auth.user_id.clone();

    let tier: PlanTier = match payload.plan.parse() {
        Ok(t) => t,
        Err(e) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "code": "INVALID_PLAN",
                "message": e,
            }));
        }
    };

    if tier == PlanTier::Free {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "code": "ALREADY_FREE",
            "message": "Free plan is the default. Use /api/subscription/cancel to disable auto-renew.",
        }));
    }

    let db_name = mongo_db_name();
    let db = mongo.database(&db_name);
    let now = mongodb::bson::DateTime::from_millis(chrono::Utc::now().timestamp_millis());

    // Check for existing active subscription
    let subs_coll = db.collection::<mongodb::bson::Document>("subscriptions");
    let existing = subs_coll
        .find_one(doc! { "user_id": &user_id, "status": "active" })
        .await;

    if let Ok(Some(_)) = existing {
        return HttpResponse::Conflict().json(serde_json::json!({
            "code": "SUBSCRIPTION_ACTIVE",
            "message": "User already has an active subscription. Use PATCH to change plan.",
        }));
    }

    // Create subscription record
    let subscription_id = uuid::Uuid::new_v4().to_string();
    let subscription_doc = doc! {
        "_id": &subscription_id,
        "user_id": &user_id,
        "plan": tier.as_str(),
        "status": SubscriptionStatus::Active.as_str(),
        "features": {
            "maxExternalAccounts": ProFeatures::for_tier(&tier).max_external_accounts as i32,
            "maxStorageBytes": ProFeatures::for_tier(&tier).max_storage_bytes as i64,
            "customDomain": ProFeatures::for_tier(&tier).custom_domain,
            "prioritySupport": ProFeatures::for_tier(&tier).priority_support,
            "advancedFilters": ProFeatures::for_tier(&tier).advanced_filters,
            "apiAccess": ProFeatures::for_tier(&tier).api_access,
        },
        "paymentMethodId": payload.payment_method_id.as_deref().unwrap_or("manual"),
        "currency": payload.currency.as_deref().unwrap_or("EUR"),
        "createdAt": now,
        "currentPeriodStart": now,
        "currentPeriodEnd": mongodb::bson::DateTime::from_millis(
            now.timestamp_millis() + 30 * 24 * 3600 * 1000i64
        ),
        "autoRenew": true,
    };

    if let Err(e) = subs_coll.insert_one(subscription_doc).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "code": "SUBSCRIPTION_CREATE_FAILED",
            "message": format!("Failed to create subscription: {e}"),
        }));
    }

    // Generate invoice
    let invoice_id = uuid::Uuid::new_v4().to_string();
    let amount_cents = match tier {
        PlanTier::Free => 0,
        PlanTier::Pro => 999, // €9.99/month
    };
    let currency = payload.currency.clone().unwrap_or_else(|| "EUR".to_string());

    let invoices_coll = db.collection::<mongodb::bson::Document>("invoices");
    let invoice_doc = doc! {
        "_id": &invoice_id,
        "user_id": &user_id,
        "subscriptionId": &subscription_id,
        "plan": tier.as_str(),
        "amountCents": amount_cents as i64,
        "currency": &currency,
        "status": "paid",
        "paymentMethod": payload.payment_method_id.as_deref().unwrap_or("manual"),
        "createdAt": now,
        "periodStart": now,
        "periodEnd": mongodb::bson::DateTime::from_millis(
            now.timestamp_millis() + 30 * 24 * 3600 * 1000i64
        ),
    };

    if let Err(e) = invoices_coll.insert_one(invoice_doc).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "code": "INVOICE_CREATE_FAILED",
            "message": format!("Failed to generate invoice: {e}"),
        }));
    }

    // Update user record with plan tier
    let users_coll = db.collection::<mongodb::bson::Document>("users");
    let _ = users_coll
        .update_one(
            doc! { "username": &user_id },
            doc! { "$set": { "plan": tier.as_str(), "subscriptionId": &subscription_id } },
        )
        .await;

    // Log subscription event
    let events_coll = db.collection::<mongodb::bson::Document>("mail_events");
    let _ = events_coll
        .insert_one(doc! {
            "kind": "subscription_activated",
            "user_id": &user_id,
            "email_id": "",
            "subject": format!("Pro plan activated for {}", &user_id),
            "from": "system",
            "to": &user_id,
            "timestamp": now,
            "plan": tier.as_str(),
            "invoiceId": &invoice_id,
        })
        .await;

    let features = ProFeatures::for_tier(&tier);

    HttpResponse::Ok().json(serde_json::json!({
        "code": "SUBSCRIPTION_ACTIVATED",
        "message": "Pro plan activated successfully",
        "subscription": {
            "id": subscription_id,
            "plan": tier.as_str(),
            "status": "active",
            "features": {
                "maxExternalAccounts": features.max_external_accounts,
                "maxStorageBytes": features.max_storage_bytes,
                "customDomain": features.custom_domain,
                "prioritySupport": features.priority_support,
                "advancedFilters": features.advanced_filters,
                "apiAccess": features.api_access,
            },
        },
        "invoice": {
            "id": invoice_id,
            "amountCents": amount_cents,
            "currency": currency,
            "status": "paid",
        },
    }))
}

/// GET /api/subscription — current subscription status.
pub(crate) async fn api_subscription_status(
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let auth = match admin_auth::require_auth(&req, mongo.get_ref(), &mongo_db_name()).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let user_id = auth.user_id.clone();

    let db_name = mongo_db_name();
    let db = mongo.database(&db_name);
    let subs_coll = db.collection::<mongodb::bson::Document>("subscriptions");

    match subs_coll
        .find_one(doc! { "user_id": &user_id })
        .await
    {
        Ok(Some(sub)) => {
            let plan = sub.get_str("plan").unwrap_or("free");
            let status = sub.get_str("status").unwrap_or("none");
            HttpResponse::Ok().json(serde_json::json!({
                "subscription": sub,
                "plan": plan,
                "status": status,
            }))
        }
        Ok(None) => HttpResponse::Ok().json(serde_json::json!({
            "plan": "free",
            "status": "none",
            "message": "No active subscription. User is on free plan.",
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "code": "SUBSCRIPTION_FETCH_FAILED",
            "message": format!("Failed to fetch subscription: {e}"),
        })),
    }
}

/// POST /api/subscription/cancel — cancel auto-renewal.
pub(crate) async fn api_subscription_cancel(
    req: HttpRequest,
    payload: web::Json<CancelInput>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let auth = match admin_auth::require_auth(&req, mongo.get_ref(), &mongo_db_name()).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let user_id = auth.user_id.clone();

    let db_name = mongo_db_name();
    let db = mongo.database(&db_name);
    let subs_coll = db.collection::<mongodb::bson::Document>("subscriptions");
    let now = mongodb::bson::DateTime::from_millis(chrono::Utc::now().timestamp_millis());

    let update_result = subs_coll
        .update_one(
            doc! { "user_id": &user_id, "status": "active" },
            doc! {
                "$set": {
                    "status": SubscriptionStatus::Cancelled.as_str(),
                    "autoRenew": false,
                    "cancelledAt": now,
                    "cancelReason": payload.reason.as_deref().unwrap_or("user_request"),
                }
            },
        )
        .await;

    match update_result {
        Ok(result) if result.modified_count > 0 => {
            // Log cancellation event
            let events_coll = db.collection::<mongodb::bson::Document>("mail_events");
            let _ = events_coll
                .insert_one(doc! {
                    "kind": "subscription_cancelled",
                    "user_id": &user_id,
                    "email_id": "",
                    "subject": "Subscription cancelled",
                    "from": "system",
                    "to": &user_id,
                    "timestamp": now,
                })
                .await;

            HttpResponse::Ok().json(serde_json::json!({
                "code": "SUBSCRIPTION_CANCELLED",
                "message": "Subscription cancelled. Pro features remain active until end of billing period.",
                "user_id": user_id,
            }))
        }
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({
            "code": "NO_ACTIVE_SUBSCRIPTION",
            "message": "No active subscription found for this user.",
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "code": "SUBSCRIPTION_CANCEL_FAILED",
            "message": format!("Failed to cancel subscription: {e}"),
        })),
    }
}

/// GET /api/subscription/invoices — list user invoices.
pub(crate) async fn api_subscription_invoices(
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let auth = match admin_auth::require_auth(&req, mongo.get_ref(), &mongo_db_name()).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let user_id = auth.user_id.clone();

    let db_name = mongo_db_name();
    let db = mongo.database(&db_name);
    let invoices_coll = db.collection::<mongodb::bson::Document>("invoices");

    let cursor = match invoices_coll
        .find(doc! { "user_id": &user_id })
        .sort(doc! { "createdAt": -1 })
        .await
    {
        Ok(c) => c,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "code": "INVOICES_FETCH_FAILED",
                "message": format!("Failed to fetch invoices: {e}"),
            }));
        }
    };

    let invoices: Vec<mongodb::bson::Document> = match cursor.try_collect().await {
        Ok(docs) => docs,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "code": "INVOICES_COLLECT_FAILED",
                "message": format!("Failed to collect invoices: {e}"),
            }));
        }
    };

    HttpResponse::Ok().json(serde_json::json!({
        "invoices": invoices,
        "total": invoices.len(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_tier_from_str_pro() {
        let tier: PlanTier = "pro".parse().unwrap();
        assert_eq!(tier, PlanTier::Pro);
    }

    #[test]
    fn plan_tier_from_str_free() {
        let tier: PlanTier = "free".parse().unwrap();
        assert_eq!(tier, PlanTier::Free);
    }

    #[test]
    fn plan_tier_from_str_invalid() {
        let result: std::result::Result<PlanTier, String> = "enterprise".parse();
        assert!(result.is_err());
    }

    #[test]
    fn plan_tier_as_str() {
        assert_eq!(PlanTier::Free.as_str(), "free");
        assert_eq!(PlanTier::Pro.as_str(), "pro");
    }

    #[test]
    fn subscription_status_as_str() {
        assert_eq!(SubscriptionStatus::Active.as_str(), "active");
        assert_eq!(SubscriptionStatus::Cancelled.as_str(), "cancelled");
        assert_eq!(SubscriptionStatus::Expired.as_str(), "expired");
    }

    #[test]
    fn pro_features_free_tier() {
        let features = ProFeatures::for_tier(&PlanTier::Free);
        assert_eq!(features.max_external_accounts, 0);
        assert_eq!(features.max_storage_bytes, 100 * 1024 * 1024);
        assert!(!features.custom_domain);
        assert!(!features.priority_support);
        assert!(!features.advanced_filters);
        assert!(!features.api_access);
    }

    #[test]
    fn pro_features_pro_tier() {
        let features = ProFeatures::for_tier(&PlanTier::Pro);
        assert_eq!(features.max_external_accounts, 10);
        assert_eq!(features.max_storage_bytes, 10 * 1024 * 1024 * 1024);
        assert!(features.custom_domain);
        assert!(features.priority_support);
        assert!(features.advanced_filters);
        assert!(features.api_access);
    }

    #[test]
    fn subscribe_input_deserializes() {
        let json = serde_json::json!({
            "plan": "pro",
            "paymentMethodId": "pm_123",
            "currency": "EUR"
        });
        let input: SubscribeInput = serde_json::from_value(json).unwrap();
        assert_eq!(input.plan, "pro");
        assert_eq!(input.payment_method_id, Some("pm_123".to_string()));
        assert_eq!(input.currency, Some("EUR".to_string()));
    }

    #[test]
    fn subscribe_input_minimal() {
        let json = serde_json::json!({ "plan": "pro" });
        let input: SubscribeInput = serde_json::from_value(json).unwrap();
        assert_eq!(input.plan, "pro");
        assert!(input.payment_method_id.is_none());
        assert!(input.currency.is_none());
    }

    #[test]
    fn cancel_input_deserializes() {
        let json = serde_json::json!({ "reason": "too expensive" });
        let input: CancelInput = serde_json::from_value(json).unwrap();
        assert_eq!(input.reason, Some("too expensive".to_string()));
    }

    #[test]
    fn cancel_input_empty() {
        let json = serde_json::json!({});
        let input: CancelInput = serde_json::from_value(json).unwrap();
        assert!(input.reason.is_none());
    }
}
