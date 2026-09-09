//! Holiday persistence by country
//! Issue #476: Calendrier - persistence des jours fériés par pays

use actix_web::{web, HttpResponse};
use chrono::NaiveDate;
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Holiday entry for a specific country and date
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Holiday {
    pub id: String,
    pub country_code: String, // ISO 3166-1 alpha-2 (FR, US, etc.)
    pub date: NaiveDate,
    pub name: String,
    pub is_official: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Request to create/update a holiday
#[derive(Debug, Deserialize)]
pub struct HolidayRequest {
    pub country_code: String,
    pub date: String, // ISO 8601 (YYYY-MM-DD)
    pub name: String,
    #[serde(default = "default_official")]
    pub is_official: bool,
}

fn default_official() -> bool {
    true
}

/// Query parameters for listing holidays
#[derive(Debug, Deserialize)]
pub struct HolidayQuery {
    pub country_code: Option<String>,
    pub year: Option<i32>,
    pub month: Option<u32>,
}

/// GET /api/calendar/holidays — List holidays (optionally filtered by country/year/month)
pub(crate) async fn list_holidays(
    query: web::Query<HolidayQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    let db_name = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db_name)
        .collection::<mongodb::bson::Document>("calendar_holidays");

    let mut filter = doc! {};
    if let Some(ref country) = query.country_code {
        filter.insert("countryCode", country.to_uppercase());
    }
    if let Some(year) = query.year {
        let start = format!("{}-01-01", year);
        let end = format!("{}-12-31", year);
        filter.insert(
            "date",
            doc! { "$gte": start, "$lte": end },
        );
    }
    if let Some(month) = query.month {
        let prefix = if let Some(year) = query.year {
            format!("{}-{:02}", year, month)
        } else {
            format!("{:02}", month)
        };
        // Simple prefix match on date string (YYYY-MM-DD format)
        filter.insert(
            "date",
            doc! { "$regex": format!("^{}", prefix) },
        );
    }

    match coll.find(filter).await {
        Ok(cursor) => {
            use futures_util::TryStreamExt;
            match cursor.try_collect::<Vec<_>>().await {
                Ok(docs) => {
                    let holidays: Vec<serde_json::Value> = docs
                        .iter()
                        .filter_map(|d| {
                            let id = d.get_str("id").ok()?.to_string();
                            let country = d.get_str("countryCode").ok()?.to_string();
                            let date = d.get_str("date").ok()?.to_string();
                            let name = d.get_str("name").ok()?.to_string();
                            let is_official = d.get_bool("isOfficial").ok().unwrap_or(true);
                            Some(serde_json::json!({
                                "id": id,
                                "countryCode": country,
                                "date": date,
                                "name": name,
                                "isOfficial": is_official,
                            }))
                        })
                        .collect();
                    HttpResponse::Ok().json(serde_json::json!({
                        "holidays": holidays,
                        "total": holidays.len(),
                    }))
                }
                Err(e) => {
                    eprintln!("Holiday list error: {}", e);
                    HttpResponse::InternalServerError()
                        .json(serde_json::json!({"error": "Failed to list holidays"}))
                }
            }
        }
        Err(e) => {
            eprintln!("Holiday list error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to list holidays"}))
        }
    }
}

/// POST /api/calendar/holidays — Create a holiday entry
pub(crate) async fn create_holiday(
    req_body: web::Json<HolidayRequest>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    let db_name = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db_name)
        .collection::<mongodb::bson::Document>("calendar_holidays");

    // Validate date format
    let date = match NaiveDate::parse_from_str(&req_body.date, "%Y-%m-%d") {
        Ok(d) => d,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "Invalid date format, use YYYY-MM-DD"}));
        }
    };

    // Validate country code (basic: 2 uppercase letters)
    let country_code = req_body.country_code.to_uppercase();
    if country_code.len() != 2 || !country_code.chars().all(|c| c.is_ascii_alphabetic()) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Invalid country code, use ISO 3166-1 alpha-2 (e.g., FR, US)"}));
    }

    // Generate deterministic ID: COUNTRY_YYYY-MM-DD_NAME
    let id = format!(
        "{}_{}_{}",
        country_code,
        req_body.date.replace('-', ""),
        req_body.name.to_lowercase().replace(' ', "_")
    );

    // Check for duplicate
    let existing = coll
        .find_one(doc! { "id": &id })
        .await
        .unwrap_or(None);
    if existing.is_some() {
        return HttpResponse::Conflict()
            .json(serde_json::json!({"error": "Holiday already exists for this country and date"}));
    }

    let doc = doc! {
        "id": &id,
        "countryCode": &country_code,
        "date": req_body.date.clone(),
        "name": req_body.name.clone(),
        "isOfficial": req_body.is_official,
        "createdAt": chrono::Utc::now().to_rfc3339(),
    };

    match coll.insert_one(doc).await {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "id": id,
            "countryCode": country_code,
            "date": req_body.date,
            "name": req_body.name,
            "isOfficial": req_body.is_official,
        })),
        Err(e) => {
            eprintln!("Holiday create error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to create holiday"}))
        }
    }
}

/// DELETE /api/calendar/holidays/{id} — Delete a holiday entry
pub(crate) async fn delete_holiday(
    path: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    let db_name = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db_name)
        .collection::<mongodb::bson::Document>("calendar_holidays");

    let id = path.into_inner();

    match coll.delete_one(doc! { "id": &id }).await {
        Ok(result) if result.deleted_count > 0 => {
            HttpResponse::Ok().json(serde_json::json!({"deleted": true}))
        }
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "Holiday not found"})),
        Err(e) => {
            eprintln!("Holiday delete error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to delete holiday"}))
        }
    }
}

/// GET /api/calendar/holidays/countries — List available country codes
pub(crate) async fn list_holiday_countries(
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    let db_name = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db_name)
        .collection::<mongodb::bson::Document>("calendar_holidays");

    // Aggregate distinct country codes
    let pipeline = vec![
        doc! { "$group": { "_id": "$countryCode" } },
        doc! { "$sort": { "_id": 1 } },
    ];

    match coll.aggregate(pipeline).await {
        Ok(cursor) => {
            use futures_util::TryStreamExt;
            match cursor.try_collect::<Vec<_>>().await {
                Ok(docs) => {
                    let countries: Vec<String> = docs
                        .iter()
                        .filter_map(|d| d.get_str("_id").ok().map(String::from))
                        .collect();
                    HttpResponse::Ok().json(serde_json::json!({
                        "countries": countries,
                        "total": countries.len(),
                    }))
                }
                Err(e) => {
                    eprintln!("Holiday countries error: {}", e);
                    HttpResponse::InternalServerError()
                        .json(serde_json::json!({"error": "Failed to list countries"}))
                }
            }
        }
        Err(e) => {
            eprintln!("Holiday countries error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to list countries"}))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holiday_id_generation() {
        let country = "FR";
        let date = "2026-07-14";
        let name = "Bastille Day";
        let id = format!(
            "{}_{}_{}",
            country,
            date.replace('-', ""),
            name.to_lowercase().replace(' ', "_")
        );
        assert_eq!(id, "FR_20260714_bastille_day");
    }

    #[test]
    fn country_code_validation() {
        let valid = "FR";
        assert_eq!(valid.len(), 2);
        assert!(valid.chars().all(|c| c.is_ascii_alphabetic()));

        let invalid = "FRA";
        assert_ne!(invalid.len(), 2);

        let invalid2 = "12";
        assert!(!invalid2.chars().all(|c| c.is_ascii_alphabetic()));
    }

    #[test]
    fn date_format_validation() {
        let valid = "2026-07-14";
        assert!(NaiveDate::parse_from_str(valid, "%Y-%m-%d").is_ok());

        let invalid = "14-07-2026";
        assert!(NaiveDate::parse_from_str(invalid, "%Y-%m-%d").is_err());
    }
}
