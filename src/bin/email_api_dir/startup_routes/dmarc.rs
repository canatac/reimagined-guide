use actix_web::{post, get, web, HttpResponse, Responder};
use mongodb::Database;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::monitoring::dmarc::{aggregate_stats, parse_dmarc_report, DmarcStats};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(post_dmarc_report).service(get_dmarc_stats);
}

#[derive(Debug, Deserialize)]
pub struct DmarcReportBody {
    pub xml: String,
}

#[post("/api/v1/dmarc/reports")]
async fn post_dmarc_report(
    db: web::Data<Arc<Database>>,
    body: web::Json<DmarcReportBody>,
) -> impl Responder {
    match parse_dmarc_report(&body.xml) {
        Ok(report) => {
            let collection = db.collection::<mongodb::bson::Document>("dmarc_reports");
            let doc = match mongodb::bson::to_bson(&report) {
                Ok(bson) => match bson {
                    mongodb::bson::Bson::Document(d) => d,
                    _ => return HttpResponse::InternalServerError().body("bson conversion failed"),
                },
                Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
            };
            if let Err(e) = collection.insert_one(doc, None).await {
                return HttpResponse::InternalServerError().body(e.to_string());
            }
            HttpResponse::Created().json(serde_json::json!({"status": "stored"}))
        }
        Err(e) => HttpResponse::BadRequest().body(e.to_string()),
    }
}

#[get("/api/v1/dmarc/stats")]
async fn get_dmarc_stats(db: web::Data<Arc<Database>>) -> impl Responder {
    let collection = db.collection::<mongodb::bson::Document>("dmarc_reports");
    let cursor = match collection.find(None, None).await {
        Ok(c) => c,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let docs: Vec<mongodb::bson::Document> = cursor
        .try_collect::<Vec<_>>()
        .await
        .unwrap_or_default();

    let reports: Vec<serde_json::Value> = docs
        .iter()
        .filter_map(|d| mongodb::bson::from_bson::<serde_json::Value>(d.clone().into()).ok())
        .collect();

    let stats: DmarcStats = aggregate_stats(&reports);
    HttpResponse::Ok().json(stats)
}
