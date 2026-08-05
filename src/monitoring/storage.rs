use futures_util::TryStreamExt;
use mongodb::bson::{self, doc};
use mongodb::{Client, IndexModel};
use std::sync::Arc;
use tokio::sync::broadcast;

use super::SmtpEvent;

const COLLECTION: &str = "smtp_events";

pub fn db_name() -> String {
    std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string())
}

pub fn events_coll(client: &Client) -> mongodb::Collection<bson::Document> {
    client.database(&db_name()).collection(COLLECTION)
}

pub async fn ensure_indexes(client: &Client) {
    let coll = events_coll(client);
    let indexes = vec![
        IndexModel::builder().keys(doc! { "message_id": 1 }).build(),
        IndexModel::builder().keys(doc! { "ts": -1 }).build(),
        IndexModel::builder().keys(doc! { "status": 1, "ts": -1 }).build(),
        IndexModel::builder().keys(doc! { "country": 1, "ts": -1 }).build(),
        IndexModel::builder().keys(doc! { "company": 1, "ts": -1 }).build(),
        IndexModel::builder().keys(doc! { "smtp_code": 1, "ts": -1 }).build(),
        IndexModel::builder().keys(doc! { "correlation_id": 1 }).build(),
        IndexModel::builder().keys(doc! { "risk_score": -1, "ts": -1 }).build(),
    ];
    for idx in indexes {
        if let Err(e) = coll.create_index(idx).await {
            eprintln!("monitoring: index creation error: {}", e);
        }
    }
}

pub async fn insert_event(client: &Client, event: &SmtpEvent) {
    let coll = events_coll(client);
    match bson::to_document(event) {
        Ok(mut doc) => {
            // Also store a BSON DateTime for efficient range queries
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&event.ts) {
                doc.insert(
                    "ts_dt",
                    bson::DateTime::from_millis(dt.timestamp_millis()),
                );
            }
            if let Err(e) = coll.insert_one(doc).await {
                eprintln!("monitoring: insert_event error: {}", e);
            }
        }
        Err(e) => eprintln!("monitoring: bson serialize error: {}", e),
    }
}

/// Spawns a background task that drains the broadcast bus into MongoDB.
pub fn start_persistence_task(client: Arc<Client>) {
    if let Some(tx) = super::get_bus() {
        let mut rx = tx.subscribe();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(event) => insert_event(&client, &event).await,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("monitoring: persistence lagged {} events", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Query helpers used by monitoring REST handlers
// ---------------------------------------------------------------------------

pub async fn query_events(
    client: &Client,
    filter: bson::Document,
    page: u32,
    page_size: u32,
) -> Vec<SmtpEvent> {
    let coll = events_coll(client);
    let skip = ((page.saturating_sub(1)) * page_size) as u64;
    let limit = page_size.clamp(1, 200) as i64;

    match coll
        .find(filter)
        .sort(doc! { "ts": -1 })
        .skip(skip)
        .limit(limit)
        .await
    {
        Ok(cursor) => cursor
            .try_collect::<Vec<_>>()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|d| bson::from_document::<SmtpEvent>(d).ok())
            .collect(),
        Err(_) => vec![],
    }
}

pub async fn count_events(client: &Client, filter: bson::Document) -> u64 {
    events_coll(client)
        .count_documents(filter)
        .await
        .unwrap_or(0)
}

pub async fn aggregate(
    client: &Client,
    pipeline: Vec<bson::Document>,
) -> Vec<bson::Document> {
    match events_coll(client).aggregate(pipeline).await {
        Ok(cursor) => cursor.try_collect().await.unwrap_or_default(),
        Err(_) => vec![],
    }
}

/// Compute P95 of total_ms from the last `sample_size` events matching filter.
pub async fn p95_total_ms(client: &Client, filter: bson::Document, sample_size: i64) -> Option<u64> {
    let coll = events_coll(client);
    let docs = match coll
        .find(filter)
        .projection(doc! { "total_ms": 1, "_id": 0 })
        .sort(doc! { "ts": -1 })
        .limit(sample_size)
        .await
    {
        Ok(c) => c.try_collect::<Vec<_>>().await.unwrap_or_default(),
        Err(_) => return None,
    };

    let mut ms_values: Vec<u64> = docs
        .iter()
        .filter_map(|d| d.get_i64("total_ms").ok().map(|v| v as u64))
        .collect();

    if ms_values.is_empty() {
        return None;
    }
    ms_values.sort_unstable();
    let idx = ((ms_values.len() as f64) * 0.95) as usize;
    Some(ms_values[idx.min(ms_values.len() - 1)])
}
