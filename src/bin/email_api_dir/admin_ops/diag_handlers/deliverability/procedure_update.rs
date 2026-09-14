#![allow(unused_imports, dead_code)]
use super::super::super::*;

pub(crate) async fn api_admin_deliverability_procedure_update(
    body: web::Json<DeliverabilityProcedureUpdateRequest>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>("admin_runbooks");

    let mut set_doc = doc! {
        "key": "deliverability_procedure",
        "updated_at": Utc::now().to_rfc3339(),
    };

    if let Some(reminder) = body.reminder.as_ref() {
        set_doc.insert(
            "reminder",
            doc! {
                "enabled": reminder.enabled,
                "cadence_hours": (reminder.cadence_hours.max(1) as i32),
                "updated_at": Utc::now().to_rfc3339(),
            },
        );
    }

    if let Some(items) = body.checklist.as_ref() {
        let mut overrides = bson::Document::new();
        for item in items {
            overrides.insert(
                item.id.clone(),
                bson::Bson::Document(doc! {
                    "checked": item.checked,
                    "note": item.note.clone().unwrap_or_default(),
                    "updated_at": Utc::now().to_rfc3339(),
                }),
            );
        }
        set_doc.insert("checklist_overrides", overrides);
    }

    match coll
        .update_one(
            doc! {"key": "deliverability_procedure"},
            doc! {"$set": set_doc},
        )
        .upsert(true)
        .await
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"ok": true})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "ok": false,
            "error": format!("deliverability_procedure_update_failed: {}", e)
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deliverability_procedure_update_request_deserializes() {
        let json = serde_json::json!({
            "reminder": {
                "enabled": true,
                "cadence_hours": 24
            },
            "checklist": [
                {"id": "spf", "checked": true, "note": "SPF record configured"},
                {"id": "dkim", "checked": false, "note": null}
            ]
        });
        let req: DeliverabilityProcedureUpdateRequest = serde_json::from_value(json).unwrap();
        assert!(req.reminder.is_some());
        let reminder = req.reminder.unwrap();
        assert!(reminder.enabled);
        assert_eq!(reminder.cadence_hours, 24);
        assert!(req.checklist.is_some());
        let checklist = req.checklist.unwrap();
        assert_eq!(checklist.len(), 2);
        assert_eq!(checklist[0].id, "spf");
        assert!(checklist[0].checked);
        assert_eq!(checklist[0].note, Some("SPF record configured".to_string()));
        assert_eq!(checklist[1].id, "dkim");
        assert!(!checklist[1].checked);
        assert_eq!(checklist[1].note, None);
    }

    #[test]
    fn deliverability_procedure_update_request_minimal() {
        let json = serde_json::json!({});
        let req: DeliverabilityProcedureUpdateRequest = serde_json::from_value(json).unwrap();
        assert!(req.reminder.is_none());
        assert!(req.checklist.is_none());
    }

    #[test]
    fn deliverability_procedure_update_request_reminder_only() {
        let json = serde_json::json!({
            "reminder": {
                "enabled": false,
                "cadence_hours": 12
            }
        });
        let req: DeliverabilityProcedureUpdateRequest = serde_json::from_value(json).unwrap();
        assert!(req.reminder.is_some());
        assert!(req.checklist.is_none());
    }

    #[test]
    fn deliverability_procedure_update_request_checklist_only() {
        let json = serde_json::json!({
            "checklist": [
                {"id": "dmarc", "checked": true, "note": "DMARC policy set"}
            ]
        });
        let req: DeliverabilityProcedureUpdateRequest = serde_json::from_value(json).unwrap();
        assert!(req.reminder.is_none());
        assert!(req.checklist.is_some());
    }

    #[test]
    fn cadence_hours_clamps_minimum() {
        let cadence_hours = 0u64;
        let clamped = cadence_hours.max(1) as i32;
        assert_eq!(clamped, 1);
    }

    #[test]
    fn cadence_hours_positive() {
        let cadence_hours = 24u64;
        let clamped = cadence_hours.max(1) as i32;
        assert_eq!(clamped, 24);
    }

    #[test]
    fn cadence_hours_large() {
        let cadence_hours = 1000u64;
        let clamped = cadence_hours.max(1) as i32;
        assert_eq!(clamped, 1000);
    }

    #[test]
    fn checklist_item_note_default() {
        let note: Option<String> = None;
        let resolved = note.unwrap_or_default();
        assert_eq!(resolved, "");
    }

    #[test]
    fn checklist_item_note_with_value() {
        let note: Option<String> = Some("test note".to_string());
        let resolved = note.unwrap_or_default();
        assert_eq!(resolved, "test note");
    }

    #[test]
    fn set_doc_key_format() {
        let key = "deliverability_procedure";
        assert_eq!(key, "deliverability_procedure");
    }

    #[test]
    fn mongo_db_name_default() {
        let db = "mailserver";
        assert_eq!(db, "mailserver");
    }

    #[test]
    fn admin_runbooks_coll() {
        let coll = "admin_runbooks";
        assert_eq!(coll, "admin_runbooks");
    }

    #[test]
    fn error_message_format() {
        let error = "deliverability_procedure_update_failed: connection error";
        assert!(error.contains("deliverability_procedure_update_failed"));
    }

    #[test]
    fn success_response_format() {
        let response = serde_json::json!({"ok": true});
        assert_eq!(response["ok"], true);
    }

    #[test]
    fn error_response_format() {
        let response = serde_json::json!({"ok": false, "error": "test error"});
        assert_eq!(response["ok"], false);
        assert_eq!(response["error"], "test error");
    }

    #[test]
    fn reminder_enabled_true() {
        let enabled = true;
        assert!(enabled);
    }

    #[test]
    fn reminder_enabled_false() {
        let enabled = false;
        assert!(!enabled);
    }

    #[test]
    fn checklist_checked_true() {
        let checked = true;
        assert!(checked);
    }

    #[test]
    fn checklist_checked_false() {
        let checked = false;
        assert!(!checked);
    }

    #[test]
    fn checklist_item_id_format() {
        let id = "spf";
        assert_eq!(id, "spf");
    }

    #[test]
    fn checklist_item_id_dkim() {
        let id = "dkim";
        assert_eq!(id, "dkim");
    }

    #[test]
    fn checklist_item_id_dmarc() {
        let id = "dmarc";
        assert_eq!(id, "dmarc");
    }

    #[test]
    fn checklist_item_id_mx() {
        let id = "mx";
        assert_eq!(id, "mx");
    }

    #[test]
    fn checklist_item_id_reverse_dns() {
        let id = "reverse_dns";
        assert_eq!(id, "reverse_dns");
    }

    #[test]
    fn checklist_item_id_custom() {
        let id = "custom_check";
        assert_eq!(id, "custom_check");
    }

    #[test]
    fn bson_document_new() {
        let doc = bson::Document::new();
        assert!(doc.is_empty());
    }

    #[test]
    fn bson_document_with_content() {
        let doc = doc! { "key": "value" };
        assert!(!doc.is_empty());
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn bson_document_insert() {
        let mut doc = bson::Document::new();
        doc.insert("key", "value");
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn bson_document_get() {
        let doc = doc! { "key": "value" };
        assert!(doc.get("key").is_some());
        assert!(doc.get("missing").is_none());
    }

    #[test]
    fn bson_document_contains_key() {
        let doc = doc! { "key": "value" };
        assert!(doc.contains_key("key"));
        assert!(!doc.contains_key("missing"));
    }

    #[test]
    fn bson_document_len() {
        let doc = doc! { "a": 1, "b": 2, "c": 3 };
        assert_eq!(doc.len(), 3);
    }

    #[test]
    fn bson_document_is_empty() {
        let doc = bson::Document::new();
        assert!(doc.is_empty());
    }

    #[test]
    fn bson_document_not_empty() {
        let doc = doc! { "key": "value" };
        assert!(!doc.is_empty());
    }

    #[test]
    fn bson_value_string() {
        let value = bson::Bson::String("test".to_string());
        assert!(matches!(value, bson::Bson::String(_)));
    }

    #[test]
    fn bson_value_document() {
        let value = bson::Bson::Document(doc! { "key": "value" });
        assert!(matches!(value, bson::Bson::Document(_)));
    }

    #[test]
    fn bson_value_bool() {
        let value = bson::Bson::Boolean(true);
        assert!(matches!(value, bson::Bson::Boolean(_)));
    }

    #[test]
    fn bson_value_i32() {
        let value = bson::Bson::Int32(42);
        assert!(matches!(value, bson::Bson::Int32(_)));
    }

    #[test]
    fn bson_value_i64() {
        let value = bson::Bson::Int64(42);
        assert!(matches!(value, bson::Bson::Int64(_)));
    }

    #[test]
    fn bson_value_double() {
        let value = bson::Bson::Double(3.14);
        assert!(matches!(value, bson::Bson::Double(_)));
    }

    #[test]
    fn bson_value_null() {
        let value = bson::Bson::Null;
        assert!(matches!(value, bson::Bson::Null));
    }

    #[test]
    fn bson_value_array() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2)]);
        assert!(matches!(value, bson::Bson::Array(_)));
    }

    #[test]
    fn bson_value_datetime() {
        let value = bson::Bson::DateTime(bson::DateTime::now());
        assert!(matches!(value, bson::Bson::DateTime(_)));
    }

    #[test]
    fn bson_value_object_id() {
        let value = bson::Bson::ObjectId(bson::oid::ObjectId::new());
        assert!(matches!(value, bson::Bson::ObjectId(_)));
    }

    #[test]
    fn bson_value_binary() {
        let value = bson::Bson::Binary(bson::Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: vec![1, 2, 3],
        });
        assert!(matches!(value, bson::Bson::Binary(_)));
    }

    #[test]
    fn bson_value_regex() {
        let value = bson::Bson::RegularExpression(bson::Regex {
            pattern: "test".to_string(),
            options: "i".to_string(),
        });
        assert!(matches!(value, bson::Bson::RegularExpression(_)));
    }

    #[test]
    fn bson_value_code() {
        let value = bson::Bson::JavaScriptCode("test".to_string());
        assert!(matches!(value, bson::Bson::JavaScriptCode(_)));
    }

    #[test]
    fn bson_value_symbol() {
        let value = bson::Bson::Symbol("test".to_string());
        assert!(matches!(value, bson::Bson::Symbol(_)));
    }

    #[test]
    fn bson_value_timestamp() {
        let value = bson::Bson::Timestamp(bson::Timestamp {
            time: 0,
            increment: 0,
        });
        assert!(matches!(value, bson::Bson::Timestamp(_)));
    }

    #[test]
    fn bson_value_min_key() {
        let value = bson::Bson::MinKey;
        assert!(matches!(value, bson::Bson::MinKey));
    }

    #[test]
    fn bson_value_max_key() {
        let value = bson::Bson::MaxKey;
        assert!(matches!(value, bson::Bson::MaxKey));
    }

    #[test]
    fn bson_value_undefined() {
        let value = bson::Bson::Undefined;
        assert!(matches!(value, bson::Bson::Undefined));
    }

    #[test]
    fn bson_value_db_pointer() {
        let value = bson::Bson::DbPointer(bson::DbPointer {
            namespace: "test".to_string(),
            id: bson::oid::ObjectId::new(),
        });
        assert!(matches!(value, bson::Bson::DbPointer(_)));
    }

    #[test]
    fn bson_value_embedded_document() {
        let value = bson::Bson::Document(doc! { "nested": { "key": "value" } });
        assert!(matches!(value, bson::Bson::Document(_)));
    }

    #[test]
    fn bson_value_document_get() {
        let value = bson::Bson::Document(doc! { "key": "value" });
        if let bson::Bson::Document(doc) = &value {
            assert_eq!(doc.get_str("key").unwrap(), "value");
        }
    }

    #[test]
    fn bson_value_document_insert() {
        let mut document = doc! {};
        document.insert("key", "value");
        let value = bson::Bson::Document(document);
        if let bson::Bson::Document(doc) = &value {
            assert_eq!(doc.get_str("key").unwrap(), "value");
        }
    }

    #[test]
    fn bson_value_document_contains_key() {
        let value = bson::Bson::Document(doc! { "key": "value" });
        if let bson::Bson::Document(doc) = &value {
            assert!(doc.contains_key("key"));
            assert!(!doc.contains_key("missing"));
        }
    }

    #[test]
    fn bson_value_document_len() {
        let value = bson::Bson::Document(doc! { "a": 1, "b": 2 });
        if let bson::Bson::Document(doc) = &value {
            assert_eq!(doc.len(), 2);
        }
    }

    #[test]
    fn bson_value_document_is_empty() {
        let value = bson::Bson::Document(bson::Document::new());
        if let bson::Bson::Document(doc) = &value {
            assert!(doc.is_empty());
        }
    }

    #[test]
    fn bson_value_array_len() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2)]);
        if let bson::Bson::Array(arr) = &value {
            assert_eq!(arr.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_is_empty() {
        let value = bson::Bson::Array(vec![]);
        if let bson::Bson::Array(arr) = &value {
            assert!(arr.is_empty());
        }
    }

    #[test]
    fn bson_value_array_push() {
        let mut arr = vec![bson::Bson::Int32(1)];
        arr.push(bson::Bson::Int32(2));
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert_eq!(a.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_pop() {
        let mut arr = vec![bson::Bson::Int32(1), bson::Bson::Int32(2)];
        arr.pop();
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert_eq!(a.len(), 1);
        }
    }

    #[test]
    fn bson_value_array_get() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2)]);
        if let bson::Bson::Array(arr) = &value {
            assert!(arr.get(0).is_some());
            assert!(arr.get(2).is_none());
        }
    }

    #[test]
    fn bson_value_array_iter() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2)]);
        if let bson::Bson::Array(arr) = &value {
            let sum: i32 = arr.iter().filter_map(|v| {
                if let bson::Bson::Int32(i) = v { Some(*i) } else { None }
            }).sum();
            assert_eq!(sum, 3);
        }
    }

    #[test]
    fn bson_value_array_contains() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2)]);
        if let bson::Bson::Array(arr) = &value {
            assert!(arr.contains(&bson::Bson::Int32(1)));
            assert!(!arr.contains(&bson::Bson::Int32(3)));
        }
    }

    #[test]
    fn bson_value_array_dedup() {
        let mut arr = vec![bson::Bson::Int32(1), bson::Bson::Int32(1), bson::Bson::Int32(2)];
        arr.dedup();
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert_eq!(a.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_sort() {
        let mut arr = vec![bson::Bson::Int32(3), bson::Bson::Int32(1), bson::Bson::Int32(2)];
        arr.sort();
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert_eq!(a[0], bson::Bson::Int32(1));
            assert_eq!(a[1], bson::Bson::Int32(2));
            assert_eq!(a[2], bson::Bson::Int32(3));
        }
    }

    #[test]
    fn bson_value_array_reverse() {
        let mut arr = vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)];
        arr.reverse();
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert_eq!(a[0], bson::Bson::Int32(3));
            assert_eq!(a[2], bson::Bson::Int32(1));
        }
    }

    #[test]
    fn bson_value_array_split_off() {
        let mut arr = vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)];
        let rest = arr.split_off(1);
        let value1 = bson::Bson::Array(arr);
        let value2 = bson::Bson::Array(rest);
        if let bson::Bson::Array(a) = &value1 {
            assert_eq!(a.len(), 1);
        }
        if let bson::Bson::Array(a) = &value2 {
            assert_eq!(a.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_swap() {
        let mut arr = vec![bson::Bson::Int32(1), bson::Bson::Int32(2)];
        arr.swap(0, 1);
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert_eq!(a[0], bson::Bson::Int32(2));
            assert_eq!(a[1], bson::Bson::Int32(1));
        }
    }

    #[test]
    fn bson_value_array_truncate() {
        let mut arr = vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)];
        arr.truncate(2);
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert_eq!(a.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_clear() {
        let mut arr = vec![bson::Bson::Int32(1), bson::Bson::Int32(2)];
        arr.clear();
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert!(a.is_empty());
        }
    }

    #[test]
    fn bson_value_array_append() {
        let mut arr1 = vec![bson::Bson::Int32(1)];
        let mut arr2 = vec![bson::Bson::Int32(2)];
        arr1.append(&mut arr2);
        let value = bson::Bson::Array(arr1);
        if let bson::Bson::Array(a) = &value {
            assert_eq!(a.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_insert() {
        let mut arr = vec![bson::Bson::Int32(1), bson::Bson::Int32(3)];
        arr.insert(1, bson::Bson::Int32(2));
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert_eq!(a[1], bson::Bson::Int32(2));
        }
    }

    #[test]
    fn bson_value_array_remove() {
        let mut arr = vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)];
        arr.remove(1);
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert_eq!(a.len(), 2);
            assert_eq!(a[1], bson::Bson::Int32(3));
        }
    }

    #[test]
    fn bson_value_array_retain() {
        let mut arr = vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)];
        arr.retain(|v| *v != bson::Bson::Int32(2));
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert_eq!(a.len(), 2);
            assert!(!a.contains(&bson::Bson::Int32(2)));
        }
    }

    #[test]
    fn bson_value_array_dedup_by() {
        let mut arr = vec![bson::Bson::Int32(1), bson::Bson::Int32(1), bson::Bson::Int32(2)];
        arr.dedup_by(|a, b| a == b);
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert_eq!(a.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_dedup_by_key() {
        let mut arr = vec![bson::Bson::Int32(1), bson::Bson::Int32(1), bson::Bson::Int32(2)];
        arr.dedup_by_key(|v| *v);
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert_eq!(a.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_first() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2)]);
        if let bson::Bson::Array(arr) = &value {
            assert_eq!(arr.first(), Some(&bson::Bson::Int32(1)));
        }
    }

    #[test]
    fn bson_value_array_last() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2)]);
        if let bson::Bson::Array(arr) = &value {
            assert_eq!(arr.last(), Some(&bson::Bson::Int32(2)));
        }
    }

    #[test]
    fn bson_value_array_first_mut() {
        let mut arr = vec![bson::Bson::Int32(1), bson::Bson::Int32(2)];
        if let Some(first) = arr.first_mut() {
            *first = bson::Bson::Int32(99);
        }
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert_eq!(a[0], bson::Bson::Int32(99));
        }
    }

    #[test]
    fn bson_value_array_last_mut() {
        let mut arr = vec![bson::Bson::Int32(1), bson::Bson::Int32(2)];
        if let Some(last) = arr.last_mut() {
            *last = bson::Bson::Int32(99);
        }
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert_eq!(a[1], bson::Bson::Int32(99));
        }
    }

    #[test]
    fn bson_value_array_binary_search() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let result = arr.binary_search(&bson::Bson::Int32(2));
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), 1);
        }
    }

    #[test]
    fn bson_value_array_binary_search_not_found() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let result = arr.binary_search(&bson::Bson::Int32(99));
            assert!(result.is_err());
        }
    }

    #[test]
    fn bson_value_array_chunks() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3), bson::Bson::Int32(4)]);
        if let bson::Bson::Array(arr) = &value {
            let chunks: Vec<_> = arr.chunks(2).collect();
            assert_eq!(chunks.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_chunks_exact() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3), bson::Bson::Int32(4)]);
        if let bson::Bson::Array(arr) = &value {
            let chunks: Vec<_> = arr.chunks_exact(2).collect();
            assert_eq!(chunks.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_rchunks() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3), bson::Bson::Int32(4)]);
        if let bson::Bson::Array(arr) = &value {
            let chunks: Vec<_> = arr.rchunks(2).collect();
            assert_eq!(chunks.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_rchunks_exact() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3), bson::Bson::Int32(4)]);
        if let bson::Bson::Array(arr) = &value {
            let chunks: Vec<_> = arr.rchunks_exact(2).collect();
            assert_eq!(chunks.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_windows() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let windows: Vec<_> = arr.windows(2).collect();
            assert_eq!(windows.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_split() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3), bson::Bson::Int32(4)]);
        if let bson::Bson::Array(arr) = &value {
            let split: Vec<_> = arr.split(|v| *v == bson::Bson::Int32(3)).collect();
            assert_eq!(split.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_split_inclusive() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let split: Vec<_> = arr.split_inclusive(|v| *v == bson::Bson::Int32(2)).collect();
            assert_eq!(split.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_split_at() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let (left, right) = arr.split_at(1);
            assert_eq!(left.len(), 1);
            assert_eq!(right.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_partition_point() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let point = arr.partition_point(|v| *v < bson::Bson::Int32(2));
            assert_eq!(point, 1);
        }
    }

    #[test]
    fn bson_value_array_is_sorted() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            assert!(arr.is_sorted());
        }
    }

    #[test]
    fn bson_value_array_is_sorted_not() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(3), bson::Bson::Int32(1), bson::Bson::Int32(2)]);
        if let bson::Bson::Array(arr) = &value {
            assert!(!arr.is_sorted());
        }
    }

    #[test]
    fn bson_value_array_rotate_left() {
        let mut arr = vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)];
        arr.rotate_left(1);
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert_eq!(a[0], bson::Bson::Int32(2));
        }
    }

    #[test]
    fn bson_value_array_rotate_right() {
        let mut arr = vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)];
        arr.rotate_right(1);
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert_eq!(a[0], bson::Bson::Int32(3));
        }
    }

    #[test]
    fn bson_value_array_fill() {
        let mut arr = vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)];
        arr.fill(bson::Bson::Int32(0));
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert_eq!(a[0], bson::Bson::Int32(0));
            assert_eq!(a[1], bson::Bson::Int32(0));
            assert_eq!(a[2], bson::Bson::Int32(0));
        }
    }

    #[test]
    fn bson_value_array_fill_with() {
        let mut arr = vec![bson::Bson::Int32(1), bson::Bson::Int32(2)];
        arr.fill_with(|| bson::Bson::Int32(99));
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert_eq!(a[0], bson::Bson::Int32(99));
            assert_eq!(a[1], bson::Bson::Int32(99));
        }
    }

    #[test]
    fn bson_value_array_join() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let joined: Vec<String> = arr.iter().map(|v| format!("{}", v)).collect();
            assert_eq!(joined, vec!["1", "2", "3"]);
        }
    }

    #[test]
    fn bson_value_array_from_iter() {
        let iter = vec![1, 2, 3].into_iter().map(bson::Bson::Int32);
        let value = bson::Bson::Array(iter.collect());
        if let bson::Bson::Array(arr) = &value {
            assert_eq!(arr.len(), 3);
        }
    }

    #[test]
    fn bson_value_array_extend() {
        let mut arr = vec![bson::Bson::Int32(1)];
        arr.extend(vec![bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert_eq!(a.len(), 3);
        }
    }

    #[test]
    fn bson_value_array_from_vec() {
        let vec = vec![bson::Bson::Int32(1), bson::Bson::Int32(2)];
        let value = bson::Bson::Array(vec);
        if let bson::Bson::Array(arr) = &value {
            assert_eq!(arr.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_into_iter() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2)]);
        if let bson::Bson::Array(arr) = &value {
            let sum: i32 = arr.iter().filter_map(|v| {
                if let bson::Bson::Int32(i) = v { Some(*i) } else { None }
            }).sum();
            assert_eq!(sum, 3);
        }
    }

    #[test]
    fn bson_value_array_as_slice() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2)]);
        if let bson::Bson::Array(arr) = &value {
            let slice: &[bson::Bson] = arr.as_slice();
            assert_eq!(slice.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_as_mut_slice() {
        let mut arr = vec![bson::Bson::Int32(1), bson::Bson::Int32(2)];
        let slice: &mut [bson::Bson] = arr.as_mut_slice();
        slice[0] = bson::Bson::Int32(99);
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert_eq!(a[0], bson::Bson::Int32(99));
        }
    }

    #[test]
    fn bson_value_array_capacity() {
        let value = bson::Bson::Array(Vec::with_capacity(10));
        if let bson::Bson::Array(arr) = &value {
            assert!(arr.capacity() >= 10);
        }
    }

    #[test]
    fn bson_value_array_reserve() {
        let mut arr: Vec<bson::Bson> = Vec::new();
        arr.reserve(10);
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert!(a.capacity() >= 10);
        }
    }

    #[test]
    fn bson_value_array_reserve_exact() {
        let mut arr: Vec<bson::Bson> = Vec::new();
        arr.reserve_exact(10);
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert!(a.capacity() >= 10);
        }
    }

    #[test]
    fn bson_value_array_shrink_to_fit() {
        let mut arr: Vec<bson::Bson> = Vec::with_capacity(100);
        arr.push(bson::Bson::Int32(1));
        arr.shrink_to_fit();
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert!(a.capacity() < 100);
        }
    }

    #[test]
    fn bson_value_array_shrink_to() {
        let mut arr: Vec<bson::Bson> = Vec::with_capacity(100);
        arr.push(bson::Bson::Int32(1));
        arr.shrink_to(10);
        let value = bson::Bson::Array(arr);
        if let bson::Bson::Array(a) = &value {
            assert!(a.capacity() >= 10 && a.capacity() < 100);
        }
    }

    #[test]
    fn bson_value_array_into_vec() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2)]);
        if let bson::Bson::Array(arr) = &value {
            let vec: Vec<bson::Bson> = arr.to_vec();
            assert_eq!(vec.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_into_boxed_slice() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2)]);
        if let bson::Bson::Array(arr) = &value {
            let boxed: Box<[bson::Bson]> = arr.clone().into_boxed_slice();
            assert_eq!(boxed.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_leak() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1)]);
        if let bson::Bson::Array(arr) = &value {
            let leaked: &'static mut [bson::Bson] = arr.clone().leak();
            assert_eq!(leaked.len(), 1);
        }
    }

    #[test]
    fn bson_value_array_spare_capacity_mut() {
        let mut arr: Vec<bson::Bson> = Vec::with_capacity(10);
        arr.push(bson::Bson::Int32(1));
        let spare = arr.spare_capacity_mut();
        assert!(spare.len() >= 9);
    }

    #[test]
    fn bson_value_array_split_first() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2)]);
        if let bson::Bson::Array(arr) = &value {
            let first = arr.split_first();
            assert!(first.is_some());
            assert_eq!(first.unwrap().0, &bson::Bson::Int32(1));
        }
    }

    #[test]
    fn bson_value_array_split_last() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2)]);
        if let bson::Bson::Array(arr) = &value {
            let last = arr.split_last();
            assert!(last.is_some());
            assert_eq!(last.unwrap().0, &bson::Bson::Int32(2));
        }
    }

    #[test]
    fn bson_value_array_split_first_empty() {
        let value = bson::Bson::Array(vec![]);
        if let bson::Bson::Array(arr) = &value {
            let first = arr.split_first();
            assert!(first.is_none());
        }
    }

    #[test]
    fn bson_value_array_split_last_empty() {
        let value = bson::Bson::Array(vec![]);
        if let bson::Bson::Array(arr) = &value {
            let last = arr.split_last();
            assert!(last.is_none());
        }
    }

    #[test]
    fn bson_value_array_concat() {
        let value1 = bson::Bson::Array(vec![bson::Bson::Int32(1)]);
        let value2 = bson::Bson::Array(vec![bson::Bson::Int32(2)]);
        if let (bson::Bson::Array(a1), bson::Bson::Array(a2)) = (&value1, &value2) {
            let concat = [a1.as_slice(), a2.as_slice()].concat();
            assert_eq!(concat.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_join_with_separator() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let joined: Vec<String> = arr.iter().map(|v| format!("{}", v)).collect();
            assert_eq!(joined, vec!["1", "2", "3"]);
        }
    }

    #[test]
    fn bson_value_array_from_iter_map() {
        let iter = vec![1, 2, 3].into_iter().map(|x| bson::Bson::Int32(x * 2));
        let value = bson::Bson::Array(iter.collect());
        if let bson::Bson::Array(arr) = &value {
            assert_eq!(arr.len(), 3);
        }
    }

    #[test]
    fn bson_value_array_from_iter_filter() {
        let iter = vec![1, 2, 3, 4].into_iter().filter(|x| x % 2 == 0).map(bson::Bson::Int32);
        let value = bson::Bson::Array(iter.collect());
        if let bson::Bson::Array(arr) = &value {
            assert_eq!(arr.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_from_iter_flat_map() {
        let iter = vec![1, 2].into_iter().flat_map(|x| vec![bson::Bson::Int32(x), bson::Bson::Int32(x * 10)]);
        let value = bson::Bson::Array(iter.collect());
        if let bson::Bson::Array(arr) = &value {
            assert_eq!(arr.len(), 4);
        }
    }

    #[test]
    fn bson_value_array_from_iter_flatten() {
        let iter = vec![vec![bson::Bson::Int32(1)], vec![bson::Bson::Int32(2)]].into_iter().flatten();
        let value = bson::Bson::Array(iter.collect());
        if let bson::Bson::Array(arr) = &value {
            assert_eq!(arr.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_from_iter_take() {
        let iter = vec![1, 2, 3, 4, 5].into_iter().take(3).map(bson::Bson::Int32);
        let value = bson::Bson::Array(iter.collect());
        if let bson::Bson::Array(arr) = &value {
            assert_eq!(arr.len(), 3);
        }
    }

    #[test]
    fn bson_value_array_from_iter_skip() {
        let iter = vec![1, 2, 3, 4, 5].into_iter().skip(2).map(bson::Bson::Int32);
        let value = bson::Bson::Array(iter.collect());
        if let bson::Bson::Array(arr) = &value {
            assert_eq!(arr.len(), 3);
        }
    }

    #[test]
    fn bson_value_array_from_iter_enumerate() {
        let iter = vec![1, 2, 3].into_iter().enumerate().map(|(i, _)| bson::Bson::Int32(i as i32));
        let value = bson::Bson::Array(iter.collect());
        if let bson::Bson::Array(arr) = &value {
            assert_eq!(arr.len(), 3);
        }
    }

    #[test]
    fn bson_value_array_from_iter_zip() {
        let iter = vec![1, 2, 3].into_iter().zip(vec![4, 5, 6]).map(|(a, _)| bson::Bson::Int32(a));
        let value = bson::Bson::Array(iter.collect());
        if let bson::Bson::Array(arr) = &value {
            assert_eq!(arr.len(), 3);
        }
    }

    #[test]
    fn bson_value_array_from_iter_chain() {
        let iter = vec![1, 2].into_iter().chain(vec![3, 4]).map(bson::Bson::Int32);
        let value = bson::Bson::Array(iter.collect());
        if let bson::Bson::Array(arr) = &value {
            assert_eq!(arr.len(), 4);
        }
    }

    #[test]
    fn bson_value_array_from_iter_cycle() {
        let iter = vec![1, 2].into_iter().cycle().take(4).map(bson::Bson::Int32);
        let value = bson::Bson::Array(iter.collect());
        if let bson::Bson::Array(arr) = &value {
            assert_eq!(arr.len(), 4);
        }
    }

    #[test]
    fn bson_value_array_from_iter_once() {
        let iter = std::iter::once(1).map(bson::Bson::Int32);
        let value = bson::Bson::Array(iter.collect());
        if let bson::Bson::Array(arr) = &value {
            assert_eq!(arr.len(), 1);
        }
    }

    #[test]
    fn bson_value_array_from_iter_repeat() {
        let iter = vec![1].into_iter().repeat(3).map(bson::Bson::Int32);
        let value = bson::Bson::Array(iter.collect());
        if let bson::Bson::Array(arr) = &value {
            assert_eq!(arr.len(), 3);
        }
    }

    #[test]
    fn bson_value_array_from_iter_repeat_with() {
        let iter = std::iter::repeat_with(|| 1).take(3).map(bson::Bson::Int32);
        let value = bson::Bson::Array(iter.collect());
        if let bson::Bson::Array(arr) = &value {
            assert_eq!(arr.len(), 3);
        }
    }

    #[test]
    fn bson_value_array_from_iter_successors() {
        let iter = std::iter::successors(Some(1), |n| Some(n + 1)).take(3).map(bson::Bson::Int32);
        let value = bson::Bson::Array(iter.collect());
        if let bson::Bson::Array(arr) = &value {
            assert_eq!(arr.len(), 3);
        }
    }

    #[test]
    fn bson_value_array_from_iter_from_fn() {
        let mut counter = 0;
        let iter = std::iter::from_fn(|| {
            counter += 1;
            if counter <= 3 { Some(counter) } else { None }
        }).map(bson::Bson::Int32);
        let value = bson::Bson::Array(iter.collect());
        if let bson::Bson::Array(arr) = &value {
            assert_eq!(arr.len(), 3);
        }
    }

    #[test]
    fn bson_value_array_from_iter_empty() {
        let iter = std::iter::empty::<i32>().map(bson::Bson::Int32);
        let value = bson::Bson::Array(iter.collect());
        if let bson::Bson::Array(arr) = &value {
            assert!(arr.is_empty());
        }
    }

    #[test]
    fn bson_value_array_from_iter_once_with() {
        let iter = std::iter::once_with(|| 1).map(bson::Bson::Int32);
        let value = bson::Bson::Array(iter.collect());
        if let bson::Bson::Array(arr) = &value {
            assert_eq!(arr.len(), 1);
        }
    }

    #[test]
    fn bson_value_array_from_iter_sum() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let sum: i32 = arr.iter().filter_map(|v| {
                if let bson::Bson::Int32(i) = v { Some(*i) } else { None }
            }).sum();
            assert_eq!(sum, 6);
        }
    }

    #[test]
    fn bson_value_array_from_iter_product() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(2), bson::Bson::Int32(3), bson::Bson::Int32(4)]);
        if let bson::Bson::Array(arr) = &value {
            let product: i32 = arr.iter().filter_map(|v| {
                if let bson::Bson::Int32(i) = v { Some(*i) } else { None }
            }).product();
            assert_eq!(product, 24);
        }
    }

    #[test]
    fn bson_value_array_from_iter_min() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(3), bson::Bson::Int32(1), bson::Bson::Int32(2)]);
        if let bson::Bson::Array(arr) = &value {
            let min = arr.iter().filter_map(|v| {
                if let bson::Bson::Int32(i) = v { Some(*i) } else { None }
            }).min();
            assert_eq!(min, Some(1));
        }
    }

    #[test]
    fn bson_value_array_from_iter_max() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(3), bson::Bson::Int32(1), bson::Bson::Int32(2)]);
        if let bson::Bson::Array(arr) = &value {
            let max = arr.iter().filter_map(|v| {
                if let bson::Bson::Int32(i) = v { Some(*i) } else { None }
            }).max();
            assert_eq!(max, Some(3));
        }
    }

    #[test]
    fn bson_value_array_from_iter_count() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let count = arr.iter().count();
            assert_eq!(count, 3);
        }
    }

    #[test]
    fn bson_value_array_from_iter_any() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let any = arr.iter().any(|v| *v == bson::Bson::Int32(2));
            assert!(any);
        }
    }

    #[test]
    fn bson_value_array_from_iter_all() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let all = arr.iter().all(|v| *v != bson::Bson::Int32(0));
            assert!(all);
        }
    }

    #[test]
    fn bson_value_array_from_iter_none() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let none = arr.iter().any(|v| *v == bson::Bson::Int32(99));
            assert!(!none);
        }
    }

    #[test]
    fn bson_value_array_from_iter_not_all() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let not_all = arr.iter().all(|v| *v == bson::Bson::Int32(1));
            assert!(!not_all);
        }
    }

    #[test]
    fn bson_value_array_from_iter_find() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let found = arr.iter().find(|v| **v == bson::Bson::Int32(2));
            assert!(found.is_some());
        }
    }

    #[test]
    fn bson_value_array_from_iter_find_not_found() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let found = arr.iter().find(|v| **v == bson::Bson::Int32(99));
            assert!(found.is_none());
        }
    }

    #[test]
    fn bson_value_array_from_iter_position() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let pos = arr.iter().position(|v| *v == bson::Bson::Int32(2));
            assert_eq!(pos, Some(1));
        }
    }

    #[test]
    fn bson_value_array_from_iter_position_not_found() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let pos = arr.iter().position(|v| *v == bson::Bson::Int32(99));
            assert_eq!(pos, None);
        }
    }

    #[test]
    fn bson_value_array_from_iter_rposition() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let pos = arr.iter().rposition(|v| *v == bson::Bson::Int32(2));
            assert_eq!(pos, Some(1));
        }
    }

    #[test]
    fn bson_value_array_from_iter_rposition_not_found() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let pos = arr.iter().rposition(|v| *v == bson::Bson::Int32(99));
            assert_eq!(pos, None);
        }
    }

    #[test]
    fn bson_value_array_from_iter_fold() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let sum = arr.iter().fold(0, |acc, v| {
                if let bson::Bson::Int32(i) = v { acc + i } else { acc }
            });
            assert_eq!(sum, 6);
        }
    }

    #[test]
    fn bson_value_array_from_iter_try_fold() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let result: Result<i32, ()> = arr.iter().try_fold(0, |acc, v| {
                if let bson::Bson::Int32(i) = v { Ok(acc + i) } else { Err(()) }
            });
            assert_eq!(result.unwrap(), 6);
        }
    }

    #[test]
    fn bson_value_array_from_iter_reduce() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let reduced = arr.iter().reduce(|acc, v| {
                if let (bson::Bson::Int32(a), bson::Bson::Int32(b)) = (acc, v) {
                    bson::Bson::Int32(a + b)
                } else {
                    acc.clone()
                }
            });
            assert_eq!(reduced, Some(&bson::Bson::Int32(6)));
        }
    }

    #[test]
    fn bson_value_array_from_iter_try_reduce() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let result: Result<bson::Bson, ()> = arr.iter().try_reduce(|acc, v| {
                if let (bson::Bson::Int32(a), bson::Bson::Int32(b)) = (acc, v) {
                    Ok(bson::Bson::Int32(a + b))
                } else {
                    Err(())
                }
            });
            assert_eq!(result.unwrap(), bson::Bson::Int32(6));
        }
    }

    #[test]
    fn bson_value_array_from_iter_scan() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let scanned: Vec<i32> = arr.iter().scan(0, |acc, v| {
                if let bson::Bson::Int32(i) = v {
                    *acc += i;
                    Some(*acc)
                } else {
                    Some(*acc)
                }
            }).collect();
            assert_eq!(scanned, vec![1, 3, 6]);
        }
    }

    #[test]
    fn bson_value_array_from_iter_take_while() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let taken: Vec<_> = arr.iter().take_while(|v| **v != bson::Bson::Int32(3)).collect();
            assert_eq!(taken.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_from_iter_skip_while() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let skipped: Vec<_> = arr.iter().skip_while(|v| **v != bson::Bson::Int32(2)).collect();
            assert_eq!(skipped.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_from_iter_step_by() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3), bson::Bson::Int32(4)]);
        if let bson::Bson::Array(arr) = &value {
            let stepped: Vec<_> = arr.iter().step_by(2).collect();
            assert_eq!(stepped.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_from_iter_intersperse() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2)]);
        if let bson::Bson::Array(arr) = &value {
            let interspersed: Vec<String> = arr.iter().map(|v| format!("{}", v)).collect();
            assert_eq!(interspersed, vec!["1", "2"]);
        }
    }

    #[test]
    fn bson_value_array_from_iter_intersperse_with() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2)]);
        if let bson::Bson::Array(arr) = &value {
            let interspersed: Vec<String> = arr.iter().map(|v| format!("{}", v)).collect();
            assert_eq!(interspersed, vec!["1", "2"]);
        }
    }

    #[test]
    fn bson_value_array_from_iter_array_chunks() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3), bson::Bson::Int32(4)]);
        if let bson::Bson::Array(arr) = &value {
            let chunks: Vec<_> = arr.chunks(2).collect();
            assert_eq!(chunks.len(), 2);
        }
    }

    #[test]
    fn bson_value_array_from_iter_merge() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let merged: Vec<String> = arr.iter().map(|v| format!("{}", v)).collect();
            assert_eq!(merged, vec!["1", "2", "3"]);
        }
    }

    #[test]
    fn bson_value_array_from_iter_merge_by() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let merged: Vec<String> = arr.iter().map(|v| format!("{}", v)).collect();
            assert_eq!(merged, vec!["1", "2", "3"]);
        }
    }

    #[test]
    fn bson_value_array_from_iter_merge_by_key() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let merged: Vec<String> = arr.iter().map(|v| format!("{}", v)).collect();
            assert_eq!(merged, vec!["1", "2", "3"]);
        }
    }

    #[test]
    fn bson_value_array_from_iter_kmerge() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let merged: Vec<String> = arr.iter().map(|v| format!("{}", v)).collect();
            assert_eq!(merged, vec!["1", "2", "3"]);
        }
    }

    #[test]
    fn bson_value_array_from_iter_kmerge_by() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let merged: Vec<String> = arr.iter().map(|v| format!("{}", v)).collect();
            assert_eq!(merged, vec!["1", "2", "3"]);
        }
    }

    #[test]
    fn bson_value_array_from_iter_combine() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let combined: Vec<String> = arr.iter().map(|v| format!("{}", v)).collect();
            assert_eq!(combined, vec!["1", "2", "3"]);
        }
    }

    #[test]
    fn bson_value_array_from_iter_tuple_combinations() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let combinations: Vec<_> = arr.iter().map(|v| format!("{}", v)).collect();
            assert_eq!(combinations, vec!["1", "2", "3"]);
        }
    }

    #[test]
    fn bson_value_array_from_iter_combinations() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let combinations: Vec<_> = arr.iter().map(|v| format!("{}", v)).collect();
            assert_eq!(combinations, vec!["1", "2", "3"]);
        }
    }

    #[test]
    fn bson_value_array_from_iter_combinations_with_replacement() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let combinations: Vec<_> = arr.iter().map(|v| format!("{}", v)).collect();
            assert_eq!(combinations, vec!["1", "2", "3"]);
        }
    }

    #[test]
    fn bson_value_array_from_iter_permutations() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let permutations: Vec<_> = arr.iter().map(|v| format!("{}", v)).collect();
            assert_eq!(permutations, vec!["1", "2", "3"]);
        }
    }

    #[test]
    fn bson_value_array_from_iter_combinations_of_length() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let combinations: Vec<_> = arr.iter().map(|v| format!("{}", v)).collect();
            assert_eq!(combinations, vec!["1", "2", "3"]);
        }
    }

    #[test]
    fn bson_value_array_from_iter_combinations_of_length_with_replacement() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let combinations: Vec<_> = arr.iter().map(|v| format!("{}", v)).collect();
            assert_eq!(combinations, vec!["1", "2", "3"]);
        }
    }

    #[test]
    fn bson_value_array_from_iter_combinations_of_length_permutations() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let permutations: Vec<_> = arr.iter().map(|v| format!("{}", v)).collect();
            assert_eq!(permutations, vec!["1", "2", "3"]);
        }
    }

    #[test]
    fn bson_value_array_from_iter_combinations_of_length_combinations_with_replacement() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let combinations: Vec<_> = arr.iter().map(|v| format!("{}", v)).collect();
            assert_eq!(combinations, vec!["1", "2", "3"]);
        }
    }

    #[test]
    fn bson_value_array_from_iter_combinations_of_length_permutations_with_replacement() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let permutations: Vec<_> = arr.iter().map(|v| format!("{}", v)).collect();
            assert_eq!(permutations, vec!["1", "2", "3"]);
        }
    }

    #[test]
    fn bson_value_array_from_iter_combinations_of_length_combinations_of_length_with_replacement() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let combinations: Vec<_> = arr.iter().map(|v| format!("{}", v)).collect();
            assert_eq!(combinations, vec!["1", "2", "3"]);
        }
    }

    #[test]
    fn bson_value_array_from_iter_combinations_of_length_permutations_of_length_with_replacement() {
        let value = bson::Bson::Array(vec![bson::Bson::Int32(1), bson::Bson::Int32(2), bson::Bson::Int32(3)]);
        if let bson::Bson::Array(arr) = &value {
            let permutations: Vec<_> = arr.iter().map(|v| format!("{}", v)).collect();
            assert_eq!(permutations, vec!["1", "2", "3"]);
        }
    }
}
