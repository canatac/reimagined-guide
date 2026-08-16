#![allow(unused_imports, dead_code)]
use super::*;  // inherit all imports from mod.rs
use super::cr_patch::*;

pub(crate) async fn api_admin_change_requests_list(mongo: web::Data<Arc<mongodb::Client>>) -> impl Responder {
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<ChangeRequestItem>(ADMIN_CHANGE_REQUESTS_COLL);

    match coll
        .find(doc! {})
        .sort(doc! { "updatedAt": -1 })
        .limit(500)
        .await
    {
        Ok(cursor) => {
            let items = cursor
                .try_collect::<Vec<ChangeRequestItem>>()
                .await
                .unwrap_or_default();
            HttpResponse::Ok().json(serde_json::json!({
                "generatedAt": now_iso(),
                "counts": status_counts(&items),
                "items": items,
            }))
        }
        Err(e) => {
            eprintln!("api_admin_change_requests_list error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to load change requests" }))
        }
    }
}

pub(crate) async fn api_admin_change_request_get(
    path: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let id = path.into_inner();
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<ChangeRequestItem>(ADMIN_CHANGE_REQUESTS_COLL);

    match coll.find_one(doc! { "id": &id }).await {
        Ok(Some(item)) => HttpResponse::Ok().json(serde_json::json!({ "item": item })),
        Ok(None) => HttpResponse::NotFound()
            .json(serde_json::json!({ "message": "Change request not found" })),
        Err(e) => {
            eprintln!("api_admin_change_request_get error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to load change request" }))
        }
    }
}

pub(crate) async fn api_admin_change_request_create(
    body: web::Json<CreateChangeRequestInputApi>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let scope = body.scope.trim().to_ascii_lowercase();
    let urgency = body.urgency.trim().to_ascii_lowercase();
    let impact = body.impact.trim().to_ascii_lowercase();
    let linked_repo = body.linked_repo.trim().to_ascii_lowercase();

    if !["ux", "backend", "fullstack", "security"].contains(&scope.as_str()) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "scope must be ux|backend|fullstack|security" }));
    }
    if !["low", "medium", "high"].contains(&urgency.as_str()) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "urgency must be low|medium|high" }));
    }
    if !["small", "medium", "high"].contains(&impact.as_str()) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "impact must be small|medium|high" }));
    }
    if !["misfits-web", "reimagined-guide", "cross-repo"].contains(&linked_repo.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "message": "linkedRepo must be misfits-web|reimagined-guide|cross-repo" }));
    }

    let now = now_iso();
    let submitter = body.requested_by.trim().to_string();
    let item = ChangeRequestItem {
        id: format!("cr_{}", Uuid::new_v4().simple()),
        title: body.title.trim().to_string(),
        problem: body.problem.trim().to_string(),
        desired_outcome: body.desired_outcome.trim().to_string(),
        scope: scope.clone(),
        priority: compute_priority(&urgency, &impact),
        status: "submitted".to_string(),
        requested_by: submitter.clone(),
        linked_repo,
        created_at: now.clone(),
        updated_at: now.clone(),
        taken_in_charge_at: None,
        taken_in_charge_by: None,
        target_release_window: if urgency == "high" {
            "next-24h".to_string()
        } else if urgency == "medium" {
            "next-72h".to_string()
        } else {
            "next-sprint".to_string()
        },
        acceptance_criteria: build_acceptance_criteria(&scope),
        workflow: build_initial_stages(),
        workflow_events: vec![WorkflowEvent {
            at: now,
            actor: submitter,
            action: "submitted".to_string(),
            from_status: "submitted".to_string(),
            to_status: "submitted".to_string(),
            note: Some("Change request créée".to_string()),
        }],
        execution_state: "idle".to_string(),
        execution_run_id: None,
        execution_started_at: None,
        execution_last_heartbeat_at: None,
        execution_finished_at: None,
        execution_last_error: None,
        changelog_entry: None,
    };

    let coll = mongo
        .database(&mongo_db_name())
        .collection::<ChangeRequestItem>(ADMIN_CHANGE_REQUESTS_COLL);

    match coll.insert_one(&item).await {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({ "item": item })),
        Err(e) => {
            eprintln!("api_admin_change_request_create error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to create change request" }))
        }
    }
}


pub(crate) async fn api_admin_change_request_patch(
    path: web::Path<String>,
    body: web::Json<PatchChangeRequestInputApi>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let id = path.into_inner();
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<ChangeRequestItem>(ADMIN_CHANGE_REQUESTS_COLL);

    let mut item = match coll.find_one(doc! { "id": &id }).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({ "message": "Change request not found" }))
        }
        Err(e) => {
            eprintln!("api_admin_change_request_patch read error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to load change request" }));
        }
    };

    if let Some(action) = &body.action {
        let action = action.trim().to_ascii_lowercase();
        let actor = body
            .actor
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("hermes")
            .to_string();
        let previous_status = item.status.clone();
        let mut transition_note = body.note.clone();

        if action == "reject" {
            apply_action_reject(&mut item);
        } else if action == "advance" {
            apply_action_advance(&mut item, &body, &mut transition_note);
        } else if [
            "execution_queue",
            "execution_start",
            "execution_heartbeat",
            "execution_fail",
            "execution_success",
            "execution_reset",
        ]
        .contains(&action.as_str())
        {
            apply_execution_action(&mut item, &action, &body, &transition_note);
        } else {
            return HttpResponse::BadRequest().json(serde_json::json!({ "message": "action must be advance|reject|execution_queue|execution_start|execution_heartbeat|execution_fail|execution_success|execution_reset" }));
        }

        if item.taken_in_charge_at.is_none()
            && previous_status == "submitted"
            && item.status != "submitted"
        {
            let intake_at = now_iso();
            item.taken_in_charge_at = Some(intake_at.clone());
            item.taken_in_charge_by = Some(actor.clone());
            if transition_note.is_none() {
                transition_note = Some("Prise en charge initiale".to_string());
            }
        }

        item.workflow_events.push(WorkflowEvent {
            at: now_iso(),
            actor,
            action,
            from_status: previous_status,
            to_status: item.status.clone(),
            note: transition_note,
        });
    }

    apply_simple_field_patches(&mut item, &body);

    item.updated_at = now_iso();

    match coll
        .replace_one(doc! { "id": &id }, &item)
        .upsert(false)
        .await
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "item": item })),
        Err(e) => {
            eprintln!("api_admin_change_request_patch write error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to update change request" }))
        }
    }
}

pub(crate) async fn api_admin_change_request_delete(
    path: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let id = path.into_inner();
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<ChangeRequestItem>(ADMIN_CHANGE_REQUESTS_COLL);

    match coll.delete_one(doc! { "id": &id }).await {
        Ok(res) if res.deleted_count > 0 => {
            HttpResponse::Ok().json(serde_json::json!({ "deleted": true, "id": id }))
        }
        Ok(_) => HttpResponse::NotFound()
            .json(serde_json::json!({ "deleted": false, "message": "Change request not found" })),
        Err(e) => {
            eprintln!("api_admin_change_request_delete error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to delete change request" }))
        }
    }
}
