#![allow(unused_imports, dead_code)]
use super::super::*;
use super::audit::log_admin_action;

/// PR1 (RBAC) — GET /api/admin/whoami
///
/// Utilisé par le frontend pour connaître le rôle réel de l'utilisateur
/// courant et adapter l'UI (viewer vs admin). Respecte le feature flag :
/// - RBAC OFF → répond `{ role: "admin", email: "system@...", enforced: false }`
///   (compat rétro : le front continue à voir un admin).
/// - RBAC ON  → nécessite un token valide, renvoie l'identité réelle.
pub(crate) async fn api_admin_whoami(
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    match admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        Ok(user) => HttpResponse::Ok().json(serde_json::json!({
            "userId": user.user_id,
            "email": user.email,
            "role": user.role,
            "enforced": admin_auth::rbac_enabled(),
        })),
        Err(resp) => resp,
    }
}
