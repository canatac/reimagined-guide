use warp::Filter;
use std::sync::Arc;

mod logic;
use crate::logic::{Logic, User, Email};
use reqwest::Client;
async fn login(logic: Arc<Logic>, username: String, password: String) -> Result<impl warp::Reply, warp::Rejection> {
    match logic.authenticate_user(&username, &password).await {
        Ok(Some(user)) => Ok(warp::reply::json(&user)),
        Ok(None) => Err(warp::reject::custom(warp::reject::not_found())),
        Err(_) => Err(warp::reject()),
    }
}

async fn get_emails(logic: Arc<Logic>, mailbox: String) -> Result<impl warp::Reply, warp::Rejection> {
    match logic.get_emails(&mailbox).await {
        Ok(emails) => Ok(warp::reply::json(&emails)),
        Err(_) => Err(warp::reject()),
    }
}

async fn fetch_email(logic: Arc<Logic>, email_id: String) -> Result<impl warp::Reply, warp::Rejection> {
    match logic.fetch_email(&email_id).await {
        Ok(Some(email)) => Ok(warp::reply::json(&email)),
        Ok(None) => Err(warp::reject::custom(warp::reject::not_found())),
        Err(_) => Err(warp::reject()),
    }
}

async fn store_email_flag(logic: Arc<Logic>, email_id: String, flag: String) -> Result<impl warp::Reply, warp::Rejection> {
    match logic.store_email_flag(&email_id, &flag).await {
        Ok(_) => Ok(warp::reply::with_status("Flag updated", warp::http::StatusCode::OK)),
        Err(_) => Err(warp::reject()),
    }
}

async fn delete_email(logic: Arc<Logic>, email_id: String) -> Result<impl warp::Reply, warp::Rejection> {
    match logic.delete_email(&email_id).await {
        Ok(_) => Ok(warp::reply::with_status("Email deleted", warp::http::StatusCode::OK)),
        Err(_) => Err(warp::reject()),
    }
}

async fn archive_email(logic: Arc<Logic>, email_id: String) -> Result<impl warp::Reply, warp::Rejection> {
    match logic.archive_email(&email_id).await {
        Ok(_) => Ok(warp::reply::with_status("Email archived", warp::http::StatusCode::OK)),
        Err(_) => Err(warp::reject()),
    }
}

pub fn api_routes(client: Arc<Client>) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let logic = Arc::new(Logic::new(client));

    let login_route = warp::path!("login" / String / String)
        .and(warp::get())
        .and(with_logic(logic.clone()))
        .and_then(login);

    let get_emails_route = warp::path!("emails" / String)
        .and(warp::get())
        .and(with_logic(logic.clone()))
        .and_then(get_emails);

    let fetch_email_route = warp::path!("email" / String)
        .and(warp::get())
        .and(with_logic(logic.clone()))
        .and_then(fetch_email);

    let store_email_flag_route = warp::path!("email" / "flag" / String / String)
        .and(warp::post())
        .and(with_logic(logic.clone()))
        .and_then(store_email_flag);

    let delete_email_route = warp::path!("email" / String)
        .and(warp::delete())
        .and(with_logic(logic.clone()))
        .and_then(delete_email);

    let archive_email_route = warp::path!("email" / "archive" / String)
        .and(warp::post())
        .and(with_logic(logic.clone()))
        .and_then(archive_email);

    login_route
        .or(get_emails_route)
        .or(fetch_email_route)
        .or(store_email_flag_route)
        .or(delete_email_route)
        .or(archive_email_route)
}

fn with_logic(logic: Arc<Logic>) -> impl Filter<Extract = (Arc<Logic>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || logic.clone())
} 