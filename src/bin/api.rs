use simple_smtp_server::logic::Logic;
use warp::Filter;
use std::sync::Arc;
use warp::reject::Reject;
use dotenv::dotenv;
use simple_smtp_server::logic::User;
use warp::http::StatusCode;
use std::env;

#[derive(Debug)]
struct MyCustomError;
impl Reject for MyCustomError {}

async fn create_user(logic: Arc<Logic>, user: User) -> Result<impl warp::Reply, warp::Rejection> {
    match logic.create_user(&user.username, &user.password, &user.mailbox).await {
        Ok(_) => Ok(warp::reply::with_status("User created", StatusCode::CREATED)),
        Err(_) => Err(warp::reject()),
    }
}

async fn login(logic: Arc<Logic>, username: String, password: String) -> Result<impl warp::Reply, warp::Rejection> {
    match logic.authenticate_user(&username, &password).await {
        Ok(Some(user)) => Ok(warp::reply::json(&user)),
        Ok(None) => Err(warp::reject::custom(MyCustomError)),
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
        Ok(None) => Err(warp::reject::custom(MyCustomError)),
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

pub fn api_routes(client: Arc<mongodb::Client>) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let logic = Arc::new(Logic::new(client));

    // Pour login(logic: Arc<Logic>, username: String, password: String)
    let login_route = warp::path!("login" / String / String)
        .and(warp::get())
        .and(with_logic(logic.clone()))
        .and_then(|username: String, password: String, logic: Arc<Logic>| 
            login(logic, username, password)
        );

    // Pour create_user(logic: Arc<Logic>, user: User)
    let create_user_route = warp::path!("users")
        .and(warp::post())
        .and(with_logic(logic.clone()))
        .and(warp::body::json::<User>())  // Désérialise le body en User, pas en Logic
        .and_then(|logic: Arc<Logic>, user: User| create_user(logic, user));


    // Pour get_emails(logic: Arc<Logic>, mailbox: String)
    let get_emails_route = warp::path!("emails" / String)
        .and(warp::get())
        .and(with_logic(logic.clone()))
        .and_then(|mailbox: String, logic: Arc<Logic>| 
            get_emails(logic, mailbox)
        );

    // Pour fetch_email(logic: Arc<Logic>, email_id: String)
    let fetch_email_route = warp::path!("email" / String)
        .and(warp::get())
        .and(with_logic(logic.clone()))
        .and_then(|email_id: String, logic: Arc<Logic>| 
            fetch_email(logic, email_id)
        );

    // Pour store_email_flag(logic: Arc<Logic>, email_id: String, flag: String)
    let store_email_flag_route = warp::path!("email" / "flag" / String / String)
        .and(warp::post())
        .and(with_logic(logic.clone()))
        .and_then(|email_id: String, flag: String, logic: Arc<Logic>| 
            store_email_flag(logic, email_id, flag)
        );

    // Pour delete_email(logic: Arc<Logic>, email_id: String)
    let delete_email_route = warp::path!("email" / String)
        .and(warp::delete())
        .and(with_logic(logic.clone()))
        .and_then(|email_id: String, logic: Arc<Logic>| 
            delete_email(logic, email_id)
        );

    // Pour archive_email(logic: Arc<Logic>, email_id: String)
    let archive_email_route = warp::path!("email" / "archive" / String)
        .and(warp::post())
        .and(with_logic(logic.clone()))
        .and_then(|email_id: String, logic: Arc<Logic>| 
            archive_email(logic, email_id)
        );

    login_route
        .or(get_emails_route)
        .or(fetch_email_route)
        .or(store_email_flag_route)
        .or(delete_email_route)
        .or(archive_email_route)
        .or(create_user_route)
}

fn with_logic(logic: Arc<Logic>) -> impl Filter<Extract = (Arc<Logic>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || logic.clone())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialisation de l'environnement
    dotenv().ok();
    env_logger::init();

    // Création du client MongoDB
    let client = Arc::new(
        mongodb::Client::with_uri_str("mongodb://localhost:27017")
            .await?
    );

    // Configuration des routes
    let routes = api_routes(client);

    // Démarrage du serveur
    let api_port = env::var("IMAP_SERVER_API_PORT").expect("IMAP_SERVER_API_PORT must be set");
    println!("Starting server at http://localhost:{}", api_port);
    warp::serve(routes)
        .run(([127, 0, 0, 1], api_port.parse::<u16>().unwrap()))
        .await;

    Ok(())
}