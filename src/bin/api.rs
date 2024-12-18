use simple_smtp_server::logic::Logic;
use warp::Filter;
use std::sync::Arc;
use warp::reject::Reject;
use dotenv::dotenv;
use simple_smtp_server::logic::User;
use warp::http::StatusCode;


use std::env;
use simple_smtp_server::logic::LogicTrait;
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // Subject (username)
    exp: usize,  // Expiration time
}


#[derive(Debug)]
struct MyCustomError;
impl Reject for MyCustomError {}

async fn create_user(logic: Arc<dyn LogicTrait>, user: User) -> Result<impl warp::Reply, warp::Rejection> {
    println!("Creating user: {:?}", user);
    match logic.create_user(&user.username, &user.password, &user.mailbox).await {
        Ok(_) => Ok(warp::reply::with_status("User created", StatusCode::CREATED)),
        Err(e) => {
            eprintln!("Error creating user: {:?}", e);
            Err(warp::reject())
        },
    }
}

async fn login(logic: Arc<Logic>, username: String, password: String) -> Result<impl warp::Reply, warp::Rejection> {
    match logic.authenticate_user(&username, &password).await {
        Ok(Some(user)) => {
            let claims = Claims {
                sub: user.username.clone(),
                exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
            };
            let token = encode(&Header::default(), &claims, &EncodingKey::from_secret("secret".as_ref())).unwrap();
            Ok(warp::reply::json(&token))
        }
        Ok(None) => Err(warp::reject::custom(MyCustomError)),
        Err(_) => Err(warp::reject()),
    }
}
fn with_auth() -> impl Filter<Extract = (String,), Error = warp::Rejection> + Clone {
    warp::header::<String>("authorization")
        .and_then(|auth_header: String| async move {
            let token = auth_header.trim_start_matches("Bearer ");
            let token_data = decode::<Claims>(&token, &DecodingKey::from_secret("secret".as_ref()), &Validation::default())
                .map_err(|_| warp::reject::custom(MyCustomError))?;
            Ok::<_, warp::Rejection>(token_data.claims.sub)
        })
} 
async fn get_emails(logic: Arc<Logic>, mailbox: String, username: String) -> Result<impl warp::Reply, warp::Rejection> {
    match logic.get_emails(&username, &mailbox).await {
        Ok(emails) => Ok(warp::reply::json(&emails)),
        Err(_) => Err(warp::reject()),
    }
}

async fn fetch_email(logic: Arc<Logic>, email_id: String, username: String) -> Result<impl warp::Reply, warp::Rejection> {
    match logic.fetch_email(&username, &email_id).await {
        Ok(Some(email)) => Ok(warp::reply::json(&email)),
        Ok(None) => Err(warp::reject::custom(MyCustomError)),
        Err(_) => Err(warp::reject()),
    }
}

async fn store_email_flag(logic: Arc<Logic>, email_id: String, flag: String, username: String) -> Result<impl warp::Reply, warp::Rejection> {
    match logic.store_email_flag(&username, &email_id, &flag).await {
        Ok(_) => Ok(warp::reply::with_status("Flag updated", warp::http::StatusCode::OK)),
        Err(_) => Err(warp::reject()),
    }
}

async fn delete_email(logic: Arc<Logic>, email_id: String, username: String) -> Result<impl warp::Reply, warp::Rejection> {
    match logic.delete_email(&username, &email_id).await {
        Ok(_) => Ok(warp::reply::with_status("Email deleted", warp::http::StatusCode::OK)),
        Err(_) => Err(warp::reject()),
    }
}

async fn archive_email(logic: Arc<Logic>, email_id: String, username: String) -> Result<impl warp::Reply, warp::Rejection> {
    match logic.archive_email(&username, &email_id).await {
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
    let create_user_route = warp::path!("create_user")
        .and(warp::post())
        .and(with_logic(logic.clone()))
        .and(warp::body::json::<User>())
        .and_then(|logic: Arc<Logic>, user: User| create_user(logic, user));


    // Pour get_emails(logic: Arc<Logic>, mailbox: String)
    let get_emails_route = warp::path!("emails" / String)
        .and(warp::get())
        .and(with_logic(logic.clone()))
        .and(with_auth())
        .and_then(|mailbox: String, logic: Arc<Logic>, username: String| 
            get_emails(logic, mailbox, username)
        );

    // Pour fetch_email(logic: Arc<Logic>, email_id: String)
    let fetch_email_route = warp::path!("email" / String)
        .and(warp::get())
        .and(with_logic(logic.clone()))
        .and(with_auth())
        .and_then(|email_id: String, logic: Arc<Logic>, username: String| 
            fetch_email(logic, email_id, username)
        );

    // Pour store_email_flag(logic: Arc<Logic>, email_id: String, flag: String)
    let store_email_flag_route = warp::path!("email" / "flag" / String / String)
        .and(warp::post())
        .and(with_logic(logic.clone()))
        .and(with_auth())
        .and_then(|email_id: String, flag: String, logic: Arc<Logic>, username: String| 
            store_email_flag(logic, email_id, flag, username)
        );

    // Pour delete_email(logic: Arc<Logic>, email_id: String)
    let delete_email_route = warp::path!("email" / String)
        .and(warp::delete())
        .and(with_logic(logic.clone()))
        .and(with_auth())
        .and_then(|email_id: String, logic: Arc<Logic>, username: String| 
            delete_email(logic, email_id, username)
        );

    // Pour archive_email(logic: Arc<Logic>, email_id: String)
    let archive_email_route = warp::path!("email" / "archive" / String)
        .and(warp::post())
        .and(with_logic(logic.clone()))
        .and(with_auth())
        .and_then(|email_id: String, logic: Arc<Logic>, username: String| 
            archive_email(logic, email_id, username)
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
    let client_uri = format!(
        "mongodb+srv://{}:{}@{}/?retryWrites=true&w=majority&appName={}",
        env::var("MONGODB_USERNAME").expect("MONGODB_USERNAME must be set"),
        env::var("MONGODB_PASSWORD").expect("MONGODB_PASSWORD must be set"),
        env::var("MONGODB_CLUSTER_URL").expect("MONGODB_CLUSTER_URL must be set"),
        env::var("MONGODB_APP_NAME").expect("MONGODB_APP_NAME must be set")
    );
    println!("Client URI: {}", client_uri);
    let client = Arc::new(
        mongodb::Client::with_uri_str(&client_uri)
            .await?
    );
    // Configuration des routes
    let routes = api_routes(client);

    // Démarrage du serveur
    let api_port = env::var("IMAP_SERVER_API_PORT").expect("IMAP_SERVER_API_PORT must be set");
    println!("Starting server at http://0.0.0.0:{}", api_port);
    warp::serve(routes)
        .run(([0, 0, 0, 0], api_port.parse::<u16>().unwrap()))
        .await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::test::request;
    use std::sync::Arc;
    use simple_smtp_server::logic::{Logic, User};
    use mockall::predicate::eq;
    use mockall::mock;

    // Mock the Logic struct
    mock! {
        pub Logic {
            pub async fn create_user(&self, username: &str, password: &str, mailbox: &str) -> Result<(), mongodb::error::Error>;
        }
    }

    #[async_trait::async_trait]
    impl LogicTrait for MockLogic {
        async fn create_user(&self, username: &str, password: &str, mailbox: &str) -> Result<(), mongodb::error::Error> {
            self.create_user(username, password, mailbox).await
        }
    }

    #[tokio::test]
    async fn test_create_user_route() {
        dotenv::from_filename(".env.test").ok();

        // Créer une instance mockée de Logic
        let mut mock_logic = MockLogic::new();
        mock_logic
            .expect_create_user()
            .with(eq("testuser"), eq("password"), eq("testmailbox"))
            .times(1)
            .returning(|_, _, _| Ok(()));

        let logic: Arc<dyn LogicTrait> = Arc::new(mock_logic);

        let user = User {
            username: "testuser".to_string(),
            password: "password".to_string(),
            mailbox: "testmailbox".to_string(),
        };

        // Créer un filtre pour le handler create_user
        let create_user_filter = warp::path!("create_user")
            .and(warp::post())
            .and(warp::any().map(move || logic.clone()))
            .and(warp::body::json())
            .and_then(create_user);

        let res = request()
            .method("POST")
            .path("/create_user")
            .json(&user)
            .reply(&create_user_filter)
            .await;

        assert_eq!(res.status(), 201);
    }

    // Ajoutez d'autres tests pour les autres routes ici
}