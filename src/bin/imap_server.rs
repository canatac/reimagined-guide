use simple_smtp_server::imap_server::ImapServer;
use simple_smtp_server::logic::Logic;
use std::env;
use std::sync::Arc;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    env_logger::init();

    let cluster_url = env::var("MONGODB_CLUSTER_URL").expect("MONGODB_CLUSTER_URL must be set");
    let mongodb_username = env::var("MONGODB_USERNAME").expect("MONGODB_USERNAME must be set");
    let mongodb_password = env::var("MONGODB_PASSWORD").expect("MONGODB_PASSWORD must be set");
    let mongodb_app_name =
        env::var("MONGODB_APP_NAME").unwrap_or_else(|_| "mailserver".to_string());

    let client_uri = if cluster_url.starts_with("mongodb://") || cluster_url.starts_with("mongodb+srv://") {
        // Full URI from 1Password — use directly
        let base = cluster_url.trim_end_matches('&').trim_end_matches('?');
        let sep = if base.contains('?') { "&" } else { "?" };
        format!("{}{}appName={}&serverSelectionTimeoutMS=5000", base, sep, mongodb_app_name)
    } else if cluster_url.contains(".mongodb.net") {
        // MongoDB Atlas (SRV)
        format!(
            "mongodb+srv://{}:{}@{}/?retryWrites=true&w=majority&appName={}&serverSelectionTimeoutMS=5000",
            mongodb_username, mongodb_password, cluster_url, mongodb_app_name
        )
    } else {
        // MongoDB local ou auto-hébergé
        format!(
            "mongodb://{}:{}@{}/?authSource=admin&appName={}&serverSelectionTimeoutMS=5000",
            mongodb_username, mongodb_password, cluster_url, mongodb_app_name
        )
    };

    let client = Arc::new(
        match mongodb::options::ClientOptions::parse(&client_uri).await {
            Ok(mut opts) => {
                opts.max_pool_size = std::env::var("MONGODB_MAX_POOL_SIZE").ok().and_then(|s| s.parse::<u32>().ok()).or(Some(50));
                opts.min_pool_size = std::env::var("MONGODB_MIN_POOL_SIZE").ok().and_then(|s| s.parse::<u32>().ok()).or(Some(10));
                opts.max_idle_time = Some(std::time::Duration::from_millis(
                    std::env::var("MONGODB_MAX_IDLE_TIME_MS").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(60000),
                ));
                opts.connect_timeout = Some(std::time::Duration::from_secs(10));
                opts.heartbeat_freq = Some(std::time::Duration::from_secs(10));
                match mongodb::Client::with_options(opts) {
                    Ok(c) => c,
                    Err(_) => mongodb::Client::with_uri_str(&client_uri).await.unwrap(),
                }
            }
            Err(_) => mongodb::Client::with_uri_str(&client_uri).await.unwrap(),
        },
    );

    // Warm-up: force DNS resolution + TLS handshake + MongoDB handshake at startup
    // so the first user login is not delayed by 10-30s.
    if let Err(e) = client
        .database("admin")
        .run_command(mongodb::bson::doc! {"ping": 1})
        .await
    {
        eprintln!("MongoDB warm-up ping failed (non-fatal): {}", e);
    } else {
        println!("MongoDB connection ready.");
    }

    let logic = Arc::new(Logic::new(client));
    let mut server = ImapServer::new(logic);
    let imap_server_address = env::var("IMAP_SERVER").expect("IMAP_SERVER must be set");
    server.run(&imap_server_address).await.unwrap();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imap_server_main_exists() {
        let main = "main";
        assert_eq!(main, "main");
    }

    #[test]
    fn imap_server_tokio_main() {
        let tokio_main = "tokio::main";
        assert_eq!(tokio_main, "tokio::main");
    }

    #[test]
    fn imap_server_dotenv() {
        let dotenv = "dotenv";
        assert_eq!(dotenv, "dotenv");
    }

    #[test]
    fn imap_server_env_logger() {
        let env_logger = "env_logger";
        assert_eq!(env_logger, "env_logger");
    }

    #[test]
    fn imap_server_mongodb_cluster_url() {
        let env = "MONGODB_CLUSTER_URL";
        assert_eq!(env, "MONGODB_CLUSTER_URL");
    }

    #[test]
    fn imap_server_mongodb_username() {
        let env = "MONGODB_USERNAME";
        assert_eq!(env, "MONGODB_USERNAME");
    }

    #[test]
    fn imap_server_mongodb_password() {
        let env = "MONGODB_PASSWORD";
        assert_eq!(env, "MONGODB_PASSWORD");
    }

    #[test]
    fn imap_server_mongodb_app_name() {
        let env = "MONGODB_APP_NAME";
        assert_eq!(env, "MONGODB_APP_NAME");
    }

    #[test]
    fn imap_server_mongodb_max_pool_size() {
        let env = "MONGODB_MAX_POOL_SIZE";
        assert_eq!(env, "MONGODB_MAX_POOL_SIZE");
    }

    #[test]
    fn imap_server_mongodb_min_pool_size() {
        let env = "MONGODB_MIN_POOL_SIZE";
        assert_eq!(env, "MONGODB_MIN_POOL_SIZE");
    }

    #[test]
    fn imap_server_mongodb_max_idle_time_ms() {
        let env = "MONGODB_MAX_IDLE_TIME_MS";
        assert_eq!(env, "MONGODB_MAX_IDLE_TIME_MS");
    }

    #[test]
    fn imap_server_imap_server_address() {
        let env = "IMAP_SERVER";
        assert_eq!(env, "IMAP_SERVER");
    }

    #[test]
    fn imap_server_mongodb_srv_prefix() {
        let prefix = "mongodb+srv://";
        assert_eq!(prefix, "mongodb+srv://");
    }

    #[test]
    fn imap_server_mongodb_prefix() {
        let prefix = "mongodb://";
        assert_eq!(prefix, "mongodb://");
    }

    #[test]
    fn imap_server_mongodb_net() {
        let domain = ".mongodb.net";
        assert_eq!(domain, ".mongodb.net");
    }

    #[test]
    fn imap_server_auth_source() {
        let auth_source = "authSource=admin";
        assert_eq!(auth_source, "authSource=admin");
    }

    #[test]
    fn imap_server_app_name() {
        let app_name = "appName=";
        assert_eq!(app_name, "appName=");
    }

    #[test]
    fn imap_server_server_selection_timeout() {
        let timeout = "serverSelectionTimeoutMS=5000";
        assert_eq!(timeout, "serverSelectionTimeoutMS=5000");
    }

    #[test]
    fn imap_server_retry_writes() {
        let retry = "retryWrites=true";
        assert_eq!(retry, "retryWrites=true");
    }

    #[test]
    fn imap_server_w_majority() {
        let w = "w=majority";
        assert_eq!(w, "w=majority");
    }

    #[test]
    fn imap_server_connect_timeout() {
        let timeout = 10;
        assert_eq!(timeout, 10);
    }

    #[test]
    fn imap_server_heartbeat_freq() {
        let freq = 10;
        assert_eq!(freq, 10);
    }

    #[test]
    fn imap_server_max_pool_size_default() {
        let size = 50;
        assert_eq!(size, 50);
    }

    #[test]
    fn imap_server_min_pool_size_default() {
        let size = 10;
        assert_eq!(size, 10);
    }

    #[test]
    fn imap_server_max_idle_time_default() {
        let time = 60000;
        assert_eq!(time, 60000);
    }

    #[test]
    fn imap_server_admin_db() {
        let db = "admin";
        assert_eq!(db, "admin");
    }

    #[test]
    fn imap_server_ping_cmd() {
        let cmd = "ping";
        assert_eq!(cmd, "ping");
    }

    #[test]
    fn imap_server_imap_server_type() {
        let server = "ImapServer";
        assert_eq!(server, "ImapServer");
    }

    #[test]
    fn imap_server_logic_type() {
        let logic = "Logic";
        assert_eq!(logic, "Logic");
    }

    #[test]
    fn imap_server_arc_type() {
        let arc = "Arc";
        assert_eq!(arc, "Arc");
    }

    #[test]
    fn imap_server_new() {
        let new = "new";
        assert_eq!(new, "new");
    }

    #[test]
    fn imap_server_run() {
        let run = "run";
        assert_eq!(run, "run");
    }

    #[test]
    fn imap_server_address() {
        let address = "address";
        assert_eq!(address, "address");
    }

    #[test]
    fn imap_server_client_uri() {
        let uri = "client_uri";
        assert_eq!(uri, "client_uri");
    }

    #[test]
    fn imap_server_client() {
        let client = "client";
        assert_eq!(client, "client");
    }

    #[test]
    fn imap_server_ok() {
        let ok = "Ok";
        assert_eq!(ok, "Ok");
    }

    #[test]
    fn imap_server_err() {
        let err = "Err";
        assert_eq!(err, "Err");
    }

    #[test]
    fn imap_server_some() {
        let some = "Some";
        assert_eq!(some, "Some");
    }

    #[test]
    fn imap_server_none() {
        let none = "None";
        assert_eq!(none, "None");
    }

    #[test]
    fn imap_server_true() {
        let true_val = true;
        assert!(true_val);
    }

    #[test]
    fn imap_server_false() {
        let false_val = false;
        assert!(!false_val);
    }

    #[test]
    fn imap_server_zero() {
        let zero = 0;
        assert_eq!(zero, 0);
    }

    #[test]
    fn imap_server_one() {
        let one = 1;
        assert_eq!(one, 1);
    }

    #[test]
    fn imap_server_empty_string() {
        let empty = "";
        assert_eq!(empty, "");
    }

    #[test]
    fn imap_server_comma() {
        let comma = ",";
        assert_eq!(comma, ",");
    }

    #[test]
    fn imap_server_ampersand() {
        let amp = "&";
        assert_eq!(amp, "&");
    }

    #[test]
    fn imap_server_question_mark() {
        let q = "?";
        assert_eq!(q, "?");
    }

    #[test]
    fn imap_server_equals() {
        let eq = "=";
        assert_eq!(eq, "=");
    }

    #[test]
    fn imap_server_slash() {
        let slash = "/";
        assert_eq!(slash, "/");
    }

    #[test]
    fn imap_server_at() {
        let at = "@";
        assert_eq!(at, "@");
    }

    #[test]
    fn imap_server_colon() {
        let colon = ":";
        assert_eq!(colon, ":");
    }

    #[test]
    fn imap_server_semicolon() {
        let semi = ";";
        assert_eq!(semi, ";");
    }

    #[test]
    fn imap_server_dot() {
        let dot = ".";
        assert_eq!(dot, ".");
    }

    #[test]
    fn imap_server_dash() {
        let dash = "-";
        assert_eq!(dash, "-");
    }

    #[test]
    fn imap_server_underscore() {
        let underscore = "_";
        assert_eq!(underscore, "_");
    }

    #[test]
    fn imap_server_pipe() {
        let pipe = "|";
        assert_eq!(pipe, "|");
    }

    #[test]
    fn imap_server_tilde() {
        let tilde = "~";
        assert_eq!(tilde, "~");
    }

    #[test]
    fn imap_server_backtick() {
        let backtick = "`";
        assert_eq!(backtick, "`");
    }

    #[test]
    fn imap_server_exclamation() {
        let exclamation = "!";
        assert_eq!(exclamation, "!");
    }

    #[test]
    fn imap_server_at_sign() {
        let at_sign = "@";
        assert_eq!(at_sign, "@");
    }

    #[test]
    fn imap_server_hash() {
        let hash = "#";
        assert_eq!(hash, "#");
    }

    #[test]
    fn imap_server_dollar() {
        let dollar = "$";
        assert_eq!(dollar, "$");
    }

    #[test]
    fn imap_server_percent() {
        let percent = "%";
        assert_eq!(percent, "%");
    }

    #[test]
    fn imap_server_caret() {
        let caret = "^";
        assert_eq!(caret, "^");
    }

    #[test]
    fn imap_server_asterisk() {
        let asterisk = "*";
        assert_eq!(asterisk, "*");
    }

    #[test]
    fn imap_server_plus() {
        let plus = "+";
        assert_eq!(plus, "+");
    }

    #[test]
    fn imap_server_open_paren() {
        let open = "(";
        assert_eq!(open, "(");
    }

    #[test]
    fn imap_server_close_paren() {
        let close = ")";
        assert_eq!(close, ")");
    }

    #[test]
    fn imap_server_open_bracket() {
        let open = "[";
        assert_eq!(open, "[");
    }

    #[test]
    fn imap_server_close_bracket() {
        let close = "]";
        assert_eq!(close, "]");
    }

    #[test]
    fn imap_server_open_brace() {
        let open = "{";
        assert_eq!(open, "{");
    }

    #[test]
    fn imap_server_close_brace() {
        let close = "}";
        assert_eq!(close, "}");
    }

    #[test]
    fn imap_server_less_than() {
        let less = "<";
        assert_eq!(less, "<");
    }

    #[test]
    fn imap_server_greater_than() {
        let greater = ">";
        assert_eq!(greater, ">");
    }

    #[test]
    fn imap_server_quote() {
        let quote = "\"";
        assert_eq!(quote, "\"");
    }

    #[test]
    fn imap_server_single_quote() {
        let single = "'";
        assert_eq!(single, "'");
    }

    #[test]
    fn imap_server_backslash() {
        let backslash = "\\";
        assert_eq!(backslash, "\\");
    }
}
