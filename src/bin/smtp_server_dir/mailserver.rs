//! MailServer struct + write_response + env_bool (refactor cycle 21).
#![allow(dead_code)]

use chrono::Utc;
use std::env;
use std::fs;
use std::path::Path;
use tokio::io::AsyncWriteExt;

use super::stream_helpers::StreamType;
use super::CustomEmail;

pub(crate) fn env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(raw) => {
            let v = raw.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
                || (!matches!(v.as_str(), "0" | "false" | "no" | "off") && default)
        }
        Err(_) => default,
    }
}

pub(crate) struct MailServer {
    pub(crate) mail_dir: String,
}

impl MailServer {
    pub(crate) fn new(mail_dir: &str) -> Self {
        if let Err(err) = fs::create_dir_all(mail_dir) {
            eprintln!("Failed to create mail dir '{}': {}", mail_dir, err);
        }
        MailServer {
            mail_dir: mail_dir.to_string(),
        }
    }

    pub(crate) async fn store_email(&self, email: &CustomEmail) -> std::io::Result<()> {
        let timestamp = Utc::now().format("%Y%m%d%H%M%S");
        let filename = format!("{}-{}.eml", timestamp, email.email.to.replace("@", "_at_"));
        let path = Path::new(&self.mail_dir).join(filename);

        let mut file = tokio::fs::File::create(path).await?;
        file.write_all(format!("From: {}\r\n", email.email.from).as_bytes())
            .await?;
        file.write_all(format!("To: {}\r\n", email.email.to).as_bytes())
            .await?;
        file.write_all(format!("Subject: {}\r\n\r\n", email.email.subject).as_bytes())
            .await?;
        file.write_all(email.email.body.as_bytes()).await?;

        Ok(())
    }
}

pub(crate) async fn write_response(stream: &mut StreamType, response: &str) -> std::io::Result<()> {
    match stream {
        StreamType::Tls(ref mut s) => {
            s.write_all(response.as_bytes()).await?;
            s.flush().await
        }
        StreamType::Plain(ref mut s) => {
            s.write_all(response.as_bytes()).await?;
            s.flush().await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_bool_true_values() {
        std::env::set_var("TEST_BOOL_TRUE", "1");
        assert!(env_bool("TEST_BOOL_TRUE", false));
        std::env::set_var("TEST_BOOL_TRUE", "true");
        assert!(env_bool("TEST_BOOL_TRUE", false));
        std::env::set_var("TEST_BOOL_TRUE", "yes");
        assert!(env_bool("TEST_BOOL_TRUE", false));
        std::env::set_var("TEST_BOOL_TRUE", "on");
        assert!(env_bool("TEST_BOOL_TRUE", false));
        std::env::remove_var("TEST_BOOL_TRUE");
    }

    #[test]
    fn env_bool_false_values() {
        std::env::set_var("TEST_BOOL_FALSE", "0");
        assert!(!env_bool("TEST_BOOL_FALSE", true));
        std::env::set_var("TEST_BOOL_FALSE", "false");
        assert!(!env_bool("TEST_BOOL_FALSE", true));
        std::env::set_var("TEST_BOOL_FALSE", "no");
        assert!(!env_bool("TEST_BOOL_FALSE", true));
        std::env::set_var("TEST_BOOL_FALSE", "off");
        assert!(!env_bool("TEST_BOOL_FALSE", true));
        std::env::remove_var("TEST_BOOL_FALSE");
    }

    #[test]
    fn env_bool_default_when_unset() {
        std::env::remove_var("TEST_BOOL_UNSET");
        assert!(env_bool("TEST_BOOL_UNSET", true));
        assert!(!env_bool("TEST_BOOL_UNSET", false));
    }

    #[test]
    fn mail_server_new_creates_dir() {
        let dir = "/tmp/test_mail_server_dir";
        let _ = fs::remove_dir_all(dir);
        let server = MailServer::new(dir);
        assert_eq!(server.mail_dir, dir);
        assert!(Path::new(dir).exists());
        let _ = fs::remove_dir_all(dir);
    }
}
