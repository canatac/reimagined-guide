use mongodb::{Client, bson::doc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use mongodb::error::Result;
use futures_util::TryStreamExt;

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password: String,
    pub mailbox: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Email {
    pub id: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub body: String,
    pub flags: Vec<String>,
}

pub struct Logic {
    client: Arc<Client>,
}

impl Logic {
    pub fn new(client: Arc<Client>) -> Self {
        Logic { client }
    }

    pub async fn authenticate_user(&self, username: &str, password: &str) -> Result<Option<User>> {
        let database_name = std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
        let collection = self.client.database(&database_name).collection::<User>("users");
        let filter = doc! { "username": username, "password": password };
        collection.find_one(filter, None).await
    }

    pub async fn get_emails(&self, mailbox: &str) -> Result<Vec<Email>> {
        let database_name = std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
        let collection = self.client.database(&database_name).collection::<Email>("emails");
        let filter = doc! { "mailbox": mailbox };
        let cursor = collection.find(filter, None).await?;
        cursor.try_collect().await
    }

    pub async fn fetch_email(&self, email_id: &str) -> Result<Option<Email>> {
        let database_name = std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
        let collection = self.client.database(&database_name).collection::<Email>("emails");
        let filter = doc! { "id": email_id };
        collection.find_one(filter, None).await
    }

    pub async fn store_email_flag(&self, email_id: &str, flag: &str) -> Result<()> {
        let database_name = std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
        let collection = self.client.database(&database_name).collection::<Email>("emails");
        let update = doc! { "$addToSet": { "flags": flag } };
        collection.update_one(doc! { "id": email_id }, update, None).await?;
        Ok(())
    }

    pub async fn delete_email(&self, email_id: &str) -> Result<()> {
        let database_name = std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
        let collection = self.client.database(&database_name).collection::<Email>("emails");
        collection.delete_one(doc! { "id": email_id }, None).await?;
        Ok(())
    }

    pub async fn archive_email(&self, email_id: &str) -> Result<()> {
        let database_name = std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
        let collection = self.client.database(&database_name).collection::<Email>("emails");
        let archive_collection = self.client.database(&database_name).collection::<Email>("archive");

        if let Some(document) = collection.find_one(doc! { "id": email_id }, None).await? {
            archive_collection.insert_one(document, None).await?;
            collection.delete_one(doc! { "id": email_id }, None).await?;
            Ok(())
        } else {
            Err(mongodb::error::Error::from(mongodb::error::ErrorKind::CommandError {
                code: 0,
                code_name: "EmailNotFound".to_string(),
                message: "Email not found".to_string(),
            }))
        }
    }
} 