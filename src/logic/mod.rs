use mongodb::{Client, bson::doc, error::Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use futures_util::TryStreamExt;
use mongodb::error::Error;

#[derive(Debug, Serialize, Deserialize, Clone)]
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

    pub async fn create_user(&self, username: &str, password: &str, mailbox: &str) -> Result<()> {
        let database_name = std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
        let collection_name = std::env::var("MONGODB_COLLECTION").expect("MONGODB_COLLECTION must be set");
        println!("Collection name: {:?}", collection_name);
        let collection = self.client.database(&database_name).collection::<User>(&collection_name);

        let new_user = User {
            username: username.to_string(),
            password: password.to_string(),
            mailbox: mailbox.to_string(),
        };
        println!("Creating user - before insert: {:?}", new_user);
        collection.insert_one(new_user, None).await?;
        println!("User created");
        Ok(())
    }

    pub async fn authenticate_user(&self, username: &str, password: &str) -> Result<Option<User>> {
        let database_name = std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
        println!("Database name: {:?}", database_name);
        let collection_name = std::env::var("MONGODB_COLLECTION").expect("MONGODB_COLLECTION must be set");
        println!("Collection name: {:?}", collection_name);
        let collection = self.client.database(&database_name).collection::<User>(&collection_name);
        
        let filter = doc! { 
            "username": username, 
            "password": password 
        };
        println!("Filter: {:?}", filter);
        let user = collection.find_one(filter, None).await?;
        if let Some(user) = user {
            println!("Found user: {:?}", user);
            Ok(Some(user))
        } else {
            println!("No user found with the given username, mailbox, and password.");
            Ok(None)
        }
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
            Err(Error::from(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Email not found",
            )))
        }
    }
}   
