use mongodb::{Client, bson::doc, error::Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use futures_util::TryStreamExt;
use mongodb::error::Error;
use std::collections::HashMap;
use chrono::{DateTime, Utc};

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
    pub sequence_number: u32,      
    pub uid: u32,                  
    pub internal_date: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Mailbox {
    pub name: String,
    pub flags: Vec<String>,
    pub exists: u32,
    pub recent: u32,
    pub unseen: u32,
    pub permanent_flags: Vec<String>,
    pub uid_validity: u32,
    pub uid_next: u32,
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
    pub async fn select_mailbox(&self, mailbox: &str) -> Result<Mailbox> {
        let database_name = std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
        let collection = self.client.database(&database_name).collection::<Email>("emails");
        
        let exists = collection.count_documents(doc! { "mailbox": mailbox }, None).await? as u32;
        let recent = collection.count_documents(
            doc! { "mailbox": mailbox, "flags": "\\Recent" }, 
            None
        ).await? as u32;
        let unseen = collection.count_documents(
            doc! { "mailbox": mailbox, "flags": { "$nin": ["\\Seen"] } }, 
            None
        ).await? as u32;

        Ok(Mailbox {
            name: mailbox.to_string(),
            flags: vec![String::from("\\Answered"), String::from("\\Flagged"), 
                       String::from("\\Deleted"), String::from("\\Seen"), 
                       String::from("\\Draft")],
            exists,
            recent,
            unseen,
            permanent_flags: vec![String::from("\\*")],
            uid_validity: 1, // Devrait être persistant et unique
            uid_next: exists + 1,
        })
    }

    pub async fn search_messages(&self, criteria: &str) -> Result<Vec<u32>> {
        let database_name = std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
        let collection = self.client.database(&database_name).collection::<Email>("emails");
        
        // Exemple basique de recherche
        let filter = match criteria {
            "ALL" => doc! {},
            "UNSEEN" => doc! { "flags": { "$nin": ["\\Seen"] } },
            "SEEN" => doc! { "flags": "\\Seen" },
            _ => doc! {},
        };

        let mut cursor = collection.find(filter, None).await?;
        let mut sequence_numbers = Vec::new();
        while let Some(email) = cursor.try_next().await? {
            sequence_numbers.push(email.sequence_number);
        }
        Ok(sequence_numbers)
    }

    pub async fn expunge_mailbox(&self) -> Result<Vec<u32>> {
        let database_name = std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
        let collection = self.client.database(&database_name).collection::<Email>("emails");
        
        let filter = doc! { "flags": "\\Deleted" };
        let mut cursor = collection.find(filter.clone(), None).await?;
        let mut deleted_sequence_numbers = Vec::new();
        
        while let Some(email) = cursor.try_next().await? {
            deleted_sequence_numbers.push(email.sequence_number);
        }
        
        collection.delete_many(filter, None).await?;
        Ok(deleted_sequence_numbers)
    }

    pub async fn copy_messages(&self, sequence_set: &str, target_mailbox: &str) -> Result<()> {
        let database_name = std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
        let collection = self.client.database(&database_name).collection::<Email>("emails");
        
        // Exemple simple pour un seul ID
        let filter = doc! { "sequence_number": sequence_set.parse::<u32>().unwrap_or(0) };
        if let Some(mut email) = collection.find_one(filter, None).await? {
            email.id = format!("{}_{}", email.id, Utc::now().timestamp());
            collection.insert_one(email, None).await?;
        }
        Ok(())
    }

    pub async fn store_flags(&self, sequence_set: &str, flags: Vec<String>, mode: &str) -> Result<()> {
        let database_name = std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
        let collection = self.client.database(&database_name).collection::<Email>("emails");
        
        let filter = doc! { "sequence_number": sequence_set.parse::<u32>().unwrap_or(0) };
        let update = match mode {
            "+" => doc! { "$addToSet": { "flags": { "$each": flags } } },
            "-" => doc! { "$pullAll": { "flags": flags } },
            _ => doc! { "$set": { "flags": flags } },
        };
        
        collection.update_one(filter, update, None).await?;
        Ok(())
    }

    pub async fn check_mailbox(&self) -> Result<()> {
        // Checkpoint the current mailbox state
        Ok(())
    }

    pub async fn close_mailbox(&self) -> Result<()> {
        self.expunge_mailbox().await?;
        Ok(())
    }

    pub async fn noop(&self) -> Result<()> {
        // No operation, just return OK
        Ok(())
    }

    pub async fn get_mailbox_status(&self, mailbox: &str) -> Result<Mailbox> {
        // Similaire à select_mailbox mais sans modifier l'état
        self.select_mailbox(mailbox).await
    }

    pub async fn create_mailbox(&self, mailbox: &str) -> Result<()> {
        let database_name = std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
        let collection = self.client.database(&database_name).collection::<Mailbox>("mailboxes");
        
        let new_mailbox = Mailbox {
            name: mailbox.to_string(),
            flags: vec![],
            exists: 0,
            recent: 0,
            unseen: 0,
            permanent_flags: vec![String::from("\\*")],
            uid_validity: 1,
            uid_next: 1,
        };

        collection.insert_one(new_mailbox, None).await?;
        Ok(())
    }

    pub async fn delete_mailbox(&self, mailbox: &str) -> Result<()> {
        let database_name = std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
        let collection = self.client.database(&database_name).collection::<Mailbox>("mailboxes");
        
        collection.delete_one(doc! { "name": mailbox }, None).await?;
        Ok(())
    }

    pub async fn rename_mailbox(&self, old_name: &str, new_name: &str) -> Result<()> {
        let database_name = std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
        let collection = self.client.database(&database_name).collection::<Mailbox>("mailboxes");
        
        collection.update_one(
            doc! { "name": old_name },
            doc! { "$set": { "name": new_name } },
            None
        ).await?;
        Ok(())
    }

    pub async fn subscribe_mailbox(&self, mailbox: &str) -> Result<()> {
        let database_name = std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
        let collection = self.client.database(&database_name).collection::<User>("subscriptions");
        
        collection.update_one(
            doc! { "mailbox": mailbox },
            doc! { "$set": { "subscribed": true } },
            None
        ).await?;
        Ok(())
    }

    pub async fn unsubscribe_mailbox(&self, mailbox: &str) -> Result<()> {
        let database_name = std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
        let collection = self.client.database(&database_name).collection::<User>("subscriptions");
        
        collection.update_one(
            doc! { "mailbox": mailbox },
            doc! { "$set": { "subscribed": false } },
            None
        ).await?;
        Ok(())
    }

    pub async fn list_subscribed_mailboxes(&self, reference: &str, pattern: &str) -> Result<Vec<String>> {
        let database_name = std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
        let collection = self.client.database(&database_name).collection::<User>("subscriptions");
        
        let filter = doc! { "subscribed": true };
        let mut cursor = collection.find(filter, None).await?;
        let mut mailboxes = Vec::new();
        
        while let Some(subscription) = cursor.try_next().await? {
            mailboxes.push(subscription.mailbox);
        }
        
        Ok(mailboxes)
    }

    pub async fn get_mailbox_status_items(&self, mailbox: &str, items: &str) -> Result<String> {
        let status = self.select_mailbox(mailbox).await?;
        let mut response = Vec::new();

        // Parse les items demandés et ajoute les valeurs correspondantes
        for item in items.split_whitespace() {
            match item.trim_matches(|c| c == '(' || c == ')') {
                "MESSAGES" => response.push(format!("MESSAGES {}", status.exists)),
                "RECENT" => response.push(format!("RECENT {}", status.recent)),
                "UNSEEN" => response.push(format!("UNSEEN {}", status.unseen)),
                "UIDNEXT" => response.push(format!("UIDNEXT {}", status.uid_next)),
                "UIDVALIDITY" => response.push(format!("UIDVALIDITY {}", status.uid_validity)),
                _ => continue,
            }
        }

        Ok(response.join(" "))
    }

}   
