// email_impl.rs — split from logic/mod.rs (Sprint 11)
// Extends impl Logic with a subset of methods.
#![allow(unused_imports)]
use super::*;

impl Logic {

    pub async fn get_emails(&self, username: &str, mailbox: &str) -> Result<Vec<Email>> {
        self.get_emails_page(username, mailbox, 200, 0).await
    }

    /// Sorted newest-first page; omits heavy headers projection at the driver level when possible.
    pub async fn get_emails_page(
        &self,
        username: &str,
        mailbox: &str,
        limit: i64,
        skip: u64,
    ) -> Result<Vec<Email>> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Email>("emails");
            let filter = doc! { "user_id": username, "mailbox": mailbox };
            let cursor = collection
                .find(filter)
                .sort(doc! { "internal_date": -1 })
                .skip(skip)
                .limit(limit.max(1).min(200))
                .await?;
            cursor.try_collect().await
        }
        #[cfg(test)]
        {
            let _ = (limit, skip);
            let emails = vec![Email::new(
                "testemail",
                "from@test.com",
                "to@test.com",
                "Test Subject",
                "Test Body",
            )];
            Ok(emails)
        }
    }

    pub async fn fetch_email(&self, username: &str, email_id: &str) -> Result<Option<Email>> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Email>("emails");
            let filter = doc! { "user_id": username, "id": email_id };
            collection.find_one(filter).await
        }
        #[cfg(test)]
        {
            //For test, we need to return an email
            let email = Email::new(
                "testemail",
                "from@test.com",
                "to@test.com",
                "Test Subject",
                "Test Body",
            );
            Ok(Some(email))
        }
    }

    pub async fn store_email_flag(&self, username: &str, email_id: &str, flag: &str) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Email>("emails");
            let filter = doc! { "user_id": username, "id": email_id };
            let update = doc! { "$addToSet": { "flags": flag } };
            collection.update_one(filter, update).await?;
            Ok(())
        }
        #[cfg(test)]
        {
            //For test, we need to return an empty result
            Ok(())
        }
    }

    pub async fn move_email_to_mailbox(
        &self,
        username: &str,
        email_id: &str,
        mailbox: &str,
    ) -> Result<bool> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Email>("emails");
            let filter = doc! { "user_id": username, "id": email_id };
            let update = doc! { "$set": { "mailbox": mailbox.to_ascii_lowercase() } };
            let res = collection.update_one(filter, update).await?;
            Ok(res.matched_count > 0)
        }
        #[cfg(test)]
        {
            Ok(true)
        }
    }

    pub async fn set_email_read(
        &self,
        username: &str,
        email_id: &str,
        is_read: bool,
    ) -> Result<bool> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Email>("emails");
            let filter = doc! { "user_id": username, "id": email_id };
            let update = if is_read {
                doc! { "$addToSet": { "flags": "\\Seen" } }
            } else {
                doc! { "$pull": { "flags": { "$in": ["\\Seen", "Seen", "seen"] } } }
            };
            let res = collection.update_one(filter, update).await?;
            Ok(res.matched_count > 0)
        }
        #[cfg(test)]
        {
            Ok(true)
        }
    }

    pub async fn set_email_starred(
        &self,
        username: &str,
        email_id: &str,
        is_starred: bool,
    ) -> Result<bool> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Email>("emails");
            let filter = doc! { "user_id": username, "id": email_id };
            let update = if is_starred {
                doc! { "$addToSet": { "flags": "\\Flagged" } }
            } else {
                doc! { "$pull": { "flags": { "$in": ["\\Flagged", "Flagged", "flagged", "starred"] } } }
            };
            let res = collection.update_one(filter, update).await?;
            Ok(res.matched_count > 0)
        }
        #[cfg(test)]
        {
            Ok(true)
        }
    }

    pub async fn delete_email(&self, username: &str, email_id: &str) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Email>("emails");
            let filter = doc! { "user_id": username, "id": email_id };
            collection.delete_one(filter).await?;
            Ok(())
        }
        #[cfg(test)]
        {
            self.client.delete_email(email_id).await
        }
    }

    pub async fn archive_email(&self, username: &str, email_id: &str) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Email>("emails");
            let archive_collection = self
                .client
                .database(&database_name)
                .collection::<Email>("archive");

            let filter = doc! { "user_id": username, "id": email_id };
            if let Some(document) = collection.find_one(filter.clone()).await? {
                archive_collection.insert_one(document).await?;
                collection.delete_one(filter).await?;
                Ok(())
            } else {
                Err(Error::from(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Email not found",
                )))
            }
        }
        #[cfg(test)]
        {
            self.client.archive_email(email_id).await
        }
    }
}
