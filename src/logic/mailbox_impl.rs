// mailbox_impl.rs — split from logic/mod.rs (Sprint 11)
// Extends impl Logic with a subset of methods.
#![allow(unused_imports)]
use super::*;

impl Logic {

    pub async fn select_mailbox(&self, username: &str, mailbox: &str) -> Result<Mailbox> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Mailbox>("mailboxes");

            let filter = doc! { "user_id": username, "name": mailbox };
            if let Some(mailbox) = collection.find_one(filter).await? {
                Ok(mailbox)
            } else {
                Err(Error::from(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Mailbox not found",
                )))
            }
        }
        #[cfg(test)]
        {
            Ok(Mailbox {
                name: mailbox.to_string(),
                flags: vec![],
                exists: 10,
                recent: 2,
                unseen: 5,
                permanent_flags: vec![],
                uid_validity: 1,
                uid_next: 11,
                user_id: username.to_string(),
            })
        }
    }

    pub async fn search_messages(&self, username: &str, criteria: &str) -> Result<Vec<u32>> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Email>("emails");

            let filter = match criteria {
                "ALL" => doc! { "user_id": username },
                "UNSEEN" => doc! { "user_id": username, "flags": { "$nin": ["\\Seen"] } },
                "SEEN" => doc! { "user_id": username, "flags": "\\Seen" },
                _ => doc! { "user_id": username },
            };

            let mut cursor = collection.find(filter).await?;
            let mut sequence_numbers = Vec::new();
            while let Some(email) = cursor.try_next().await? {
                sequence_numbers.push(email.sequence_number);
            }
            Ok(sequence_numbers)
        }
        #[cfg(test)]
        {
            //For test, we need to return a vector of sequence numbers
            let sequence_numbers = vec![1, 2, 3];
            Ok(sequence_numbers)
        }
    }

    pub async fn expunge_mailbox(&self, username: &str) -> Result<Vec<u32>> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Email>("emails");

            let filter = doc! { "user_id": username, "flags": "\\Deleted" };
            let mut cursor = collection.find(filter.clone()).await?;
            let mut deleted_sequence_numbers = Vec::new();

            while let Some(email) = cursor.try_next().await? {
                deleted_sequence_numbers.push(email.sequence_number);
            }

            collection.delete_many(filter).await?;
            Ok(deleted_sequence_numbers)
        }
        #[cfg(test)]
        {
            self.client.expunge_mailbox().await
        }
    }

    pub async fn copy_messages(
        &self,
        username: &str,
        sequence_set: &str,
        _target_mailbox: &str,
    ) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Email>("emails");

            let filter = doc! { "user_id": username, "sequence_number": sequence_set.parse::<u32>().unwrap_or(0) };
            if let Some(mut email) = collection.find_one(filter).await? {
                email.id = format!("{}_{}", email.id, Utc::now().timestamp());
                collection.insert_one(email).await?;
            }
            Ok(())
        }
        #[cfg(test)]
        {
            self.client
                .copy_messages(sequence_set, _target_mailbox)
                .await
        }
    }

    pub async fn store_flags(
        &self,
        username: &str,
        sequence_set: &str,
        flags: Vec<String>,
        mode: &str,
    ) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Email>("emails");

            let filter = doc! { "user_id": username, "sequence_number": sequence_set.parse::<u32>().unwrap_or(0) };
            let update = match mode {
                "+" => doc! { "$addToSet": { "flags": { "$each": flags } } },
                "-" => doc! { "$pullAll": { "flags": flags } },
                _ => doc! { "$set": { "flags": flags } },
            };

            collection.update_one(filter, update).await?;
            Ok(())
        }
        #[cfg(test)]
        {
            self.client.store_flags(sequence_set, flags, mode).await
        }
    }

    pub async fn check_mailbox(&self) -> Result<()> {
        Ok(())
    }

    pub async fn close_mailbox(&self, username: &str) -> Result<()> {
        self.expunge_mailbox(username).await?;
        Ok(())
    }

    pub async fn noop(&self) -> Result<()> {
        Ok(())
    }

    pub async fn get_mailbox_status(&self, username: &str, mailbox: &str) -> Result<Mailbox> {
        self.select_mailbox(username, mailbox).await
    }

    pub async fn create_mailbox(&self, username: &str, mailbox: &str) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Mailbox>("mailboxes");

            // Vérifiez si la boîte aux lettres existe déjà
            let mailbox_filter = doc! { "name": mailbox, "user_id": username };
            if collection.find_one(mailbox_filter.clone()).await?.is_none() {
                println!("Creating mailbox: {}", mailbox);
                let new_mailbox = Mailbox {
                    name: mailbox.to_string(),
                    flags: vec![],
                    exists: 0,
                    recent: 0,
                    unseen: 0,
                    permanent_flags: vec![String::from("\\*")],
                    uid_validity: 1,
                    uid_next: 1,
                    user_id: username.to_string(),
                };
                collection.insert_one(new_mailbox).await?;
                println!("Mailbox created: {}", mailbox);
            } else {
                println!("Mailbox already exists: {}", mailbox);
            }
            Ok(())
        }
        #[cfg(test)]
        {
            // Pour les tests, nous devons retourner un résultat vide
            Ok(())
        }
    }

    pub async fn delete_mailbox(&self, username: &str, mailbox: &str) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Mailbox>("mailboxes");

            let filter = doc! { "user_id": username, "name": mailbox };
            collection.delete_one(filter).await?;

            Ok(())
        }
        #[cfg(test)]
        {
            //For test, we need to return an empty result
            Ok(())
        }
    }

    pub async fn rename_mailbox(
        &self,
        username: &str,
        old_name: &str,
        new_name: &str,
    ) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Mailbox>("mailboxes");

            let filter = doc! { "user_id": username, "name": old_name };
            let update = doc! { "$set": { "name": new_name } };
            collection.update_one(filter, update).await?;
            Ok(())
        }
        #[cfg(test)]
        {
            //For test, we need to return an empty result
            Ok(())
        }
    }

    pub async fn subscribe_mailbox(&self, username: &str, mailbox: &str) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<User>("subscriptions");

            let filter = doc! { "user_id": username, "mailbox": mailbox };
            let update = doc! { "$set": { "subscribed": true } };
            collection.update_one(filter, update).await?;
            Ok(())
        }
        #[cfg(test)]
        {
            //For test, we need to return an empty result
            Ok(())
        }
    }

    pub async fn unsubscribe_mailbox(&self, username: &str, mailbox: &str) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<User>("subscriptions");

            let filter = doc! { "user_id": username, "mailbox": mailbox };
            let update = doc! { "$set": { "subscribed": false } };
            collection.update_one(filter, update).await?;
            Ok(())
        }
        #[cfg(test)]
        {
            //For test, we need to return an empty result
            Ok(())
        }
    }

    pub async fn list_subscribed_mailboxes(
        &self,
        username: &str,
        _reference: &str,
        _pattern: &str,
    ) -> Result<Vec<String>> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<User>("subscriptions");

            let filter = doc! { "user_id": username, "subscribed": true };
            let mut cursor = collection.find(filter).await?;
            let mut mailboxes = Vec::new();

            while let Some(subscription) = cursor.try_next().await? {
                mailboxes.push(subscription.mailbox);
            }

            Ok(mailboxes)
        }
        #[cfg(test)]
        {
            self.client
                .list_subscribed_mailboxes(username, _reference, _pattern)
                .await
        }
    }

    pub async fn get_mailbox_status_items(
        &self,
        username: &str,
        mailbox: &str,
        items: &str,
    ) -> Result<String> {
        #[cfg(not(test))]
        {
            let status = self.select_mailbox(username, mailbox).await?;
            let mut response = Vec::new();

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
        #[cfg(test)]
        {
            //For test, we need to return an empty result
            Ok(String::new())
        }
    }

    pub async fn store_email(&self, username: &str, mailbox: &str, email: &Email) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<mongodb::bson::Document>("emails");

            // Count existing emails to generate sequence_number and uid
            let count = collection
                .count_documents(doc! {"user_id": username, "mailbox": mailbox})
                .await?;
            let sequence_number = (count + 1) as u32;
            let uid = (count + 1) as u32;

            // Serialize the Email struct into a BSON document
            let mut document = bson::to_document(email)?;
            document.insert("user_id", username);
            document.insert("mailbox", mailbox);
            document.insert("sequence_number", sequence_number as i64);
            document.insert("uid", uid as i64);
            // Store internal_date as BSON datetime
            document.insert(
                "internal_date",
                mongodb::bson::DateTime::from_millis(email.internal_date.timestamp_millis()),
            );
            // Insert the document into the collection
            collection.insert_one(document).await?;
            Ok(())
        }
        #[cfg(test)]
        {
            Ok(())
        }
    }

    pub async fn list_mailboxes(
        &self,
        username: &str,
        reference: &str,
        mailbox: &str,
    ) -> Result<Vec<String>> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Mailbox>("mailboxes");

            let filter = doc! {
                "user_id": username,
                "name": { "$regex": format!("^{}.*{}", reference, mailbox) }
            };

            let cursor = collection.find(filter).await?;
            let mailboxes: Vec<String> = cursor.map_ok(|doc| doc.name).try_collect().await?;
            Ok(mailboxes)
        }
        #[cfg(test)]
        {
            Ok(vec![
                "inbox".to_string(),
                "sent".to_string(),
                "drafts".to_string(),
            ])
        }
    }

    // --- Calendar Event CRUD ---
}
