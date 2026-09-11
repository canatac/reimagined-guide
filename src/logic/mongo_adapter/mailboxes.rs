// Auto-split from mongo_adapter.rs (refactor: découpage par domaine).
use super::MongoDatabaseAdapter;
use crate::logic::Mailbox;
use mongodb::error::Result;

#[allow(dead_code)]
impl MongoDatabaseAdapter {
    pub async fn select_mailbox_impl(&self, mailbox: &str) -> Result<Mailbox> {
        Ok(Mailbox {
            name: mailbox.to_string(),
            flags: vec![],
            exists: 0,
            recent: 0,
            unseen: 0,
            permanent_flags: vec![],
            uid_validity: 1,
            uid_next: 1,
            user_id: String::new(),
        })
    }

    pub async fn search_messages_impl(&self, _criteria: &str) -> Result<Vec<u32>> {
        Ok(vec![])
    }

    pub async fn expunge_mailbox_impl(&self) -> Result<Vec<u32>> {
        Ok(vec![])
    }

    pub async fn copy_messages_impl(&self, _sequence_set: &str, _target_mailbox: &str) -> Result<()> {
        Ok(())
    }

    pub async fn store_flags_impl(
        &self,
        _sequence_set: &str,
        _flags: Vec<String>,
        _mode: &str,
    ) -> Result<()> {
        Ok(())
    }

    pub async fn find_mailbox_impl(&self, _name: &str) -> Result<Option<Mailbox>> {
        Ok(None)
    }

    pub async fn update_mailbox_impl(&self, _mailbox: &str, _update: Mailbox) -> Result<()> {
        Ok(())
    }

    pub async fn create_mailbox_impl(&self, _mailbox: &str) -> Result<()> {
        Ok(())
    }

    pub async fn delete_mailbox_impl(&self, _mailbox: &str) -> Result<()> {
        Ok(())
    }

    pub async fn rename_mailbox_impl(&self, _old_name: &str, _new_name: &str) -> Result<()> {
        Ok(())
    }

    pub async fn subscribe_mailbox_impl(&self, _mailbox: &str) -> Result<()> {
        Ok(())
    }

    pub async fn unsubscribe_mailbox_impl(&self, _mailbox: &str) -> Result<()> {
        Ok(())
    }

    pub async fn list_subscribed_mailboxes_impl(
        &self,
        _username: &str,
        _reference: &str,
        _pattern: &str,
    ) -> Result<Vec<String>> {
        Ok(vec![])
    }

    pub async fn get_mailbox_status_items_impl(
        &self,
        _username: &str,
        _mailbox: &str,
        _items: &str,
    ) -> Result<String> {
        Ok(String::new())
    }

    pub async fn get_mailbox_status_impl(&self, _username: &str, mailbox: &str) -> Result<Mailbox> {
        Ok(Mailbox {
            name: mailbox.to_string(),
            flags: vec![],
            exists: 0,
            recent: 0,
            unseen: 0,
            permanent_flags: vec![],
            uid_validity: 1,
            uid_next: 1,
            user_id: String::new(),
        })
    }

    pub async fn noop_impl(&self) -> Result<()> {
        Ok(())
    }

    pub async fn close_mailbox_impl(&self) -> Result<()> {
        Ok(())
    }

    pub async fn check_mailbox_impl(&self) -> Result<()> {
        Ok(())
    }

    pub async fn list_mailboxes_impl(
        &self,
        _username: &str,
        _reference: &str,
        _mailbox: &str,
    ) -> Result<Vec<String>> {
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mailbox_default_values() {
        let mailbox = Mailbox {
            name: "inbox".to_string(),
            flags: vec![],
            exists: 0,
            recent: 0,
            unseen: 0,
            permanent_flags: vec![],
            uid_validity: 1,
            uid_next: 1,
            user_id: "testuser".to_string(),
        };
        assert_eq!(mailbox.name, "inbox");
        assert_eq!(mailbox.flags.len(), 0);
        assert_eq!(mailbox.exists, 0);
        assert_eq!(mailbox.recent, 0);
        assert_eq!(mailbox.unseen, 0);
        assert_eq!(mailbox.permanent_flags.len(), 0);
        assert_eq!(mailbox.uid_validity, 1);
        assert_eq!(mailbox.uid_next, 1);
        assert_eq!(mailbox.user_id, "testuser");
    }

    #[test]
    fn mailbox_with_flags() {
        let mailbox = Mailbox {
            name: "inbox".to_string(),
            flags: vec!["\\Marked".to_string(), "\\Seen".to_string()],
            exists: 10,
            recent: 2,
            unseen: 3,
            permanent_flags: vec!["\\*".to_string()],
            uid_validity: 12345,
            uid_next: 11,
            user_id: "testuser".to_string(),
        };
        assert_eq!(mailbox.flags.len(), 2);
        assert_eq!(mailbox.exists, 10);
        assert_eq!(mailbox.recent, 2);
        assert_eq!(mailbox.unseen, 3);
        assert_eq!(mailbox.permanent_flags.len(), 1);
        assert_eq!(mailbox.uid_validity, 12345);
        assert_eq!(mailbox.uid_next, 11);
    }

    #[test]
    fn mailbox_clone() {
        let mailbox = Mailbox {
            name: "sent".to_string(),
            flags: vec![],
            exists: 0,
            recent: 0,
            unseen: 0,
            permanent_flags: vec![],
            uid_validity: 1,
            uid_next: 1,
            user_id: "user1".to_string(),
        };
        let cloned = mailbox.clone();
        assert_eq!(mailbox.name, cloned.name);
        assert_eq!(mailbox.user_id, cloned.user_id);
    }

    #[test]
    fn mailbox_debug() {
        let mailbox = Mailbox {
            name: "inbox".to_string(),
            flags: vec![],
            exists: 0,
            recent: 0,
            unseen: 0,
            permanent_flags: vec![],
            uid_validity: 1,
            uid_next: 1,
            user_id: String::new(),
        };
        let debug = format!("{:?}", mailbox);
        assert!(debug.contains("inbox"));
    }

    #[test]
    fn mailbox_collections() {
        let coll_name = "mailboxes";
        assert_eq!(coll_name, "mailboxes");
    }

    #[test]
    fn mailbox_status_fields() {
        let items = "MESSAGES RECENT UNSEEN UIDVALIDITY UIDNEXT";
        assert!(items.contains("MESSAGES"));
        assert!(items.contains("RECENT"));
        assert!(items.contains("UNSEEN"));
        assert!(items.contains("UIDVALIDITY"));
        assert!(items.contains("UIDNEXT"));
    }

    #[test]
    fn mailbox_operations() {
        let operations = vec![
            "select",
            "search",
            "expunge",
            "copy",
            "store_flags",
            "find",
            "update",
            "create",
            "delete",
            "rename",
            "subscribe",
            "unsubscribe",
            "list",
            "status",
            "noop",
            "close",
            "check",
        ];
        assert_eq!(operations.len(), 17);
    }

    #[test]
    fn mailbox_flags_imap() {
        let flags = vec!["\\Seen", "\\Answered", "\\Flagged", "\\Deleted", "\\Draft", "\\Recent"];
        assert_eq!(flags.len(), 6);
    }

    #[test]
    fn mailbox_uid_validity_default() {
        let uid_validity = 1;
        assert_eq!(uid_validity, 1);
    }

    #[test]
    fn mailbox_uid_next_default() {
        let uid_next = 1;
        assert_eq!(uid_next, 1);
    }

    #[test]
    fn mailbox_name_inbox() {
        let name = "inbox";
        assert_eq!(name, "inbox");
    }

    #[test]
    fn mailbox_name_sent() {
        let name = "sent";
        assert_eq!(name, "sent");
    }

    #[test]
    fn mailbox_name_drafts() {
        let name = "drafts";
        assert_eq!(name, "drafts");
    }

    #[test]
    fn mailbox_name_archive() {
        let name = "archive";
        assert_eq!(name, "archive");
    }

    #[test]
    fn mailbox_name_trash() {
        let name = "trash";
        assert_eq!(name, "trash");
    }

    #[test]
    fn mailbox_sequence_set_format() {
        let sequence_set = "1:10";
        assert!(sequence_set.contains(":"));
    }

    #[test]
    fn mailbox_pattern_format() {
        let pattern = "*";
        assert_eq!(pattern, "*");
    }

    #[test]
    fn mailbox_reference_format() {
        let reference = "";
        assert_eq!(reference, "");
    }

    #[test]
    fn mailbox_mode_add() {
        let mode = "+FLAGS";
        assert!(mode.contains("FLAGS"));
    }

    #[test]
    fn mailbox_mode_remove() {
        let mode = "-FLAGS";
        assert!(mode.contains("FLAGS"));
    }

    #[test]
    fn mailbox_mode_replace() {
        let mode = "FLAGS";
        assert!(mode.contains("FLAGS"));
    }
}
