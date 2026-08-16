use super::super::*;
use crate::entities::Email;
use crate::logic::Logic;
use mockall::predicate::eq;

    #[tokio::test]
    async fn test_select_mailbox() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_select_mailbox()
            .with(eq("testmailbox"))
            .times(1)
            .returning(|name| {
                Ok(Mailbox {
                    name: name.to_string(),
                    flags: vec![],
                    exists: 0,
                    recent: 0,
                    unseen: 0,
                    permanent_flags: vec![],
                    uid_validity: 1,
                    uid_next: 1,
                    user_id: "testuser".to_string(),
                })
            });

        let logic = Logic::new_with_mock(mock_client);
        let mailbox = logic
            .select_mailbox("testuser", "testmailbox")
            .await
            .unwrap();
        assert_eq!(mailbox.name, "testmailbox");
    }

    #[tokio::test]
    async fn test_search_messages() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_search_messages()
            .with(eq("ALL"))
            .times(1)
            .returning(|_| Ok(vec![1, 2, 3]));

        let logic = Logic::new_with_mock(mock_client);
        let messages = logic.search_messages("testuser", "ALL").await.unwrap();
        assert!(!messages.is_empty());
    }

    #[tokio::test]
    async fn test_expunge_mailbox() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_expunge_mailbox()
            .times(1)
            .returning(|| Ok(vec![1, 2, 3]));

        let logic = Logic::new_with_mock(mock_client);
        let result = logic.expunge_mailbox("testuser").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_copy_messages() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_copy_messages()
            .with(eq("1"), eq("testmailbox"))
            .times(1)
            .returning(|_, _| Ok(()));

        let logic = Logic::new_with_mock(mock_client);
        let result = logic.copy_messages("testuser", "1", "testmailbox").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_store_flags() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_store_flags()
            .with(eq("1"), eq(vec!["Seen".to_string()]), eq("+"))
            .times(1)
            .returning(|_, _, _| Ok(()));

        let logic = Logic::new_with_mock(mock_client);
        let result = logic
            .store_flags("testuser", "1", vec!["Seen".to_string()], "+")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_noop() {
        dotenv().ok();
        let mock_client = Box::new(MockDatabaseInterface::new());
        let logic = Logic::new_with_mock(mock_client);
        let result = logic.noop().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_mailbox_status() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_select_mailbox()
            .with(eq("testmailbox"))
            .times(1)
            .returning(|name| {
                Ok(Mailbox {
                    name: name.to_string(),
                    flags: vec![],
                    exists: 0,
                    recent: 0,
                    unseen: 0,
                    permanent_flags: vec![],
                    uid_validity: 1,
                    uid_next: 1,
                    user_id: "testuser".to_string(),
                })
            });

        let logic = Logic::new_with_mock(mock_client);
        let mailbox = logic
            .get_mailbox_status("testuser", "testmailbox")
            .await
            .unwrap();
        assert_eq!(mailbox.name, "testmailbox");
    }

    #[tokio::test]
    async fn test_get_mailbox_status_items() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_get_mailbox_status_items()
            .with(
                eq("testuser"),
                eq("testmailbox"),
                eq("MESSAGES RECENT UNSEEN UIDNEXT UIDVALIDITY"),
            )
            .times(1)
            .returning(|_, _, _| {
                Ok("MESSAGES 1 RECENT 1 UNSEEN 1 UIDNEXT 2 UIDVALIDITY 1".to_string())
            });

        let logic = Logic::new_with_mock(mock_client);
        let status = logic
            .get_mailbox_status_items(
                "testuser",
                "testmailbox",
                "MESSAGES RECENT UNSEEN UIDNEXT UIDVALIDITY",
            )
            .await
            .unwrap();
        assert_eq!(
            status,
            "MESSAGES 1 RECENT 1 UNSEEN 1 UIDNEXT 2 UIDVALIDITY 1"
        );
    }

