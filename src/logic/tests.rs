    use super::*;
    use crate::entities::Email;
    use crate::logic::Logic;
    use dotenv::dotenv;
    use mockall::predicate::eq;

    #[tokio::test]
    async fn test_create_user() {
        dotenv::from_filename(".env.test").ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());
        let test_password = uuid::Uuid::new_v4().to_string();

        mock_client
            .expect_insert_user()
            .times(1)
            .returning(|_user| Ok(()));

        let logic = Logic::new_with_mock(mock_client);
        let result = logic
            .create_user("testuser", &test_password, "testmailbox")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_authenticate_user() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());
        let test_password = uuid::Uuid::new_v4().to_string();
        let expected_password = test_password.clone();

        mock_client
            .expect_find_user()
            .with(eq("testuser"), eq(test_password.as_str()))
            .times(1)
            .returning(move |_, _| {
                Ok(Some(User {
                    id: None,
                    username: "testuser".to_string(),
                    password: expected_password.clone(),
                    mailbox: "testmailbox".to_string(),
                    condition_accepted: false,
                }))
            });

        let logic = Logic::new_with_mock(mock_client);
        let user = logic
            .authenticate_user("testuser", &test_password)
            .await
            .unwrap();
        assert!(user.is_some());
    }

    #[tokio::test]
    async fn test_get_emails() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_find_emails()
            .with(eq("testmailbox"))
            .times(1)
            .returning(|_| {
                Ok(vec![Email::new(
                    "1",
                    "from@test.com",
                    "to@test.com",
                    "Test Subject",
                    "Test Body",
                )])
            });

        let logic = Logic::new_with_mock(mock_client);
        let emails = logic.get_emails("testuser", "testmailbox").await.unwrap();
        assert!(!emails.is_empty());
    }

    #[tokio::test]
    async fn test_fetch_email() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_find_email()
            .with(eq("testemail"))
            .times(1)
            .returning(|_| {
                Ok(Some(Email::new(
                    "testemail",
                    "from@test.com",
                    "to@test.com",
                    "Test Subject",
                    "Test Body",
                )))
            });

        let logic = Logic::new_with_mock(mock_client);
        let email = logic.fetch_email("testuser", "testemail").await.unwrap();
        assert!(email.is_some());
    }

    #[tokio::test]
    async fn test_store_email_flag() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_update_email_flag()
            .with(eq("testemail"), eq("Seen"))
            .times(1)
            .returning(|_, _| Ok(()));

        let logic = Logic::new_with_mock(mock_client);
        let result = logic
            .store_email_flag("testuser", "testemail", "Seen")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_delete_email() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_delete_email()
            .with(eq("testemail"))
            .times(1)
            .returning(|_| Ok(()));

        let logic = Logic::new_with_mock(mock_client);
        let result = logic.delete_email("testuser", "testemail").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_archive_email() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_archive_email()
            .with(eq("testemail"))
            .times(1)
            .returning(|_| Ok(()));

        let logic = Logic::new_with_mock(mock_client);
        let result = logic.archive_email("testuser", "testemail").await;
        assert!(result.is_ok());
    }

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

    #[tokio::test]
    async fn test_store_email() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_store_email()
            .times(1)
            .returning(|_, _, _| Ok(()));

        let email = Email::new(
            "testemail",
            "from@test.com",
            "to@test.com",
            "Test Subject",
            "Test Body",
        );
        let logic = Logic::new_with_mock(mock_client);
        let result = logic.store_email("testuser", "testmailbox", &email).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_list_mailboxes() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_list_mailboxes()
            .with(eq("testuser"), eq("*"), eq("testmailbox"))
            .times(1)
            .returning(|_, _, _| {
                Ok(vec![
                    "inbox".to_string(),
                    "sent".to_string(),
                    "drafts".to_string(),
                ])
            });

        let logic = Logic::new_with_mock(mock_client);
        let mailboxes = logic
            .list_mailboxes("testuser", "*", "testmailbox")
            .await
            .unwrap();
        assert_eq!(mailboxes, vec!["inbox", "sent", "drafts"]);
    }
