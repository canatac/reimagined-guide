use super::super::*;
use crate::entities::Email;
use crate::logic::Logic;
use mockall::predicate::eq;

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
