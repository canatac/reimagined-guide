use super::super::*;
use crate::entities::Email;
use crate::logic::Logic;
use mockall::predicate::eq;

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

