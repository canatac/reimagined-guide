use super::super::*;
use crate::entities::Email;
use crate::logic::Logic;
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

