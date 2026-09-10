use super::super::*;
use crate::entities::CalendarEvent;
use crate::logic::Logic;

    #[tokio::test]
    async fn test_create_calendar_event() {
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_create_calendar_event()
            .times(1)
            .returning(|_event| Ok(()));

        let event = CalendarEvent::new("alice", "Team Standup", chrono::Utc::now(), chrono::Utc::now() + chrono::Duration::hours(1));

        let logic = Logic::new_with_mock(mock_client);
        let result = logic.create_calendar_event(&event).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_calendar_events() {
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_get_calendar_events()
            .times(1)
            .returning(|_user, _after, _before| {
                Ok(vec![CalendarEvent::new("alice", "Meeting", chrono::Utc::now(), chrono::Utc::now() + chrono::Duration::hours(1))])
            });

        let logic = Logic::new_with_mock(mock_client);
        let events = logic
            .get_calendar_events("alice", None, None)
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].title, "Meeting");
    }

    #[tokio::test]
    async fn test_get_calendar_event_by_id() {
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_get_calendar_event()
            .times(1)
            .returning(|_user, _id| {
                Ok(Some(CalendarEvent::new("alice", "1:1", chrono::Utc::now(), chrono::Utc::now() + chrono::Duration::hours(1))))
            });

        let logic = Logic::new_with_mock(mock_client);
        let event = logic.get_calendar_event("alice", "evt-1").await.unwrap();
        assert!(event.is_some());
        assert_eq!(event.unwrap().title, "1:1");
    }

    #[tokio::test]
    async fn test_delete_calendar_event() {
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_delete_calendar_event()
            .times(1)
            .returning(|_user, _id| Ok(()));

        let logic = Logic::new_with_mock(mock_client);
        let result = logic.delete_calendar_event("alice", "evt-1").await;
        assert!(result.is_ok());
    }
