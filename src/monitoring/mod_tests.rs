    use super::*;

    #[test]
    fn test_risk_score_forbidden_country() {
        std::env::set_var("MONITORING_FORBIDDEN_COUNTRIES", "CN,RU");
        let mut ev = SmtpEvent::new("mid1", SmtpEventType::Delivered, "a@b.com", "c@d.com");
        ev.country = Some("CN".into());
        ev.company = Some("Alibaba Cloud".into());
        ev.compute_risk_score();
        assert!(ev.risk_score.unwrap() >= 50.0);
        std::env::remove_var("MONITORING_FORBIDDEN_COUNTRIES");
    }

    #[test]
    fn test_risk_score_clean() {
        let mut ev = SmtpEvent::new("mid2", SmtpEventType::Delivered, "a@b.com", "c@d.com");
        ev.country = Some("FR".into());
        ev.company = Some("OVH".into());
        ev.status = SmtpStatus::Delivered;
        ev.compute_risk_score();
        // Unknown company penalty removed since OVH is known
        assert!(ev.risk_score.unwrap() < 30.0);
    }

    #[test]
    fn test_parse_smtp_code() {
        assert_eq!(parse_smtp_code("Unexpected response: 550 User unknown"), Some(550));
        assert_eq!(parse_smtp_code("Connection refused"), None);
        assert_eq!(parse_smtp_code("421 Too many connections"), Some(421));
    }

    #[test]
    fn test_event_with_geo() {
        let ev = SmtpEvent::new("mid3", SmtpEventType::SmtpConnect, "a@b.com", "c@d.com");
        let geo = GeoInfo {
            ip: Some("1.2.3.4".into()),
            country: "DE".into(),
            city: "Frankfurt".into(),
            asn: "AS24940".into(),
            company: "Hetzner Online GmbH".into(),
            datacenter: Some("Hetzner".into()),
        };
        let ev = ev.with_geo(geo);
        assert_eq!(ev.country.as_deref(), Some("DE"));
        assert_eq!(ev.datacenter.as_deref(), Some("Hetzner"));
    }
