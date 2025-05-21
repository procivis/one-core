use std::env;

use rusty_fork::rusty_fork_test;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::core_config::*;
use crate::config::ConfigParsingError::GeneralParsingError;

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SystemConfig {
    pub database_url: String,
    pub server_ip: Option<String>,
}

rusty_fork_test! {
    #[test]
    #[cfg(all(
        feature = "config_yaml",
        feature = "config_json",
        feature = "config_env"
    ))]
    fn test_parse_config() {
        let config1 = indoc::indoc! {"
            app:
                databaseUrl: 'test'
            format:
                JWT:
                    type: 'JWT'
                    display: 'display'
                    order: 0
                    params:
                        public:
                            leeway: 60
        "};

        let config2 = indoc::indoc! {"
            app:
                databaseUrl: 'test2'
                serverIp: '127.0.0.1'
            format:
                JWT:
                    params:
                        public:
                            leeway: 90
            transport:
                HTTP:
                    type: 'HTTP'
                    display: 'transport.http'
                    enabled: true
                    order: 0
                    params: {}
            identifier:
              DID:
                display: 'identifier.did'
                enabled: true
                order: 0
            issuanceProtocol:
                OPENID4VCI_DRAFT13:
                    display: 'display'
                    order: 1
                    type: 'OPENID4VCI_DRAFT13'
                    params:
                        public:
                            preAuthorizedCodeExpiresIn: 300
                            tokenExpiresIn: 86400
            verificationProtocol:
                OPENID4VP_DRAFT20:
                    display: 'display'
                    order: 1
                    type: 'OPENID4VP_DRAFT20'
                    params:
                        public:
                            useRequestUri: true
            revocation:
                NONE:
                    display: 'revocation.none'
                    order: 0
                    type: 'NONE'
                    params: null
                BITSTRINGSTATUSLIST:
                    display: 'display'
                    order: 1
                    type: 'BITSTRINGSTATUSLIST'
                    params: null
            did:
                KEY:
                    display: 'did.key'
                    order: 0
                    type: 'KEY'
                    params: null
            datatype:
                STRING:
                    display: 'display'
                    type: 'STRING'
                    order: 100
                    params: null
                NUMBER:
                    display: 'display'
                    type: 'NUMBER'
                    order: 200
                    params: null
            keyAlgorithm:
                EDDSA:
                    display: 'display'
                    order: 0
            keyStorage:
                INTERNAL:
                    display: 'display'
                    type: 'INTERNAL'
                    order: 0
                    params: null
            task: {}
            trustManagement: {}
            cacheEntities: {}
        "};

        let config3 = indoc::indoc! {"
            keyAlgorithm:
                EDDSA:
                    order: 10
        "};

        let config4 = indoc::indoc! {"
            keyAlgorithm:
                BBS_PLUS:
                    order: 10
                    display: 'display'
        "};

        #[cfg(feature = "config_json")]
        let config5 = indoc::indoc! {"
        {
            \"keyAlgorithm\": {
                \"BBS_PLUS\": {
                    \"order\": 15,
                    \"display\": \"display\"
                }
            }
        }
        "};

        // SAFETY: `rusty_fork` spawns each test as separate subprocess so that should be safe
        unsafe {
            env::set_var("ONE_keyAlgorithm__BBS_PLUS__display", "NewDisplay");
            env::set_var("ONE_app__serverIp", "192.168.1.1");
        };

        let config = AppConfig::<SystemConfig>::parse(vec![
            InputFormat::yaml_str(config1),
            InputFormat::yaml_str(config2),
            InputFormat::yaml_str(config3),
            InputFormat::yaml_str(config4),
            InputFormat::yaml_str(config5),
        ])
        .unwrap();

        if let Ok(db_url) = std::env::var("ONE_app__databaseUrl") {
            assert_eq!(config.app.database_url, db_url); // via env_var
        } else {
            assert_eq!(config.app.database_url, "test2"); // via config2
        }

        let jwt = config.core.format.get_fields("JWT").unwrap();

        assert_eq!(
            jwt.params.as_ref().unwrap().public,
            Some(json!({ "leeway": 90 })) // via config 2
        );

        let eddsa = config
            .core
            .key_algorithm
            .get(&KeyAlgorithmType::Eddsa)
            .unwrap();

        assert_eq!(eddsa.order, Some(10)); // via config 3

        let bbs_plus = config
            .core
            .key_algorithm
            .get(&KeyAlgorithmType::BbsPlus)
            .unwrap();

        assert_eq!(bbs_plus.order, Some(15));

        assert_eq!(bbs_plus.display, ConfigEntryDisplay::from("NewDisplay")); // via env 2

        assert_eq!(config.app.server_ip, Some("192.168.1.1".into())); // via env 3
    }
}

rusty_fork_test! {
    #[test]
    #[cfg(all(
        feature = "config_yaml",
        feature = "config_json",
        feature = "config_env"
    ))]
    fn test_parse_config_missing_field() {
        // given
        let config1 = indoc::indoc! {"
            app:
                databaseUrl: 'test'
            format:
                JWT:
                    type: 'JWT'
                    display: 'display'
                    order: 0
                    params:
                        public:
                            leeway: 60
            identifier:
              DID:
                enabled: true
                order: 0
        "};

        // when
        let config = AppConfig::<SystemConfig>::parse(vec![
            InputFormat::yaml_str(config1),
        ]);

        // then
        assert!(
            matches!(
                config,
                Err(GeneralParsingError(m)) if m == "missing field `display` for key \"default.identifier.DID\" in YAML source string")
        )
    }
}
