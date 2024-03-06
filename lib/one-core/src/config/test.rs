use rusty_fork::rusty_fork_test;
use serde::{Deserialize, Serialize};

use super::core_config::*;
use serde_json::json;
use std::env;

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
            exchange:
                PROCIVIS_TEMPORARY:
                    display: 'display'
                    type: 'PROCIVIS_TEMPORARY'
                    order: 0
                    params: null
                OPENID4VC:
                    display: 'display'
                    order: 1
                    type: 'OPENID4VC'
                    params:
                        public:
                            preAuthorizedCodeExpiresIn: 300
                            tokenExpiresIn: 86400
            transport:
                HTTP:
                    type: 'HTTP'
                    display: 'transport.http'
                    order: 0
                    params: null
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
                    type: 'EDDSA'
                    params:
                        public:
                            algorithm: 'Ed25519'
            keyStorage:
                INTERNAL:
                    display: 'display'
                    type: 'INTERNAL'
                    order: 0
                    params: null
            task: {}
    "};

        let config3 = indoc::indoc! {"
            keyAlgorithm:
                EDDSA:
                    order: 10
                    type: 'EDDSA'
                    params:
                        public:
                            algorithm: 'TestAlg'
    "};

        let config4 = indoc::indoc! {"
            keyAlgorithm:
                BBS_PLUS:
                    order: 10
                    display: 'display'
                    type: 'BBS_PLUS'
                    params:
                        public:
                            algorithm: 'TestAlg'
                        private:
                            test_array: ['1', '2']
    "};

        #[cfg(feature = "config_json")]
        let config5 = indoc::indoc! {"
        {
            \"keyAlgorithm\": {
                \"BBS_PLUS\": {
                    \"order\": 15,
                    \"display\": \"display\",
                    \"type\": \"BBS_PLUS\",
                    \"params\": {
                        \"public\": {
                            \"algorithm\": \"TestAlg\"
                        },
                        \"private\": {
                            \"test_array\": [
                                \"4\",
                                \"5\",
                                \"6\"
                                ]
                            }
                        }
                    }
            }
        }
        "};

        env::set_var("ONE_exchange__PROCIVIS_TEMPORARY__order", "10");
        env::set_var("ONE_keyAlgorithm__BBS_PLUS__display", "NewDisplay");
        env::set_var("ONE_app__serverIp", "192.168.1.1");

        let config = AppConfig::<SystemConfig>::parse(vec![
            InputFormat::Yaml {
                content: config1.to_owned(),
            },
            InputFormat::Yaml {
                content: config2.to_owned(),
            },
            InputFormat::Yaml {
                content: config3.to_owned(),
            },
            InputFormat::Yaml {
                content: config4.to_owned(),
            },
            InputFormat::Json {
                content: config5.to_owned(),
            },
        ])
        .unwrap();

        assert_eq!(config.app.database_url, "test2"); // via config2

        let jwt = config.core.format.get_fields("JWT").unwrap();

        assert_eq!(
            jwt.params.as_ref().unwrap().public,
            Some(json!({ "leeway": 90 })) // via config 2
        );

        let eddsa = config
            .core
            .key_algorithm
            .get_fields("EDDSA")
            .unwrap();

        assert_eq!(eddsa.order, Some(10)); // via config 3
        assert_eq!(
            eddsa.params.as_ref().unwrap().public,
            Some(json!({ "algorithm": "TestAlg" })) // via config 3
        );

        let bbs_plus = config
            .core
            .key_algorithm
            .get_fields("BBS_PLUS")
            .ok();

        assert!(bbs_plus.is_some());

        let bbs_plus = bbs_plus.unwrap();

        assert_eq!(bbs_plus.order, Some(15));

        assert_eq!(
            bbs_plus.params.as_ref().unwrap().private,
            Some(json!({ "test_array": ["4", "5", "6"] })) // via config 5
        );

        let temporary = config
            .core
            .exchange
            .get_fields("PROCIVIS_TEMPORARY")
            .unwrap();

        assert_eq!(temporary.order, Some(10)); // via env 1

        assert_eq!(bbs_plus.display, "NewDisplay"); // via env 2

        assert_eq!(config.app.server_ip, Some("192.168.1.1".into())); // via env 3
    }
}
