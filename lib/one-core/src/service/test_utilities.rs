use std::io::Cursor;

use indoc::indoc;

use crate::config::core_config::CoreConfig;

pub fn generic_config() -> CoreConfig {
    let config = indoc! {"
        format:
            JWT:
                type: 'JWT'
                display: 'display'
                order: 0
                params:
                    public:
                        leeway: 60
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
            STATUSLIST2021:
                display: 'display'
                order: 1
                type: 'STATUSLIST2021'
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

    "};

    CoreConfig::yaml_from_reader(Cursor::new(config)).unwrap()
}
