use indoc::indoc;
use one_providers::common_models::credential_schema::OpenWalletStorageTypeEnum;
use one_providers::credential_formatter::model::FormatterCapabilities;
use serde::{Deserialize, Serialize};
use time::macros::datetime;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::core_config::AppConfig;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialState, CredentialStateEnum};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaType, LayoutType,
};
use crate::model::did::{Did, DidType};
use crate::model::interaction::Interaction;
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::model::proof_schema::ProofSchema;
use one_providers::common_models::key::OpenKey;

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomConfig {}

pub fn generic_config() -> AppConfig<CustomConfig> {
    let config = indoc! {"
        transport:
            HTTP:
                type: 'HTTP'
                display: 'transport.http'
                disabled: false
                order: 0
                params: {}
        format:
            JWT:
                type: 'JWT'
                display: 'display'
                order: 0
                params:
                    public:
                        leeway: 60
            SDJWT:
                type: 'SDJWT'
                display: 'format.sdjwt'
                order: 1
                params:
                    public:
                        leeway: 60
            JSON_LD_CLASSIC:
                type: 'JSON_LD_CLASSIC'
                display: 'display'
                order: 2
                params: null
            PHYSICAL_CARD:
                type: 'PHYSICAL_CARD'
                display: 'format.physicalCard'
                order: 5
            MDOC:
              type: 'MDOC'
              display: 'format.mdoc'
              order: 4
              params:
                public:
                  msoExpiresIn: 259200 # 72h in seconds
                  msoExpectedUpdateIn: 86400 # 24h in seconds
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
                        refreshExpiresIn: 886400
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
            OBJECT:
                display: 'display'
                type: 'OBJECT'
                order: 300
                params: null
        keyAlgorithm:
            EDDSA:
                display: 'display'
                order: 0
                type: 'EDDSA'
                params:
                    public:
                        algorithm: 'Ed25519'
            BBS_PLUS:
                display: 'keyAlgorithm.bbs_plus'
                order: 2
                type: 'BBS_PLUS'
                params: null
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

    AppConfig::from_yaml_str_configs(vec![config]).unwrap()
}

pub fn dummy_credential() -> Credential {
    dummy_credential_with_exchange("EXCHANGE")
}

pub fn get_dummy_date() -> OffsetDateTime {
    datetime!(2005-04-02 21:37 +1)
}

pub fn dummy_credential_with_exchange(exchange: &str) -> Credential {
    let claim_schema_id = Uuid::new_v4().into();
    let credential_id = Uuid::new_v4().into();

    Credential {
        id: credential_id,
        created_date: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        credential: b"credential".to_vec(),
        exchange: exchange.to_owned(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        state: Some(vec![CredentialState {
            created_date: OffsetDateTime::now_utc(),
            state: CredentialStateEnum::Pending,
            suspend_end_date: None,
        }]),
        claims: Some(vec![Claim {
            id: Uuid::new_v4(),
            credential_id,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            value: "claim value".to_string(),
            path: "key".to_string(),
            schema: Some(ClaimSchema {
                id: claim_schema_id,
                key: "key".to_string(),
                data_type: "STRING".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: false,
            }),
        }]),
        issuer_did: None,
        holder_did: None,
        schema: Some(CredentialSchema {
            id: Uuid::new_v4().into(),
            deleted_at: None,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "schema".to_string(),
            wallet_storage_type: Some(OpenWalletStorageTypeEnum::Software),
            format: "format".to_string(),
            revocation_method: "revocation method".to_string(),
            claim_schemas: Some(vec![CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: claim_schema_id,
                    key: "key".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    array: false,
                },
                required: true,
            }]),
            organisation: Some(Organisation {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            }),
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            schema_id: "CredentialSchemaId".to_owned(),
        }),
        interaction: Some(Interaction {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            host: Some("http://www.host.co".parse().unwrap()),
            data: Some(b"interaction data".to_vec()),
        }),
        revocation_list: None,
        key: None,
    }
}

pub fn dummy_did() -> Did {
    Did {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "John".to_string(),
        did: "did".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "INTERNAL".to_string(),
        keys: None,
        organisation: Some(dummy_organisation()),
        deactivated: false,
    }
}

pub fn dummy_proof() -> Proof {
    dummy_proof_with_protocol("protocol")
}

pub fn dummy_proof_with_protocol(protocol: &str) -> Proof {
    Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        exchange: protocol.to_string(),
        transport: "HTTP".to_string(),
        redirect_uri: None,
        state: None,
        schema: Some(ProofSchema {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            deleted_at: None,
            name: "dummy".to_string(),
            expire_duration: 0,
            organisation: Some(Organisation {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            }),
            input_schemas: None,
        }),
        claims: None,
        verifier_did: None,
        holder_did: None,
        verifier_key: None,
        interaction: None,
    }
}

pub fn dummy_key() -> OpenKey {
    OpenKey {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        public_key: vec![],
        name: "dummy".into(),
        key_reference: vec![],
        storage_type: "foo".into(),
        key_type: "bar".into(),
        organisation: None,
    }
}

pub fn dummy_organisation() -> Organisation {
    Organisation {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
    }
}

pub fn dummy_proof_schema() -> ProofSchema {
    ProofSchema {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        name: "Proof schema".to_string(),
        expire_duration: 100,
        organisation: None,
        input_schemas: None,
    }
}

pub fn dummy_credential_schema() -> CredentialSchema {
    CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "name".to_string(),
        wallet_storage_type: Some(OpenWalletStorageTypeEnum::Software),
        format: "format".to_string(),
        revocation_method: "format".to_string(),
        claim_schemas: None,
        organisation: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_type: CredentialSchemaType::ProcivisOneSchema2024,
        schema_id: "CredentialSchemaId".to_owned(),
    }
}

pub fn dummy_claim_schema() -> ClaimSchema {
    ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "key".to_string(),
        data_type: "data type".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: false,
    }
}

pub fn generic_formatter_capabilities() -> FormatterCapabilities {
    FormatterCapabilities {
        signing_key_algorithms: vec!["EDDSA".to_string()],
        features: vec![],
        allowed_schema_ids: vec![],
        selective_disclosure: vec![],
        issuance_did_methods: vec![
            "KEY".to_string(),
            "WEB".to_string(),
            "JWK".to_string(),
            "X509".to_string(),
        ],
        issuance_exchange_protocols: vec![
            "OPENID4VC".to_string(),
            "PROCIVIS_TEMPORARY".to_string(),
        ],
        proof_exchange_protocols: vec!["OPENID4VC".to_string(), "PROCIVIS_TEMPORARY".to_string()],
        revocation_methods: vec![
            "NONE".to_string(),
            "BITSTRINGSTATUSLIST".to_string(),
            "LVVC".to_string(),
        ],
        verification_key_algorithms: vec!["EDDSA".to_string()],
        datatypes: vec![],
        forbidden_claim_names: vec![],
    }
}
