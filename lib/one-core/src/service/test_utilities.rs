use std::collections::HashMap;
use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use indoc::indoc;
use serde::{Deserialize, Serialize};
use shared_types::DidValue;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::core_config::AppConfig;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialState, CredentialStateEnum};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaType, LayoutType,
    WalletStorageTypeEnum,
};
use crate::model::did::{Did, DidType};
use crate::model::interaction::Interaction;
use crate::model::key::{Key, PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::model::proof_schema::ProofSchema;
use crate::provider::credential_formatter::json_ld::context::caching_loader::JsonLdCachingLoader;
use crate::provider::credential_formatter::model::FormatterCapabilities;
use crate::provider::did_method::model::{DidDocument, DidVerificationMethod};
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::provider::remote_entity_storage::{RemoteEntity, RemoteEntityType};

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
                        refreshExpiresIn: 886400
            ISO_MDL:
                type: 'ISO_MDL'
                display: 'exchange.isoMdl'
                order: 3
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
        issuer_did: Some(dummy_did()),
        holder_did: None,
        schema: Some(CredentialSchema {
            id: Uuid::new_v4().into(),
            deleted_at: None,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "schema".to_string(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            format: "format".to_string(),
            imported_source_url: "CORE_URL".to_string(),
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
            allow_suspension: true,
        }),
        interaction: Some(Interaction {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            host: Some("http://www.host.co".parse().unwrap()),
            data: Some(b"interaction data".to_vec()),
            organisation: None,
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
            imported_source_url: Some("CORE_URL".to_string()),
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

pub fn dummy_key() -> Key {
    Key {
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
        imported_source_url: Some("CORE_URL".to_string()),
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
        wallet_storage_type: Some(WalletStorageTypeEnum::Software),
        imported_source_url: "CORE_URL".to_string(),
        format: "format".to_string(),
        revocation_method: "format".to_string(),
        claim_schemas: None,
        organisation: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_type: CredentialSchemaType::ProcivisOneSchema2024,
        schema_id: "CredentialSchemaId".to_owned(),
        allow_suspension: true,
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
        verification_key_storages: vec!["INTERNAL".to_string()],
        datatypes: vec![],
        forbidden_claim_names: vec![],
    }
}

pub fn prepare_caching_loader(additional: Option<(&str, &str)>) -> JsonLdCachingLoader {
    let mut contexts = vec![
        (
            "https://www.w3.org/ns/credentials/v2".to_string(),
            RemoteEntity {
                last_modified: OffsetDateTime::now_utc(),
                entity_type: RemoteEntityType::JsonLdContext,
                key: "https://www.w3.org/ns/credentials/v2".to_string(),
                value: W3_ORG_NS_CREDENTIALS_V2.to_string().into_bytes(),
                hit_counter: 0,
            },
        ),
        (
            "https://www.w3.org/ns/credentials/examples/v2".to_string(),
            RemoteEntity {
                last_modified: OffsetDateTime::now_utc(),
                entity_type: RemoteEntityType::JsonLdContext,
                key: "https://www.w3.org/ns/credentials/examples/v2".to_string(),
                value: W3_ORG_NS_CREDENTIALS_EXAMPLES_V2.to_string().into_bytes(),
                hit_counter: 0,
            },
        ),
    ];

    if let Some((id, content)) = additional {
        contexts.push((
            id.to_string(),
            RemoteEntity {
                last_modified: OffsetDateTime::now_utc(),
                entity_type: RemoteEntityType::JsonLdContext,
                key: id.to_string(),
                value: content.to_string().into_bytes(),
                hit_counter: 0,
            },
        ))
    }

    JsonLdCachingLoader::new(
        RemoteEntityType::JsonLdContext,
        Arc::new(InMemoryStorage::new(HashMap::from_iter(contexts))),
        10000,
        Duration::seconds(999999),
        Duration::seconds(300),
    )
}

const W3_ORG_NS_CREDENTIALS_EXAMPLES_V2: &str = r#"{
  "@context": {
    "@vocab": "https://www.w3.org/ns/credentials/examples#"
  }
}"#;

const W3_ORG_NS_CREDENTIALS_V2: &str = r#"{
  "@context": {
    "@protected": true,
    "@vocab": "https://www.w3.org/ns/credentials/issuer-dependent#",
    "id": "@id",
    "type": "@type",
    "kid": {
      "@id": "https://www.iana.org/assignments/jose#kid",
      "@type": "@id"
    },
    "iss": {
      "@id": "https://www.iana.org/assignments/jose#iss",
      "@type": "@id"
    },
    "sub": {
      "@id": "https://www.iana.org/assignments/jose#sub",
      "@type": "@id"
    },
    "jku": {
      "@id": "https://www.iana.org/assignments/jose#jku",
      "@type": "@id"
    },
    "x5u": {
      "@id": "https://www.iana.org/assignments/jose#x5u",
      "@type": "@id"
    },
    "aud": {
      "@id": "https://www.iana.org/assignments/jwt#aud",
      "@type": "@id"
    },
    "exp": {
      "@id": "https://www.iana.org/assignments/jwt#exp",
      "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
    },
    "nbf": {
      "@id": "https://www.iana.org/assignments/jwt#nbf",
      "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
    },
    "iat": {
      "@id": "https://www.iana.org/assignments/jwt#iat",
      "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
    },
    "cnf": {
      "@id": "https://www.iana.org/assignments/jwt#cnf",
      "@context": {
        "@protected": true,
        "kid": {
          "@id": "https://www.iana.org/assignments/jwt#kid",
          "@type": "@id"
        },
        "jwk": {
          "@id": "https://www.iana.org/assignments/jwt#jwk",
          "@type": "@json"
        }
      }
    },
    "_sd_alg": {
      "@id": "https://www.iana.org/assignments/jwt#_sd_alg"
    },
    "_sd": {
      "@id": "https://www.iana.org/assignments/jwt#_sd"
    },
    "...": {
      "@id": "https://www.iana.org/assignments/jwt#..."
    },
    "digestSRI": {
      "@id": "https://www.w3.org/2018/credentials#digestSRI",
      "@type": "https://www.w3.org/2018/credentials#sriString"
    },
    "digestMultibase": {
      "@id": "https://w3id.org/security#digestMultibase",
      "@type": "https://w3id.org/security#multibase"
    },
    "mediaType": {
      "@id": "https://schema.org/encodingFormat"
    },
    "description": "https://schema.org/description",
    "name": "https://schema.org/name",
    "EnvelopedVerifiableCredential": "https://www.w3.org/2018/credentials#EnvelopedVerifiableCredential",
    "VerifiableCredential": {
      "@id": "https://www.w3.org/2018/credentials#VerifiableCredential",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "credentialSchema": {
          "@id": "https://www.w3.org/2018/credentials#credentialSchema",
          "@type": "@id"
        },
        "credentialStatus": {
          "@id": "https://www.w3.org/2018/credentials#credentialStatus",
          "@type": "@id"
        },
        "credentialSubject": {
          "@id": "https://www.w3.org/2018/credentials#credentialSubject",
          "@type": "@id"
        },
        "description": "https://schema.org/description",
        "evidence": {
          "@id": "https://www.w3.org/2018/credentials#evidence",
          "@type": "@id"
        },
        "validFrom": {
          "@id": "https://www.w3.org/2018/credentials#validFrom",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "validUntil": {
          "@id": "https://www.w3.org/2018/credentials#validUntil",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "issuer": {
          "@id": "https://www.w3.org/2018/credentials#issuer",
          "@type": "@id"
        },
        "name": "https://schema.org/name",
        "proof": {
          "@id": "https://w3id.org/security#proof",
          "@type": "@id",
          "@container": "@graph"
        },
        "refreshService": {
          "@id": "https://www.w3.org/2018/credentials#refreshService",
          "@type": "@id"
        },
        "termsOfUse": {
          "@id": "https://www.w3.org/2018/credentials#termsOfUse",
          "@type": "@id"
        },
        "confidenceMethod": {
          "@id": "https://www.w3.org/2018/credentials#confidenceMethod",
          "@type": "@id"
        },
        "relatedResource": {
          "@id": "https://www.w3.org/2018/credentials#relatedResource",
          "@type": "@id"
        }
      }
    },
    "VerifiablePresentation": {
      "@id": "https://www.w3.org/2018/credentials#VerifiablePresentation",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "holder": {
          "@id": "https://www.w3.org/2018/credentials#holder",
          "@type": "@id"
        },
        "proof": {
          "@id": "https://w3id.org/security#proof",
          "@type": "@id",
          "@container": "@graph"
        },
        "verifiableCredential": {
          "@id": "https://www.w3.org/2018/credentials#verifiableCredential",
          "@type": "@id",
          "@container": "@graph",
          "@context": null
        },
        "termsOfUse": {
          "@id": "https://www.w3.org/2018/credentials#termsOfUse",
          "@type": "@id"
        }
      }
    },
    "JsonSchemaCredential": "https://www.w3.org/2018/credentials#JsonSchemaCredential",
    "JsonSchema": {
      "@id": "https://www.w3.org/2018/credentials#JsonSchema",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "jsonSchema": {
          "@id": "https://w3.org/2018/credentials#jsonSchema",
          "@type": "@json"
        }
      }
    },
    "BitstringStatusListCredential": "https://www.w3.org/ns/credentials/status#BitstringStatusListCredential",
    "BitstringStatusList": {
      "@id": "https://www.w3.org/ns/credentials/status#BitstringStatusList",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "statusPurpose": "https://www.w3.org/ns/credentials/status#statusPurpose",
        "encodedList": {
          "@id": "https://www.w3.org/ns/credentials/status#encodedList",
          "@type": "https://w3id.org/security#multibase"
        },
        "ttl": "https://www.w3.org/ns/credentials/status#ttl",
        "statusReference": {
          "@id": "https://www.w3.org/ns/credentials/status#statusReference",
          "@type": "@id"
        },
        "statusSize": {
          "@id": "https://www.w3.org/ns/credentials/status#statusSize",
          "@type": "https://www.w3.org/2001/XMLSchema#positiveInteger"
        },
        "statusMessage": {
          "@id": "https://www.w3.org/ns/credentials/status#statusMessage",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "status": "https://www.w3.org/ns/credentials/status#status",
            "message": "https://www.w3.org/ns/credentials/status#message"
          }
        }
      }
    },
    "BitstringStatusListEntry": {
      "@id": "https://www.w3.org/ns/credentials/status#BitstringStatusListEntry",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "statusPurpose": "https://www.w3.org/ns/credentials/status#statusPurpose",
        "statusListIndex": "https://www.w3.org/ns/credentials/status#statusListIndex",
        "statusListCredential": {
          "@id": "https://www.w3.org/ns/credentials/status#statusListCredential",
          "@type": "@id"
        }
      }
    },
    "DataIntegrityProof": {
      "@id": "https://w3id.org/security#DataIntegrityProof",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "challenge": "https://w3id.org/security#challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "domain": "https://w3id.org/security#domain",
        "expires": {
          "@id": "https://w3id.org/security#expiration",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "nonce": "https://w3id.org/security#nonce",
        "previousProof": {
          "@id": "https://w3id.org/security#previousProof",
          "@type": "@id"
        },
        "proofPurpose": {
          "@id": "https://w3id.org/security#proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "assertionMethod": {
              "@id": "https://w3id.org/security#assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "https://w3id.org/security#authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "capabilityInvocation": {
              "@id": "https://w3id.org/security#capabilityInvocationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "capabilityDelegation": {
              "@id": "https://w3id.org/security#capabilityDelegationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "keyAgreement": {
              "@id": "https://w3id.org/security#keyAgreementMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "cryptosuite": {
          "@id": "https://w3id.org/security#cryptosuite",
          "@type": "https://w3id.org/security#cryptosuiteString"
        },
        "proofValue": {
          "@id": "https://w3id.org/security#proofValue",
          "@type": "https://w3id.org/security#multibase"
        },
        "verificationMethod": {
          "@id": "https://w3id.org/security#verificationMethod",
          "@type": "@id"
        }
      }
    }
  }
}"#;

pub fn dummy_did_document(did: &DidValue) -> DidDocument {
    DidDocument {
        context: serde_json::json!({}),
        id: did.clone(),
        verification_method: vec![DidVerificationMethod {
            id: "did-vm-id".to_string(),
            r#type: "did-vm-type".to_string(),
            controller: "did-vm-controller".to_string(),
            public_key_jwk: PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
                r#use: None,
                crv: "P-256".to_string(),
                x: Base64UrlSafeNoPadding::encode_to_string("xabc").unwrap(),
                y: Some(Base64UrlSafeNoPadding::encode_to_string("yabc").unwrap()),
            }),
        }],
        authentication: None,
        assertion_method: Some(vec!["did-vm-id".to_string()]),
        key_agreement: None,
        capability_invocation: None,
        capability_delegation: None,
        rest: Default::default(),
    }
}
