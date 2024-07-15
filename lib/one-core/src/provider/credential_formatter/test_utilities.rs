use mockall::predicate;
use one_providers::credential_formatter::imp::json_ld::context::caching_loader::CachingLoader;
use shared_types::DidValue;
use std::str::FromStr as _;
use std::sync::Arc;
use time::{macros::datetime, Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::core_config::JsonLdContextConfig;
use crate::model::json_ld_context::JsonLdContext;
use crate::provider::credential_formatter::json_ld::storage::db_storage::DbStorage;
use crate::repository::json_ld_context_repository::MockJsonLdContextRepository;
use crate::service::credential::dto::DetailCredentialClaimValueResponseDTO;
use crate::{
    model::{credential_schema::LayoutType, did::DidType},
    service::{
        credential::dto::{
            CredentialDetailResponseDTO, CredentialRole, CredentialSchemaType, CredentialStateEnum,
            DetailCredentialClaimResponseDTO, DetailCredentialSchemaResponseDTO,
        },
        credential_schema::dto::CredentialClaimSchemaDTO,
        did::dto::DidListItemResponseDTO,
    },
};

pub fn get_dummy_date() -> OffsetDateTime {
    datetime!(2005-04-02 21:37 +1)
}

pub fn test_credential_detail_response_dto() -> CredentialDetailResponseDTO {
    let id = Uuid::from_str("9a414a60-9e6b-4757-8011-9aa870ef4788").unwrap();

    CredentialDetailResponseDTO {
        id: id.into(),
        created_date: get_dummy_date(),
        issuance_date: get_dummy_date(),
        revocation_date: None,
        state: CredentialStateEnum::Created,
        last_modified: get_dummy_date(),
        schema: DetailCredentialSchemaResponseDTO {
            id: id.into(),
            created_date: get_dummy_date(),
            deleted_at: None,
            last_modified: get_dummy_date(),
            wallet_storage_type: None,
            name: "Credential schema name".to_string(),
            format: "Credential schema format".to_string(),
            revocation_method: "Credential schema revocation method".to_string(),
            organisation_id: id.into(),
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            schema_id: "CredentialSchemaId".to_owned(),
            layout_type: Some(LayoutType::Card),
            layout_properties: None,
        },
        issuer_did: Some(DidListItemResponseDTO {
            id: id.into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: "foo".into(),
            did: DidValue::from_str("Issuer DID").unwrap(),
            did_type: DidType::Remote,
            did_method: "KEY".into(),
            deactivated: false,
        }),
        claims: vec![
            DetailCredentialClaimResponseDTO {
                path: "name".to_string(),
                schema: CredentialClaimSchemaDTO {
                    id: id.into(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    key: "name".to_string(),
                    datatype: "STRING".to_string(),
                    required: true,
                    array: false,
                    claims: vec![],
                },
                value: DetailCredentialClaimValueResponseDTO::String("John".to_string()),
            },
            DetailCredentialClaimResponseDTO {
                path: "age".to_string(),
                schema: CredentialClaimSchemaDTO {
                    id: id.into(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    key: "age".to_string(),
                    datatype: "NUMBER".to_string(),
                    required: true,
                    array: false,
                    claims: vec![],
                },
                value: DetailCredentialClaimValueResponseDTO::String("42".to_string()),
            },
        ],
        redirect_uri: None,
        role: CredentialRole::Holder,
        lvvc_issuance_date: None,
        suspend_end_date: None,
    }
}

pub fn test_credential_detail_response_dto_with_array() -> CredentialDetailResponseDTO {
    let id = Uuid::from_str("9a414a60-9e6b-4757-8011-9aa870ef4788").unwrap();

    CredentialDetailResponseDTO {
        id: id.into(),
        created_date: get_dummy_date(),
        issuance_date: get_dummy_date(),
        revocation_date: None,
        state: CredentialStateEnum::Created,
        last_modified: get_dummy_date(),
        schema: DetailCredentialSchemaResponseDTO {
            id: id.into(),
            created_date: get_dummy_date(),
            deleted_at: None,
            last_modified: get_dummy_date(),
            wallet_storage_type: None,
            name: "Credential schema name".to_string(),
            format: "Credential schema format".to_string(),
            revocation_method: "Credential schema revocation method".to_string(),
            organisation_id: id.into(),
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            schema_id: "CredentialSchemaId".to_owned(),
            layout_type: Some(LayoutType::Card),
            layout_properties: None,
        },
        issuer_did: Some(DidListItemResponseDTO {
            id: id.into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: "foo".into(),
            did: DidValue::from_str("Issuer DID").unwrap(),
            did_type: DidType::Remote,
            did_method: "KEY".into(),
            deactivated: false,
        }),
        claims: vec![
            DetailCredentialClaimResponseDTO {
                schema: CredentialClaimSchemaDTO {
                    id: id.into(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    key: "root".to_string(),
                    datatype: "OBJECT".to_string(),
                    required: true,
                    array: false,
                    claims: vec![],
                },
                path: "root".to_string(),
                value: DetailCredentialClaimValueResponseDTO::Nested(vec![
                    DetailCredentialClaimResponseDTO {
                        schema: CredentialClaimSchemaDTO {
                            id: id.into(),
                            created_date: get_dummy_date(),
                            last_modified: get_dummy_date(),
                            key: "array".to_string(),
                            datatype: "STRING".to_string(),
                            required: true,
                            array: true,
                            claims: vec![],
                        },
                        path: "root/array".to_string(),
                        value: DetailCredentialClaimValueResponseDTO::Nested(vec![
                            DetailCredentialClaimResponseDTO {
                                schema: CredentialClaimSchemaDTO {
                                    id: id.into(),
                                    created_date: get_dummy_date(),
                                    last_modified: get_dummy_date(),
                                    key: "0".to_string(),
                                    datatype: "STRING".to_string(),
                                    required: true,
                                    array: false,
                                    claims: vec![],
                                },
                                path: "root/array/0".to_string(),
                                value: DetailCredentialClaimValueResponseDTO::String(
                                    "array_item".to_string(),
                                ),
                            },
                        ]),
                    },
                    DetailCredentialClaimResponseDTO {
                        schema: CredentialClaimSchemaDTO {
                            id: id.into(),
                            created_date: get_dummy_date(),
                            last_modified: get_dummy_date(),
                            key: "nested".to_string(),
                            datatype: "STRING".to_string(),
                            required: true,
                            array: false,
                            claims: vec![],
                        },
                        path: "root/nested".to_string(),
                        value: DetailCredentialClaimValueResponseDTO::String(
                            "nested_item".to_string(),
                        ),
                    },
                ]),
            },
            DetailCredentialClaimResponseDTO {
                schema: CredentialClaimSchemaDTO {
                    id: id.into(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    key: "root_item".to_string(),
                    datatype: "STRING".to_string(),
                    required: true,
                    array: false,
                    claims: vec![],
                },
                path: "root_item".to_string(),
                value: DetailCredentialClaimValueResponseDTO::String("root_item".to_string()),
            },
        ],
        redirect_uri: None,
        role: CredentialRole::Holder,
        lvvc_issuance_date: None,
        suspend_end_date: None,
    }
}

pub fn prepare_caching_loader() -> CachingLoader {
    let config = prepare_json_ld_context_config();

    CachingLoader {
        cache_size: config.cache_size as usize,
        cache_refresh_timeout: config.cache_refresh_timeout,
        client: Default::default(),
        json_ld_context_storage: Arc::new(DbStorage::new(Arc::new(
            prepare_json_ld_context_repository(),
        ))),
    }
}

pub fn prepare_json_ld_context_config() -> JsonLdContextConfig {
    JsonLdContextConfig {
        cache_refresh_timeout: Duration::seconds(999999),
        cache_size: 10000,
        cache_type: Default::default(),
    }
}

pub fn prepare_json_ld_context_repository() -> MockJsonLdContextRepository {
    let mut repository = MockJsonLdContextRepository::default();
    repository
        .expect_get_json_ld_context_by_url()
        .with(predicate::eq("https://www.w3.org/ns/credentials/v2"))
        .returning(|url| {
            let now = OffsetDateTime::now_utc();
            Ok(Some(JsonLdContext {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                context: W3_ORG_NS_CREDENTIALS_V2.to_string().into_bytes(),
                url: url.parse().unwrap(),
                hit_counter: 0,
            }))
        });

    repository
        .expect_get_json_ld_context_by_url()
        .with(predicate::eq(
            "https://www.w3.org/ns/credentials/examples/v2",
        ))
        .returning(|url| {
            let now = OffsetDateTime::now_utc();
            Ok(Some(JsonLdContext {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                context: W3_ORG_NS_CREDENTIALS_EXAMPLES_V2.to_string().into_bytes(),
                url: url.parse().unwrap(),
                hit_counter: 0,
            }))
        });

    repository
        .expect_update_json_ld_context()
        .returning(|_| Ok(()));
    repository
        .expect_get_repository_size()
        .returning(|| Ok(2u32));

    repository
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
