use std::str::FromStr;

use indexmap::indexset;
use shared_types::DidValue;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::core_config::{self, DatatypeConfig, DatatypeType};
use crate::model::credential::Credential;
use crate::model::credential_schema::CredentialSchema;
use crate::model::did::{Did, DidType};
use crate::model::identifier::Identifier;
use crate::provider::credential_formatter::mapper::credential_data_from_credential_detail_response;
use crate::provider::credential_formatter::model::{PublishedClaim, PublishedClaimValue};
use crate::service::credential::dto::{
    CredentialDetailResponseDTO, CredentialRole, CredentialStateEnum,
    DetailCredentialClaimResponseDTO, DetailCredentialClaimValueResponseDTO,
    DetailCredentialSchemaResponseDTO,
};
use crate::service::credential_schema::dto::CredentialClaimSchemaDTO;
use crate::service::test_utilities::{dummy_did, dummy_identifier};

fn generate_credential_detail_response(
    claims: Vec<DetailCredentialClaimResponseDTO>,
) -> CredentialDetailResponseDTO<DetailCredentialClaimResponseDTO> {
    let now = OffsetDateTime::now_utc();

    CredentialDetailResponseDTO {
        id: Uuid::new_v4().into(),
        created_date: now,
        issuance_date: None,
        revocation_date: None,
        state: CredentialStateEnum::Created,
        last_modified: now,
        schema: DetailCredentialSchemaResponseDTO {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            imported_source_url: "CORE_URL".to_string(),
            deleted_at: None,
            name: "".to_string(),
            format: "".into(),
            revocation_method: None,
            organisation_id: Uuid::new_v4().into(),
            key_storage_security: None,
            layout_type: None,
            schema_id: "".to_string(),
            layout_properties: None,
            allow_suspension: true,
        },
        issuer: None,
        issuer_certificate: None,
        claims,
        redirect_uri: None,
        role: CredentialRole::Holder,
        lvvc_issuance_date: None,
        suspend_end_date: None,
        mdoc_mso_validity: None,
        holder: None,
        protocol: "OPENID4VCI_DRAFT13".to_string(),
        profile: None,
        wallet_app_attestation: None,
        wallet_unit_attestation: None,
    }
}

fn generate_credential_matching_detail(
    detail: &CredentialDetailResponseDTO<DetailCredentialClaimResponseDTO>,
) -> Credential {
    let detail = detail.clone();
    Credential {
        id: detail.id,
        created_date: detail.created_date,
        issuance_date: detail.issuance_date,
        last_modified: detail.last_modified,
        deleted_at: None,
        protocol: detail.protocol,
        redirect_uri: detail.redirect_uri,
        role: crate::model::credential::CredentialRole::Holder,
        state: crate::model::credential::CredentialStateEnum::Created,
        suspend_end_date: detail.suspend_end_date,
        claims: None,
        issuer_identifier: Some(Identifier {
            id: Uuid::new_v4().into(),
            created_date: detail.created_date,
            last_modified: detail.last_modified,
            name: "issuer".to_string(),
            r#type: crate::model::identifier::IdentifierType::Did,
            is_remote: true,
            state: crate::model::identifier::IdentifierState::Active,
            deleted_at: None,
            organisation: None,
            did: Some(Did {
                id: Uuid::new_v4().into(),
                created_date: detail.created_date,
                last_modified: detail.last_modified,
                name: "issuer".to_string(),
                did: DidValue::from_str("did:key:issuer").unwrap(),
                did_type: DidType::Remote,
                did_method: "".to_string(),
                deactivated: false,
                log: None,
                keys: None,
                organisation: None,
            }),
            key: None,
            certificates: None,
        }),
        issuer_certificate: None,
        holder_identifier: Some(Identifier {
            id: Uuid::new_v4().into(),
            created_date: detail.created_date,
            last_modified: detail.last_modified,
            name: "holder".to_string(),
            r#type: crate::model::identifier::IdentifierType::Did,
            is_remote: true,
            state: crate::model::identifier::IdentifierState::Active,
            deleted_at: None,
            organisation: None,
            did: Some(Did {
                id: Uuid::new_v4().into(),
                created_date: detail.created_date,
                last_modified: detail.last_modified,
                name: "holder".to_string(),
                did: DidValue::from_str("did:key:holder").unwrap(),
                did_type: DidType::Remote,
                did_method: "".to_string(),
                deactivated: false,
                log: None,
                keys: None,
                organisation: None,
            }),
            key: None,
            certificates: None,
        }),
        schema: Some(CredentialSchema {
            id: detail.schema.id,
            deleted_at: None,
            created_date: detail.schema.created_date,
            last_modified: detail.schema.last_modified,
            name: detail.schema.name,
            format: detail.schema.format,
            revocation_method: detail.schema.revocation_method,
            key_storage_security: detail.schema.key_storage_security,
            layout_type: crate::model::credential_schema::LayoutType::Card,
            layout_properties: None,
            schema_id: detail.schema.schema_id,
            imported_source_url: detail.schema.imported_source_url,
            allow_suspension: detail.schema.allow_suspension,
            requires_app_attestation: false,
            claim_schemas: None,
            organisation: None,
        }),
        interaction: None,
        key: None,
        profile: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_app_attestation_blob_id: None,
    }
}

#[test]
fn test_from_credential_detail_response_nested_claim_mapping() {
    let now = OffsetDateTime::now_utc();
    let holder_did = DidValue::from_str("did:key:holder").unwrap();

    let credential_detail = generate_credential_detail_response(vec![
        DetailCredentialClaimResponseDTO {
            path: "location".to_string(),
            schema: CredentialClaimSchemaDTO {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                key: "location".to_string(),
                datatype: "OBJECT".to_string(),
                required: false,
                array: false,
                claims: vec![],
            },
            value: DetailCredentialClaimValueResponseDTO::Nested(vec![
                DetailCredentialClaimResponseDTO {
                    path: "location/x".to_string(),
                    schema: CredentialClaimSchemaDTO {
                        id: Uuid::new_v4().into(),
                        created_date: now,
                        last_modified: now,
                        key: "x".to_string(),
                        datatype: "STRING".to_string(),
                        required: false,
                        array: false,
                        claims: vec![],
                    },
                    value: DetailCredentialClaimValueResponseDTO::String("123".to_string()),
                },
                DetailCredentialClaimResponseDTO {
                    path: "location/y".to_string(),
                    schema: CredentialClaimSchemaDTO {
                        id: Uuid::new_v4().into(),
                        created_date: now,
                        last_modified: now,
                        key: "y".to_string(),
                        datatype: "STRING".to_string(),
                        required: false,
                        array: false,
                        claims: vec![],
                    },
                    value: DetailCredentialClaimValueResponseDTO::String("456".to_string()),
                },
            ]),
        },
        DetailCredentialClaimResponseDTO {
            path: "street".to_string(),
            schema: CredentialClaimSchemaDTO {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                key: "street".to_string(),
                datatype: "STRING".to_string(),
                required: false,
                array: false,
                claims: vec![],
            },
            value: DetailCredentialClaimValueResponseDTO::String("some street".to_string()),
        },
    ]);
    let credential = generate_credential_matching_detail(&credential_detail);

    let holder_identifier = Identifier {
        did: Some(Did {
            did: holder_did.clone(),
            ..dummy_did()
        }),
        ..dummy_identifier()
    };

    let actual = credential_data_from_credential_detail_response(
        credential_detail,
        &credential,
        None,
        Some(holder_identifier),
        format!("{holder_did}#0"),
        "http://127.0.0.1",
        vec![],
        indexset![],
    )
    .unwrap()
    .claims;

    let expected: Vec<PublishedClaim> = vec![
        PublishedClaim {
            key: "location/x".to_string(),
            value: PublishedClaimValue::String("123".to_string()),
            datatype: Some("STRING".to_string()),
            array_item: false,
        },
        PublishedClaim {
            key: "location/y".to_string(),
            value: PublishedClaimValue::String("456".to_string()),
            datatype: Some("STRING".to_string()),
            array_item: false,
        },
        PublishedClaim {
            key: "street".to_string(),
            value: PublishedClaimValue::String("some street".to_string()),
            datatype: Some("STRING".to_string()),
            array_item: false,
        },
    ];

    assert_eq!(expected, actual);
}

#[test]
fn test_from_credential_detail_response_nested_claim_mapping_array() {
    let now = OffsetDateTime::now_utc();
    let holder_did = DidValue::from_str("did:key:holder").unwrap();

    let mut datatype_config = DatatypeConfig::default();
    datatype_config.insert(
        "OBJECT".to_owned(),
        core_config::Fields {
            r#type: DatatypeType::Object,
            display: "".into(),
            order: Some(1),
            priority: None,
            enabled: true,
            capabilities: None,
            params: None,
        },
    );
    let credential_detail = generate_credential_detail_response(vec![
        DetailCredentialClaimResponseDTO {
            schema: CredentialClaimSchemaDTO {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                key: "location".to_string(),
                datatype: "OBJECT".to_string(),
                required: false,
                array: true,
                claims: vec![],
            },
            path: "location".to_string(),
            value: DetailCredentialClaimValueResponseDTO::Nested(vec![
                DetailCredentialClaimResponseDTO {
                    schema: CredentialClaimSchemaDTO {
                        id: Uuid::new_v4().into(),
                        created_date: now,
                        last_modified: now,
                        key: "location/x".to_string(),
                        datatype: "STRING".to_string(),
                        array: false,
                        required: false,
                        claims: vec![],
                    },
                    path: "location/0/x".to_string(),
                    value: DetailCredentialClaimValueResponseDTO::String("123".to_string()),
                },
                DetailCredentialClaimResponseDTO {
                    schema: CredentialClaimSchemaDTO {
                        id: Uuid::new_v4().into(),
                        created_date: now,
                        last_modified: now,
                        key: "location/y".to_string(),
                        array: false,
                        datatype: "STRING".to_string(),
                        required: false,
                        claims: vec![],
                    },
                    path: "location/0/y".to_string(),
                    value: DetailCredentialClaimValueResponseDTO::String("456".to_string()),
                },
            ]),
        },
        DetailCredentialClaimResponseDTO {
            schema: CredentialClaimSchemaDTO {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                key: "street".to_string(),
                array: false,
                datatype: "STRING".to_string(),
                required: false,
                claims: vec![],
            },
            path: "street".to_string(),
            value: DetailCredentialClaimValueResponseDTO::String("some street".to_string()),
        },
    ]);
    let credential = generate_credential_matching_detail(&credential_detail);

    let holder_identifier = Identifier {
        did: Some(Did {
            did: holder_did.clone(),
            ..dummy_did()
        }),
        ..dummy_identifier()
    };

    let actual = credential_data_from_credential_detail_response(
        credential_detail,
        &credential,
        None,
        Some(holder_identifier),
        format!("{holder_did}#0"),
        "http://127.0.0.1",
        vec![],
        indexset![],
    )
    .unwrap()
    .claims;

    let expected: Vec<PublishedClaim> = vec![
        PublishedClaim {
            key: "location/0/x".to_string(),
            value: PublishedClaimValue::String("123".to_string()),
            datatype: Some("STRING".to_string()),
            array_item: true,
        },
        PublishedClaim {
            key: "location/0/y".to_string(),
            value: PublishedClaimValue::String("456".to_string()),
            datatype: Some("STRING".to_string()),
            array_item: true,
        },
        PublishedClaim {
            key: "street".to_string(),
            value: PublishedClaimValue::String("some street".to_string()),
            datatype: Some("STRING".to_string()),
            array_item: false,
        },
    ];

    assert_eq!(expected, actual);
}
