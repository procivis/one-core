use std::str::FromStr;

use indexmap::indexset;
use maplit::hashmap;
use shared_types::DidValue;
use shared_types::i18n::I18nString;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::config::core_config::{self, DatatypeConfig, DatatypeType};
use crate::model::credential::{Credential, CredentialType};
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::did::{Did, DidType};
use crate::model::identifier::{Identifier, IdentifierData};
use crate::provider::credential_formatter::mapper::credential_data_from_credential_detail_response;
use crate::provider::credential_formatter::model::{PublishedClaim, PublishedClaimValue};
use crate::provider::credential_formatter::nest_claims;
use crate::service::credential::dto::{
    CredentialDetailResponseDTO, CredentialRole, CredentialStateEnum, CredentialTypeEnum,
    DetailCredentialClaimResponseDTO, DetailCredentialClaimValueResponseDTO,
    DetailCredentialSchemaResponseDTO,
};
use crate::service::credential_schema::dto::{
    CredentialClaimSchemaDTO, CredentialClaimSchemaTranslationsDTO, CredentialSchemaTranslationsDTO,
};
use crate::service::test_utilities::{dummy_organisation, generic_config};

fn generate_credential_detail_response(
    claims: Vec<DetailCredentialClaimResponseDTO>,
) -> CredentialDetailResponseDTO<DetailCredentialClaimResponseDTO> {
    let now = crate::clock::now_utc();

    CredentialDetailResponseDTO {
        id: Uuid::new_v4().into(),
        created_date: now,
        issuance_date: None,
        revocation_date: None,
        expires_at: None,
        consumed_at: None,
        state: CredentialStateEnum::Created,
        last_modified: now,
        schema: DetailCredentialSchemaResponseDTO {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            imported_source_url: "CORE_URL".to_string(),
            deleted_at: None,
            name: "".to_string(),
            format: "JWT".into(),
            revocation_method: None,
            organisation_id: Uuid::new_v4().into(),
            key_storage_security: None,
            schema_id: "".to_string(),
            layout_properties: None,
            allow_suspension: true,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            translations: CredentialSchemaTranslationsDTO {
                name: I18nString(hashmap! { "en".to_string() => "name".to_string()}),
                description: None,
            },
        },
        issuer: None,
        issuer_certificate: None,
        claims,
        redirect_uri: None,
        role: CredentialRole::Holder,
        r#type: CredentialTypeEnum::Single,
        interaction_id: None,
        suspend_end_date: None,
        mdoc_mso_validity: None,
        holder: None,
        protocol: "OPENID4VCI_DRAFT13".to_string(),
        profile: None,
        wallet_instance_attestation: None,
        wallet_unit_attestation: None,
        webhook_destination_url: None,
        trust_information: None,
        remaining_batch_item_count: None,
        parent_id: None,
        subscriber_information: None,
        ecosystem: None,
    }
}

fn generate_credential_matching_detail(
    detail: &CredentialDetailResponseDTO<DetailCredentialClaimResponseDTO>,
) -> Credential {
    let detail = detail.clone();
    Credential {
        expires_at: None,
        ecosystem: None,
        id: detail.id,
        created_date: detail.created_date,
        issuance_date: detail.issuance_date,
        last_modified: detail.last_modified,
        deleted_at: None,
        consumed_at: None,
        protocol: detail.protocol,
        redirect_uri: detail.redirect_uri,
        role: crate::model::credential::CredentialRole::Holder,
        r#type: CredentialType::Single,
        state: crate::model::credential::CredentialStateEnum::Created,
        suspend_end_date: detail.suspend_end_date,
        claims: Default::default(),
        issuer_identifier: Some(
            Identifier {
                id: Uuid::new_v4().into(),
                created_date: detail.created_date,
                last_modified: detail.last_modified,
                name: "issuer".to_string(),
                data: IdentifierData::Did(
                    (Did {
                        deleted_at: None,
                        id: Uuid::new_v4().into(),
                        created_date: detail.created_date,
                        last_modified: detail.last_modified,
                        name: "issuer".to_string(),
                        did: DidValue::from_str("did:key:issuer").unwrap(),
                        did_type: DidType::Remote,
                        did_method: "".into(),
                        deactivated: false,
                        log: None,
                        keys: Default::default(),
                        organisation: dummy_organisation(None).into(),
                    })
                    .into(),
                ),
                is_remote: true,
                state: crate::model::identifier::IdentifierState::Active,
                deleted_at: None,
                organisation: dummy_organisation(Some(uuid::Uuid::new_v4().into())).into(),
                trust_information: Default::default(),
            }
            .into(),
        ),
        issuer_certificate: None,
        holder_identifier: Some(
            Identifier {
                id: Uuid::new_v4().into(),
                created_date: detail.created_date,
                last_modified: detail.last_modified,
                name: "holder".to_string(),
                data: IdentifierData::Did(
                    (Did {
                        deleted_at: None,
                        id: Uuid::new_v4().into(),
                        created_date: detail.created_date,
                        last_modified: detail.last_modified,
                        name: "holder".to_string(),
                        did: DidValue::from_str("did:key:holder").unwrap(),
                        did_type: DidType::Remote,
                        did_method: "".into(),
                        deactivated: false,
                        log: None,
                        keys: Default::default(),
                        organisation: dummy_organisation(None).into(),
                    })
                    .into(),
                ),
                is_remote: true,
                state: crate::model::identifier::IdentifierState::Active,
                deleted_at: None,
                organisation: dummy_organisation(Some(uuid::Uuid::new_v4().into())).into(),
                trust_information: Default::default(),
            }
            .into(),
        ),
        schema: CredentialSchema {
            expiration: None,
            ecosystem: None,
            batch_size: None,
            allow_revocation: detail.schema.revocation_method.is_some(),
            id: detail.schema.id,
            deleted_at: None,
            created_date: detail.schema.created_date,
            last_modified: detail.schema.last_modified,
            name: detail.schema.name,
            formats: vec![CredentialSchemaFormat {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                credential_schema_id: detail.schema.id,
                format: detail.schema.format,
                schema_id: detail.schema.schema_id,
                claim_mappings: Default::default(),
            }]
            .into(),
            key_storage_security: detail.schema.key_storage_security,
            layout_properties: None,
            imported_source_url: detail.schema.imported_source_url,
            allow_suspension: detail.schema.allow_suspension,
            requires_wallet_instance_attestation: false,
            claim_schemas: Default::default(),
            organisation: dummy_organisation(None).into(),
            transaction_code: None,
            translations: Default::default(),
            embedded_disclosure_policy: None,
        }
        .into(),
        interaction: None,
        key: None,
        profile: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: None,
        parent: None,
        embedded_disclosure_policy: None,

        subscriber_information: None,
    }
}

#[tokio::test]
async fn test_from_credential_detail_response_nested_claim_mapping() {
    let now = crate::clock::now_utc();

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
                translations: CredentialClaimSchemaTranslationsDTO {
                    name: I18nString(hashmap! { "en".to_string() => "name".to_string()}),
                },
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
                        translations: CredentialClaimSchemaTranslationsDTO {
                            name: I18nString(hashmap! { "en".to_string() => "name".to_string()}),
                        },
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
                        translations: CredentialClaimSchemaTranslationsDTO {
                            name: I18nString(hashmap! { "en".to_string() => "name".to_string()}),
                        },
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
                translations: CredentialClaimSchemaTranslationsDTO {
                    name: I18nString(hashmap! { "en".to_string() => "name".to_string()}),
                },
            },
            value: DetailCredentialClaimValueResponseDTO::String("some street".to_string()),
        },
    ]);
    let credential = generate_credential_matching_detail(&credential_detail);
    let schema = credential.schema.as_ref().await.unwrap();
    let formats = schema.formats.as_ref().await.unwrap();

    let actual = credential_data_from_credential_detail_response(
        credential_detail,
        &credential,
        "http://127.0.0.1",
        vec![],
        indexset![],
        &schema,
        formats.first().unwrap(),
        &generic_config().core,
    )
    .await
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

#[tokio::test]
async fn test_from_credential_detail_response_nested_claim_mapping_array() {
    let now = crate::clock::now_utc();

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
    let location_cs_id = Uuid::new_v4().into();
    let location_x_cs_id = Uuid::new_v4().into();
    let location_y_cs_id = Uuid::new_v4().into();
    let street_cs_id = Uuid::new_v4().into();
    let credential_detail = generate_credential_detail_response(vec![
        DetailCredentialClaimResponseDTO {
            schema: CredentialClaimSchemaDTO {
                id: location_cs_id,
                created_date: now,
                last_modified: now,
                key: "location".to_string(),
                datatype: "OBJECT".to_string(),
                required: false,
                array: true,
                claims: vec![],
                translations: CredentialClaimSchemaTranslationsDTO {
                    name: I18nString(hashmap! { "en".to_string() => "name".to_string()}),
                },
            },
            path: "location".to_string(),
            value: DetailCredentialClaimValueResponseDTO::Nested(vec![
                DetailCredentialClaimResponseDTO {
                    schema: CredentialClaimSchemaDTO {
                        id: location_x_cs_id,
                        created_date: now,
                        last_modified: now,
                        key: "location/x".to_string(),
                        datatype: "STRING".to_string(),
                        array: false,
                        required: false,
                        claims: vec![],
                        translations: CredentialClaimSchemaTranslationsDTO {
                            name: I18nString(hashmap! { "en".to_string() => "name".to_string()}),
                        },
                    },
                    path: "location/0/x".to_string(),
                    value: DetailCredentialClaimValueResponseDTO::String("123".to_string()),
                },
                DetailCredentialClaimResponseDTO {
                    schema: CredentialClaimSchemaDTO {
                        id: location_y_cs_id,
                        created_date: now,
                        last_modified: now,
                        key: "location/y".to_string(),
                        array: false,
                        datatype: "STRING".to_string(),
                        required: false,
                        claims: vec![],
                        translations: CredentialClaimSchemaTranslationsDTO {
                            name: I18nString(hashmap! { "en".to_string() => "name".to_string()}),
                        },
                    },
                    path: "location/0/y".to_string(),
                    value: DetailCredentialClaimValueResponseDTO::String("456".to_string()),
                },
            ]),
        },
        DetailCredentialClaimResponseDTO {
            schema: CredentialClaimSchemaDTO {
                id: street_cs_id,
                created_date: now,
                last_modified: now,
                key: "street".to_string(),
                array: false,
                datatype: "STRING".to_string(),
                required: false,
                claims: vec![],
                translations: CredentialClaimSchemaTranslationsDTO {
                    name: I18nString(hashmap! { "en".to_string() => "name".to_string()}),
                },
            },
            path: "street".to_string(),
            value: DetailCredentialClaimValueResponseDTO::String("some street".to_string()),
        },
    ]);
    let credential = generate_credential_matching_detail(&credential_detail);
    let schema = credential.schema.as_ref().await.unwrap();
    let formats = schema.formats.as_ref().await.unwrap();

    let actual = credential_data_from_credential_detail_response(
        credential_detail.clone(),
        &credential,
        "http://127.0.0.1",
        vec![],
        indexset![],
        &schema,
        formats.first().unwrap(),
        &generic_config().core,
    )
    .await
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

#[test]
fn test_nest_claims_array_with_more_than_ten_items() {
    let claims = (0..11).map(|i| PublishedClaim {
        key: format!("representative/{i}/name"),
        value: PublishedClaimValue::String(format!("name {i}")),
        datatype: Some("STRING".to_string()),
        array_item: true,
    });

    let nested = nest_claims(claims).unwrap();

    let representatives = nested["representative"].as_array().unwrap();
    assert_eq!(11, representatives.len());
    for (i, representative) in representatives.iter().enumerate() {
        assert_eq!(
            format!("name {i}"),
            representative["name"].as_str().unwrap()
        );
    }
}
