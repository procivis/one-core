use shared_types::{ClaimSchemaId, CredentialSchemaFormatId, CredentialSchemaId, EntityId};
use similar_asserts::assert_eq;
use standardized_types::openid4vci::{
    ClaimDisplay, ClaimMetadata, CredentialDisplay, CredentialMetadata,
};
use standardized_types::openid4vp::dcql::PathSegment;
use uuid::Uuid;

use super::apply_issuer_metadata_to_schema;
use crate::clock::now_utc;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::service::test_utilities::dummy_organisation;

#[tokio::test]
async fn applies_mandatory_issuer_metadata_to_claim_schema() {
    let mut claim = claim_schema("localKey", "STRING");
    claim.required = false;
    let claim_id = claim.id;
    let format_id = Uuid::new_v4().into();
    let mut schema = credential_schema(
        Uuid::new_v4().into(),
        format_id,
        "JWT",
        vec![claim],
        vec![mapping(format_id, claim_id, "issuerKey", Some("namespace"))],
    );
    let metadata = CredentialMetadata {
        claims: Some(vec![ClaimMetadata {
            path: vec!["namespace".to_string(), "issuerKey".to_string()].into(),
            display: None,
            mandatory: Some(true),
            additional_values: Default::default(),
        }]),
        ..Default::default()
    };

    apply_issuer_metadata_to_schema(&mut schema, Some(&metadata), "en", None)
        .await
        .unwrap();

    let claim_schemas = schema.claim_schemas.as_ref().await.unwrap();
    assert!(claim_schemas[0].required);
}

#[tokio::test]
async fn applies_wildcard_metadata_to_array_children_and_skips_concrete_indices() {
    let claim = claim_schema("localKey", "STRING");
    let claim_id = claim.id;
    let mut degrees = claim_schema("degrees", "OBJECT");
    degrees.array = true;
    let mut degree_type = claim_schema("degrees/type", "STRING");
    degree_type.required = false;
    let mut university = claim_schema("degrees/university", "STRING");
    university.required = false;
    let format_id = Uuid::new_v4().into();
    let mut schema = credential_schema(
        Uuid::new_v4().into(),
        format_id,
        "JWT",
        vec![
            claim,
            degrees.clone(),
            degree_type.clone(),
            university.clone(),
        ],
        vec![
            mapping(format_id, claim_id, "issuerKey", None),
            mapping(format_id, degrees.id, "degrees", None),
            mapping(format_id, degree_type.id, "degrees/type", None),
            mapping(format_id, university.id, "degrees/university", None),
        ],
    );
    let metadata = CredentialMetadata {
        claims: Some(vec![
            ClaimMetadata {
                path: vec!["issuerKey".to_string()].into(),
                display: Some(vec![ClaimDisplay {
                    name: Some("Issuer key".to_string()),
                    locale: Some("en".to_string()),
                }]),
                mandatory: Some(true),
                additional_values: Default::default(),
            },
            ClaimMetadata {
                path: vec!["degrees".into(), PathSegment::ArrayAll, "type".into()].into(),
                display: Some(vec![ClaimDisplay {
                    name: Some("Degree type".to_string()),
                    locale: Some("en".to_string()),
                }]),
                mandatory: Some(true),
                additional_values: Default::default(),
            },
            ClaimMetadata {
                path: vec![
                    "degrees".into(),
                    PathSegment::ArrayIndex(0),
                    "university".into(),
                ]
                .into(),
                display: Some(vec![ClaimDisplay {
                    name: Some("University".to_string()),
                    locale: Some("en".to_string()),
                }]),
                mandatory: Some(true),
                additional_values: Default::default(),
            },
        ]),
        ..Default::default()
    };

    let translations = apply_issuer_metadata_to_schema(&mut schema, Some(&metadata), "en", None)
        .await
        .unwrap();

    assert_eq!(translations.len(), 2);
    assert!(translations.iter().any(|t| t.value == "Issuer key"));
    assert!(translations.iter().any(|t| t.value == "Degree type"));
    let claims = schema.claim_schemas.as_ref().await.unwrap();
    assert!(claims[0].required);
    assert!(claims[2].required);
    assert!(!claims[3].required);
}

#[tokio::test]
async fn own_issuer_array_child_path_without_wildcard_is_skipped() {
    let mut degrees = claim_schema("degrees", "OBJECT");
    degrees.array = true;
    let mut degree_type = claim_schema("degrees/type", "STRING");
    degree_type.required = false;
    let format_id = Uuid::new_v4().into();
    let mut schema = credential_schema(
        Uuid::new_v4().into(),
        format_id,
        "JWT",
        vec![degrees.clone(), degree_type.clone()],
        vec![
            mapping(format_id, degrees.id, "degrees", None),
            mapping(format_id, degree_type.id, "degrees/type", None),
        ],
    );
    let metadata = CredentialMetadata {
        claims: Some(vec![ClaimMetadata {
            path: vec!["degrees".to_string(), "type".to_string()].into(),
            display: Some(vec![ClaimDisplay {
                name: Some("Degree type".into()),
                locale: Some("en".into()),
            }]),
            mandatory: Some(true),
            additional_values: Default::default(),
        }]),
        ..Default::default()
    };

    let translations = apply_issuer_metadata_to_schema(&mut schema, Some(&metadata), "en", None)
        .await
        .unwrap();

    assert!(translations.is_empty());
    assert!(!schema.claim_schemas.as_ref().await.unwrap()[1].required);
}

#[tokio::test]
async fn wildcard_metadata_requires_an_array_parent() {
    let mut parent = claim_schema("degrees", "OBJECT");
    parent.array = false;
    let mut child = claim_schema("degrees/type", "STRING");
    child.required = false;
    let format_id = Uuid::new_v4().into();
    let mut schema = credential_schema(
        Uuid::new_v4().into(),
        format_id,
        "JWT",
        vec![parent.clone(), child.clone()],
        vec![
            mapping(format_id, parent.id, "degrees", None),
            mapping(format_id, child.id, "degrees/type", None),
        ],
    );
    let metadata = CredentialMetadata {
        claims: Some(vec![ClaimMetadata {
            path: vec!["degrees".into(), PathSegment::ArrayAll, "type".into()].into(),
            display: None,
            mandatory: Some(true),
            additional_values: Default::default(),
        }]),
        ..Default::default()
    };

    let translations = apply_issuer_metadata_to_schema(&mut schema, Some(&metadata), "en", None)
        .await
        .unwrap();

    assert!(translations.is_empty());
    assert!(!schema.claim_schemas.as_ref().await.unwrap()[1].required);
}

#[tokio::test]
async fn errors_when_mandatory_issuer_metadata_claims_are_missing_from_parsed_schema() {
    let claim = claim_schema("present", "STRING");
    let claim_id = claim.id;
    let format_id = Uuid::new_v4().into();
    let mut schema = credential_schema(
        Uuid::new_v4().into(),
        format_id,
        "JWT",
        vec![claim],
        vec![mapping(format_id, claim_id, "present", None)],
    );
    let metadata = CredentialMetadata {
        claims: Some(vec![
            ClaimMetadata {
                path: vec!["present".to_string()].into(),
                display: None,
                mandatory: Some(true),
                additional_values: Default::default(),
            },
            ClaimMetadata {
                path: vec!["missing".to_string()].into(),
                display: None,
                mandatory: Some(true),
                additional_values: Default::default(),
            },
            ClaimMetadata {
                path: vec!["address".to_string(), "street".to_string()].into(),
                display: None,
                mandatory: Some(true),
                additional_values: Default::default(),
            },
            ClaimMetadata {
                path: vec!["optional".to_string()].into(),
                display: None,
                mandatory: Some(false),
                additional_values: Default::default(),
            },
        ]),
        ..Default::default()
    };

    let error = apply_issuer_metadata_to_schema(&mut schema, Some(&metadata), "en", None)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("['missing', 'address/street']"));
}

#[tokio::test]
async fn returns_all_issuer_metadata_translations_for_persistence() {
    let claim = claim_schema("givenName", "STRING");
    let claim_id = claim.id;
    let format_id = Uuid::new_v4().into();
    let mut schema = credential_schema(
        Uuid::new_v4().into(),
        format_id,
        "JWT",
        vec![claim],
        vec![mapping(format_id, claim_id, "given_name", None)],
    );
    let metadata = CredentialMetadata {
        display: Some(vec![
            CredentialDisplay {
                name: "Identity".to_string(),
                locale: Some("en".to_string()),
                description: Some("Identity credential".to_string()),
                ..Default::default()
            },
            CredentialDisplay {
                name: "Identität".to_string(),
                locale: Some("de".to_string()),
                description: Some("Identitätsnachweis".to_string()),
                ..Default::default()
            },
        ]),
        claims: Some(vec![ClaimMetadata {
            path: vec!["given_name".to_string()].into(),
            display: Some(vec![
                ClaimDisplay {
                    name: Some("Given name".to_string()),
                    locale: Some("en".to_string()),
                },
                ClaimDisplay {
                    name: Some("Vorname".to_string()),
                    locale: Some("de".to_string()),
                },
            ]),
            mandatory: None,
            additional_values: Default::default(),
        }]),
    };

    let translations = apply_issuer_metadata_to_schema(&mut schema, Some(&metadata), "en", None)
        .await
        .unwrap();

    assert_eq!(translations.len(), 6);
    assert!(translations.iter().any(|translation| {
        translation.entity_id == EntityId::from(schema.id)
            && translation.field == crate::model::localized_text::LocalizedTextField::Description
            && translation.lang == "de"
            && translation.value == "Identitätsnachweis"
    }));
    assert!(translations.iter().any(|translation| {
        translation.entity_id == EntityId::from(claim_id)
            && translation.field == crate::model::localized_text::LocalizedTextField::Name
            && translation.lang == "en"
            && translation.value == "Given name"
    }));
}

fn claim_schema(key: &str, data_type: &str) -> ClaimSchema {
    let now = now_utc();
    ClaimSchema {
        id: Uuid::new_v4().into(),
        key: key.to_string(),
        data_type: data_type.to_string(),
        created_date: now,
        last_modified: now,
        array: false,
        metadata: false,
        required: true,
        translations: Default::default(),
    }
}

fn mapping(
    format_id: CredentialSchemaFormatId,
    claim_schema_id: ClaimSchemaId,
    technical_key: &str,
    namespace: Option<&str>,
) -> CredentialSchemaFormatClaimSchema {
    let now = now_utc();
    CredentialSchemaFormatClaimSchema {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        credential_schema_format_id: format_id,
        claim_schema_id,
        technical_key: technical_key.to_string(),
        namespace: namespace.map(ToString::to_string),
    }
}

fn credential_schema(
    id: CredentialSchemaId,
    format_id: CredentialSchemaFormatId,
    format: &str,
    claim_schemas: Vec<ClaimSchema>,
    mappings: Vec<CredentialSchemaFormatClaimSchema>,
) -> CredentialSchema {
    let now = now_utc();
    CredentialSchema {
        expiration: None,
        ecosystem: None,
        id,
        deleted_at: None,
        created_date: now,
        last_modified: now,
        name: "schema".to_string(),
        wallet_attestation: Default::default(),
        layout_properties: None,
        imported_source_url: "CORE_URL".to_string(),
        transaction_code: None,
        batch_size: None,
        embedded_disclosure_policy: None,
        allow_revocation: false,
        allow_suspension: true,
        claim_schemas: claim_schemas.into(),
        organisation: dummy_organisation(None).into(),
        formats: vec![CredentialSchemaFormat {
            id: format_id,
            created_date: now,
            last_modified: now,
            credential_schema_id: id,
            format: format.into(),
            ecosystem_schema_id: "schemaId".to_owned(),
            claim_mappings: mappings.into(),
        }]
        .into(),
        translations: Default::default(),
    }
}
