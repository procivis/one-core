use std::collections::HashSet;
use std::sync::Arc;

use mockall::predicate::eq;
use shared_types::{
    ClaimSchemaId, CredentialFormat, CredentialSchemaFormatId, CredentialSchemaId, EntityId,
};
use similar_asserts::assert_eq;
use standardized_types::openid4vci::{
    ClaimDisplay, ClaimMetadata, CredentialDisplay, CredentialMetadata,
};
use standardized_types::openid4vp::dcql::PathSegment;
use uuid::Uuid;

use super::{
    apply_issuer_metadata_to_schema, ensure_required_claims, issuer_mandatory_claim_ids,
    map_issuer_claim_metadata,
};
use crate::clock::now_utc;
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::FormatterCapabilities;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::service::test_utilities::{
    CredentialBuilder, dummy_credential, dummy_organisation, generic_formatter_capabilities,
};

#[test]
fn rejects_holder_batch_parent() {
    let mut credential = crate::model::credential::Credential::HolderBatchParent {
        common: dummy_credential().common().clone(),
    };

    let error = credential.holder_mut().unwrap_err();
    assert_eq!(error.error_code(), ErrorCode::BR_0047);
    assert!(
        error
            .to_string()
            .contains("Expected a concrete holder credential, got HolderBatchParent")
    );
}

#[tokio::test]
async fn validates_mandatory_issuer_metadata_without_changing_required_flag() {
    let mut claim = claim_schema("localKey", "STRING");
    claim.required = false;
    let claim_id = claim.id;
    let format_id = Uuid::new_v4().into();
    let schema = credential_schema(
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

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq::<CredentialFormat>("JWT".into()))
        .returning(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter
                .expect_get_capabilities()
                .return_const(generic_formatter_capabilities());
            Ok(Arc::new(formatter))
        });

    let format = schema.formats.as_ref().await.unwrap()[0].clone();
    let issuer_claim_metadata =
        map_issuer_claim_metadata(&schema, &metadata, &format, &formatter_provider)
            .await
            .unwrap();
    let mandatory_claim_ids = issuer_mandatory_claim_ids(&issuer_claim_metadata).unwrap();

    assert_eq!(mandatory_claim_ids, vec![claim_id]);
    assert!(!schema.claim_schemas.as_ref().await.unwrap()[0].required);

    let credential = {
        let mut updated_credential = dummy_credential();
        updated_credential.common_mut().schema = schema.clone().into();
        updated_credential = CredentialBuilder {
            role: crate::model::credential::CredentialRole::Holder,
            format: Some(schema.formats.as_ref().await.unwrap()[0].clone().into()),
            ..updated_credential.into()
        }
        .build();
        updated_credential.holder_mut().unwrap().data.claims = vec![].into();
        updated_credential
    };
    let error = ensure_required_claims(
        &schema,
        credential.holder().unwrap().data,
        &issuer_claim_metadata,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("localKey"));
    // Another issuer can omit this claim when it is not mandatory in its metadata.
    ensure_required_claims(&schema, credential.holder().unwrap().data, &[])
        .await
        .unwrap();
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

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq::<CredentialFormat>("JWT".into()))
        .returning(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter
                .expect_get_capabilities()
                .return_const(generic_formatter_capabilities());
            Ok(Arc::new(formatter))
        });

    let format = schema.formats.as_ref().await.unwrap()[0].clone();
    let issuer_claim_metadata =
        map_issuer_claim_metadata(&schema, &metadata, &format, &formatter_provider)
            .await
            .unwrap();
    let translations =
        apply_issuer_metadata_to_schema(&mut schema, Some(&metadata), "en", &issuer_claim_metadata)
            .await
            .unwrap();

    assert_eq!(
        issuer_mandatory_claim_ids(&issuer_claim_metadata).unwrap(),
        vec![claim_id, degree_type.id]
    );
    assert_eq!(translations.len(), 2);
    assert!(translations.iter().any(|t| t.value == "Issuer key"));
    assert!(translations.iter().any(|t| t.value == "Degree type"));
    let claims = schema.claim_schemas.as_ref().await.unwrap();
    assert!(claims[0].required);
    assert!(!claims[2].required);
    assert!(!claims[3].required);
}

#[tokio::test]
async fn array_child_path_without_wildcard_is_skipped() {
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

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq::<CredentialFormat>("JWT".into()))
        .returning(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter
                .expect_get_capabilities()
                .return_const(generic_formatter_capabilities());
            Ok(Arc::new(formatter))
        });

    let format = schema.formats.as_ref().await.unwrap()[0].clone();
    let issuer_claim_metadata =
        map_issuer_claim_metadata(&schema, &metadata, &format, &formatter_provider)
            .await
            .unwrap();
    let translations =
        apply_issuer_metadata_to_schema(&mut schema, Some(&metadata), "en", &issuer_claim_metadata)
            .await
            .unwrap();

    assert!(translations.is_empty());
    assert!(
        issuer_mandatory_claim_ids(&issuer_claim_metadata)
            .unwrap()
            .is_empty()
    );
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

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq::<CredentialFormat>("JWT".into()))
        .returning(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter
                .expect_get_capabilities()
                .return_const(generic_formatter_capabilities());
            Ok(Arc::new(formatter))
        });

    let format = schema.formats.as_ref().await.unwrap()[0].clone();
    let issuer_claim_metadata =
        map_issuer_claim_metadata(&schema, &metadata, &format, &formatter_provider)
            .await
            .unwrap();
    let translations =
        apply_issuer_metadata_to_schema(&mut schema, Some(&metadata), "en", &issuer_claim_metadata)
            .await
            .unwrap();

    assert!(translations.is_empty());
    assert!(
        issuer_mandatory_claim_ids(&issuer_claim_metadata)
            .unwrap()
            .is_empty()
    );
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

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq::<CredentialFormat>("JWT".into()))
        .returning(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter
                .expect_get_capabilities()
                .return_const(generic_formatter_capabilities());
            Ok(Arc::new(formatter))
        });

    let format = schema.formats.as_ref().await.unwrap()[0].clone();
    let issuer_claim_metadata =
        map_issuer_claim_metadata(&schema, &metadata, &format, &formatter_provider)
            .await
            .unwrap();
    // Display enrichment does not validate issuer requirements.
    apply_issuer_metadata_to_schema(&mut schema, Some(&metadata), "en", &issuer_claim_metadata)
        .await
        .unwrap();
    let error = issuer_mandatory_claim_ids(&issuer_claim_metadata).unwrap_err();

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

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq::<CredentialFormat>("JWT".into()))
        .returning(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter
                .expect_get_capabilities()
                .return_const(generic_formatter_capabilities());
            Ok(Arc::new(formatter))
        });

    let format = schema.formats.as_ref().await.unwrap()[0].clone();
    let issuer_claim_metadata =
        map_issuer_claim_metadata(&schema, &metadata, &format, &formatter_provider)
            .await
            .unwrap();
    let translations =
        apply_issuer_metadata_to_schema(&mut schema, Some(&metadata), "en", &issuer_claim_metadata)
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

#[tokio::test]
async fn filters_out_forbidden_technical_keys_from_issuer_metadata() {
    let claim = claim_schema("givenName", "STRING");
    let claim_id = claim.id;
    let format_id = Uuid::new_v4().into();
    let schema = credential_schema(
        Uuid::new_v4().into(),
        format_id,
        "SD_JWT_VC",
        vec![claim],
        vec![mapping(format_id, claim_id, "given_name", None)],
    );
    let metadata = CredentialMetadata {
        display: None,
        claims: Some(vec![
            ClaimMetadata {
                path: vec!["given_name".to_string()].into(),
                display: None,
                mandatory: None,
                additional_values: Default::default(),
            },
            ClaimMetadata {
                path: vec!["vct".to_string()].into(),
                display: None,
                mandatory: None,
                additional_values: Default::default(),
            },
            ClaimMetadata {
                path: vec!["_sd".to_string()].into(),
                display: None,
                mandatory: None,
                additional_values: Default::default(),
            },
            ClaimMetadata {
                path: vec!["nested".to_string(), "vct".to_string()].into(),
                display: None,
                mandatory: None,
                additional_values: Default::default(),
            },
            ClaimMetadata {
                path: vec!["nested".to_string(), "_sd".to_string()].into(),
                display: None,
                mandatory: None,
                additional_values: Default::default(),
            },
        ]),
    };

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq::<CredentialFormat>("SD_JWT_VC".into()))
        .returning(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter
                .expect_get_capabilities()
                .return_const(FormatterCapabilities {
                    forbidden_claim_technical_keys: vec!["_sd".to_string()],
                    forbidden_root_claim_technical_keys: vec!["vct".to_string()],
                    ..generic_formatter_capabilities()
                });
            Ok(Arc::new(formatter))
        });

    let format = schema.formats.as_ref().await.unwrap()[0].clone();
    let issuer_claim_metadata =
        map_issuer_claim_metadata(&schema, &metadata, &format, &formatter_provider)
            .await
            .unwrap();

    let formatted_keys: HashSet<_> = issuer_claim_metadata
        .iter()
        .map(|claim| claim.formatted_key.as_str())
        .collect();
    assert_eq!(formatted_keys, ["given_name", "nested/vct"].into());
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
