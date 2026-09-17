use shared_types::{ClaimSchemaId, CredentialSchemaFormatId, CredentialSchemaId};
use standardized_types::openid4vci::{ClaimMetadata, CredentialMetadata};
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
            path: vec!["namespace".to_string(), "issuerKey".to_string()],
            display: None,
            mandatory: Some(true),
            additional_values: Default::default(),
        }]),
        ..Default::default()
    };

    apply_issuer_metadata_to_schema(&mut schema, Some(&metadata), "en")
        .await
        .unwrap();

    let claim_schemas = schema.claim_schemas.as_ref().await.unwrap();
    assert!(claim_schemas[0].required);
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
                path: vec!["present".to_string()],
                display: None,
                mandatory: Some(true),
                additional_values: Default::default(),
            },
            ClaimMetadata {
                path: vec!["missing".to_string()],
                display: None,
                mandatory: Some(true),
                additional_values: Default::default(),
            },
            ClaimMetadata {
                path: vec!["address".to_string(), "street".to_string()],
                display: None,
                mandatory: Some(true),
                additional_values: Default::default(),
            },
            ClaimMetadata {
                path: vec!["optional".to_string()],
                display: None,
                mandatory: Some(false),
                additional_values: Default::default(),
            },
        ]),
        ..Default::default()
    };

    let error = apply_issuer_metadata_to_schema(&mut schema, Some(&metadata), "en")
        .await
        .unwrap_err();

    assert!(error.to_string().contains("['missing', 'address/street']"));
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
