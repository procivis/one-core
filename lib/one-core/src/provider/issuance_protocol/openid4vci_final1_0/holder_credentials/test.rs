use shared_types::{ClaimSchemaId, CredentialFormat, CredentialSchemaFormatId, CredentialSchemaId};
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::validate_existing_and_find_new_claim_schemas;
use crate::clock::now_utc;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum, CredentialType};
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::service::test_utilities::dummy_organisation;

#[tokio::test]
async fn matches_existing_schema() {
    let format: CredentialFormat = "JWT".into();

    let parsed_cs = claim_schema("address/city", "STRING");
    let parsed_format_id = Uuid::new_v4().into();
    let parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        parsed_format_id,
        "JWT",
        vec![parsed_cs.clone()],
        vec![mapping(
            parsed_format_id,
            parsed_cs.id,
            "city",
            Some("address"),
        )],
    );

    // stored V2 schema: non-empty mappings, matched by technical_key + namespace
    let stored_cs = claim_schema("addr/city", "STRING");
    let stored_cs_id = stored_cs.id;
    let stored_format_id = Uuid::new_v4().into();
    let stored_id: CredentialSchemaId = Uuid::new_v4().into();
    let mut stored_schema = credential_schema(
        stored_id,
        stored_format_id,
        "JWT",
        vec![stored_cs.clone()],
        vec![mapping(
            stored_format_id,
            stored_cs.id,
            "city",
            Some("address"),
        )],
    );

    let mut credential = credential(parsed_schema, vec![claim("address/city", &parsed_cs)]);

    let (claim_schemas, mappings) = validate_existing_and_find_new_claim_schemas(
        &mut stored_schema,
        &mut credential,
        &format,
        "en",
        false,
    )
    .await
    .unwrap();

    assert!(claim_schemas.is_empty());
    assert!(mappings.is_empty());
    let claims = credential.claims.as_ref().await.unwrap();
    assert_eq!(claims[0].schema.as_ref().await.unwrap().id, stored_cs_id);
    assert_eq!(claims[0].path, "addr/city");
    assert_eq!(credential.schema.as_ref().await.unwrap().id, stored_id);
}

#[tokio::test]
async fn remaps_nested_and_array_claim_paths() {
    let format: CredentialFormat = "JWT".into();

    // parsed schema: array of objects `addresses` with a child `addresses/street`
    let mut parsed_root = claim_schema("addresses", "OBJECT");
    parsed_root.array = true;
    let parsed_street = claim_schema("addresses/street", "STRING");

    let parsed_format_id = Uuid::new_v4().into();
    let parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        parsed_format_id,
        "JWT",
        vec![parsed_root.clone(), parsed_street.clone()],
        vec![
            mapping(parsed_format_id, parsed_root.id, "addresses", None),
            mapping(parsed_format_id, parsed_street.id, "addresses/street", None),
        ],
    );

    let mut stored_root = claim_schema("addr", "OBJECT");
    stored_root.array = true;
    let stored_root_id = stored_root.id;
    let stored_street = claim_schema("addr/street", "STRING");
    let stored_street_id = stored_street.id;
    let stored_format_id = Uuid::new_v4().into();
    let mut stored_schema = credential_schema(
        Uuid::new_v4().into(),
        stored_format_id,
        "JWT",
        vec![stored_root, stored_street],
        vec![
            mapping(stored_format_id, stored_root_id, "addresses", None),
            mapping(stored_format_id, stored_street_id, "addresses/street", None),
        ],
    );

    let mut credential = credential(
        parsed_schema,
        vec![
            claim("addresses", &parsed_root),
            claim("addresses/0", &parsed_root),
            claim("addresses/0/street", &parsed_street),
        ],
    );

    let (claim_schemas, mappings) = validate_existing_and_find_new_claim_schemas(
        &mut stored_schema,
        &mut credential,
        &format,
        "en",
        false,
    )
    .await
    .unwrap();

    assert!(claim_schemas.is_empty());
    assert!(mappings.is_empty());
    let claims = credential.claims.as_ref().await.unwrap();
    // claims keep their (original-path) sort order; only the path strings are rewritten
    assert_eq!(claims[0].path, "addr");
    assert_eq!(claims[0].schema.as_ref().await.unwrap().id, stored_root_id);
    assert_eq!(claims[1].path, "addr/0");
    assert_eq!(claims[1].schema.as_ref().await.unwrap().id, stored_root_id);
    assert_eq!(claims[2].path, "addr/0/street");
    assert_eq!(
        claims[2].schema.as_ref().await.unwrap().id,
        stored_street_id
    );
}

#[tokio::test]
async fn returns_new_claim_schemas_when_allowed() {
    let format: CredentialFormat = "JWT".into();

    let parsed_cs = claim_schema("newClaim", "STRING");
    let parsed_format_id = Uuid::new_v4().into();
    let parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        parsed_format_id,
        "JWT",
        vec![parsed_cs.clone()],
        vec![mapping(parsed_format_id, parsed_cs.id, "newClaim", None)],
    );

    let stored_id: CredentialSchemaId = Uuid::new_v4().into();
    let stored_format_id = Uuid::new_v4().into();
    let cs = claim_schema("other", "STRING");
    let cs_id = cs.id;
    let mut stored_schema = credential_schema(
        stored_id,
        stored_format_id,
        "JWT",
        vec![cs],
        vec![mapping(stored_format_id, cs_id, "other", None)],
    );

    let mut credential = credential(parsed_schema, vec![claim("newClaim", &parsed_cs)]);

    let (claim_schemas, mappings) = validate_existing_and_find_new_claim_schemas(
        &mut stored_schema,
        &mut credential,
        &format,
        "en",
        true,
    )
    .await
    .unwrap();

    assert_eq!(claim_schemas.len(), 1);
    assert_eq!(claim_schemas[0].key, "newClaim");
    assert_eq!(mappings.len(), 1);
    assert_eq!(mappings[0].technical_key, "newClaim");
    assert_eq!(mappings[0].namespace, None);

    // fallback translation for the default language was added
    let translations = claim_schemas[0].translations.as_ref().await.unwrap();
    assert!(translations.iter().any(|t| t.lang == "en"));

    // the new claim schema was appended to the stored schema
    let stored_claim_schemas = stored_schema.claim_schemas.as_ref().await.unwrap();
    assert_eq!(stored_claim_schemas.iter().count(), 2);

    assert_eq!(credential.schema.as_ref().await.unwrap().id, stored_id);
}

#[tokio::test]
async fn errors_on_new_claim_schema_when_disallowed() {
    let format: CredentialFormat = "JWT".into();

    let parsed_cs = claim_schema("newClaim", "STRING");
    let parsed_format_id = Uuid::new_v4().into();
    let parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        parsed_format_id,
        "JWT",
        vec![parsed_cs.clone()],
        vec![mapping(parsed_format_id, parsed_cs.id, "newClaim", None)],
    );

    let stored_format_id = Uuid::new_v4().into();
    let cs = claim_schema("other", "STRING");
    let cs_id = cs.id;
    let mut stored_schema = credential_schema(
        Uuid::new_v4().into(),
        stored_format_id,
        "JWT",
        vec![cs],
        vec![mapping(stored_format_id, cs_id, "other", None)],
    );

    let mut credential = credential(parsed_schema, vec![claim("newClaim", &parsed_cs)]);

    let result = validate_existing_and_find_new_claim_schemas(
        &mut stored_schema,
        &mut credential,
        &format,
        "en",
        false,
    )
    .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn errors_when_parsed_format_missing() {
    // parsed schema only has the "JWT" format, but we ask for "SD_JWT"
    let format: CredentialFormat = "SD_JWT".into();

    let parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        Uuid::new_v4().into(),
        "JWT",
        vec![],
        vec![],
    );

    let mut stored_schema = credential_schema(
        Uuid::new_v4().into(),
        Uuid::new_v4().into(),
        "JWT",
        vec![],
        vec![],
    );

    let mut credential = credential(parsed_schema, vec![]);

    let result = validate_existing_and_find_new_claim_schemas(
        &mut stored_schema,
        &mut credential,
        &format,
        "en",
        false,
    )
    .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn errors_when_stored_format_missing() {
    let format: CredentialFormat = "JWT".into();

    let parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        Uuid::new_v4().into(),
        format.as_ref(),
        vec![],
        vec![],
    );

    // stored schema only has the "SD_JWT" format
    let mut stored_schema = credential_schema(
        Uuid::new_v4().into(),
        Uuid::new_v4().into(),
        "SD_JWT",
        vec![],
        vec![],
    );

    let mut credential = credential(parsed_schema, vec![]);

    let result = validate_existing_and_find_new_claim_schemas(
        &mut stored_schema,
        &mut credential,
        &format,
        "en",
        false,
    )
    .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn errors_when_parsed_mapping_missing() {
    let format: CredentialFormat = "JWT".into();

    // parsed schema has a claim schema but no corresponding claim mapping
    let parsed_cs = claim_schema("NUMBER", "NUMBER");
    let parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        Uuid::new_v4().into(),
        format.as_ref(),
        vec![parsed_cs],
        vec![],
    );

    let mut stored_schema = credential_schema(
        Uuid::new_v4().into(),
        Uuid::new_v4().into(),
        format.as_ref(),
        vec![],
        vec![],
    );

    let mut credential = credential(parsed_schema, vec![]);

    let result = validate_existing_and_find_new_claim_schemas(
        &mut stored_schema,
        &mut credential,
        &format,
        "en",
        false,
    )
    .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn remaps_new_nested_and_array_claim_paths() {
    let format: CredentialFormat = "JWT".into();

    // parsed schema: array of objects `addresses` with a child `addresses/street`
    let parsed_root = claim_schema("root_mapped", "OBJECT");
    let mut parsed_nested2_array = claim_schema("root_mapped/nested2", "STRING");
    parsed_nested2_array.array = true;

    let parsed_format_id = Uuid::new_v4().into();
    let parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        parsed_format_id,
        format.as_ref(),
        vec![parsed_root.clone(), parsed_nested2_array.clone()],
        vec![
            mapping(parsed_format_id, parsed_root.id, "root_mapped", None),
            mapping(
                parsed_format_id,
                parsed_nested2_array.id,
                "root_mapped/nested2",
                None,
            ),
        ],
    );

    // stored V1 schema with differing keys -> claim paths must be remapped
    let mut stored_root = claim_schema("root", "OBJECT");
    stored_root.array = true;
    let stored_root_id = stored_root.id;
    let mut stored_nested = claim_schema("root/nested", "STRING");
    stored_nested.required = false;
    let stored_nested_id = stored_nested.id;
    let stored_format_id = Uuid::new_v4().into();
    let mut stored_schema = credential_schema(
        Uuid::new_v4().into(),
        stored_format_id,
        format.as_ref(),
        vec![stored_root, stored_nested],
        vec![
            mapping(stored_format_id, stored_root_id, "root_mapped", None),
            mapping(
                stored_format_id,
                stored_nested_id,
                "root_mapped/nested_mapped",
                None,
            ),
        ],
    );

    let mut credential = credential(
        parsed_schema,
        vec![
            claim("root_mapped", &parsed_root),
            claim("root_mapped/nested2/2", &parsed_nested2_array),
            claim("root_mapped/nested2/0", &parsed_nested2_array),
            claim("root_mapped/nested2/1", &parsed_nested2_array),
            claim("root_mapped/nested2", &parsed_nested2_array),
        ],
    );

    let (claim_schemas, mappings) = validate_existing_and_find_new_claim_schemas(
        &mut stored_schema,
        &mut credential,
        &format,
        "en",
        true,
    )
    .await
    .unwrap();

    assert_eq!(claim_schemas.len(), 1);
    assert_eq!(claim_schemas[0].key, "root/nested2");
    assert_eq!(mappings.len(), 1);
    assert_eq!(mappings[0].technical_key, "root_mapped/nested2");
    assert_eq!(mappings[0].namespace, None);
    let claims = credential.claims.as_ref().await.unwrap();
    assert_eq!(claims.len(), 5);
    assert_eq!(claims[0].path, "root");
    assert_eq!(claims[1].path, "root/nested2");
    assert_eq!(
        claims[1].schema.as_ref().await.unwrap().id,
        parsed_nested2_array.id
    );
    for (i, claim) in claims.iter().skip(2).enumerate() {
        assert_eq!(claim.path, format!("root/nested2/{i}"));
        assert_eq!(
            claim.schema.as_ref().await.unwrap().id,
            parsed_nested2_array.id
        );
    }
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

fn claim(path: &str, schema: &ClaimSchema) -> Claim {
    let now = now_utc();
    Claim {
        id: Uuid::new_v4().into(),
        credential_id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        value: Some("value".to_string()),
        path: path.to_string(),
        selectively_disclosable: false,
        schema: schema.clone().into(),
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
        key_storage_security: None,
        layout_properties: None,
        imported_source_url: "CORE_URL".to_string(),
        requires_wallet_instance_attestation: false,
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

fn credential(parsed_schema: CredentialSchema, claims: Vec<Claim>) -> Credential {
    let now = now_utc();
    Credential {
        expires_at: None,
        ecosystem: None,
        id: Uuid::new_v4().into(),
        created_date: now,
        issuance_date: None,
        last_modified: now,
        deleted_at: None,
        consumed_at: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        redirect_uri: None,
        role: CredentialRole::Holder,
        r#type: CredentialType::Single,
        state: CredentialStateEnum::Created,
        suspend_end_date: None,
        profile: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: None,
        embedded_disclosure_policy: None,
        claims: claims.into(),
        issuer_identifier: None,
        issuer_certificate: None,
        holder_identifier: None,
        schema: parsed_schema.into(),
        interaction: None,
        key: None,
        parent: None,
        subscriber_information: None,
        format: None,
    }
}
