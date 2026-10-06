use rstest::rstest;
use shared_types::{ClaimSchemaId, CredentialFormat, CredentialSchemaFormatId, CredentialSchemaId};
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::{
    align_format_claim_schemas_and_mappings, find_or_import_credential_schema,
    missing_required_claims,
};
use crate::clock::now_utc;
use crate::config::core_config::{CoreConfig, DatatypeType, Fields};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{
    Credential, CredentialCommon, CredentialRole, CredentialStateEnum, CredentialType,
};
use crate::model::credential_schema::{CredentialSchema, GetCredentialSchemaList};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::localized_text::{LocalizedText, LocalizedTextEntityType, LocalizedTextField};
use crate::proto::credential_schema::importer::MockCredentialSchemaImporter;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::service::credential_schema::dto::CredentialSchemaFilterValue;
use crate::service::test_utilities::{CredentialBuilder, dummy_organisation};

#[rstest]
#[case::stored_requirements(true)]
#[case::issuer_requirements(false)]
#[tokio::test]
async fn required_array_child_must_exist_in_every_element(#[case] stored_required: bool) {
    let mut degrees = claim_schema("degrees", "OBJECT");
    degrees.array = true;
    let degree_type = claim_schema("degrees/type", "STRING");
    let name = claim_schema("name", "STRING");
    let format_id = Uuid::new_v4().into();
    let mut schema = credential_schema(
        Uuid::new_v4().into(),
        format_id,
        "JWT",
        vec![degrees.clone(), degree_type.clone(), name.clone()],
        vec![
            mapping(format_id, degrees.id, "degrees", None),
            mapping(format_id, degree_type.id, "degrees/type", None),
            mapping(format_id, name.id, "name", None),
        ],
    );
    let mandatory_claim_ids = if stored_required {
        vec![]
    } else {
        schema
            .claim_schemas
            .as_mut()
            .await
            .unwrap()
            .iter_mut()
            .map(|claim| {
                claim.required = false;
                claim.id
            })
            .collect()
    };
    let mut claims = vec![
        claim("degrees", &degrees),
        claim("degrees/0", &degrees),
        claim("degrees/0/type", &degree_type),
        claim("degrees/1", &degrees),
    ];
    let incomplete = credential(schema.clone(), claims.clone()).await;
    assert_eq!(
        missing_required_claims(&schema, &incomplete, &mandatory_claim_ids)
            .await
            .unwrap(),
        vec!["degrees/1/type", "name"]
    );

    claims.push(claim("degrees/1/type", &degree_type));
    claims.push(claim("name", &name));
    let complete = credential(schema.clone(), claims).await;
    assert!(
        missing_required_claims(&schema, &complete, &mandatory_claim_ids)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn required_child_of_nested_arrays_must_exist_at_every_nested_index() {
    let mut degrees = claim_schema("degrees", "OBJECT");
    degrees.array = true;
    let mut courses = claim_schema("degrees/courses", "OBJECT");
    courses.array = true;
    let course_type = claim_schema("degrees/courses/type", "STRING");
    let format_id = Uuid::new_v4().into();
    let schema = credential_schema(
        Uuid::new_v4().into(),
        format_id,
        "JWT",
        vec![degrees.clone(), courses.clone(), course_type.clone()],
        vec![
            mapping(format_id, degrees.id, "degrees", None),
            mapping(format_id, courses.id, "degrees/courses", None),
            mapping(format_id, course_type.id, "degrees/courses/type", None),
        ],
    );
    let credential = credential(
        schema.clone(),
        vec![
            claim("degrees", &degrees),
            claim("degrees/0", &degrees),
            claim("degrees/0/courses", &courses),
            claim("degrees/0/courses/0", &courses),
            claim("degrees/0/courses/0/type", &course_type),
            claim("degrees/0/courses/1", &courses),
        ],
    )
    .await;
    assert_eq!(
        missing_required_claims(&schema, &credential, &[])
            .await
            .unwrap(),
        vec!["degrees/0/courses/1/type"]
    );
}

#[tokio::test]
async fn required_array_child_not_mapped_to_current_format_is_ignored() {
    let mut degrees = claim_schema("degrees", "OBJECT");
    degrees.array = true;
    let degree_type = claim_schema("degrees/type", "STRING");
    let format_id = Uuid::new_v4().into();
    let schema = credential_schema(
        Uuid::new_v4().into(),
        format_id,
        "JWT",
        vec![degrees.clone(), degree_type],
        vec![mapping(format_id, degrees.id, "degrees", None)],
    );
    let credential = credential(
        schema.clone(),
        vec![claim("degrees", &degrees), claim("degrees/0", &degrees)],
    )
    .await;
    assert!(
        missing_required_claims(&schema, &credential, &[])
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn required_child_is_checked_only_when_optional_parent_is_present() {
    let mut address = claim_schema("address", "OBJECT");
    address.required = false;
    let city = claim_schema("address/city", "STRING");
    let format_id = Uuid::new_v4().into();
    let schema = credential_schema(
        Uuid::new_v4().into(),
        format_id,
        "JWT",
        vec![address.clone(), city.clone()],
        vec![
            mapping(format_id, address.id, "address", None),
            mapping(format_id, city.id, "address/city", None),
        ],
    );

    let absent_parent = credential(schema.clone(), vec![]).await;
    assert!(
        missing_required_claims(&schema, &absent_parent, &[])
            .await
            .unwrap()
            .is_empty()
    );

    let present_parent = credential(schema.clone(), vec![claim("address", &address)]).await;
    assert_eq!(
        missing_required_claims(&schema, &present_parent, &[])
            .await
            .unwrap(),
        vec!["address/city"]
    );

    let mut required_parent_schema = schema.clone();
    required_parent_schema.claim_schemas.as_mut().await.unwrap()[0].required = true;
    let missing_required_parent = credential(required_parent_schema.clone(), vec![]).await;
    assert_eq!(
        missing_required_claims(&required_parent_schema, &missing_required_parent, &[])
            .await
            .unwrap(),
        vec!["address"]
    );
}

#[tokio::test]
async fn required_child_is_checked_only_in_array_elements_with_optional_parent() {
    let mut degrees = claim_schema("degrees", "OBJECT");
    degrees.array = true;
    let mut details = claim_schema("degrees/details", "OBJECT");
    details.required = false;
    let detail_type = claim_schema("degrees/details/type", "STRING");
    let format_id = Uuid::new_v4().into();
    let schema = credential_schema(
        Uuid::new_v4().into(),
        format_id,
        "JWT",
        vec![degrees.clone(), details.clone(), detail_type.clone()],
        vec![
            mapping(format_id, degrees.id, "degrees", None),
            mapping(format_id, details.id, "degrees/details", None),
            mapping(format_id, detail_type.id, "degrees/details/type", None),
        ],
    );
    let credential = credential(
        schema.clone(),
        vec![
            claim("degrees", &degrees),
            claim("degrees/0", &degrees),
            claim("degrees/0/details", &details),
            claim("degrees/1", &degrees),
        ],
    )
    .await;

    assert_eq!(
        missing_required_claims(&schema, &credential, &[])
            .await
            .unwrap(),
        vec!["degrees/0/details/type"]
    );
}

#[tokio::test]
async fn missing_ancestor_claim_schema_is_an_error() {
    let city = claim_schema("address/city", "STRING");
    let format_id = Uuid::new_v4().into();
    let schema = credential_schema(
        Uuid::new_v4().into(),
        format_id,
        "JWT",
        vec![city.clone()],
        vec![mapping(format_id, city.id, "address/city", None)],
    );
    let missing_root_credential = credential(schema.clone(), vec![]).await;

    let error = missing_required_claims(&schema, &missing_root_credential, &[])
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("claim `address/city` is missing ancestor `address`")
    );

    let address = claim_schema("address", "OBJECT");
    let nested_city = claim_schema("address/location/city", "STRING");
    let nested_schema = credential_schema(
        Uuid::new_v4().into(),
        format_id,
        "JWT",
        vec![address.clone(), nested_city.clone()],
        vec![
            mapping(format_id, address.id, "address", None),
            mapping(format_id, nested_city.id, "address/location/city", None),
        ],
    );
    let nested_credential = credential(nested_schema.clone(), vec![]).await;
    let error = missing_required_claims(&nested_schema, &nested_credential, &[])
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("claim `address/location/city` is missing ancestor `address/location`")
    );
}

#[tokio::test]
async fn existing_ecosystem_schema_id_checks_required_claim_after_alignment() {
    let mut parsed_claim = claim_schema("present", "STRING");
    parsed_claim.required = false;
    let parsed_format_id = Uuid::new_v4().into();
    let parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        parsed_format_id,
        "JWT",
        vec![parsed_claim.clone()],
        vec![mapping(parsed_format_id, parsed_claim.id, "present", None)],
    );
    let parsed_format = parsed_schema.formats.as_ref().await.unwrap()[0].clone();
    let mut parsed_credential = credential(parsed_schema.clone(), vec![]).await;

    let required_claim = claim_schema("required", "STRING");
    let stored_format_id = Uuid::new_v4().into();
    let stored_schema = credential_schema(
        Uuid::new_v4().into(),
        stored_format_id,
        "JWT",
        vec![required_claim.clone()],
        vec![mapping(
            stored_format_id,
            required_claim.id,
            "required",
            None,
        )],
    );

    let mut repository = MockCredentialSchemaRepository::new();
    repository
        .expect_get_credential_schema_list()
        .once()
        .return_once(move |_| Ok(credential_schema_list(vec![stored_schema])));
    let importer = MockCredentialSchemaImporter::new();

    let resolution = find_or_import_credential_schema(
        &importer,
        &repository,
        parsed_schema,
        &parsed_format,
        dummy_organisation(None).id,
        &CoreConfig::default(),
    )
    .await
    .unwrap();
    let mut selected_schema = resolution.schema;
    align_format_claim_schemas_and_mappings(
        &mut selected_schema,
        &mut parsed_credential,
        "en",
        None,
    )
    .await
    .unwrap();

    assert_eq!(
        missing_required_claims(&selected_schema, &parsed_credential, &[])
            .await
            .unwrap(),
        vec!["required"]
    );
}

#[tokio::test]
async fn formatted_key_match_with_different_namespace_does_not_satisfy_stored_requirement() {
    let parsed_claim = claim_schema("parsed-city", "STRING");
    let parsed_format_id = Uuid::new_v4().into();
    let parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        parsed_format_id,
        "JWT",
        vec![parsed_claim.clone()],
        vec![mapping(
            parsed_format_id,
            parsed_claim.id,
            "address/city",
            None,
        )],
    );
    let parsed_format = parsed_schema.formats.as_ref().await.unwrap()[0].clone();
    let mut parsed_credential = credential(
        parsed_schema.clone(),
        vec![claim("parsed-city", &parsed_claim)],
    )
    .await;

    let required_claim = claim_schema("stored-city", "STRING");
    let stored_format_id = Uuid::new_v4().into();
    let stored_schema_id = Uuid::new_v4().into();
    let stored_schema = credential_schema(
        stored_schema_id,
        stored_format_id,
        "JWT",
        vec![required_claim.clone()],
        vec![mapping(
            stored_format_id,
            required_claim.id,
            "city",
            Some("address"),
        )],
    );

    let mut repository = MockCredentialSchemaRepository::new();
    repository
        .expect_get_credential_schema_list()
        .once()
        .return_once(move |_| Ok(credential_schema_list(vec![stored_schema])));
    let importer = MockCredentialSchemaImporter::new();

    let resolution = find_or_import_credential_schema(
        &importer,
        &repository,
        parsed_schema,
        &parsed_format,
        dummy_organisation(None).id,
        &CoreConfig::default(),
    )
    .await
    .unwrap();

    assert_eq!(resolution.schema.id, stored_schema_id);
    assert!(resolution.new_format.is_none());
    let mut selected_schema = resolution.schema;
    align_format_claim_schemas_and_mappings(
        &mut selected_schema,
        &mut parsed_credential,
        "en",
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        missing_required_claims(&selected_schema, &parsed_credential, &[])
            .await
            .unwrap(),
        vec!["stored-city"]
    );
}

#[rstest]
#[tokio::test]
async fn existing_multiformat_schema_ignores_missing_metadata_claims(
    #[values("JWT", "SD_JWT")] format: &str,
) {
    let parsed_claim = claim_schema("name", "STRING");
    let parsed_format_id = Uuid::new_v4().into();
    let parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        parsed_format_id,
        format,
        vec![parsed_claim.clone()],
        vec![mapping(parsed_format_id, parsed_claim.id, "name", None)],
    );
    let parsed_format = parsed_schema.formats.as_ref().await.unwrap()[0].clone();
    let mut parsed_credential =
        credential(parsed_schema.clone(), vec![claim("name", &parsed_claim)]).await;

    let stored_claim = claim_schema("name", "STRING");
    let mut vct = claim_schema("vct", "STRING");
    vct.metadata = true;
    let stored_format_id = Uuid::new_v4().into();
    let stored_schema_id = Uuid::new_v4().into();
    let mut stored_schema = credential_schema(
        stored_schema_id,
        stored_format_id,
        format,
        vec![stored_claim.clone(), vct.clone()],
        vec![mapping(stored_format_id, stored_claim.id, "name", None)],
    );
    let sd_jwt_vc_format_id = Uuid::new_v4().into();
    stored_schema
        .formats
        .as_mut()
        .await
        .unwrap()
        .push(CredentialSchemaFormat {
            id: sd_jwt_vc_format_id,
            created_date: now_utc(),
            last_modified: now_utc(),
            credential_schema_id: stored_schema_id,
            format: "SD_JWT_VC".into(),
            ecosystem_schema_id: "sd-jwt-vc-schema-id".to_string(),
            claim_mappings: vec![
                mapping(sd_jwt_vc_format_id, stored_claim.id, "name", None),
                mapping(sd_jwt_vc_format_id, vct.id, "vct", None),
            ]
            .into(),
        });

    let mut repository = MockCredentialSchemaRepository::new();
    let importer = MockCredentialSchemaImporter::new();
    repository
        .expect_get_credential_schema_list()
        .once()
        .return_once(move |_| Ok(credential_schema_list(vec![stored_schema])));

    let resolution = find_or_import_credential_schema(
        &importer,
        &repository,
        parsed_schema,
        &parsed_format,
        dummy_organisation(None).id,
        &CoreConfig::default(),
    )
    .await
    .unwrap();

    assert_eq!(resolution.schema.id, stored_schema_id);
    assert!(resolution.new_format.is_none());
    let mut selected_schema = resolution.schema;
    align_format_claim_schemas_and_mappings(
        &mut selected_schema,
        &mut parsed_credential,
        "en",
        None,
    )
    .await
    .unwrap();
    assert!(
        missing_required_claims(&selected_schema, &parsed_credential, &[])
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn ecosystem_schema_id_match_takes_precedence_over_display_name_match() {
    let parsed_format_id = Uuid::new_v4().into();
    let mut parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        parsed_format_id,
        "JWT",
        vec![],
        vec![],
    );
    add_name_translation(&mut parsed_schema, "en", "Display name").await;
    let parsed_format = parsed_schema.formats.as_ref().await.unwrap()[0].clone();

    let mut display_name_schema = credential_schema(
        Uuid::new_v4().into(),
        Uuid::new_v4().into(),
        "SD_JWT",
        vec![],
        vec![],
    );
    set_ecosystem_schema_id(&mut display_name_schema, "other-schema-id").await;
    add_name_translation(&mut display_name_schema, "en", "Display name").await;

    let exact_schema_id = Uuid::new_v4().into();
    let exact_schema = credential_schema(
        exact_schema_id,
        Uuid::new_v4().into(),
        "JWT",
        vec![],
        vec![],
    );

    let mut repository = MockCredentialSchemaRepository::new();
    repository
        .expect_get_credential_schema_list()
        .once()
        .return_once(move |_| {
            Ok(credential_schema_list(vec![
                display_name_schema,
                exact_schema,
            ]))
        });
    let importer = MockCredentialSchemaImporter::new();

    let resolution = find_or_import_credential_schema(
        &importer,
        &repository,
        parsed_schema,
        &parsed_format,
        dummy_organisation(None).id,
        &CoreConfig::default(),
    )
    .await
    .unwrap();

    assert_eq!(resolution.schema.id, exact_schema_id);
    assert!(resolution.new_format.is_none());
}

#[rstest]
#[case::string_email("STRING", "EMAIL")]
#[case::number_date("NUMBER", "DATE")]
#[case::object("OBJECT", "OBJECT")]
#[case::custom_object("CUSTOM_OBJECT", "OBJECT")]
#[case::stored_custom_object("OBJECT", "CUSTOM_OBJECT")]
#[tokio::test]
async fn matches_display_name_translation_and_adds_new_format(
    #[case] parsed_data_type: &str,
    #[case] stored_data_type: &str,
) {
    let mut parsed_claim = claim_schema("parsed-name", parsed_data_type);
    add_claim_name_translation(&mut parsed_claim, "en", "Full name").await;
    let parsed_format_id = Uuid::new_v4().into();
    let mut parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        parsed_format_id,
        "SD_JWT",
        vec![parsed_claim.clone()],
        vec![mapping(
            parsed_format_id,
            parsed_claim.id,
            "profile/name",
            None,
        )],
    );
    set_ecosystem_schema_id(&mut parsed_schema, "new-schema-id").await;
    add_name_translation(&mut parsed_schema, "de", "Mein Ausweis").await;
    let parsed_format = parsed_schema.formats.as_ref().await.unwrap()[0].clone();

    // The internal and technical keys are entirely different. Claim display names establish the
    // match, and the heuristic data type mismatch must not reject it.
    let mut stored_claim = claim_schema("stored-name", stored_data_type);
    add_claim_name_translation(&mut stored_claim, "en", "Full name").await;
    let stored_format_id = Uuid::new_v4().into();
    let stored_schema_id = Uuid::new_v4().into();
    let mut stored_schema = credential_schema(
        stored_schema_id,
        stored_format_id,
        "JWT",
        vec![stored_claim.clone()],
        vec![mapping(
            stored_format_id,
            stored_claim.id,
            "legal-name",
            Some("subject"),
        )],
    );
    set_ecosystem_schema_id(&mut stored_schema, "old-schema-id").await;
    add_name_translation(&mut stored_schema, "de", "Mein Ausweis").await;

    let mut repository = MockCredentialSchemaRepository::new();
    repository
        .expect_get_credential_schema_list()
        .withf(|query| {
            query.filtering.as_ref().is_some_and(|filter| {
                filter.contains(&|value| {
                    matches!(value, CredentialSchemaFilterValue::DisplayNames(_))
                })
            })
        })
        .once()
        .return_once(move |_| Ok(credential_schema_list(vec![stored_schema])));
    let importer = MockCredentialSchemaImporter::new();

    let resolution = find_or_import_credential_schema(
        &importer,
        &repository,
        parsed_schema,
        &parsed_format,
        dummy_organisation(None).id,
        &config_with_datatypes(),
    )
    .await
    .unwrap();

    assert_eq!(resolution.schema.id, stored_schema_id);
    assert_eq!(
        resolution.new_format.as_ref().map(|format| format.id),
        Some(parsed_format_id)
    );
    let formats = resolution.schema.formats.as_ref().await.unwrap();
    assert_eq!(formats.len(), 2);
    let new_format = formats
        .iter()
        .find(|format| format.id == parsed_format_id)
        .unwrap();
    assert_eq!(new_format.credential_schema_id, stored_schema_id);
    let new_mapping = &new_format.claim_mappings.as_ref().await.unwrap()[0];
    assert_eq!(new_mapping.claim_schema_id, stored_claim.id);
    assert_eq!(new_mapping.technical_key, "profile/name");
    assert_eq!(new_mapping.namespace, None);
}

#[tokio::test]
async fn display_name_match_reuses_shared_metadata_claim_across_formats() {
    let mut parsed_exp = claim_schema("exp", "NUMBER");
    parsed_exp.metadata = true;
    parsed_exp.required = false;
    let parsed_format_id = Uuid::new_v4().into();
    let mut parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        parsed_format_id,
        "SD_JWT",
        vec![parsed_exp.clone()],
        vec![mapping(parsed_format_id, parsed_exp.id, "exp", None)],
    );
    set_ecosystem_schema_id(&mut parsed_schema, "sd-jwt-schema-id").await;
    add_name_translation(&mut parsed_schema, "en", "Combined credential").await;
    let parsed_format = parsed_schema.formats.as_ref().await.unwrap()[0].clone();
    let mut parsed_credential =
        credential(parsed_schema.clone(), vec![claim("exp", &parsed_exp)]).await;

    let mut stored_exp = claim_schema("exp", "NUMBER");
    stored_exp.metadata = true;
    stored_exp.required = false;
    let stored_exp_id = stored_exp.id;
    let stored_format_id = Uuid::new_v4().into();
    let stored_schema_id = Uuid::new_v4().into();
    let mut stored_schema = credential_schema(
        stored_schema_id,
        stored_format_id,
        "JWT",
        vec![stored_exp],
        vec![mapping(stored_format_id, stored_exp_id, "exp", None)],
    );
    set_ecosystem_schema_id(&mut stored_schema, "jwt-schema-id").await;
    add_name_translation(&mut stored_schema, "en", "Combined credential").await;

    let mut repository = MockCredentialSchemaRepository::new();
    repository
        .expect_get_credential_schema_list()
        .once()
        .return_once(move |_| Ok(credential_schema_list(vec![stored_schema])));
    let importer = MockCredentialSchemaImporter::new();

    let resolution = find_or_import_credential_schema(
        &importer,
        &repository,
        parsed_schema,
        &parsed_format,
        dummy_organisation(None).id,
        &CoreConfig::default(),
    )
    .await
    .unwrap();

    assert_eq!(resolution.schema.id, stored_schema_id);
    let new_format = resolution.new_format.as_ref().unwrap();
    let new_mappings = new_format.claim_mappings.as_ref().await.unwrap();
    assert_eq!(new_mappings.len(), 1);
    assert_eq!(new_mappings[0].claim_schema_id, stored_exp_id);
    assert_eq!(new_mappings[0].technical_key, "exp");
    drop(new_mappings);

    let mut resolved_schema = resolution.schema;
    let alignment = align_format_claim_schemas_and_mappings(
        &mut resolved_schema,
        &mut parsed_credential,
        "en",
        None,
    )
    .await
    .unwrap();

    assert!(alignment.new_claim_schemas.is_empty());
    assert!(alignment.new_mappings.is_empty());
    assert_eq!(
        resolved_schema.claim_schemas.as_ref().await.unwrap().len(),
        1
    );
}

#[tokio::test]
async fn display_name_match_renames_a_new_claim_with_a_conflicting_internal_key() {
    let mut parsed_claim = claim_schema("claim", "STRING");
    add_claim_name_translation(&mut parsed_claim, "en", "New claim").await;
    let parsed_format_id = Uuid::new_v4().into();
    let mut parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        parsed_format_id,
        "SD_JWT",
        vec![parsed_claim.clone()],
        vec![mapping(
            parsed_format_id,
            parsed_claim.id,
            "serialized-claim",
            None,
        )],
    );
    set_ecosystem_schema_id(&mut parsed_schema, "sd-jwt-schema-id").await;
    add_name_translation(&mut parsed_schema, "en", "Combined credential").await;
    let parsed_format = parsed_schema.formats.as_ref().await.unwrap()[0].clone();
    let mut parsed_credential =
        credential(parsed_schema.clone(), vec![claim("claim", &parsed_claim)]).await;

    let mut stored_claim = claim_schema("claim", "STRING");
    stored_claim.required = false;
    add_claim_name_translation(&mut stored_claim, "en", "Existing claim").await;
    let stored_format_id = Uuid::new_v4().into();
    let mut stored_schema = credential_schema(
        Uuid::new_v4().into(),
        stored_format_id,
        "JWT",
        vec![stored_claim.clone()],
        vec![mapping(
            stored_format_id,
            stored_claim.id,
            "existing-claim",
            None,
        )],
    );
    set_ecosystem_schema_id(&mut stored_schema, "jwt-schema-id").await;
    add_name_translation(&mut stored_schema, "en", "Combined credential").await;

    let mut repository = MockCredentialSchemaRepository::new();
    repository
        .expect_get_credential_schema_list()
        .once()
        .return_once(move |_| Ok(credential_schema_list(vec![stored_schema])));
    let importer = MockCredentialSchemaImporter::new();

    let resolution = find_or_import_credential_schema(
        &importer,
        &repository,
        parsed_schema,
        &parsed_format,
        dummy_organisation(None).id,
        &CoreConfig::default(),
    )
    .await
    .unwrap();

    let mut resolved_schema = resolution.schema;
    let alignment = align_format_claim_schemas_and_mappings(
        &mut resolved_schema,
        &mut parsed_credential,
        "en",
        None,
    )
    .await
    .unwrap();

    assert_eq!(alignment.new_claim_schemas.len(), 1);
    let new_key = alignment.new_claim_schemas[0].key.to_owned();
    let suffix = new_key.strip_prefix("claim_").unwrap();
    Uuid::parse_str(suffix).unwrap();
    assert_eq!(alignment.new_mappings.len(), 1);
    assert_eq!(alignment.new_mappings[0].technical_key, "serialized-claim");
    assert_eq!(
        parsed_credential.claims().unwrap().as_ref().await.unwrap()[0].path,
        new_key
    );
}

#[tokio::test]
async fn matches_duplicate_claim_display_names_within_their_parent_hierarchy() {
    let parsed_mother = claim_schema_with_name("mother", "OBJECT", "Mother").await;
    let parsed_mother_name = claim_schema_with_name("mother/name", "STRING", "Name").await;
    let parsed_mother_birthday =
        claim_schema_with_name("mother/birthday", "DATE", "Birthday").await;
    let parsed_father = claim_schema_with_name("father", "OBJECT", "Father").await;
    let parsed_father_name = claim_schema_with_name("father/name", "STRING", "Name").await;
    let parsed_father_birthday =
        claim_schema_with_name("father/birthday", "DATE", "Birthday").await;
    let parsed_claim_schemas = vec![
        parsed_mother.clone(),
        parsed_mother_name.clone(),
        parsed_mother_birthday.clone(),
        parsed_father.clone(),
        parsed_father_name.clone(),
        parsed_father_birthday.clone(),
    ];
    let parsed_format_id = Uuid::new_v4().into();
    let mut parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        parsed_format_id,
        "SD_JWT",
        parsed_claim_schemas.clone(),
        parsed_claim_schemas
            .iter()
            .map(|claim_schema| mapping(parsed_format_id, claim_schema.id, &claim_schema.key, None))
            .collect(),
    );
    set_ecosystem_schema_id(&mut parsed_schema, "new-schema-id").await;
    add_name_translation(&mut parsed_schema, "en", "Family").await;
    let parsed_format = parsed_schema.formats.as_ref().await.unwrap()[0].clone();

    let stored_mother = claim_schema_with_name("maternal", "OBJECT", "Mother").await;
    let stored_mother_name = claim_schema_with_name("maternal/full-name", "STRING", "Name").await;
    let stored_mother_birthday =
        claim_schema_with_name("maternal/date-of-birth", "DATE", "Birthday").await;
    let stored_father = claim_schema_with_name("paternal", "OBJECT", "Father").await;
    let stored_father_name = claim_schema_with_name("paternal/full-name", "STRING", "Name").await;
    let stored_father_birthday =
        claim_schema_with_name("paternal/date-of-birth", "DATE", "Birthday").await;
    let stored_claim_schemas = vec![
        stored_mother.clone(),
        stored_mother_name.clone(),
        stored_mother_birthday.clone(),
        stored_father.clone(),
        stored_father_name.clone(),
        stored_father_birthday.clone(),
    ];
    let stored_format_id = Uuid::new_v4().into();
    let stored_schema_id = Uuid::new_v4().into();
    let mut stored_schema = credential_schema(
        stored_schema_id,
        stored_format_id,
        "JWT",
        stored_claim_schemas.clone(),
        stored_claim_schemas
            .iter()
            .enumerate()
            .map(|(index, claim_schema)| {
                mapping(
                    stored_format_id,
                    claim_schema.id,
                    &format!("old-claim-{index}"),
                    None,
                )
            })
            .collect(),
    );
    set_ecosystem_schema_id(&mut stored_schema, "old-schema-id").await;
    add_name_translation(&mut stored_schema, "en", "Family").await;

    let mut repository = MockCredentialSchemaRepository::new();
    repository
        .expect_get_credential_schema_list()
        .once()
        .return_once(move |_| Ok(credential_schema_list(vec![stored_schema])));
    let importer = MockCredentialSchemaImporter::new();

    let resolution = find_or_import_credential_schema(
        &importer,
        &repository,
        parsed_schema,
        &parsed_format,
        dummy_organisation(None).id,
        &CoreConfig::default(),
    )
    .await
    .unwrap();

    assert_eq!(resolution.schema.id, stored_schema_id);
    let new_format = resolution.new_format.unwrap();
    let mappings = new_format.claim_mappings.as_ref().await.unwrap();
    for (technical_key, expected_claim_schema_id) in [
        ("mother", stored_mother.id),
        ("mother/name", stored_mother_name.id),
        ("mother/birthday", stored_mother_birthday.id),
        ("father", stored_father.id),
        ("father/name", stored_father_name.id),
        ("father/birthday", stored_father_birthday.id),
    ] {
        let mapping = mappings
            .iter()
            .find(|mapping| mapping.technical_key == technical_key)
            .unwrap();
        assert_eq!(mapping.claim_schema_id, expected_claim_schema_id);
    }
}

#[tokio::test]
async fn display_name_match_with_same_format_and_different_schema_id_imports_new_schema() {
    let parsed_format_id = Uuid::new_v4().into();
    let mut parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        parsed_format_id,
        "JWT",
        vec![],
        vec![],
    );
    set_ecosystem_schema_id(&mut parsed_schema, "new-schema-id").await;
    add_name_translation(&mut parsed_schema, "en", "Display name").await;
    let parsed_format = parsed_schema.formats.as_ref().await.unwrap()[0].clone();

    let mut stored_schema = credential_schema(
        Uuid::new_v4().into(),
        Uuid::new_v4().into(),
        "JWT",
        vec![],
        vec![],
    );
    set_ecosystem_schema_id(&mut stored_schema, "other-schema-id").await;
    add_name_translation(&mut stored_schema, "en", "Display name").await;

    let mut repository = MockCredentialSchemaRepository::new();
    repository
        .expect_get_credential_schema_list()
        .once()
        .return_once(move |_| Ok(credential_schema_list(vec![stored_schema])));
    let parsed_schema_id = parsed_schema.id;
    let mut importer = MockCredentialSchemaImporter::new();
    importer
        .expect_import_credential_schema()
        .once()
        .return_once(Ok);

    let resolution = find_or_import_credential_schema(
        &importer,
        &repository,
        parsed_schema,
        &parsed_format,
        dummy_organisation(None).id,
        &CoreConfig::default(),
    )
    .await
    .unwrap();

    assert_eq!(resolution.schema.id, parsed_schema_id);
    assert!(resolution.new_format.is_none());
}

#[rstest]
#[case::array("NUMBER", "NUMBER", false, true)]
#[case::parsed_object("OBJECT", "STRING", false, false)]
#[case::stored_object("STRING", "OBJECT", false, false)]
#[case::parsed_custom_object("CUSTOM_OBJECT", "STRING", false, false)]
#[case::stored_custom_object("STRING", "CUSTOM_OBJECT", false, false)]
#[case::object_array("OBJECT", "STRING", true, true)]
#[case::stored_object_array("STRING", "OBJECT", true, true)]
#[tokio::test]
async fn display_name_match_with_conflicting_claim_imports_new_schema(
    #[case] parsed_data_type: &str,
    #[case] stored_data_type: &str,
    #[case] parsed_array: bool,
    #[case] stored_array: bool,
) {
    let mut parsed_claim = claim_schema("claim", parsed_data_type);
    parsed_claim.array = parsed_array;
    add_claim_name_translation(&mut parsed_claim, "en", "Claim").await;
    let parsed_format_id = Uuid::new_v4().into();
    let mut parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        parsed_format_id,
        "SD_JWT",
        vec![parsed_claim.clone()],
        vec![mapping(parsed_format_id, parsed_claim.id, "claim", None)],
    );
    set_ecosystem_schema_id(&mut parsed_schema, "new-schema-id").await;
    add_name_translation(&mut parsed_schema, "en", "Display name").await;
    let parsed_format = parsed_schema.formats.as_ref().await.unwrap()[0].clone();

    let mut stored_claim = claim_schema("claim", stored_data_type);
    stored_claim.array = stored_array;
    add_claim_name_translation(&mut stored_claim, "en", "Claim").await;
    let stored_format_id = Uuid::new_v4().into();
    let mut stored_schema = credential_schema(
        Uuid::new_v4().into(),
        stored_format_id,
        "JWT",
        vec![stored_claim.clone()],
        vec![mapping(stored_format_id, stored_claim.id, "claim", None)],
    );
    set_ecosystem_schema_id(&mut stored_schema, "old-schema-id").await;
    add_name_translation(&mut stored_schema, "en", "Display name").await;

    let mut repository = MockCredentialSchemaRepository::new();
    repository
        .expect_get_credential_schema_list()
        .once()
        .return_once(move |_| Ok(credential_schema_list(vec![stored_schema])));
    let parsed_schema_id = parsed_schema.id;
    let mut importer = MockCredentialSchemaImporter::new();
    importer
        .expect_import_credential_schema()
        .once()
        .return_once(Ok);

    let resolution = find_or_import_credential_schema(
        &importer,
        &repository,
        parsed_schema,
        &parsed_format,
        dummy_organisation(None).id,
        &config_with_datatypes(),
    )
    .await
    .unwrap();

    assert_eq!(resolution.schema.id, parsed_schema_id);
    assert!(resolution.new_format.is_none());
}

#[rstest]
#[case::missing_user_claim("stored-missing", false)]
#[case::missing_metadata_claim("vct", true)]
#[tokio::test]
async fn display_name_match_requires_only_non_metadata_claims(
    #[case] missing_claim_key: &str,
    #[case] metadata: bool,
) {
    let mut parsed_claim = claim_schema("parsed-present", "STRING");
    add_claim_name_translation(&mut parsed_claim, "en", "Present").await;
    let parsed_format_id = Uuid::new_v4().into();
    let mut parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        parsed_format_id,
        "SD_JWT",
        vec![parsed_claim.clone()],
        vec![mapping(
            parsed_format_id,
            parsed_claim.id,
            "serialized-present",
            None,
        )],
    );
    set_ecosystem_schema_id(&mut parsed_schema, "new-schema-id").await;
    add_name_translation(&mut parsed_schema, "en", "Display name").await;
    let parsed_format = parsed_schema.formats.as_ref().await.unwrap()[0].clone();

    let mut stored_present = claim_schema("stored-present", "STRING");
    add_claim_name_translation(&mut stored_present, "en", "Present").await;
    let mut stored_missing = claim_schema(missing_claim_key, "STRING");
    stored_missing.metadata = metadata;
    add_claim_name_translation(&mut stored_missing, "en", "Missing").await;
    let stored_format_id = Uuid::new_v4().into();
    let mut stored_schema = credential_schema(
        Uuid::new_v4().into(),
        stored_format_id,
        "SD_JWT_VC",
        vec![stored_present.clone(), stored_missing.clone()],
        vec![
            mapping(stored_format_id, stored_present.id, "old-present", None),
            mapping(stored_format_id, stored_missing.id, missing_claim_key, None),
        ],
    );
    set_ecosystem_schema_id(&mut stored_schema, "old-schema-id").await;
    add_name_translation(&mut stored_schema, "en", "Display name").await;
    let stored_schema_id = stored_schema.id;

    let mut repository = MockCredentialSchemaRepository::new();
    repository
        .expect_get_credential_schema_list()
        .once()
        .return_once(move |_| Ok(credential_schema_list(vec![stored_schema])));
    let parsed_schema_id = parsed_schema.id;
    let mut importer = MockCredentialSchemaImporter::new();
    if !metadata {
        importer
            .expect_import_credential_schema()
            .once()
            .return_once(Ok);
    }

    let resolution = find_or_import_credential_schema(
        &importer,
        &repository,
        parsed_schema,
        &parsed_format,
        dummy_organisation(None).id,
        &CoreConfig::default(),
    )
    .await
    .unwrap();

    assert_eq!(
        resolution.schema.id,
        if metadata {
            stored_schema_id
        } else {
            parsed_schema_id
        }
    );
    assert_eq!(resolution.new_format.is_some(), metadata);
}

#[tokio::test]
async fn display_name_match_with_metadata_mismatch_imports_new_schema() {
    let mut parsed_claim = claim_schema("parsed-claim", "STRING");
    add_claim_name_translation(&mut parsed_claim, "en", "Claim").await;
    let parsed_format_id = Uuid::new_v4().into();
    let mut parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        parsed_format_id,
        "SD_JWT",
        vec![parsed_claim.clone()],
        vec![mapping(
            parsed_format_id,
            parsed_claim.id,
            "serialized-claim",
            None,
        )],
    );
    set_ecosystem_schema_id(&mut parsed_schema, "new-schema-id").await;
    add_name_translation(&mut parsed_schema, "en", "Display name").await;
    let parsed_format = parsed_schema.formats.as_ref().await.unwrap()[0].clone();

    let mut stored_claim = claim_schema("stored-claim", "STRING");
    stored_claim.metadata = true;
    add_claim_name_translation(&mut stored_claim, "en", "Claim").await;
    let stored_format_id = Uuid::new_v4().into();
    let mut stored_schema = credential_schema(
        Uuid::new_v4().into(),
        stored_format_id,
        "JWT",
        vec![stored_claim.clone()],
        vec![mapping(
            stored_format_id,
            stored_claim.id,
            "old-claim",
            None,
        )],
    );
    set_ecosystem_schema_id(&mut stored_schema, "old-schema-id").await;
    add_name_translation(&mut stored_schema, "en", "Display name").await;

    let mut repository = MockCredentialSchemaRepository::new();
    repository
        .expect_get_credential_schema_list()
        .once()
        .return_once(move |_| Ok(credential_schema_list(vec![stored_schema])));
    let parsed_schema_id = parsed_schema.id;
    let mut importer = MockCredentialSchemaImporter::new();
    importer
        .expect_import_credential_schema()
        .once()
        .return_once(Ok);

    let resolution = find_or_import_credential_schema(
        &importer,
        &repository,
        parsed_schema,
        &parsed_format,
        dummy_organisation(None).id,
        &CoreConfig::default(),
    )
    .await
    .unwrap();

    assert_eq!(resolution.schema.id, parsed_schema_id);
    assert!(resolution.new_format.is_none());
}

#[tokio::test]
async fn matches_existing_schema() {
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

    let mut credential = credential(parsed_schema, vec![claim("address/city", &parsed_cs)]).await;

    let alignment =
        align_format_claim_schemas_and_mappings(&mut stored_schema, &mut credential, "en", None)
            .await
            .unwrap();

    assert!(alignment.new_claim_schemas.is_empty());
    assert!(alignment.new_mappings.is_empty());
    let claims = credential.claims().unwrap().as_ref().await.unwrap();
    assert_eq!(claims[0].schema.as_ref().await.unwrap().id, stored_cs_id);
    assert_eq!(claims[0].path, "addr/city");
}

#[tokio::test]
async fn remaps_nested_and_array_claim_paths() {
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
    )
    .await;

    let alignment =
        align_format_claim_schemas_and_mappings(&mut stored_schema, &mut credential, "en", None)
            .await
            .unwrap();

    assert!(alignment.new_claim_schemas.is_empty());
    assert!(alignment.new_mappings.is_empty());
    let claims = credential.claims().unwrap().as_ref().await.unwrap();
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
async fn returns_new_claim_schemas() {
    let parsed_cs = ClaimSchema {
        required: false,
        ..claim_schema("newClaim", "STRING")
    };
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

    let mut credential = credential(parsed_schema, vec![claim("newClaim", &parsed_cs)]).await;

    let alignment =
        align_format_claim_schemas_and_mappings(&mut stored_schema, &mut credential, "en", None)
            .await
            .unwrap();

    assert_eq!(alignment.new_claim_schemas.len(), 1);
    assert_eq!(alignment.new_claim_schemas[0].key, "newClaim");
    assert!(!alignment.new_claim_schemas[0].required);
    assert_eq!(alignment.new_mappings.len(), 1);
    assert_eq!(alignment.new_mappings[0].technical_key, "newClaim");
    assert_eq!(alignment.new_mappings[0].namespace, None);

    // fallback translation for the default language was added
    let translations = alignment.new_claim_schemas[0]
        .translations
        .as_ref()
        .await
        .unwrap();
    assert!(translations.iter().any(|t| t.lang == "en"));

    // the new claim schema was appended to the stored schema
    let stored_claim_schemas = stored_schema.claim_schemas.as_ref().await.unwrap();
    assert_eq!(stored_claim_schemas.iter().count(), 2);
    assert!(
        stored_claim_schemas
            .iter()
            .find(|claim| claim.id == cs_id)
            .unwrap()
            .required
    );
    assert!(
        !stored_claim_schemas
            .iter()
            .find(|claim| claim.id == parsed_cs.id)
            .unwrap()
            .required
    );
}

#[tokio::test]
async fn renames_a_new_nested_claim_after_parent_remapping_if_its_key_conflicts() {
    let parsed_parent = claim_schema("parsed-parent", "OBJECT");
    let parsed_child = claim_schema("parsed-parent/value", "STRING");
    let parsed_format_id = Uuid::new_v4().into();
    let parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        parsed_format_id,
        "JWT",
        vec![parsed_parent.clone(), parsed_child.clone()],
        vec![
            mapping(
                parsed_format_id,
                parsed_parent.id,
                "serialized-parent",
                None,
            ),
            mapping(
                parsed_format_id,
                parsed_child.id,
                "serialized-new-value",
                None,
            ),
        ],
    );

    let stored_parent = claim_schema("stored-parent", "OBJECT");
    let mut stored_child = claim_schema("stored-parent/value", "STRING");
    stored_child.required = false;
    let stored_format_id = Uuid::new_v4().into();
    let mut stored_schema = credential_schema(
        Uuid::new_v4().into(),
        stored_format_id,
        "JWT",
        vec![stored_parent.clone(), stored_child.clone()],
        vec![
            mapping(
                stored_format_id,
                stored_parent.id,
                "serialized-parent",
                None,
            ),
            mapping(
                stored_format_id,
                stored_child.id,
                "serialized-existing-value",
                None,
            ),
        ],
    );
    let mut credential = credential(
        parsed_schema,
        vec![
            claim("parsed-parent", &parsed_parent),
            claim("parsed-parent/value", &parsed_child),
        ],
    )
    .await;

    let alignment =
        align_format_claim_schemas_and_mappings(&mut stored_schema, &mut credential, "en", None)
            .await
            .unwrap();

    assert_eq!(alignment.new_claim_schemas.len(), 1);
    let new_key = alignment.new_claim_schemas[0].key.to_owned();
    let suffix = new_key.strip_prefix("stored-parent/value_").unwrap();
    Uuid::parse_str(suffix).unwrap();
    assert_eq!(alignment.new_mappings.len(), 1);
    assert_eq!(
        alignment.new_mappings[0].technical_key,
        "serialized-new-value"
    );
    let claims = credential.claims().unwrap().as_ref().await.unwrap();
    assert_eq!(claims[0].path, "stored-parent");
    assert_eq!(claims[1].path, new_key);
}

#[tokio::test]
async fn rejects_holder_batch_parent() {
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

    let mut credential = credential(parsed_schema, vec![]).await;
    credential = Credential::HolderBatchParent {
        common: credential.common().clone(),
    };

    let result =
        align_format_claim_schemas_and_mappings(&mut stored_schema, &mut credential, "en", None)
            .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn errors_when_stored_format_missing() {
    let parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        Uuid::new_v4().into(),
        "JWT",
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

    let mut credential = credential(parsed_schema, vec![]).await;

    let result =
        align_format_claim_schemas_and_mappings(&mut stored_schema, &mut credential, "en", None)
            .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn errors_when_parsed_mapping_missing() {
    // parsed schema has a claim schema but no corresponding claim mapping
    let parsed_cs = claim_schema("NUMBER", "NUMBER");
    let parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        Uuid::new_v4().into(),
        "JWT",
        vec![parsed_cs],
        vec![],
    );

    let mut stored_schema = credential_schema(
        Uuid::new_v4().into(),
        Uuid::new_v4().into(),
        "JWT",
        vec![],
        vec![],
    );

    let mut credential = credential(parsed_schema, vec![]).await;

    let result =
        align_format_claim_schemas_and_mappings(&mut stored_schema, &mut credential, "en", None)
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
    )
    .await;

    let alignment =
        align_format_claim_schemas_and_mappings(&mut stored_schema, &mut credential, "en", None)
            .await
            .unwrap();

    assert_eq!(alignment.new_claim_schemas.len(), 1);
    assert_eq!(alignment.new_claim_schemas[0].key, "root/nested2");
    assert_eq!(alignment.new_mappings.len(), 1);
    assert_eq!(
        alignment.new_mappings[0].technical_key,
        "root_mapped/nested2"
    );
    assert_eq!(alignment.new_mappings[0].namespace, None);
    let claims = credential.claims().unwrap().as_ref().await.unwrap();
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

fn config_with_datatypes() -> CoreConfig {
    let mut config = CoreConfig::default();
    for (key, r#type) in [
        ("STRING", DatatypeType::String),
        ("EMAIL", DatatypeType::String),
        ("NUMBER", DatatypeType::Number),
        ("DATE", DatatypeType::Date),
        ("OBJECT", DatatypeType::Object),
        ("CUSTOM_OBJECT", DatatypeType::Object),
    ] {
        config.datatype.insert(
            key.to_string(),
            Fields {
                r#type,
                display: key.into(),
                order: None,
                priority: None,
                enabled: true,
                capabilities: None,
                params: None,
            },
        );
    }
    config
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

fn credential_schema_list(values: Vec<CredentialSchema>) -> GetCredentialSchemaList {
    GetCredentialSchemaList {
        total_pages: Some(u64::from(!values.is_empty())),
        total_items: Some(values.len() as u64),
        values,
    }
}

async fn set_ecosystem_schema_id(schema: &mut CredentialSchema, ecosystem_schema_id: &str) {
    schema.formats.as_mut().await.unwrap()[0].ecosystem_schema_id = ecosystem_schema_id.to_string();
}

async fn add_name_translation(schema: &mut CredentialSchema, lang: &str, value: &str) {
    let now = now_utc();
    schema
        .translations
        .as_mut()
        .await
        .unwrap()
        .push(LocalizedText {
            entity_id: schema.id.into(),
            field: LocalizedTextField::Name,
            created_date: now,
            last_modified: now,
            lang: lang.to_string(),
            value: value.to_string(),
            entity_type: LocalizedTextEntityType::CredentialSchema,
        });
}

async fn add_claim_name_translation(claim_schema: &mut ClaimSchema, lang: &str, value: &str) {
    let now = now_utc();
    claim_schema
        .translations
        .as_mut()
        .await
        .unwrap()
        .push(LocalizedText {
            entity_id: claim_schema.id.into(),
            field: LocalizedTextField::Name,
            created_date: now,
            last_modified: now,
            lang: lang.to_string(),
            value: value.to_string(),
            entity_type: LocalizedTextEntityType::ClaimSchema,
        });
}

async fn claim_schema_with_name(key: &str, data_type: &str, name: &str) -> ClaimSchema {
    let mut claim_schema = claim_schema(key, data_type);
    add_claim_name_translation(&mut claim_schema, "en", name).await;
    claim_schema
}

async fn credential(parsed_schema: CredentialSchema, claims: Vec<Claim>) -> Credential {
    let now = now_utc();
    let format = {
        let formats = parsed_schema.formats.as_ref().await.unwrap();
        formats.first().unwrap().clone()
    };
    CredentialBuilder {
        common: CredentialCommon {
            expires_at: None,
            ecosystem: None,
            id: Uuid::new_v4().into(),
            created_date: now,
            issuance_date: None,
            last_modified: now,
            deleted_at: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            redirect_uri: None,
            state: CredentialStateEnum::Created,
            profile: None,
            schema: parsed_schema.into(),
            interaction: None,
        },
        consumed_at: None,
        role: CredentialRole::Holder,
        r#type: CredentialType::Single,
        suspend_end_date: None,
        credential_blob_id: None,
        wallet_key_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: None,
        embedded_disclosure_policy: None,
        claims: claims.into(),
        issuer_identifier: None,
        issuer_certificate: None,
        holder_identifier: None,
        key: None,
        parent: None,
        subscriber_information: None,
        format: Some(format.into()),
    }
    .build()
}

#[tokio::test]
async fn relinks_claims_of_new_root_array_claim_schema() {
    let parsed_name = claim_schema("name", "STRING");
    let mut parsed_addresses = claim_schema("addresses", "OBJECT");
    parsed_addresses.array = true;
    let parsed_street = claim_schema("addresses/street", "STRING");

    let parsed_format_id = Uuid::new_v4().into();
    let parsed_schema = credential_schema(
        Uuid::new_v4().into(),
        parsed_format_id,
        "JWT",
        vec![
            parsed_name.clone(),
            parsed_addresses.clone(),
            parsed_street.clone(),
        ],
        vec![
            mapping(parsed_format_id, parsed_name.id, "name", None),
            mapping(parsed_format_id, parsed_addresses.id, "addresses", None),
            mapping(parsed_format_id, parsed_street.id, "addresses/street", None),
        ],
    );

    // stored: only `name` known (first accepted credential had no `addresses`)
    let stored_name = claim_schema("name", "STRING");
    let stored_format_id = Uuid::new_v4().into();
    let mut stored_schema = credential_schema(
        Uuid::new_v4().into(),
        stored_format_id,
        "JWT",
        vec![stored_name.clone()],
        vec![mapping(stored_format_id, stored_name.id, "name", None)],
    );

    let mut credential = credential(
        parsed_schema,
        vec![
            claim("name", &parsed_name),
            claim("addresses", &parsed_addresses),
            claim("addresses/0", &parsed_addresses),
            claim("addresses/0/street", &parsed_street),
        ],
    )
    .await;

    let alignment =
        align_format_claim_schemas_and_mappings(&mut stored_schema, &mut credential, "en", None)
            .await
            .unwrap();

    assert_eq!(alignment.new_claim_schemas.len(), 2);
    let claims = credential.claims().unwrap().as_ref().await.unwrap();
    let paths: Vec<_> = claims.iter().map(|c| c.path.as_str()).collect();
    assert_eq!(
        paths,
        vec!["addresses", "addresses/0", "addresses/0/street", "name"]
    );
}
