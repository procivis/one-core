use std::sync::Arc;

use one_core::clock::now_utc;
use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential_schema::{
    BackgroundProperties, CredentialSchema, CredentialSchemaListQuery, LayoutProperties,
    UpdateCredentialSchemaRequest, WalletAttestation,
};
use one_core::model::credential_schema_format::CredentialSchemaFormat;
use one_core::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use one_core::model::list_filter::{ListFilterValue, StringMatch};
use one_core::model::list_query::ListPagination;
use one_core::model::localized_text::{LocalizedText, LocalizedTextEntityType, LocalizedTextField};
use one_core::model::organisation::Organisation;
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use one_core::repository::error::DataLayerError;
use one_core::repository::organisation_repository::{
    MockOrganisationRepository, OrganisationRepository,
};
use one_core::service::credential_schema::dto::CredentialSchemaFilterValue;
use rstest::rstest;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, QueryOrder, Set, Unchanged};
use shared_types::{ClaimSchemaId, CredentialSchemaId};
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::CredentialSchemaProvider;
use crate::entity::credential_schema::KeyStorageSecurity;
use crate::entity::{
    claim_schema, credential_schema, credential_schema_format,
    credential_schema_format_claim_schema, localized_text, organisation,
};
use crate::organisation::mapper::organisation_from_model;
use crate::test_utilities::*;
use crate::transaction_context::TransactionManagerImpl;

#[derive(Default)]
struct Repositories {
    pub organisation_repository: MockOrganisationRepository,
}

struct TestSetup {
    pub db: DatabaseConnection,
    pub organisation: Organisation,
    pub repository: Box<dyn CredentialSchemaRepository>,
}

async fn setup_empty(repositories: Repositories) -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None).await.unwrap();

    let organisation_repository: Arc<dyn OrganisationRepository> =
        Arc::from(repositories.organisation_repository);
    TestSetup {
        organisation: organisation_from_model(
            organisation::Entity::find_by_id(organisation_id)
                .one(&db)
                .await
                .expect("failed to load organisation")
                .expect("organisation not found"),
            &organisation_repository,
        ),
        repository: Box::new(CredentialSchemaProvider {
            db: TransactionManagerImpl::new(db.clone()),
            organisation_repository,
            localized_text_repository: data_layer.localized_text_repository,
        }),
        db,
    }
}

struct TestSetupWithCredentialSchema {
    pub db: DatabaseConnection,
    pub credential_schema: CredentialSchema,
    pub organisation: Organisation,
    pub repository: Box<dyn CredentialSchemaRepository>,
}

async fn setup_with_schema(repositories: Repositories) -> TestSetupWithCredentialSchema {
    let TestSetup {
        db,
        organisation,
        repository,
        ..
    } = setup_empty(repositories).await;

    let credential_schema_id = insert_credential_schema_to_database(
        &db,
        None,
        organisation.id,
        "credential schema",
        false,
        None,
    )
    .await
    .unwrap();

    let credential_schema_format_id =
        insert_credential_schema_with_revocation_to_database(&db, credential_schema_id, "JWT")
            .await
            .unwrap();

    let new_claim_schemas: Vec<ClaimInsertInfo> = (0..2)
        .map(|i| ClaimInsertInfo {
            id: Uuid::new_v4().into(),
            key: format!("key-{i}"),
            required: i % 2 == 0,
            order: i as u32,
            datatype: "STRING",
            array: false,
            metadata: false,
        })
        .collect();

    let claim_input = ProofInput {
        credential_schema_id,
        claims: &new_claim_schemas,
    };

    insert_many_claims_schema_to_database(&db, &claim_input)
        .await
        .unwrap();

    TestSetupWithCredentialSchema {
        credential_schema: CredentialSchema {
            expiration: None,
            ecosystem: None,
            batch_size: None,
            allow_revocation: false,
            id: credential_schema_id,
            deleted_at: None,
            wallet_attestation: Default::default(),
            imported_source_url: "CORE_URL".to_string(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: "credential schema".to_string(),
            formats: vec![CredentialSchemaFormat {
                id: credential_schema_format_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                credential_schema_id,
                format: "JWT".into(),
                ecosystem_schema_id: credential_schema_id.to_string(),
                claim_mappings: Default::default(),
            }]
            .into(),
            claim_schemas: new_claim_schemas
                .into_iter()
                .map(|claim| ClaimSchema {
                    id: claim.id,
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    key: claim.key.to_owned(),
                    data_type: claim.datatype.to_owned(),
                    array: false,
                    metadata: false,
                    required: claim.required,
                    translations: Default::default(),
                })
                .collect::<Vec<_>>()
                .into(),
            organisation: organisation.clone().into(),
            layout_properties: None,
            allow_suspension: true,
            transaction_code: None,
            embedded_disclosure_policy: None,
            translations: Default::default(),
        },
        organisation,
        repository,
        db,
    }
}

#[tokio::test]
async fn test_create_credential_schema_success() {
    let TestSetup {
        repository,
        organisation,
        db,
        ..
    } = setup_empty(Repositories::default()).await;

    let credential_schema_id: CredentialSchemaId = Uuid::new_v4().into();
    let claim_schemas = vec![
        ClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            key: "key1".to_string(),
            data_type: "STRING".to_string(),
            array: false,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
        ClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            key: "key2".to_string(),
            data_type: "STRING".to_string(),
            array: false,
            metadata: false,
            required: false,
            translations: Default::default(),
        },
    ];

    let result = repository
        .create_credential_schema(CredentialSchema {
            expiration: None,
            ecosystem: None,
            batch_size: None,
            allow_revocation: false,
            id: credential_schema_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            deleted_at: None,
            wallet_attestation: WalletAttestation {
                require_instance_attestation: false,
                key_storage_security_level: Some(KeyStorageSecurity::Basic.into()),
                preferred_key_storage_attestation_lifetime: None,
                preferred_instance_attestation_lifetime: None,
            },
            imported_source_url: "CORE_URL".to_string(),
            name: "schema".to_string(),
            formats: vec![CredentialSchemaFormat {
                id: Uuid::new_v4().into(),
                created_date: now_utc(),
                last_modified: now_utc(),
                credential_schema_id,
                format: "JWT".into(),
                ecosystem_schema_id: "CredentialSchemaId".to_owned(),
                claim_mappings: Default::default(),
            }]
            .into(),
            claim_schemas: claim_schemas.into(),
            organisation: organisation.into(),
            layout_properties: None,
            allow_suspension: true,
            transaction_code: None,
            translations: Default::default(),
            embedded_disclosure_policy: None,
        })
        .await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), credential_schema_id);

    assert_eq!(
        credential_schema::Entity::find()
            .all(&db)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        crate::entity::claim_schema::Entity::find()
            .all(&db)
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn test_create_credential_schema_already_exists() {
    let TestSetupWithCredentialSchema {
        credential_schema,
        repository,
        ..
    } = setup_with_schema(Repositories::default()).await;

    let result = repository.create_credential_schema(credential_schema).await;
    assert!(matches!(result, Err(DataLayerError::AlreadyExists(_))));
}

#[tokio::test]
async fn test_get_credential_schema_list_success() {
    let TestSetupWithCredentialSchema {
        organisation,
        repository,
        ..
    } = setup_with_schema(Repositories::default()).await;

    let result = repository
        .get_credential_schema_list(CredentialSchemaListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 5,
            }),
            filtering: Some(
                CredentialSchemaFilterValue::OrganisationId(organisation.id).condition(),
            ),
            ..Default::default()
        })
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(1, result.total_pages.unwrap());
    assert_eq!(1, result.total_items.unwrap());
    assert_eq!(1, result.values.len());
}

#[tokio::test]
async fn test_get_credential_schema_list_by_display_names() {
    let TestSetupWithCredentialSchema {
        organisation,
        credential_schema,
        repository,
        db,
        ..
    } = setup_with_schema(Repositories::default()).await;

    crate::entity::localized_text::ActiveModel {
        entity_id: Set(credential_schema.id.into()),
        lang: Set("de".to_string()),
        field: Set(LocalizedTextField::Name.into()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        value: Set("Deutscher Ausweis".to_string()),
        entity_type: Set(LocalizedTextEntityType::CredentialSchema.into()),
    }
    .insert(&db)
    .await
    .unwrap();

    let result = repository
        .get_credential_schema_list(CredentialSchemaListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 5,
            }),
            filtering: Some(
                CredentialSchemaFilterValue::OrganisationId(organisation.id).condition()
                    & CredentialSchemaFilterValue::DisplayNames(vec![(
                        "de".to_string(),
                        StringMatch::starts_with("Deutscher"),
                    )])
                    .condition(),
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(result.total_items.unwrap(), 1);
    assert_eq!(result.values[0].id, credential_schema.id);

    let result = repository
        .get_credential_schema_list(CredentialSchemaListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 5,
            }),
            filtering: Some(
                CredentialSchemaFilterValue::OrganisationId(organisation.id).condition()
                    & CredentialSchemaFilterValue::DisplayNames(vec![(
                        "en".to_string(),
                        StringMatch::starts_with("Deutscher"),
                    )])
                    .condition(),
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(result.total_items.unwrap(), 0);
}

#[tokio::test]
async fn test_get_credential_schema_list_deleted_schema() {
    let TestSetupWithCredentialSchema {
        organisation,
        repository,
        credential_schema,
        db,
        ..
    } = setup_with_schema(Repositories::default()).await;

    credential_schema::ActiveModel {
        id: Unchanged(credential_schema.id),
        deleted_at: Set(Some(get_dummy_date())),
        ..Default::default()
    }
    .update(&db)
    .await
    .unwrap();

    let result = repository
        .get_credential_schema_list(CredentialSchemaListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 1,
            }),
            filtering: Some(
                CredentialSchemaFilterValue::OrganisationId(organisation.id).condition(),
            ),
            ..Default::default()
        })
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(0, result.total_pages.unwrap());
    assert_eq!(0, result.total_items.unwrap());
    assert_eq!(0, result.values.len());
}

#[tokio::test]
async fn test_get_credential_schema_success() {
    let TestSetupWithCredentialSchema {
        credential_schema,
        repository,
        organisation,
        ..
    } = setup_with_schema(Default::default()).await;

    let result = repository
        .get_credential_schema(&credential_schema.id)
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(credential_schema.id, result.id);
    let claim_schemas = result.claim_schemas.as_ref().await.unwrap();
    assert_eq!(claim_schemas.len(), 2);
    assert_eq!(organisation.id, result.organisation.id());

    let empty_relations_mean_no_other_repository_calls = repository
        .get_credential_schema(&credential_schema.id)
        .await;
    assert!(empty_relations_mean_no_other_repository_calls.is_ok());
}

#[tokio::test]
async fn test_get_credential_schema_deleted() {
    let TestSetupWithCredentialSchema {
        credential_schema,
        repository,
        db,
        ..
    } = setup_with_schema(Default::default()).await;

    let delete_date = get_dummy_date();
    credential_schema::ActiveModel {
        id: Unchanged(credential_schema.id),
        deleted_at: Set(Some(delete_date)),
        ..Default::default()
    }
    .update(&db)
    .await
    .unwrap();

    let result = repository
        .get_credential_schema(&credential_schema.id)
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.id, credential_schema.id);
    assert_eq!(result.deleted_at.unwrap(), delete_date);
}

#[tokio::test]
async fn test_get_credential_schema_not_found() {
    let TestSetup { repository, .. } = setup_empty(Repositories::default()).await;

    let result = repository
        .get_credential_schema(&Uuid::new_v4().into())
        .await;
    assert!(matches!(result, Err(DataLayerError::EntityNotFound { .. })));
}

#[tokio::test]
async fn test_delete_credential_schema_success() {
    let TestSetupWithCredentialSchema {
        credential_schema,
        repository,
        db,
        ..
    } = setup_with_schema(Repositories::default()).await;

    let result = repository
        .delete_credential_schema(&credential_schema)
        .await;
    assert!(result.is_ok());

    let db_schemas = credential_schema::Entity::find().all(&db).await.unwrap();
    assert_eq!(db_schemas.len(), 1);
    assert!(db_schemas[0].deleted_at.is_some());
}

#[tokio::test]
async fn test_delete_credential_schema_not_found() {
    let TestSetup { repository, .. } = setup_empty(Repositories::default()).await;

    let credential_schema_id = Uuid::new_v4().into();
    let result = repository
        .delete_credential_schema(&CredentialSchema {
            expiration: None,
            ecosystem: None,
            batch_size: None,
            allow_revocation: false,
            id: credential_schema_id,
            deleted_at: None,
            created_date: now_utc(),
            last_modified: now_utc(),
            name: "Test".to_string(),
            formats: vec![CredentialSchemaFormat {
                id: Uuid::new_v4().into(),
                created_date: now_utc(),
                last_modified: now_utc(),
                credential_schema_id,
                format: "MDOC".into(),
                ecosystem_schema_id: "Test_schema_id".to_owned(),
                claim_mappings: Default::default(),
            }]
            .into(),
            wallet_attestation: Default::default(),
            layout_properties: None,
            imported_source_url: "".to_string(),
            allow_suspension: false,
            claim_schemas: Default::default(),
            organisation: dummy_organisation(None).into(),
            transaction_code: None,
            translations: Default::default(),
            embedded_disclosure_policy: None,
        })
        .await;
    assert!(matches!(result, Err(DataLayerError::RecordNotUpdated(_))));
}

#[tokio::test]
async fn test_update_credential_schema_success() {
    let TestSetupWithCredentialSchema {
        credential_schema,
        repository,
        db,
        ..
    } = setup_with_schema(Repositories::default()).await;

    let result = repository
        .update_credential_schema(
            &credential_schema.id,
            UpdateCredentialSchemaRequest {
                layout_properties: Some(LayoutProperties {
                    background: Some(BackgroundProperties {
                        color: Some("color".to_string()),
                        image: None,
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await;
    assert!(result.is_ok());

    let db_schemas = credential_schema::Entity::find().all(&db).await.unwrap();
    assert_eq!(db_schemas.len(), 1);
    assert_eq!(
        &db_schemas[0]
            .layout_properties
            .as_ref()
            .unwrap()
            .background
            .as_ref()
            .unwrap()
            .color,
        &Some("color".to_string())
    );
}

#[tokio::test]
async fn test_update_credential_schema_claims_success() {
    let TestSetupWithCredentialSchema {
        credential_schema,
        repository,
        db,
        ..
    } = setup_with_schema(Repositories::default()).await;

    let now = now_utc();
    let claim_schema_id = Uuid::new_v4().into();
    let result = repository
        .update_credential_schema(
            &credential_schema.id,
            UpdateCredentialSchemaRequest {
                claim_schemas: Some(vec![ClaimSchema {
                    id: claim_schema_id,
                    key: "new claim".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: now,
                    last_modified: now,
                    array: false,
                    metadata: false,
                    required: false,
                    translations: Default::default(),
                }]),
                ..Default::default()
            },
        )
        .await;
    assert!(result.is_ok());
    let claim_schema = crate::entity::claim_schema::Entity::find_by_id(claim_schema_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim_schema.order, 2);
}

#[tokio::test]
async fn test_update_credential_schema_existing_and_new_claims() {
    let TestSetupWithCredentialSchema {
        credential_schema,
        repository,
        db,
        ..
    } = setup_with_schema(Repositories::default()).await;
    let original_claims = claim_schema::Entity::find()
        .order_by_asc(claim_schema::Column::Order)
        .all(&db)
        .await
        .unwrap();
    let now = now_utc();
    let translation = LocalizedText {
        entity_id: original_claims[0].id.into(),
        field: LocalizedTextField::Name,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        lang: "de".to_string(),
        value: "Vorname".to_string(),
        entity_type: LocalizedTextEntityType::ClaimSchema,
    };
    let retained_translation = LocalizedText {
        lang: "en".to_string(),
        value: "First name".to_string(),
        ..translation.clone()
    };
    repository
        .update_credential_schema(
            &credential_schema.id,
            UpdateCredentialSchemaRequest {
                translations: Some(vec![translation.clone(), retained_translation.clone()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let updated_translation = LocalizedText {
        last_modified: now,
        value: "Alter".to_string(),
        ..translation
    };
    let updated_claim = ClaimSchema {
        id: original_claims[0].id,
        key: "updated claim".to_string(),
        data_type: "NUMBER".to_string(),
        created_date: now,
        last_modified: now,
        array: true,
        metadata: true,
        required: false,
        translations: vec![updated_translation.clone()].into(),
    };
    let new_claims: Vec<_> = (0..2)
        .map(|index| ClaimSchema {
            id: Uuid::new_v4().into(),
            key: format!("new claim {index}"),
            translations: Default::default(),
            ..updated_claim.clone()
        })
        .collect();
    repository
        .update_credential_schema(
            &credential_schema.id,
            UpdateCredentialSchemaRequest {
                claim_schemas: Some(vec![
                    new_claims[0].clone(),
                    updated_claim.clone(),
                    new_claims[1].clone(),
                ]),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Updating only an existing claim, including an unchanged one, must also succeed.
    repository
        .update_credential_schema(
            &credential_schema.id,
            UpdateCredentialSchemaRequest {
                claim_schemas: Some(vec![updated_claim.clone()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let stored_claims = claim_schema::Entity::find()
        .order_by_asc(claim_schema::Column::Order)
        .all(&db)
        .await
        .unwrap();
    assert_eq!(stored_claims.len(), 4);
    assert_eq!(
        stored_claims[0],
        claim_schema::Model {
            key: updated_claim.key,
            datatype: updated_claim.data_type,
            last_modified: now,
            array: true,
            metadata: true,
            required: false,
            ..original_claims[0].clone()
        }
    );
    assert_eq!(stored_claims[1], original_claims[1]);
    for (index, new_claim) in new_claims.iter().enumerate() {
        assert_eq!(stored_claims[index + 2].id, new_claim.id);
        assert_eq!(stored_claims[index + 2].order, (index + 2) as i32);
        assert_eq!(stored_claims[index + 2].created_date, now);
    }

    let stored_schema = repository
        .get_credential_schema(&credential_schema.id)
        .await
        .unwrap();
    let stored_claims = stored_schema.claim_schemas.as_ref().await.unwrap();
    let translations = stored_claims[0].translations.as_ref().await.unwrap();
    assert_eq!(translations.len(), 2);
    assert!(translations.iter().any(|translation| {
        translation.lang == updated_translation.lang
            && translation.value == updated_translation.value
            && translation.field == updated_translation.field
    }));
    assert!(translations.iter().any(|translation| {
        translation.lang == retained_translation.lang
            && translation.value == retained_translation.value
            && translation.field == retained_translation.field
    }));
}

#[rstest]
#[case(None)]
#[case(Some(vec![]))]
#[tokio::test]
async fn test_update_credential_schema_without_claims_preserves_existing_claims(
    #[case] claim_schemas: Option<Vec<ClaimSchema>>,
) {
    let TestSetupWithCredentialSchema {
        credential_schema,
        repository,
        db,
        ..
    } = setup_with_schema(Repositories::default()).await;
    let original_claims = claim_schema::Entity::find()
        .order_by_asc(claim_schema::Column::Order)
        .all(&db)
        .await
        .unwrap();

    repository
        .update_credential_schema(
            &credential_schema.id,
            UpdateCredentialSchemaRequest {
                claim_schemas,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let stored_claims = claim_schema::Entity::find()
        .order_by_asc(claim_schema::Column::Order)
        .all(&db)
        .await
        .unwrap();
    assert_eq!(stored_claims, original_claims);
}

#[tokio::test]
async fn test_update_credential_schema_rejects_claim_from_another_schema() {
    let TestSetupWithCredentialSchema {
        credential_schema,
        organisation,
        repository,
        db,
    } = setup_with_schema(Repositories::default()).await;
    let other_schema_id = insert_credential_schema_to_database(
        &db,
        None,
        organisation.id,
        "other schema",
        false,
        None,
    )
    .await
    .unwrap();
    let original_claims = claim_schema::Entity::find()
        .order_by_asc(claim_schema::Column::Order)
        .all(&db)
        .await
        .unwrap();
    let other_schema = credential_schema::Entity::find_by_id(other_schema_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    let foreign_claim = ClaimSchema {
        key: "must not change".to_string(),
        ..credential_schema.claim_schemas.as_ref().await.unwrap()[0].clone()
    };
    let new_claim = ClaimSchema {
        id: Uuid::new_v4().into(),
        ..foreign_claim.clone()
    };

    let result = repository
        .update_credential_schema(
            &other_schema_id,
            UpdateCredentialSchemaRequest {
                claim_schemas: Some(vec![new_claim, foreign_claim]),
                layout_properties: Some(LayoutProperties::default()),
                ..Default::default()
            },
        )
        .await;
    assert!(result.is_err());

    let stored_claims = claim_schema::Entity::find()
        .order_by_asc(claim_schema::Column::Order)
        .all(&db)
        .await
        .unwrap();
    assert_eq!(stored_claims, original_claims);
    assert_eq!(
        credential_schema::Entity::find_by_id(other_schema_id)
            .one(&db)
            .await
            .unwrap()
            .unwrap(),
        other_schema
    );
}

#[tokio::test]
async fn test_update_credential_schema_translations_success() {
    let TestSetupWithCredentialSchema {
        credential_schema,
        repository,
        ..
    } = setup_with_schema(Repositories::default()).await;

    let claim_schema_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;
    let now = now_utc();
    repository
        .update_credential_schema(
            &credential_schema.id,
            UpdateCredentialSchemaRequest {
                translations: Some(vec![
                    LocalizedText {
                        entity_id: credential_schema.id.into(),
                        field: LocalizedTextField::Name,
                        created_date: now,
                        last_modified: now,
                        lang: "de".to_string(),
                        value: "Ausweis".to_string(),
                        entity_type: LocalizedTextEntityType::CredentialSchema,
                    },
                    LocalizedText {
                        entity_id: credential_schema.id.into(),
                        field: LocalizedTextField::Description,
                        created_date: now,
                        last_modified: now,
                        lang: "de".to_string(),
                        value: "Ausweisbeschreibung".to_string(),
                        entity_type: LocalizedTextEntityType::CredentialSchema,
                    },
                    LocalizedText {
                        entity_id: claim_schema_id.into(),
                        field: LocalizedTextField::Name,
                        created_date: now,
                        last_modified: now,
                        lang: "de".to_string(),
                        value: "Vorname".to_string(),
                        entity_type: LocalizedTextEntityType::ClaimSchema,
                    },
                ]),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let stored_schema = repository
        .get_credential_schema(&credential_schema.id)
        .await
        .unwrap();
    let schema_translations = stored_schema.translations.as_ref().await.unwrap();
    assert_eq!(schema_translations.len(), 2);
    assert!(schema_translations.iter().any(|translation| {
        translation.field == LocalizedTextField::Description
            && translation.lang == "de"
            && translation.value == "Ausweisbeschreibung"
    }));

    let claim_schemas = stored_schema.claim_schemas.as_ref().await.unwrap();
    let claim_schema = claim_schemas
        .iter()
        .find(|claim_schema| claim_schema.id == claim_schema_id)
        .unwrap();
    let claim_translations = claim_schema.translations.as_ref().await.unwrap();
    assert_eq!(claim_translations.len(), 1);
    assert_eq!(claim_translations[0].value, "Vorname");
}

async fn set_name_translations(
    repository: &dyn CredentialSchemaRepository,
    credential_schema_id: CredentialSchemaId,
    claim_schema_id: ClaimSchemaId,
    schema_name: &str,
    claim_name: &str,
) {
    let now = now_utc();
    let translation = |entity_id, entity_type, value: &str| LocalizedText {
        entity_id,
        field: LocalizedTextField::Name,
        created_date: now,
        last_modified: now,
        lang: "de".to_string(),
        value: value.to_string(),
        entity_type,
    };
    repository
        .update_credential_schema(
            &credential_schema_id,
            UpdateCredentialSchemaRequest {
                translations: Some(vec![
                    translation(
                        credential_schema_id.into(),
                        LocalizedTextEntityType::CredentialSchema,
                        schema_name,
                    ),
                    translation(
                        claim_schema_id.into(),
                        LocalizedTextEntityType::ClaimSchema,
                        claim_name,
                    ),
                ]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

async fn translation_values(schema: &CredentialSchema) -> (Vec<String>, Vec<String>) {
    let schema_translations = schema
        .translations
        .as_ref()
        .await
        .unwrap()
        .iter()
        .map(|translation| translation.value.clone())
        .collect();
    let mut claim_translations = vec![];
    for claim_schema in schema.claim_schemas.as_ref().await.unwrap().iter() {
        for translation in claim_schema.translations.as_ref().await.unwrap().iter() {
            claim_translations.push(translation.value.clone());
        }
    }
    (schema_translations, claim_translations)
}

#[tokio::test]
async fn test_get_credential_schema_loads_all_translations_at_once() {
    let TestSetupWithCredentialSchema {
        credential_schema,
        repository,
        db,
        ..
    } = setup_with_schema(Repositories::default()).await;

    let claim_schema_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;
    set_name_translations(
        &*repository,
        credential_schema.id,
        claim_schema_id,
        "schema",
        "claim",
    )
    .await;

    let schema = repository
        .get_credential_schema(&credential_schema.id)
        .await
        .unwrap();
    assert_eq!(schema.translations.as_ref().await.unwrap().len(), 1);

    // the claim schema translations must be served from the batch loaded on first access
    localized_text::Entity::delete_many()
        .exec(&db)
        .await
        .unwrap();

    assert_eq!(
        translation_values(&schema).await,
        (vec!["schema".to_string()], vec!["claim".to_string()])
    );
}

#[tokio::test]
async fn test_get_credential_schema_list_batches_relations() {
    let TestSetupWithCredentialSchema {
        credential_schema,
        organisation,
        repository,
        db,
    } = setup_with_schema(Repositories::default()).await;

    let other_schema_id = insert_credential_schema_to_database(
        &db,
        None,
        organisation.id,
        "other schema",
        false,
        None,
    )
    .await
    .unwrap();
    let other_claim_schema_id = Uuid::new_v4().into();
    insert_many_claims_schema_to_database(
        &db,
        &ProofInput {
            credential_schema_id: other_schema_id,
            claims: &vec![ClaimInsertInfo {
                id: other_claim_schema_id,
                key: "other-key".to_string(),
                required: true,
                order: 0,
                datatype: "STRING",
                array: false,
                metadata: false,
            }],
        },
    )
    .await
    .unwrap();

    let claim_schema_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;
    let schemas = [
        (credential_schema.id, claim_schema_id, "first"),
        (other_schema_id, other_claim_schema_id, "other"),
    ];
    for (schema_id, claim_schema_id, prefix) in schemas {
        set_name_translations(
            &*repository,
            schema_id,
            claim_schema_id,
            &format!("{prefix} schema"),
            &format!("{prefix} claim"),
        )
        .await;
    }

    let result = repository
        .get_credential_schema_list(CredentialSchemaListQuery {
            filtering: Some(
                CredentialSchemaFilterValue::OrganisationId(organisation.id).condition(),
            ),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(result.values.len(), 2);

    // loads the schema translations of the whole page, but not the claim schema translations
    assert_eq!(
        result.values[0].translations.as_ref().await.unwrap().len(),
        1
    );

    for (schema_id, claim_schema_id, prefix) in schemas {
        set_name_translations(
            &*repository,
            schema_id,
            claim_schema_id,
            &format!("{prefix} schema updated"),
            &format!("{prefix} claim updated"),
        )
        .await;
    }

    // the first claim schema (translation) access loads them for the whole page
    let first_claim_schemas = result.values[0].claim_schemas.as_ref().await.unwrap();
    assert_eq!(
        first_claim_schemas[0]
            .translations
            .as_ref()
            .await
            .unwrap()
            .len(),
        1
    );

    insert_many_claims_schema_to_database(
        &db,
        &ProofInput {
            credential_schema_id: other_schema_id,
            claims: &vec![ClaimInsertInfo {
                id: Uuid::new_v4().into(),
                key: "added-later".to_string(),
                required: true,
                order: 1,
                datatype: "STRING",
                array: false,
                metadata: false,
            }],
        },
    )
    .await
    .unwrap();
    localized_text::Entity::delete_many()
        .exec(&db)
        .await
        .unwrap();

    for schema in &result.values {
        let (prefix, claim_schema_count) = if schema.id == credential_schema.id {
            ("first", 2)
        } else {
            ("other", 1)
        };
        assert_eq!(
            schema.claim_schemas.as_ref().await.unwrap().len(),
            claim_schema_count
        );
        assert_eq!(
            translation_values(schema).await,
            (
                vec![format!("{prefix} schema")],
                vec![format!("{prefix} claim updated")]
            )
        );
    }
}

#[tokio::test]
async fn test_update_credential_schema_formats_success() {
    let TestSetupWithCredentialSchema {
        credential_schema,
        repository,
        db,
        ..
    } = setup_with_schema(Repositories::default()).await;

    let now = now_utc();
    let format_id = Uuid::new_v4().into();
    let mapping_id = Uuid::new_v4().into();
    let claim_schema_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;
    repository
        .update_credential_schema(
            &credential_schema.id,
            UpdateCredentialSchemaRequest {
                formats: Some(vec![CredentialSchemaFormat {
                    id: format_id,
                    created_date: now,
                    last_modified: now,
                    credential_schema_id: credential_schema.id,
                    format: "SD_JWT".into(),
                    ecosystem_schema_id: "new-schema-id".to_string(),
                    claim_mappings: vec![CredentialSchemaFormatClaimSchema {
                        id: mapping_id,
                        created_date: now,
                        last_modified: now,
                        credential_schema_format_id: format_id,
                        claim_schema_id,
                        technical_key: "key-0".to_string(),
                        namespace: None,
                    }]
                    .into(),
                }]),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert!(
        credential_schema_format::Entity::find_by_id(format_id)
            .one(&db)
            .await
            .unwrap()
            .is_some()
    );
    let mapping = credential_schema_format_claim_schema::Entity::find_by_id(mapping_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mapping.credential_schema_format_id, format_id);
    assert_eq!(mapping.claim_schema_id, claim_schema_id);
}
