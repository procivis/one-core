use std::collections::HashSet;
use std::ops::Add;
use std::sync::Arc;

use one_core::clock::now_utc;
use one_core::model::claim::Claim;
use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential::{
    Clearable, Credential, CredentialFilterValue, CredentialListQuery, CredentialRole,
    CredentialStateEnum, CredentialType, UpdateCredentialRequest,
};
use one_core::model::credential_schema::{CredentialSchema, WalletAttestation};
use one_core::model::credential_schema_format::CredentialSchemaFormat;
use one_core::model::did::Did;
use one_core::model::identifier::{Identifier, IdentifierData, IdentifierState};
use one_core::model::list_filter::{ComparisonType, ListFilterValue, StringMatch, ValueComparison};
use one_core::model::list_query::ListPagination;
use one_core::repository::certificate_repository::{
    CertificateRepository, MockCertificateRepository,
};
use one_core::repository::claim_repository::{ClaimRepository, MockClaimRepository};
use one_core::repository::claim_schema_repository::MockClaimSchemaRepository;
use one_core::repository::credential_repository::CredentialRepository;
use one_core::repository::credential_schema_repository::{
    CredentialSchemaRepository, MockCredentialSchemaRepository,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::identifier_repository::{IdentifierRepository, MockIdentifierRepository};
use one_core::repository::interaction_repository::{
    InteractionRepository, MockInteractionRepository,
};
use one_core::repository::key_repository::{KeyRepository, MockKeyRepository};
use one_core::repository::organisation_repository::{
    MockOrganisationRepository, OrganisationRepository,
};
use one_dto_mapper::convert_inner;
use rstest::rstest;
use sea_orm::{DatabaseConnection, EntityTrait, Set};
use shared_types::CredentialId;
use similar_asserts::assert_eq;
use time::Duration;
use uuid::Uuid;

use super::CredentialProvider;
use crate::claim::ClaimProvider;
use crate::entity::credential_schema::KeyStorageSecurity;
use crate::entity::{credential, interaction};
use crate::test_utilities;
use crate::test_utilities::*;
use crate::transaction_context::TransactionManagerImpl;

#[path = "test/deduplication.rs"]
mod deduplication;

struct TestSetup {
    pub db: sea_orm::DatabaseConnection,
    pub credential_schema: CredentialSchema,
    pub identifier: Identifier,
}

async fn setup_empty() -> TestSetup {
    let db = setup_test_data_layer_and_connection().await.db;
    let organisation_id = insert_organisation_to_database(&db, None).await.unwrap();

    let credential_schema_id = insert_credential_schema_to_database(
        &db,
        None,
        organisation_id,
        "credential schema",
        false,
        Some(KeyStorageSecurity::Basic),
    )
    .await
    .unwrap();

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

    let credential_schema = CredentialSchema {
        expiration: None,
        ecosystem: None,
        batch_size: None,
        allow_revocation: false,
        id: credential_schema_id,
        deleted_at: None,
        imported_source_url: "CORE_URL".to_string(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "credential schema".to_string(),
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
        wallet_attestation: WalletAttestation {
            require_instance_attestation: false,
            key_storage_security_level: Some(KeyStorageSecurity::Basic.into()),
            preferred_key_storage_attestation_lifetime: None,
            preferred_instance_attestation_lifetime: None,
        },

        claim_schemas: new_claim_schemas
            .into_iter()
            .map(|schema| ClaimSchema {
                id: schema.id,
                key: schema.key.to_string(),
                data_type: schema.datatype.to_string(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                array: false,
                metadata: false,
                required: true,
                translations: Default::default(),
            })
            .collect::<Vec<_>>()
            .into(),
        organisation: dummy_organisation(Some(organisation_id)).into(),
        layout_properties: None,
        allow_suspension: true,
        transaction_code: None,
        translations: Default::default(),
        embedded_disclosure_policy: None,
    };

    let did_id = insert_did_key(
        &db,
        "issuer",
        Uuid::new_v4(),
        "did:key:123".parse().unwrap(),
        "KEY",
        organisation_id,
    )
    .await
    .unwrap();

    let did = Did {
        deleted_at: None,
        id: did_id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "name".to_string(),
        organisation: dummy_organisation(Some(organisation_id)).into(),
        did: "did:key:123".parse().unwrap(),
        did_type: one_core::model::did::DidType::Local,
        did_method: "KEY".into(),
        keys: Default::default(),
        deactivated: false,
        log: None,
    };

    let identifier_id = insert_identifier(
        &db,
        "issuer",
        Uuid::new_v4(),
        Some(did_id),
        organisation_id,
        false,
    )
    .await
    .unwrap();

    let identifier = Identifier {
        id: identifier_id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "name".to_string(),
        data: IdentifierData::Did((did.clone()).into()),
        is_remote: false,
        state: IdentifierState::Active,
        deleted_at: None,
        autogenerated: false,
        organisation: dummy_organisation(Some(organisation_id)).into(),
        trust_information: Default::default(),
        logo: None,
        translations: Default::default(),
    };

    TestSetup {
        credential_schema,
        db,
        identifier,
    }
}

struct TestSetupWithCredential {
    pub credential_schema: CredentialSchema,
    pub identifier: Identifier,
    pub credential_id: CredentialId,
    pub db: DatabaseConnection,
}

async fn setup_with_credential() -> TestSetupWithCredential {
    let TestSetup {
        credential_schema,
        db,
        identifier,
        ..
    } = setup_empty().await;

    let credential = insert_credential(
        &db,
        &credential_schema.id,
        CredentialStateEnum::Created,
        "OPENID4VCI_DRAFT13",
        identifier.id,
        None,
        None,
        Uuid::new_v4().into(),
        credential::CredentialRole::Issuer,
    )
    .await
    .unwrap();

    TestSetupWithCredential {
        credential_id: credential.id,
        credential_schema,
        db,
        identifier,
    }
}

struct Repositories {
    pub credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    pub claim_repository: Arc<dyn ClaimRepository>,
    pub identifier_repository: Arc<dyn IdentifierRepository>,
    pub interaction_repository: Arc<dyn InteractionRepository>,
    pub certificate_repository: Arc<dyn CertificateRepository>,
    pub key_repository: Arc<dyn KeyRepository>,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
}

impl Default for Repositories {
    fn default() -> Self {
        Self {
            credential_schema_repository: Arc::from(MockCredentialSchemaRepository::default()),
            claim_repository: Arc::from(MockClaimRepository::default()),
            identifier_repository: Arc::from(MockIdentifierRepository::default()),
            interaction_repository: Arc::from(MockInteractionRepository::default()),
            certificate_repository: Arc::new(MockCertificateRepository::default()),
            key_repository: Arc::new(MockKeyRepository::default()),
            organisation_repository: Arc::new(MockOrganisationRepository::default()),
        }
    }
}

fn credential_repository(
    db: DatabaseConnection,
    repositories: Option<Repositories>,
) -> impl CredentialRepository {
    let repositories = repositories.unwrap_or_default();
    CredentialProvider {
        db: TransactionManagerImpl::new(db),
        credential_schema_repository: repositories.credential_schema_repository,
        claim_repository: repositories.claim_repository,
        identifier_repository: repositories.identifier_repository,
        interaction_repository: repositories.interaction_repository,
        certificate_repository: repositories.certificate_repository,
        key_repository: repositories.key_repository,
        organisation_repository: repositories.organisation_repository,
    }
}

#[tokio::test]
async fn test_create_credential_success() {
    let TestSetup {
        credential_schema,
        db,
        identifier,
        ..
    } = setup_empty().await;

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository.expect_get().return_once({
        let identifier = identifier.clone();
        |_| Ok(identifier)
    });

    let mut schema_repository = MockCredentialSchemaRepository::default();
    let credential_schema_result = Ok(credential_schema.clone());
    schema_repository
        .expect_get_credential_schema()
        .return_once(move |_| credential_schema_result);

    let provider = credential_repository(
        db.clone(),
        Some(Repositories {
            credential_schema_repository: Arc::new(schema_repository),
            identifier_repository: Arc::new(identifier_repository),
            ..Repositories::default()
        }),
    );

    let credential_id = Uuid::new_v4().into();
    let claim_schema = credential_schema.claim_schemas.as_ref().await.unwrap()[0].to_owned();
    let claims = vec![
        Claim {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            value: Some("value1".to_string()),
            path: claim_schema.key.to_string(),
            schema: claim_schema.clone().into(),
            selectively_disclosable: false,
        },
        Claim {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            value: Some("value2".to_string()),
            path: format!("{}/0", claim_schema.key),
            schema: claim_schema.into(),
            selectively_disclosable: false,
        },
    ];

    let result = provider
        .create_credential(Credential {
            expires_at: None,
            ecosystem: None,
            id: credential_id,
            created_date: get_dummy_date(),
            issuance_date: None,
            last_modified: get_dummy_date(),
            deleted_at: None,
            consumed_at: None,
            protocol: "exchange".to_string(),
            redirect_uri: None,
            role: CredentialRole::Issuer,
            r#type: CredentialType::Single,
            state: CredentialStateEnum::Created,
            suspend_end_date: None,
            claims: claims.into(),
            issuer_identifier: Some(identifier.into()),
            issuer_certificate: None,
            holder_identifier: None,
            schema: credential_schema.into(),
            interaction: None,
            key: None,
            profile: None,
            credential_blob_id: None,
            wallet_key_attestation_blob_id: None,
            wallet_instance_attestation_blob_id: None,
            webhook_url: None,
            embedded_disclosure_policy: None,
            subscriber_information: None,
            parent: None,
            format: None,
        })
        .await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), credential_id);

    assert_eq!(
        crate::entity::credential::Entity::find()
            .all(&db)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn test_create_credential_empty_claims() {
    let TestSetup {
        credential_schema,
        db,
        identifier,
        ..
    } = setup_empty().await;

    let provider = credential_repository(db.clone(), None);

    let credential_id = Uuid::new_v4().into();
    let result = provider
        .create_credential(Credential {
            expires_at: None,
            ecosystem: None,
            id: credential_id,
            created_date: get_dummy_date(),
            issuance_date: None,
            last_modified: get_dummy_date(),
            deleted_at: None,
            consumed_at: None,
            protocol: "exchange".to_string(),
            redirect_uri: None,
            role: CredentialRole::Issuer,
            r#type: CredentialType::Single,
            state: CredentialStateEnum::Created,
            suspend_end_date: None,
            claims: Default::default(),
            issuer_identifier: Some(identifier.into()),
            issuer_certificate: None,
            holder_identifier: None,
            schema: credential_schema.into(),
            interaction: None,
            key: None,
            profile: None,
            credential_blob_id: None,
            wallet_key_attestation_blob_id: None,
            wallet_instance_attestation_blob_id: None,
            webhook_url: None,
            embedded_disclosure_policy: None,
            subscriber_information: None,
            parent: None,
            format: None,
        })
        .await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), credential_id);

    assert_eq!(
        crate::entity::credential::Entity::find()
            .all(&db)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn test_create_credential_already_exists() {
    let TestSetupWithCredential {
        credential_schema,
        credential_id,
        db,
        identifier,
        ..
    } = setup_with_credential().await;

    let provider = credential_repository(db.clone(), None);

    let claim_schema = credential_schema.claim_schemas.as_ref().await.unwrap()[0].to_owned();
    let claims = vec![Claim {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: Some("value1".to_string()),
        path: claim_schema.key.to_owned(),
        schema: claim_schema.into(),
        selectively_disclosable: false,
    }];

    let result = provider
        .create_credential(Credential {
            expires_at: None,
            ecosystem: None,
            id: credential_id,
            created_date: get_dummy_date(),
            issuance_date: None,
            last_modified: get_dummy_date(),
            deleted_at: None,
            consumed_at: None,
            protocol: "exchange".to_string(),
            redirect_uri: None,
            role: CredentialRole::Issuer,
            r#type: CredentialType::Single,
            state: CredentialStateEnum::Created,
            suspend_end_date: None,
            claims: claims.into(),
            issuer_identifier: Some(identifier.into()),
            issuer_certificate: None,
            holder_identifier: None,
            schema: credential_schema.into(),
            interaction: None,
            key: None,
            profile: None,
            credential_blob_id: None,
            wallet_key_attestation_blob_id: None,
            wallet_instance_attestation_blob_id: None,
            webhook_url: None,
            embedded_disclosure_policy: None,
            subscriber_information: None,
            parent: None,
            format: None,
        })
        .await;

    assert!(matches!(result, Err(DataLayerError::AlreadyExists)));
    let history = crate::entity::history::Entity::find()
        .all(&db)
        .await
        .unwrap();
    assert_eq!(history.len(), 0);
}

#[tokio::test]
async fn test_delete_credential_success() {
    let TestSetup {
        credential_schema,
        db,
        identifier,
        ..
    } = setup_empty().await;

    let credential = insert_credential(
        &db,
        &credential_schema.id,
        CredentialStateEnum::Created,
        "OPENID4VCI_DRAFT13",
        identifier.id,
        None,
        None,
        Uuid::new_v4().into(),
        credential::CredentialRole::Issuer,
    )
    .await
    .unwrap();

    let provider = credential_repository(db, None);

    provider
        .delete_credentials(std::slice::from_ref(&credential))
        .await
        .unwrap();

    let credential = provider.get_credential(&credential.id).await.unwrap();
    assert!(credential.deleted_at.is_some());
}

#[tokio::test]
async fn test_get_credential_list_success() {
    let TestSetup {
        credential_schema,
        mut db,
        identifier,
        ..
    } = setup_empty().await;

    let _credential_one_id = insert_credential(
        &db,
        &credential_schema.id,
        CredentialStateEnum::Created,
        "OPENID4VCI_DRAFT13",
        identifier.id,
        None,
        None,
        Uuid::new_v4().into(),
        credential::CredentialRole::Issuer,
    )
    .await
    .unwrap();
    let _credential_two_id = insert_credential(
        &db,
        &credential_schema.id,
        CredentialStateEnum::Created,
        "OPENID4VCI_DRAFT13",
        identifier.id,
        None,
        None,
        Uuid::new_v4().into(),
        credential::CredentialRole::Issuer,
    )
    .await
    .unwrap();

    let credential_three_id_should_not_be_returned = insert_credential(
        &db,
        &credential_schema.id,
        CredentialStateEnum::Created,
        "OPENID4VCI_DRAFT13",
        identifier.id,
        Some(one_core::clock::now_utc()),
        None,
        Uuid::new_v4().into(),
        credential::CredentialRole::Issuer,
    )
    .await
    .unwrap()
    .id;

    let counts = crate::test_utilities::track_count_queries(&mut db);
    let provider = credential_repository(db, None);

    for include_count in [true, false] {
        counts.store(0, std::sync::atomic::Ordering::Relaxed);
        let credentials = provider
            .get_credential_list(CredentialListQuery {
                include_count,
                pagination: Some(ListPagination {
                    page: 0,
                    page_size: 5,
                }),
                sorting: None,
                filtering: Some(
                    CredentialFilterValue::OrganisationId(credential_schema.organisation.id())
                        .condition()
                        & CredentialFilterValue::Deleted(false),
                ),
                include: None,
            })
            .await;
        assert!(credentials.is_ok());
        let credentials = credentials.unwrap();

        assert_eq!(include_count.then_some(1), credentials.total_pages);
        assert_eq!(include_count.then_some(2), credentials.total_items);
        assert_eq!(2, credentials.values.len());

        let forbidden_uuid = credential_three_id_should_not_be_returned;
        let forbidden_credential = credentials
            .values
            .iter()
            .find(|credential| credential.id == forbidden_uuid);
        assert!(forbidden_credential.is_none());
        assert_eq!(
            counts.load(std::sync::atomic::Ordering::Relaxed),
            usize::from(include_count)
        );
    }
}

#[tokio::test]
async fn test_get_credential_list_formats_or_batch_parent() {
    let TestSetupWithCredential {
        db, credential_id, ..
    } = setup_with_credential().await;
    let format_id = crate::entity::credential_schema_format::Entity::find()
        .one(&db)
        .await
        .unwrap()
        .unwrap()
        .id;
    let provider = credential_repository(db, None);
    let parent = Credential {
        id: Uuid::new_v4().into(),
        r#type: CredentialType::BatchParent,
        format: None,
        claims: Default::default(),
        ..provider.get_credential(&credential_id).await.unwrap()
    };
    provider.create_credential(parent.clone()).await.unwrap();
    provider
        .update_credential(
            credential_id,
            UpdateCredentialRequest {
                format: Some(format_id),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let result = provider
        .get_credential_list(CredentialListQuery {
            filtering: Some(
                CredentialFilterValue::Formats(vec!["MDOC".into()]).condition()
                    | CredentialFilterValue::Formats(vec!["JWT".into()])
                    | CredentialFilterValue::Types(vec![CredentialType::BatchParent]),
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    // Repeated format filters share one join, and the OR branch retains the formatless parent.
    assert_eq!(result.total_items, Some(2));
    assert_eq_unordered(
        result.values.into_iter().map(|credential| credential.id),
        [credential_id, parent.id],
    );
}

#[tokio::test]
async fn test_get_credential_list_success_filter_state() {
    let TestSetup {
        credential_schema,
        db,
        identifier,
        ..
    } = setup_empty().await;

    insert_credential(
        &db,
        &credential_schema.id,
        CredentialStateEnum::Offered,
        "OPENID4VCI_DRAFT13",
        identifier.id,
        None,
        None,
        Uuid::new_v4().into(),
        credential::CredentialRole::Issuer,
    )
    .await
    .unwrap();

    insert_credential(
        &db,
        &credential_schema.id,
        CredentialStateEnum::Revoked,
        "OPENID4VCI_DRAFT13",
        identifier.id,
        None,
        None,
        Uuid::new_v4().into(),
        credential::CredentialRole::Issuer,
    )
    .await
    .unwrap();

    let provider = credential_repository(db, None);

    let credentials = provider
        .get_credential_list(CredentialListQuery {
            filtering: Some(
                CredentialFilterValue::States(vec![CredentialStateEnum::Offered]).condition(),
            ),
            ..Default::default()
        })
        .await;
    let credentials = credentials.unwrap();
    assert_eq!(1, credentials.total_items.unwrap());
    assert_eq!(1, credentials.values.len());

    let credentials = provider
        .get_credential_list(CredentialListQuery {
            filtering: Some(
                CredentialFilterValue::States(vec![CredentialStateEnum::Created]).condition(),
            ),
            ..Default::default()
        })
        .await;
    let credentials = credentials.unwrap();
    assert_eq!(0, credentials.total_items.unwrap());
    assert_eq!(0, credentials.values.len());

    let credentials = provider
        .get_credential_list(CredentialListQuery {
            filtering: Some(
                CredentialFilterValue::States(vec![
                    CredentialStateEnum::Offered,
                    CredentialStateEnum::Revoked,
                ])
                .condition(),
            ),
            ..Default::default()
        })
        .await;
    let credentials = credentials.unwrap();
    assert_eq!(2, credentials.total_items.unwrap());
    assert_eq!(2, credentials.values.len());
}

#[tokio::test]
async fn test_get_credential_list_filter_schema_name_without_pagination() {
    let TestSetup {
        credential_schema,
        db,
        identifier,
        ..
    } = setup_empty().await;

    insert_credential(
        &db,
        &credential_schema.id,
        CredentialStateEnum::Created,
        "OPENID4VCI_DRAFT13",
        identifier.id,
        None,
        None,
        Uuid::new_v4().into(),
        credential::CredentialRole::Issuer,
    )
    .await
    .unwrap();

    let provider = credential_repository(db, None);

    // the schema name filter and the sort both read the schema, the query joins it once
    let credentials = provider
        .get_credential_list(CredentialListQuery {
            filtering: Some(
                CredentialFilterValue::CredentialSchemaName(StringMatch::starts_with(
                    credential_schema.name.clone(),
                ))
                .condition(),
            ),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(1, credentials.values.len());
}

#[tokio::test]
async fn test_get_credential_list_success_filter_suspend_end_date() {
    let TestSetupWithCredential {
        db, credential_id, ..
    } = setup_with_credential().await;

    let later = one_core::clock::now_utc().add(Duration::seconds(1));
    let much_later = one_core::clock::now_utc().add(Duration::days(1));
    update_credential_state(
        &db,
        credential_id,
        CredentialStateEnum::Suspended,
        Some(much_later),
        later,
    )
    .await
    .unwrap();

    let provider = credential_repository(db, None);

    let credentials = provider
        .get_credential_list(CredentialListQuery {
            filtering: Some(
                CredentialFilterValue::SuspendEndDate(ValueComparison {
                    comparison: ComparisonType::GreaterThanOrEqual,
                    value: much_later,
                })
                .condition(),
            ),
            ..Default::default()
        })
        .await;
    let credentials = credentials.unwrap();
    assert_eq!(1, credentials.total_items.unwrap());
    assert_eq!(1, credentials.values.len());

    let credentials = provider
        .get_credential_list(CredentialListQuery {
            filtering: Some(
                CredentialFilterValue::SuspendEndDate(ValueComparison {
                    comparison: ComparisonType::LessThan,
                    value: much_later,
                })
                .condition(),
            ),
            ..Default::default()
        })
        .await;
    let credentials = credentials.unwrap();
    assert_eq!(0, credentials.total_items.unwrap());
    assert_eq!(0, credentials.values.len());

    let credentials = provider
        .get_credential_list(CredentialListQuery {
            filtering: Some(
                CredentialFilterValue::SuspendEndDate(ValueComparison {
                    comparison: ComparisonType::GreaterThan,
                    value: much_later,
                })
                .condition(),
            ),
            ..Default::default()
        })
        .await;
    let credentials = credentials.unwrap();
    assert_eq!(0, credentials.total_items.unwrap());
    assert_eq!(0, credentials.values.len());
}

#[tokio::test]
async fn test_get_credential_list_success_filter_claim_name_value() {
    let TestSetupWithCredential {
        db,
        credential_id,
        credential_schema,
        ..
    } = setup_with_credential().await;

    let claim_schema = credential_schema.claim_schemas.as_ref().await.unwrap()[0].to_owned();
    let claims = [Claim {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: Some("test_value".to_string()),
        path: claim_schema.key.to_owned(),
        schema: claim_schema.into(),
        selectively_disclosable: false,
    }];

    insert_many_claims_to_database(
        &db,
        &claims
            .iter()
            .map(|claim| {
                (
                    claim.id,
                    claim.schema.id(),
                    credential_id,
                    convert_inner(claim.value.clone()),
                    claim.path.clone(),
                    claim.selectively_disclosable,
                )
            })
            .collect::<Vec<_>>(),
    )
    .await
    .unwrap();

    let provider = credential_repository(db, None);

    let credentials = provider
        .get_credential_list(CredentialListQuery {
            filtering: Some(
                CredentialFilterValue::ClaimName(StringMatch::contains("key")).condition(),
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(1, credentials.total_items.unwrap());
    assert_eq!(1, credentials.values.len());

    let credentials = provider
        .get_credential_list(CredentialListQuery {
            filtering: Some(
                CredentialFilterValue::ClaimValue(StringMatch::contains("value")).condition(),
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(1, credentials.total_items.unwrap());
    assert_eq!(1, credentials.values.len());

    let credentials = provider
        .get_credential_list(CredentialListQuery {
            filtering: Some(
                CredentialFilterValue::ClaimValue(StringMatch::contains("wrong")).condition(),
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(0, credentials.total_items.unwrap());
    assert_eq!(0, credentials.values.len());
}

#[rstest]
#[case::initial([false, false, true], true, Some("newest"))]
#[case::empty_latest([false, false, true], false, None)]
#[case::deleted_latest([false, true, true], false, Some("older"))]
#[case::no_live_items([true, true, true], false, None)]
#[tokio::test]
async fn holder_parent_claim_search_uses_only_newest_nondeleted_item(
    #[case] deleted_items: [bool; 3],
    #[case] newest_has_claims: bool,
    #[case] expected: Option<&str>,
    #[values("older", "newest", "deleted")] search_value: &str,
) {
    use sea_orm::{ActiveModelTrait, IntoActiveModel};

    let TestSetupWithCredential {
        db,
        credential_id,
        credential_schema,
        ..
    } = setup_with_credential().await;
    let mut parent = credential::Entity::find_by_id(credential_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap()
        .into_active_model();
    parent.role = Set(credential::CredentialRole::Holder);
    parent.r#type = Set(credential::CredentialType::BatchParent);
    let parent = parent.update(&db).await.unwrap();
    let schema_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;
    let item_ids: [CredentialId; 3] = [1, 2, 3].map(|n| Uuid::from_u128(n).into());
    for ((item_id, value), deleted) in item_ids
        .into_iter()
        .zip(["older", "newest", "deleted"])
        .zip(deleted_items)
    {
        let mut item = parent.clone().into_active_model();
        item.id = Set(item_id);
        item.parent_id = Set(Some(parent.id));
        item.r#type = Set(credential::CredentialType::BatchItem);
        item.deleted_at = Set(deleted.then_some(get_dummy_date()));
        item.insert(&db).await.unwrap();
        if value == "newest" && !newest_has_claims {
            continue;
        }
        insert_many_claims_to_database(
            &db,
            &[(
                Uuid::new_v4().into(),
                schema_id,
                item_id,
                Some(value.as_bytes().to_vec()),
                "name".into(),
                false,
            )],
        )
        .await
        .unwrap();
    }
    let provider = credential_repository(db.clone(), None);
    let result = provider
        .get_credential_list(CredentialListQuery {
            filtering: Some(
                CredentialFilterValue::Types(vec![CredentialType::BatchParent]).condition()
                    & CredentialFilterValue::ClaimValue(StringMatch::contains(search_value))
                        .condition(),
            ),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        result.values.len(),
        usize::from(expected == Some(search_value))
    );
}

#[tokio::test]
async fn test_get_credential_success() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();

    let TestSetup {
        credential_schema,
        db,
        identifier,
        ..
    } = setup_empty().await;

    let credential_id = insert_credential(
        &db,
        &credential_schema.id,
        CredentialStateEnum::Created,
        "OPENID4VCI_DRAFT13",
        identifier.id,
        None,
        None,
        Uuid::new_v4().into(),
        credential::CredentialRole::Issuer,
    )
    .await
    .unwrap()
    .id;

    let claim_schema1 = credential_schema.claim_schemas.as_ref().await.unwrap()[1].to_owned();
    let claim_schema2 = credential_schema.claim_schemas.as_ref().await.unwrap()[0].to_owned();
    let claims = [
        Claim {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            value: Some("value1".to_string()),
            path: claim_schema1.key.to_owned(),
            schema: claim_schema1.into(),
            selectively_disclosable: false,
        },
        Claim {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            value: Some("value2".to_string()),
            path: claim_schema2.key.to_owned(),
            schema: claim_schema2.into(),
            selectively_disclosable: false,
        },
    ];

    // claims need to be present for db consistence
    insert_many_claims_to_database(
        &db,
        &claims
            .iter()
            .map(|claim| {
                (
                    claim.id,
                    claim.schema.id(),
                    credential_id,
                    convert_inner(claim.value.clone()),
                    claim.path.clone(),
                    claim.selectively_disclosable,
                )
            })
            .collect::<Vec<_>>(),
    )
    .await
    .unwrap();

    let credential_schema_clone = credential_schema.clone();
    credential_schema_repository
        .expect_get_credential_schema()
        .times(1)
        .returning(move |_| Ok(credential_schema_clone.clone()));

    // real claim provider: the credential-schema ordering of the claims is implemented there
    let claim_repository = ClaimProvider {
        db: TransactionManagerImpl::new(db.clone()),
        claim_schema_repository: Arc::new(MockClaimSchemaRepository::default()),
    };

    let provider = credential_repository(
        db.clone(),
        Some(Repositories {
            credential_schema_repository: Arc::new(credential_schema_repository),
            claim_repository: Arc::new(claim_repository),
            ..Repositories::default()
        }),
    );

    let credential = provider.get_credential(&credential_id).await;

    assert!(credential.is_ok());
    let credential = credential.unwrap();
    assert_eq!(credential_id, credential.id);
    assert_eq!(
        credential_schema,
        *credential.schema.as_ref().await.unwrap()
    );
    assert!(credential.interaction.is_none());
    let credential_claims = credential.claims.as_ref().await.unwrap();
    assert_eq!(credential_claims.len(), 2);

    // claims must be ordered in the same way as in the credential_schema
    assert_eq!(credential_claims[0].id, claims[1].id);
    assert_eq!(credential_claims[1].id, claims[0].id);

    let empty_relations_mean_no_other_repository_calls =
        provider.get_credential(&credential_id).await;
    assert!(empty_relations_mean_no_other_repository_calls.is_ok());
}

#[tokio::test]
async fn test_get_credential_fail_not_found() {
    let TestSetup { db, .. } = setup_empty().await;

    let provider = credential_repository(db.clone(), None);

    let credential = provider.get_credential(&Uuid::new_v4().into()).await;

    assert!(matches!(
        credential,
        Err(DataLayerError::EntityNotFound { .. })
    ));
}

#[tokio::test]
async fn test_update_credential_success() {
    let TestSetup {
        credential_schema,
        db,
        identifier,
        ..
    } = setup_empty().await;

    let blob_id = Uuid::new_v4().into();

    let credential_id = insert_credential(
        &db,
        &credential_schema.id,
        CredentialStateEnum::Created,
        "OPENID4VCI_DRAFT13",
        identifier.id,
        None,
        None,
        blob_id,
        credential::CredentialRole::Issuer,
    )
    .await
    .unwrap()
    .id;

    let provider = credential_repository(db.clone(), None);

    let credential_before_update = provider.get_credential(&credential_id).await;
    assert!(credential_before_update.is_ok());
    let credential_before_update = credential_before_update.unwrap();
    assert_eq!(credential_id, credential_before_update.id);

    assert_eq!(
        blob_id,
        credential_before_update.credential_blob_id.unwrap()
    );

    let organisation_id = test_utilities::insert_organisation_to_database(&db, None)
        .await
        .unwrap();

    let interaction_id = insert_interaction(
        &db,
        &[],
        organisation_id,
        interaction::InteractionType::Issuance,
    )
    .await
    .unwrap();

    assert!(
        provider
            .update_credential(
                credential_id,
                UpdateCredentialRequest {
                    state: Some(CredentialStateEnum::Pending),
                    suspend_end_date: Clearable::DontTouch,
                    interaction: Some(interaction_id),
                    credential_blob_id: Some(blob_id),
                    ..Default::default()
                }
            )
            .await
            .is_ok()
    );
    let credential_after_update = provider.get_credential(&credential_id).await;
    assert!(credential_after_update.is_ok());
    let credential_after_update = credential_after_update.unwrap();
    assert_eq!(blob_id, credential_after_update.credential_blob_id.unwrap());
    assert_eq!(
        interaction_id,
        credential_after_update.interaction.unwrap().id()
    );
    assert_eq!(credential_after_update.state, CredentialStateEnum::Pending);
}

#[tokio::test]
async fn test_delete_credential_blobs_success() {
    let TestSetup {
        credential_schema,
        db,
        identifier,
        ..
    } = setup_empty().await;

    let credential = insert_credential(
        &db,
        &credential_schema.id,
        CredentialStateEnum::Created,
        "OPENID4VCI_DRAFT13",
        identifier.id,
        None,
        None,
        Uuid::new_v4().into(),
        credential::CredentialRole::Issuer,
    )
    .await
    .unwrap();

    let credential_two = insert_credential(
        &db,
        &credential_schema.id,
        CredentialStateEnum::Created,
        "OPENID4VCI_DRAFT13",
        identifier.id,
        None,
        None,
        Uuid::new_v4().into(),
        credential::CredentialRole::Issuer,
    )
    .await
    .unwrap();

    let provider = credential_repository(db, None);

    let credential = provider.get_credential(&credential.id).await.unwrap();
    assert!(credential.credential_blob_id.is_some());

    let credential_two = provider.get_credential(&credential_two.id).await.unwrap();
    assert!(credential_two.credential_blob_id.is_some());

    provider
        .delete_credential_blobs(HashSet::from([credential.id, credential_two.id]))
        .await
        .unwrap();

    let credential = provider.get_credential(&credential.id).await.unwrap();
    assert!(credential.credential_blob_id.is_none());

    let credential_two = provider.get_credential(&credential_two.id).await.unwrap();
    assert!(credential_two.credential_blob_id.is_none());
}

#[tokio::test]
async fn earliest_expiring_batch_item_is_grouped_by_parent_and_format() {
    use sea_orm::ActiveModelTrait;

    use crate::credential_schema_format::mapper::credential_schema_format_from_model;
    use crate::entity::credential_schema_format;

    let TestSetup {
        credential_schema,
        db,
        identifier,
    } = setup_empty().await;
    let provider = credential_repository(db.clone(), None);
    // Singles remain eligible independently of the batch-item grouping filter.
    let single = insert_credential(
        &db,
        &credential_schema.id,
        CredentialStateEnum::Accepted,
        "OPENID4VCI_FINAL1",
        identifier.id,
        None,
        None,
        Uuid::new_v4().into(),
        credential::CredentialRole::Holder,
    )
    .await
    .unwrap();
    let mut template = provider.get_credential(&single.id).await.unwrap();
    template.claims = Default::default();
    let jwt_format = credential_schema_format_from_model(
        credential_schema_format::Entity::find()
            .one(&db)
            .await
            .unwrap()
            .unwrap(),
        TransactionManagerImpl::new(db.clone()),
    );
    let mdoc_format = CredentialSchemaFormat {
        id: Uuid::new_v4().into(),
        format: "MDOC".into(),
        ecosystem_schema_id: "other-format".into(),
        claim_mappings: Default::default(),
        ..jwt_format.clone()
    };
    credential_schema_format::ActiveModel::from(mdoc_format.clone())
        .insert(&db)
        .await
        .unwrap();

    let new_parent = || Credential {
        id: Uuid::new_v4().into(),
        r#type: CredentialType::BatchParent,
        format: None,
        ..template.clone()
    };
    let first_parent = new_parent();
    let second_parent = new_parent();
    for parent in [&first_parent, &second_parent] {
        provider.create_credential(parent.clone()).await.unwrap();
    }
    let expiry = now_utc() + Duration::days(1);
    let new_item = |parent: &Credential, format: &CredentialSchemaFormat, seconds| Credential {
        id: Uuid::new_v4().into(),
        r#type: CredentialType::BatchItem,
        parent: Some(parent.clone().into()),
        format: Some(format.clone().into()),
        // Creation order deliberately disagrees with expiry order.
        created_date: get_dummy_date() - Duration::seconds(seconds),
        expires_at: Some(expiry + Duration::seconds(seconds)),
        ..template.clone()
    };

    // Suspended items with an earlier expiry must not hide an accepted item.
    let suspended_jwt = Credential {
        state: CredentialStateEnum::Suspended,
        ..new_item(&first_parent, &jwt_format, 0)
    };
    // An already consumed item is unavailable even though its state is Accepted.
    let consumed_jwt = Credential {
        consumed_at: Some(get_dummy_date()),
        ..new_item(&first_parent, &jwt_format, 1)
    };
    // Deleted items must likewise be skipped even if they expire earlier.
    let deleted_jwt = Credential {
        deleted_at: Some(get_dummy_date()),
        ..new_item(&first_parent, &jwt_format, 2)
    };
    // The earliest eligible expiry wins, with descending ID breaking ties.
    let earliest_expiring_jwt = Credential {
        id: Uuid::from_u128(2).into(),
        ..new_item(&first_parent, &jwt_format, 3)
    };
    let tied_jwt = Credential {
        id: Uuid::from_u128(1).into(),
        ..new_item(&first_parent, &jwt_format, 3)
    };
    let later_expiring_jwt = new_item(&first_parent, &jwt_format, 4);
    // An item without an expiry must not take precedence over expiring items.
    let non_expiring_jwt = Credential {
        expires_at: None,
        ..new_item(&first_parent, &jwt_format, 5)
    };
    // The same parent has an independent MDOC group. When all expiries are absent,
    // descending ID still selects exactly one item.
    let selected_mdoc = Credential {
        id: Uuid::from_u128(4).into(),
        expires_at: None,
        ..new_item(&first_parent, &mdoc_format, 5)
    };
    let other_mdoc = Credential {
        id: Uuid::from_u128(3).into(),
        ..selected_mdoc.clone()
    };
    // The same format has an independent group under a different parent.
    let second_parent_jwt = new_item(&second_parent, &jwt_format, 6);
    for item in [
        &suspended_jwt,
        &consumed_jwt,
        &deleted_jwt,
        &earliest_expiring_jwt,
        &tied_jwt,
        &later_expiring_jwt,
        &non_expiring_jwt,
        &selected_mdoc,
        &other_mdoc,
        &second_parent_jwt,
    ] {
        provider.create_credential(item.clone()).await.unwrap();
    }

    let result = provider
        .get_credential_list(CredentialListQuery {
            filtering: Some(
                CredentialFilterValue::Types(vec![CredentialType::Single]).condition()
                    | CredentialFilterValue::EarliestExpiringBatchItemPerFormat,
            ),
            ..Default::default()
        })
        .await
        .unwrap();
    // Keep the single plus one available item from each of the three groups:
    // first parent/JWT, first parent/MDOC, and second parent/JWT.
    assert_eq_unordered(
        result.values.into_iter().map(|credential| credential.id),
        [
            single.id,
            earliest_expiring_jwt.id,
            selected_mdoc.id,
            second_parent_jwt.id,
        ],
    );
}
