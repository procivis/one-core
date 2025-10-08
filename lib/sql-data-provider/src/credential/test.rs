use std::collections::HashSet;
use std::ops::Add;
use std::sync::Arc;

use one_core::model::claim::{Claim, ClaimId, ClaimRelations};
use one_core::model::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use one_core::model::credential::{
    Clearable, Credential, CredentialFilterValue, CredentialRelations, CredentialRole,
    CredentialStateEnum, UpdateCredentialRequest,
};
use one_core::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaRelations, CredentialSchemaType,
    LayoutType, WalletStorageTypeEnum,
};
use one_core::model::did::Did;
use one_core::model::identifier::{Identifier, IdentifierState, IdentifierType};
use one_core::model::interaction::{Interaction, InteractionRelations};
use one_core::model::list_filter::{ComparisonType, ListFilterValue, StringMatch, ValueComparison};
use one_core::model::list_query::ListPagination;
use one_core::model::organisation::OrganisationRelations;
use one_core::repository::certificate_repository::{
    CertificateRepository, MockCertificateRepository,
};
use one_core::repository::claim_repository::{ClaimRepository, MockClaimRepository};
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
use one_core::repository::revocation_list_repository::{
    MockRevocationListRepository, RevocationListRepository,
};
use one_core::service::credential::dto::GetCredentialQueryDTO;
use one_dto_mapper::convert_inner;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set};
use shared_types::CredentialId;
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::CredentialProvider;
use crate::entity::claim;
use crate::entity::credential_schema::WalletStorageType;
use crate::test_utilities;
use crate::test_utilities::*;

struct TestSetup {
    pub db: sea_orm::DatabaseConnection,
    pub credential_schema: CredentialSchema,
    pub identifier: Identifier,
}

async fn setup_empty() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();

    let credential_schema_id = insert_credential_schema_to_database(
        &db,
        None,
        organisation_id,
        "credential schema",
        "JWT",
        "NONE",
        WalletStorageType::Software,
    )
    .await
    .unwrap();

    let new_claim_schemas: Vec<ClaimInsertInfo> = (0..2)
        .map(|i| ClaimInsertInfo {
            id: Uuid::new_v4().into(),
            key: "key",
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
        id: credential_schema_id,
        deleted_at: None,
        imported_source_url: "CORE_URL".to_string(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "credential schema".to_string(),
        format: "JWT".to_string(),
        wallet_storage_type: Some(WalletStorageTypeEnum::Software),
        revocation_method: "NONE".to_string(),
        external_schema: false,
        claim_schemas: Some(
            new_claim_schemas
                .into_iter()
                .map(|schema| CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: schema.id,
                        key: schema.key.to_string(),
                        data_type: schema.datatype.to_string(),
                        created_date: get_dummy_date(),
                        last_modified: get_dummy_date(),
                        array: false,
                        metadata: false,
                    },
                    required: true,
                })
                .collect(),
        ),
        organisation: Some(dummy_organisation(Some(organisation_id))),
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_type: CredentialSchemaType::ProcivisOneSchema2024,
        schema_id: "CredentialSchemaId".to_owned(),
        allow_suspension: true,
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
        id: did_id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "name".to_string(),
        organisation: Some(dummy_organisation(Some(organisation_id))),
        did: "did:key:123".parse().unwrap(),
        did_type: one_core::model::did::DidType::Local,
        did_method: "KEY".to_string(),
        keys: None,
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
        r#type: IdentifierType::Did,
        is_remote: false,
        state: IdentifierState::Active,
        deleted_at: None,
        organisation: Some(dummy_organisation(Some(organisation_id))),
        did: Some(did.clone()),
        key: None,
        certificates: None,
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
    pub revocation_list_repository: Arc<dyn RevocationListRepository>,
    pub certificate_repository: Arc<dyn CertificateRepository>,
    pub key_repository: Arc<dyn KeyRepository>,
}

impl Default for Repositories {
    fn default() -> Self {
        Self {
            credential_schema_repository: Arc::from(MockCredentialSchemaRepository::default()),
            claim_repository: Arc::from(MockClaimRepository::default()),
            identifier_repository: Arc::from(MockIdentifierRepository::default()),
            interaction_repository: Arc::from(MockInteractionRepository::default()),
            revocation_list_repository: Arc::new(MockRevocationListRepository::default()),
            certificate_repository: Arc::new(MockCertificateRepository::default()),
            key_repository: Arc::new(MockKeyRepository::default()),
        }
    }
}

fn credential_repository(
    db: DatabaseConnection,
    repositories: Option<Repositories>,
) -> impl CredentialRepository {
    let repositories = repositories.unwrap_or_default();
    CredentialProvider {
        db,
        credential_schema_repository: repositories.credential_schema_repository,
        claim_repository: repositories.claim_repository,
        identifier_repository: repositories.identifier_repository,
        interaction_repository: repositories.interaction_repository,
        revocation_list_repository: repositories.revocation_list_repository,
        certificate_repository: repositories.certificate_repository,
        key_repository: repositories.key_repository,
    }
}

#[tokio::test]
async fn test_create_credential_success() {
    let mut claim_repository = MockClaimRepository::default();
    claim_repository
        .expect_create_claim_list()
        .times(1)
        .withf(|claims| claims.len() == 2)
        .returning(|_| Ok(()));

    let TestSetup {
        credential_schema,
        db,
        identifier,
        ..
    } = setup_empty().await;

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository.expect_get().return_once({
        let identifier = identifier.clone();
        |_, _| Ok(Some(identifier))
    });

    let mut schema_repository = MockCredentialSchemaRepository::default();
    let credential_schema_result = Ok(Some(credential_schema.clone()));
    schema_repository
        .expect_get_credential_schema()
        .return_once(move |_, _| credential_schema_result);

    let provider = credential_repository(
        db.clone(),
        Some(Repositories {
            claim_repository: Arc::new(claim_repository),
            credential_schema_repository: Arc::new(schema_repository),
            identifier_repository: Arc::new(identifier_repository),
            ..Repositories::default()
        }),
    );

    let credential_id = Uuid::new_v4().into();
    let claim_schema = credential_schema.claim_schemas.as_ref().unwrap()[0]
        .to_owned()
        .schema;
    let claims = vec![
        Claim {
            id: ClaimId::new_v4(),
            credential_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            value: Some("value1".to_string()),
            path: claim_schema.key.to_string(),
            schema: Some(claim_schema.clone()),
            selectively_disclosable: false,
        },
        Claim {
            id: ClaimId::new_v4(),
            credential_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            value: Some("value2".to_string()),
            path: claim_schema.key.to_string(),
            schema: Some(claim_schema),
            selectively_disclosable: false,
        },
    ];

    let result = provider
        .create_credential(Credential {
            id: credential_id,
            created_date: get_dummy_date(),
            issuance_date: None,
            last_modified: get_dummy_date(),
            deleted_at: None,
            protocol: "exchange".to_string(),
            redirect_uri: None,
            role: CredentialRole::Issuer,
            state: CredentialStateEnum::Created,
            suspend_end_date: None,
            claims: Some(claims),
            issuer_identifier: Some(identifier),
            issuer_certificate: None,
            holder_identifier: None,
            schema: Some(credential_schema),
            interaction: None,
            revocation_list: None,
            key: None,
            profile: None,
            credential_blob_id: None,
            wallet_unit_attestation_blob_id: None,
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
            id: credential_id,
            created_date: get_dummy_date(),
            issuance_date: None,
            last_modified: get_dummy_date(),
            deleted_at: None,
            protocol: "exchange".to_string(),
            redirect_uri: None,
            role: CredentialRole::Issuer,
            state: CredentialStateEnum::Created,
            suspend_end_date: None,
            claims: Some(vec![]),
            issuer_identifier: Some(identifier),
            issuer_certificate: None,
            holder_identifier: None,
            schema: Some(credential_schema),
            interaction: None,
            revocation_list: None,
            key: None,
            profile: None,
            credential_blob_id: None,
            wallet_unit_attestation_blob_id: None,
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

    let claim_schema = credential_schema.claim_schemas.as_ref().unwrap()[0]
        .to_owned()
        .schema;
    let claims = vec![Claim {
        id: ClaimId::new_v4(),
        credential_id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: Some("value1".to_string()),
        path: claim_schema.key.to_owned(),
        schema: Some(claim_schema),
        selectively_disclosable: false,
    }];

    let result = provider
        .create_credential(Credential {
            id: credential_id,
            created_date: get_dummy_date(),
            issuance_date: None,
            last_modified: get_dummy_date(),
            deleted_at: None,
            protocol: "exchange".to_string(),
            redirect_uri: None,
            role: CredentialRole::Issuer,
            state: CredentialStateEnum::Created,
            suspend_end_date: None,
            claims: Some(claims),
            issuer_identifier: Some(identifier),
            issuer_certificate: None,
            holder_identifier: None,
            schema: Some(credential_schema),
            interaction: None,
            revocation_list: None,
            key: None,
            profile: None,
            credential_blob_id: None,
            wallet_unit_attestation_blob_id: None,
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
    )
    .await
    .unwrap();

    let provider = credential_repository(db, None);

    provider.delete_credential(&credential).await.unwrap();

    let credential = provider
        .get_credential(&credential.id, &CredentialRelations::default())
        .await
        .unwrap()
        .unwrap();
    assert!(credential.deleted_at.is_some());
}

#[tokio::test]
async fn test_delete_credential_failed_not_found() {
    let TestSetup { db, .. } = setup_empty().await;

    let provider = credential_repository(db, None);

    let result = provider
        .delete_credential(&Credential {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            issuance_date: None,
            last_modified: OffsetDateTime::now_utc(),
            deleted_at: None,
            protocol: "OPENID4VCI_DRAFT13".to_string(),
            redirect_uri: None,
            role: CredentialRole::Issuer,
            state: CredentialStateEnum::Created,
            suspend_end_date: None,
            claims: None,
            issuer_identifier: None,
            issuer_certificate: None,
            holder_identifier: None,
            schema: None,
            interaction: None,
            revocation_list: None,
            key: None,
            profile: None,
            credential_blob_id: None,
            wallet_unit_attestation_blob_id: None,
        })
        .await;
    assert!(matches!(result, Err(DataLayerError::RecordNotUpdated)));
}

#[tokio::test]
async fn test_get_credential_list_success() {
    let TestSetup {
        credential_schema,
        db,
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
    )
    .await
    .unwrap();

    let credential_three_id_should_not_be_returned = insert_credential(
        &db,
        &credential_schema.id,
        CredentialStateEnum::Created,
        "OPENID4VCI_DRAFT13",
        identifier.id,
        Some(OffsetDateTime::now_utc()),
        None,
        Uuid::new_v4().into(),
    )
    .await
    .unwrap()
    .id;

    let provider = credential_repository(db, None);

    let credentials = provider
        .get_credential_list(GetCredentialQueryDTO {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 5,
            }),
            sorting: None,
            filtering: Some(
                CredentialFilterValue::OrganisationId(credential_schema.organisation.unwrap().id)
                    .condition(),
            ),
            include: None,
        })
        .await;
    assert!(credentials.is_ok());
    let credentials = credentials.unwrap();

    assert_eq!(1, credentials.total_pages);
    assert_eq!(2, credentials.total_items);
    assert_eq!(2, credentials.values.len());

    let forbidden_uuid = credential_three_id_should_not_be_returned;
    let forbidden_credential = credentials
        .values
        .iter()
        .find(|credential| credential.id == forbidden_uuid);
    assert!(forbidden_credential.is_none());
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
    )
    .await
    .unwrap();

    let provider = credential_repository(db, None);

    let credentials = provider
        .get_credential_list(GetCredentialQueryDTO {
            filtering: Some(
                CredentialFilterValue::States(vec![CredentialStateEnum::Offered]).condition(),
            ),
            ..Default::default()
        })
        .await;
    let credentials = credentials.unwrap();
    assert_eq!(1, credentials.total_items);
    assert_eq!(1, credentials.values.len());

    let credentials = provider
        .get_credential_list(GetCredentialQueryDTO {
            filtering: Some(
                CredentialFilterValue::States(vec![CredentialStateEnum::Created]).condition(),
            ),
            ..Default::default()
        })
        .await;
    let credentials = credentials.unwrap();
    assert_eq!(0, credentials.total_items);
    assert_eq!(0, credentials.values.len());

    let credentials = provider
        .get_credential_list(GetCredentialQueryDTO {
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
    assert_eq!(2, credentials.total_items);
    assert_eq!(2, credentials.values.len());
}

#[tokio::test]
async fn test_get_credential_list_success_filter_suspend_end_date() {
    let TestSetupWithCredential {
        db, credential_id, ..
    } = setup_with_credential().await;

    let later = OffsetDateTime::now_utc().add(Duration::seconds(1));
    let much_later = OffsetDateTime::now_utc().add(Duration::days(1));
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
        .get_credential_list(GetCredentialQueryDTO {
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
    assert_eq!(1, credentials.total_items);
    assert_eq!(1, credentials.values.len());

    let credentials = provider
        .get_credential_list(GetCredentialQueryDTO {
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
    assert_eq!(0, credentials.total_items);
    assert_eq!(0, credentials.values.len());

    let credentials = provider
        .get_credential_list(GetCredentialQueryDTO {
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
    assert_eq!(0, credentials.total_items);
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

    let claim_schema = credential_schema.claim_schemas.as_ref().unwrap()[0]
        .to_owned()
        .schema;
    let claims = vec![Claim {
        id: ClaimId::new_v4(),
        credential_id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: Some("test_value".to_string()),
        path: claim_schema.key.to_owned(),
        schema: Some(claim_schema),
        selectively_disclosable: false,
    }];

    claim::Entity::insert_many(
        claims
            .iter()
            .map(|claim| claim::ActiveModel {
                id: Set(claim.id.into()),
                credential_id: Set(credential_id),
                claim_schema_id: Set(claim.schema.as_ref().unwrap().id),
                value: Set(convert_inner(claim.value.to_owned())),
                created_date: Set(get_dummy_date()),
                last_modified: Set(get_dummy_date()),
                path: Set(claim.path.to_string()),
                selectively_disclosable: Set(claim.selectively_disclosable),
            })
            .collect::<Vec<claim::ActiveModel>>(),
    )
    .exec(&db)
    .await
    .unwrap();

    let provider = credential_repository(db, None);

    let credentials = provider
        .get_credential_list(GetCredentialQueryDTO {
            filtering: Some(
                CredentialFilterValue::ClaimName(StringMatch::contains("key")).condition(),
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(1, credentials.total_items);
    assert_eq!(1, credentials.values.len());

    let credentials = provider
        .get_credential_list(GetCredentialQueryDTO {
            filtering: Some(
                CredentialFilterValue::ClaimValue(StringMatch::contains("value")).condition(),
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(1, credentials.total_items);
    assert_eq!(1, credentials.values.len());

    let credentials = provider
        .get_credential_list(GetCredentialQueryDTO {
            filtering: Some(
                CredentialFilterValue::ClaimValue(StringMatch::contains("wrong")).condition(),
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(0, credentials.total_items);
    assert_eq!(0, credentials.values.len());
}

#[tokio::test]
async fn test_get_credential_success() {
    let mut claim_repository = MockClaimRepository::default();
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
    )
    .await
    .unwrap()
    .id;

    let claim_schema1 = credential_schema.claim_schemas.as_ref().unwrap()[1]
        .to_owned()
        .schema;
    let claim_schema2 = credential_schema.claim_schemas.as_ref().unwrap()[0]
        .to_owned()
        .schema;
    let claims = vec![
        Claim {
            id: ClaimId::new_v4(),
            credential_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            value: Some("value1".to_string()),
            path: claim_schema1.key.to_owned(),
            schema: Some(claim_schema1),
            selectively_disclosable: false,
        },
        Claim {
            id: ClaimId::new_v4(),
            credential_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            value: Some("value2".to_string()),
            path: claim_schema2.key.to_owned(),
            schema: Some(claim_schema2),
            selectively_disclosable: false,
        },
    ];

    // claims need to be present for db consistence
    claim::Entity::insert_many(
        claims
            .iter()
            .map(|claim| claim::ActiveModel {
                id: Set(claim.id.into()),
                credential_id: Set(credential_id),
                claim_schema_id: Set(claim.schema.as_ref().unwrap().id),
                value: Set(convert_inner(claim.value.to_owned())),
                created_date: Set(get_dummy_date()),
                last_modified: Set(get_dummy_date()),
                path: Set(claim.path.to_string()),
                selectively_disclosable: Set(claim.selectively_disclosable),
            })
            .collect::<Vec<claim::ActiveModel>>(),
    )
    .exec(&db)
    .await
    .unwrap();

    let credential_schema_clone = credential_schema.clone();
    credential_schema_repository
        .expect_get_credential_schema()
        .times(1)
        .returning(move |_, _| Ok(Some(credential_schema_clone.clone())));

    let claims_clone = claims.clone();
    claim_repository
        .expect_get_claim_list()
        .withf(|ids, _| ids.len() == 2)
        .times(1)
        .returning(move |ids, _| {
            // order based on the requested ids
            Ok(ids
                .into_iter()
                .map(|id| {
                    claims_clone
                        .iter()
                        .find(|claim| claim.id == id)
                        .unwrap()
                        .to_owned()
                })
                .collect())
        });

    let provider = credential_repository(
        db.clone(),
        Some(Repositories {
            credential_schema_repository: Arc::new(credential_schema_repository),
            claim_repository: Arc::new(claim_repository),
            ..Repositories::default()
        }),
    );

    let credential = provider
        .get_credential(
            &credential_id,
            &CredentialRelations {
                claims: Some(ClaimRelations {
                    schema: Some(ClaimSchemaRelations::default()),
                }),
                schema: Some(CredentialSchemaRelations {
                    claim_schemas: None,
                    organisation: Some(OrganisationRelations::default()),
                }),
                interaction: Some(InteractionRelations::default()),
                revocation_list: None, // TODO: Add check for this
                ..Default::default()
            },
        )
        .await;

    assert!(credential.is_ok());
    let credential = credential.unwrap().unwrap();
    assert_eq!(credential_id, credential.id);
    assert_eq!(credential_schema, credential.schema.unwrap());
    assert!(credential.interaction.is_none());
    let credential_claims = credential.claims.unwrap();
    assert_eq!(credential_claims.len(), 2);

    // claims must be ordered in the same way as in the credential_schema
    assert_eq!(credential_claims[0].id, claims[1].id);
    assert_eq!(credential_claims[1].id, claims[0].id);

    let empty_relations_mean_no_other_repository_calls = provider
        .get_credential(&credential_id, &CredentialRelations::default())
        .await;
    assert!(empty_relations_mean_no_other_repository_calls.is_ok());
}

#[tokio::test]
async fn test_get_credential_fail_not_found() {
    let TestSetup { db, .. } = setup_empty().await;

    let provider = credential_repository(db.clone(), None);

    let credential = provider
        .get_credential(&Uuid::new_v4().into(), &CredentialRelations::default())
        .await
        .unwrap();

    assert!(credential.is_none());
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
    )
    .await
    .unwrap()
    .id;

    let mut interaction_repository = MockInteractionRepository::default();
    interaction_repository
        .expect_get_interaction()
        .once()
        .returning(|id, _| {
            Ok(Some(Interaction {
                id: id.to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                host: Some("https://host.co".parse().unwrap()),
                data: None,
                organisation: None,
                nonce_id: None,
            }))
        });

    let provider = credential_repository(
        db.clone(),
        Some(Repositories {
            interaction_repository: Arc::new(interaction_repository),
            ..Repositories::default()
        }),
    );

    let credential_before_update = provider
        .get_credential(&credential_id, &CredentialRelations::default())
        .await;
    assert!(credential_before_update.is_ok());
    let credential_before_update = credential_before_update.unwrap().unwrap();
    assert_eq!(credential_id, credential_before_update.id);

    assert_eq!(
        blob_id,
        credential_before_update.credential_blob_id.unwrap()
    );

    let organisation_id = test_utilities::insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();

    let interaction_id = Uuid::parse_str(
        &insert_interaction(&db, "host", &[], organisation_id, None)
            .await
            .unwrap(),
    )
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
    let credential_after_update = provider
        .get_credential(
            &credential_id,
            &CredentialRelations {
                interaction: Some(InteractionRelations::default()),
                ..Default::default()
            },
        )
        .await;
    assert!(credential_after_update.is_ok());
    let credential_after_update = credential_after_update.unwrap().unwrap();
    assert_eq!(blob_id, credential_after_update.credential_blob_id.unwrap());
    assert_eq!(
        interaction_id,
        credential_after_update.interaction.unwrap().id
    );
    assert_eq!(credential_after_update.state, CredentialStateEnum::Pending);
}

#[tokio::test]
async fn test_update_credential_success_no_claims() {
    let mut claim_repository = MockClaimRepository::default();

    claim_repository
        .expect_delete_claims_for_credential()
        .returning(|_| Ok(()));

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
    )
    .await
    .unwrap()
    .id;

    let mut interaction_repository = MockInteractionRepository::default();
    interaction_repository
        .expect_get_interaction()
        .once()
        .returning(|id, _| {
            Ok(Some(Interaction {
                id: id.to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                host: Some("https://host.co".parse().unwrap()),
                data: None,
                organisation: None,
                nonce_id: None,
            }))
        });

    let provider = credential_repository(
        db.clone(),
        Some(Repositories {
            claim_repository: Arc::new(claim_repository),
            interaction_repository: Arc::new(interaction_repository),
            ..Repositories::default()
        }),
    );

    let credential_before_update = provider
        .get_credential(&credential_id, &CredentialRelations::default())
        .await;
    assert!(credential_before_update.is_ok());
    let credential_before_update = credential_before_update.unwrap().unwrap();
    assert_eq!(credential_id, credential_before_update.id);

    assert_eq!(
        blob_id,
        credential_before_update.credential_blob_id.unwrap()
    );

    let organisation_id = test_utilities::insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();

    let interaction_id = Uuid::parse_str(
        &insert_interaction(&db, "host", &[], organisation_id, None)
            .await
            .unwrap(),
    )
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
                    claims: Some(vec![]),
                    ..Default::default()
                }
            )
            .await
            .is_ok()
    );
    let credential_after_update = provider
        .get_credential(
            &credential_id,
            &CredentialRelations {
                interaction: Some(InteractionRelations::default()),
                ..Default::default()
            },
        )
        .await;
    assert!(credential_after_update.is_ok());
    let credential_after_update = credential_after_update.unwrap().unwrap();
    assert_eq!(blob_id, credential_after_update.credential_blob_id.unwrap());
    assert_eq!(
        interaction_id,
        credential_after_update.interaction.unwrap().id
    );
    assert_eq!(credential_after_update.state, CredentialStateEnum::Pending);
}

#[tokio::test]
async fn test_get_credential_by_claim_id_success() {
    let TestSetup {
        credential_schema,
        db,
        identifier,
        ..
    } = setup_empty().await;

    // an unrelated credential
    insert_credential(
        &db,
        &credential_schema.id,
        CredentialStateEnum::Created,
        "OPENID4VCI_DRAFT13",
        identifier.id,
        None,
        None,
        Uuid::new_v4().into(),
    )
    .await
    .unwrap();

    let credential = insert_credential(
        &db,
        &credential_schema.id,
        CredentialStateEnum::Created,
        "OPENID4VCI_DRAFT13",
        identifier.id,
        None,
        None,
        Uuid::new_v4().into(),
    )
    .await
    .unwrap();

    let claim_schema = credential_schema.claim_schemas.as_ref().unwrap()[0]
        .to_owned()
        .schema;
    let claim = Claim {
        id: ClaimId::new_v4(),
        credential_id: credential.id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: Some("value1".to_string()),
        path: claim_schema.key.clone(),
        schema: Some(claim_schema.clone()),
        selectively_disclosable: false,
    };

    claim::ActiveModel {
        id: Set(claim.id.into()),
        credential_id: Set(credential.id),
        claim_schema_id: Set(claim.schema.as_ref().unwrap().id),
        value: Set(convert_inner(claim.value.to_owned())),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        path: Set(claim.path),
        selectively_disclosable: Set(false),
    }
    .insert(&db)
    .await
    .unwrap();

    let provider = credential_repository(db, None);

    let expected_credential = provider
        .get_credential_by_claim_id(&claim.id, &CredentialRelations::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(credential.id, expected_credential.id);
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
    )
    .await
    .unwrap();

    let provider = credential_repository(db, None);

    let credential = provider
        .get_credential(&credential.id, &CredentialRelations::default())
        .await
        .unwrap()
        .unwrap();
    assert!(credential.credential_blob_id.is_some());

    let credential_two = provider
        .get_credential(&credential_two.id, &CredentialRelations::default())
        .await
        .unwrap()
        .unwrap();
    assert!(credential_two.credential_blob_id.is_some());

    provider
        .delete_credential_blobs(HashSet::from([credential.id, credential_two.id]))
        .await
        .unwrap();

    let credential = provider
        .get_credential(&credential.id, &CredentialRelations::default())
        .await
        .unwrap()
        .unwrap();
    assert!(credential.credential_blob_id.is_none());

    let credential_two = provider
        .get_credential(&credential_two.id, &CredentialRelations::default())
        .await
        .unwrap()
        .unwrap();
    assert!(credential_two.credential_blob_id.is_none());
}
