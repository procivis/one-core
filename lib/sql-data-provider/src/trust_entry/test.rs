use std::sync::Arc;

use one_core::model::list_filter::{ComparisonType, ListFilterValue, ValueComparison};
use one_core::model::list_query::ListPagination;
use one_core::model::trust_entry::{
    TrustEntry, TrustEntryFilterValue, TrustEntryListQuery, TrustEntryRelations,
    TrustEntryStateEnum, UpdateTrustEntryRequest,
};
use one_core::model::trust_list_publication::{
    TrustListPublication, TrustListPublicationRelations,
};
use one_core::model::trust_list_role::TrustListRoleEnum;
use one_core::repository::certificate_repository::MockCertificateRepository;
use one_core::repository::did_repository::MockDidRepository;
use one_core::repository::error::DataLayerError;
use one_core::repository::identifier_repository::MockIdentifierRepository;
use one_core::repository::identifier_trust_information_repository::MockIdentifierTrustInformationRepository;
use one_core::repository::key_repository::MockKeyRepository;
use one_core::repository::organisation_repository::MockOrganisationRepository;
use one_core::repository::trust_entry_repository::TrustEntryRepository;
use one_core::repository::trust_list_publication_repository::MockTrustListPublicationRepository;
use one_core::service::test_utilities::dummy_identifier;
use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::TrustEntryProvider;
use crate::entity::trust_list_publication;
use crate::test_utilities::*;
use crate::transaction_context::TransactionManagerImpl;

struct TestSetup {
    pub db: DatabaseConnection,
    pub provider: TrustEntryProvider,
    pub trust_list_publication_id: shared_types::TrustListPublicationId,
    pub org_id: shared_types::OrganisationId,
    pub identifier_id: shared_types::IdentifierId,
    identifier_id2: shared_types::IdentifierId,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let org_id = insert_organisation_to_database(&db, None).await.unwrap();

    let did_id = insert_did_key(
        &db,
        "test did",
        Uuid::new_v4(),
        "did:test:1".parse().unwrap(),
        "KEY",
        org_id,
    )
    .await
    .unwrap();
    let did_id2 = insert_did_key(
        &db,
        "test did 2",
        Uuid::new_v4(),
        "did:test:2".parse().unwrap(),
        "KEY",
        org_id,
    )
    .await
    .unwrap();

    let identifier_id: shared_types::IdentifierId = insert_identifier(
        &db,
        "test identifier",
        Uuid::new_v4(),
        Some(did_id),
        org_id,
        false,
    )
    .await
    .unwrap();
    let identifier_id2: shared_types::IdentifierId = insert_identifier(
        &db,
        "test identifier 2",
        Uuid::new_v4(),
        Some(did_id2),
        org_id,
        false,
    )
    .await
    .unwrap();

    let trust_list_publication_id: shared_types::TrustListPublicationId = Uuid::new_v4().into();
    trust_list_publication::ActiveModel {
        id: Set(trust_list_publication_id),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        name: Set("test-publication".to_string()),
        role: Set(trust_list_publication::TrustRoleEnum::Issuer),
        r#type: Set("LOTE".into()),
        metadata: Set(vec![]),
        deleted_at: Set(None),
        content: Set(Vec::new()),
        sequence_number: Set(0),
        organisation_id: Set(org_id),
        identifier_id: Set(identifier_id),
        key_id: Set(None),
        certificate_id: Set(None),
    }
    .insert(&db)
    .await
    .unwrap();

    TestSetup {
        provider: TrustEntryProvider {
            db: TransactionManagerImpl::new(db.clone()),
            trust_list_publication_repository: Arc::new(
                MockTrustListPublicationRepository::default(),
            ),
            identifier_repository: Arc::new(MockIdentifierRepository::default()),
            did_repository: Arc::new(MockDidRepository::default()),
            key_repository: Arc::new(MockKeyRepository::default()),
            certificate_repository: Arc::new(MockCertificateRepository::default()),
            organisation_repository: Arc::new(MockOrganisationRepository::default()),
            trust_information_repository: Arc::new(
                MockIdentifierTrustInformationRepository::default(),
            ),
        },
        db,
        trust_list_publication_id,
        org_id,
        identifier_id,
        identifier_id2,
    }
}

fn dummy_trust_entry(
    trust_list_publication_id: shared_types::TrustListPublicationId,
    identifier_id: shared_types::IdentifierId,
) -> TrustEntry {
    TrustEntry {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        state: TrustEntryStateEnum::Active,
        metadata: vec![],
        trust_list_publication_id,
        identifier_id,
        trust_list_publication: None,
        identifier: None,
    }
}

#[tokio::test]
async fn test_create_trust_entry() {
    let setup = setup().await;

    let entry = dummy_trust_entry(setup.trust_list_publication_id, setup.identifier_id);
    let id = entry.id;

    let result = setup.provider.create(entry).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), id);
}

#[tokio::test]
async fn test_get_trust_entry_missing() {
    let setup = setup().await;

    let result = setup
        .provider
        .get(Uuid::new_v4().into(), &TrustEntryRelations::default())
        .await;
    assert!(matches!(result, Err(DataLayerError::EntityNotFound { .. })));
}

#[tokio::test]
async fn test_get_trust_entry_success() {
    let setup = setup().await;

    let entry = dummy_trust_entry(setup.trust_list_publication_id, setup.identifier_id);
    let id = entry.id;
    setup.provider.create(entry).await.unwrap();

    let result = setup
        .provider
        .get(id, &TrustEntryRelations::default())
        .await;

    assert!(result.is_ok());
    let found = result.unwrap();
    assert_eq!(found.id, id);
    assert_eq!(found.state, TrustEntryStateEnum::Active);
    assert_eq!(
        found.trust_list_publication_id,
        setup.trust_list_publication_id
    );
}

#[tokio::test]
async fn test_delete_trust_entry() {
    let setup = setup().await;

    let entry = dummy_trust_entry(setup.trust_list_publication_id, setup.identifier_id);
    let id = entry.id;
    setup.provider.create(entry).await.unwrap();

    let result = setup.provider.delete(id).await;
    assert!(result.is_ok());

    let get_result = setup
        .provider
        .get(id, &TrustEntryRelations::default())
        .await;
    assert!(matches!(
        get_result,
        Err(DataLayerError::EntityNotFound { .. })
    ));
}

#[tokio::test]
async fn test_list_trust_entries() {
    let setup = setup().await;

    let entry1 = dummy_trust_entry(setup.trust_list_publication_id, setup.identifier_id);
    let entry2 = dummy_trust_entry(setup.trust_list_publication_id, setup.identifier_id2);
    setup.provider.create(entry1).await.unwrap();
    setup.provider.create(entry2).await.unwrap();

    let result = setup
        .provider
        .list(
            setup.trust_list_publication_id,
            TrustEntryListQuery {
                pagination: Some(ListPagination {
                    page: 0,
                    page_size: 10,
                }),
                ..Default::default()
            },
        )
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_items, 2);
    assert_eq!(list.total_pages, 1);
    assert_eq!(list.values.len(), 2);
}

#[tokio::test]
async fn test_list_trust_entries_filter_by_publication_id() {
    let setup = setup().await;

    // Create a second publication
    let other_pub_id: shared_types::TrustListPublicationId = Uuid::new_v4().into();
    trust_list_publication::ActiveModel {
        id: Set(other_pub_id),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        name: Set("other-publication".to_string()),
        role: Set(trust_list_publication::TrustRoleEnum::Verifier),
        r#type: Set("LOTE".into()),
        metadata: Set(vec![]),
        deleted_at: Set(None),
        content: Set(Vec::new()),
        sequence_number: Set(0),
        organisation_id: Set(setup.org_id),
        identifier_id: Set(setup.identifier_id),
        key_id: Set(None),
        certificate_id: Set(None),
    }
    .insert(&setup.db)
    .await
    .unwrap();

    let entry1 = dummy_trust_entry(setup.trust_list_publication_id, setup.identifier_id);
    let entry2 = dummy_trust_entry(other_pub_id, setup.identifier_id);
    setup.provider.create(entry1).await.unwrap();
    setup.provider.create(entry2).await.unwrap();

    let result = setup
        .provider
        .list(
            setup.trust_list_publication_id,
            TrustEntryListQuery {
                pagination: Some(ListPagination {
                    page: 0,
                    page_size: 10,
                }),
                filtering: Some(
                    TrustEntryFilterValue::TrustListPublicationId(setup.trust_list_publication_id)
                        .condition(),
                ),
                ..Default::default()
            },
        )
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_items, 1);
    assert_eq!(
        list.values[0].trust_list_publication_id,
        setup.trust_list_publication_id
    );
}

#[tokio::test]
async fn test_list_trust_entries_filter_by_status() {
    let setup = setup().await;

    let entry1 = dummy_trust_entry(setup.trust_list_publication_id, setup.identifier_id);
    let mut entry2 = dummy_trust_entry(setup.trust_list_publication_id, setup.identifier_id2);
    entry2.state = TrustEntryStateEnum::Suspended;
    setup.provider.create(entry1).await.unwrap();
    setup.provider.create(entry2).await.unwrap();

    let result = setup
        .provider
        .list(
            setup.trust_list_publication_id,
            TrustEntryListQuery {
                pagination: Some(ListPagination {
                    page: 0,
                    page_size: 10,
                }),
                filtering: Some(
                    TrustEntryFilterValue::State(vec![TrustEntryStateEnum::Active]).condition(),
                ),
                ..Default::default()
            },
        )
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_items, 1);
    assert_eq!(list.values[0].state, TrustEntryStateEnum::Active);
}

#[tokio::test]
async fn test_update_trust_entry_status() {
    let setup = setup().await;

    let entry = dummy_trust_entry(setup.trust_list_publication_id, setup.identifier_id);
    let id = entry.id;
    setup.provider.create(entry).await.unwrap();

    let result = setup
        .provider
        .update(
            id,
            UpdateTrustEntryRequest {
                state: Some(TrustEntryStateEnum::Suspended),
                ..Default::default()
            },
        )
        .await;
    assert!(result.is_ok());

    let found = setup
        .provider
        .get(id, &TrustEntryRelations::default())
        .await
        .unwrap();
    assert_eq!(found.state, TrustEntryStateEnum::Suspended);
}

#[tokio::test]
async fn test_update_trust_entry_metadata() {
    let setup = setup().await;

    let entry = dummy_trust_entry(setup.trust_list_publication_id, setup.identifier_id);
    let id = entry.id;
    setup.provider.create(entry).await.unwrap();

    let new_metadata = b"updated metadata".to_vec();
    let result = setup
        .provider
        .update(
            id,
            UpdateTrustEntryRequest {
                metadata: Some(new_metadata.clone()),
                ..Default::default()
            },
        )
        .await;
    assert!(result.is_ok());

    let found = setup
        .provider
        .get(id, &TrustEntryRelations::default())
        .await
        .unwrap();
    assert_eq!(found.metadata, new_metadata);
    assert_eq!(found.state, TrustEntryStateEnum::Active);
}

#[tokio::test]
async fn test_list_trust_entries_pagination() {
    let setup = setup().await;

    for i in 0..5 {
        let did_id = insert_did_key(
            &setup.db,
            &format!("testEntryDid{i}"),
            Uuid::new_v4(),
            format!("did:test:entry{i}").parse().unwrap(),
            "KEY",
            setup.org_id,
        )
        .await
        .unwrap();
        let identifier_id = insert_identifier(
            &setup.db,
            &format!("testEntryIdentifier{i}"),
            Uuid::new_v4(),
            Some(did_id),
            setup.org_id,
            false,
        )
        .await
        .unwrap();
        let entry = dummy_trust_entry(setup.trust_list_publication_id, identifier_id);
        setup.provider.create(entry).await.unwrap();
    }

    let result = setup
        .provider
        .list(
            setup.trust_list_publication_id,
            TrustEntryListQuery {
                pagination: Some(ListPagination {
                    page: 0,
                    page_size: 2,
                }),
                ..Default::default()
            },
        )
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_items, 5);
    assert_eq!(list.total_pages, 3);
    assert_eq!(list.values.len(), 2);
}

#[tokio::test]
async fn test_list_trust_entries_filter_by_created_date() {
    let setup = setup().await;

    let entry1 = dummy_trust_entry(setup.trust_list_publication_id, setup.identifier_id);
    let entry2 = dummy_trust_entry(setup.trust_list_publication_id, setup.identifier_id2);
    setup.provider.create(entry1).await.unwrap();
    setup.provider.create(entry2).await.unwrap();

    let result = setup
        .provider
        .list(
            setup.trust_list_publication_id,
            TrustEntryListQuery {
                pagination: Some(ListPagination {
                    page: 0,
                    page_size: 10,
                }),
                filtering: Some(
                    TrustEntryFilterValue::CreatedDate(ValueComparison {
                        comparison: ComparisonType::GreaterThan,
                        value: get_dummy_date(),
                    })
                    .condition(),
                ),
                ..Default::default()
            },
        )
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    // dummy_date is 2005, created_date is set to dummy_date, so nothing is after it
    assert_eq!(list.total_items, 0);
}

#[tokio::test]
async fn test_list_trust_entries_filter_by_last_modified() {
    let setup = setup().await;

    let entry = dummy_trust_entry(setup.trust_list_publication_id, setup.identifier_id);
    let id = entry.id;
    setup.provider.create(entry).await.unwrap();

    // Update to bump last_modified to now
    setup
        .provider
        .update(
            id,
            UpdateTrustEntryRequest {
                state: Some(TrustEntryStateEnum::Suspended),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let result = setup
        .provider
        .list(
            setup.trust_list_publication_id,
            TrustEntryListQuery {
                pagination: Some(ListPagination {
                    page: 0,
                    page_size: 10,
                }),
                filtering: Some(
                    TrustEntryFilterValue::LastModified(ValueComparison {
                        comparison: ComparisonType::GreaterThan,
                        value: get_dummy_date(),
                    })
                    .condition(),
                ),
                ..Default::default()
            },
        )
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    // The updated entry has last_modified = now() which is after dummy_date
    assert_eq!(list.total_items, 1);
}

#[tokio::test]
async fn test_get_trust_entry_with_publication_relation() {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let org_id = insert_organisation_to_database(&db, None).await.unwrap();

    let identifier_id: shared_types::IdentifierId =
        insert_identifier(&db, "test identifier", Uuid::new_v4(), None, org_id, false)
            .await
            .unwrap();

    let trust_list_publication_id: shared_types::TrustListPublicationId = Uuid::new_v4().into();
    trust_list_publication::ActiveModel {
        id: Set(trust_list_publication_id),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        name: Set("test-publication".to_string()),
        role: Set(trust_list_publication::TrustRoleEnum::Issuer),
        r#type: Set("LOTE".into()),
        metadata: Set(vec![]),
        deleted_at: Set(None),
        content: Set(Vec::new()),
        sequence_number: Set(0),
        organisation_id: Set(org_id),
        identifier_id: Set(identifier_id),
        key_id: Set(None),
        certificate_id: Set(None),
    }
    .insert(&db)
    .await
    .unwrap();

    let mut mock_pub_repo = MockTrustListPublicationRepository::default();
    mock_pub_repo.expect_get().returning(move |id| {
        Ok(TrustListPublication {
            id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: "test-publication".to_string(),
            role: TrustListRoleEnum::Issuer,
            r#type: "LOTE".into(),
            metadata: vec![],
            deleted_at: None,
            content: Vec::new(),
            sequence_number: 0,
            organisation: dummy_organisation(Some(org_id)).into(),
            identifier: dummy_identifier().into(),
            key: None,
            certificate: None,
        })
    });

    let provider = TrustEntryProvider {
        db: TransactionManagerImpl::new(db.clone()),
        trust_list_publication_repository: Arc::new(mock_pub_repo),
        identifier_repository: Arc::new(MockIdentifierRepository::default()),
        did_repository: Arc::new(MockDidRepository::default()),
        key_repository: Arc::new(MockKeyRepository::default()),
        certificate_repository: Arc::new(MockCertificateRepository::default()),
        organisation_repository: Arc::new(MockOrganisationRepository::default()),
        trust_information_repository: Arc::new(MockIdentifierTrustInformationRepository::default()),
    };

    let entry = dummy_trust_entry(trust_list_publication_id, identifier_id);
    let id = entry.id;
    provider.create(entry).await.unwrap();

    let result = provider
        .get(
            id,
            &TrustEntryRelations {
                trust_list_publication: Some(TrustListPublicationRelations::default()),
                ..Default::default()
            },
        )
        .await;

    assert!(result.is_ok());
    let found = result.unwrap();
    assert!(found.trust_list_publication.is_some());
    assert_eq!(
        found.trust_list_publication.unwrap().name,
        "test-publication"
    );
}

#[tokio::test]
async fn test_update_trust_entry_not_found() {
    let setup = setup().await;

    let result = setup
        .provider
        .update(
            Uuid::new_v4().into(),
            UpdateTrustEntryRequest {
                state: Some(TrustEntryStateEnum::Suspended),
                ..Default::default()
            },
        )
        .await;

    assert!(matches!(result, Err(DataLayerError::RecordNotUpdated)));
}

#[tokio::test]
async fn test_update_trust_entry_noop() {
    let setup = setup().await;

    let entry = dummy_trust_entry(setup.trust_list_publication_id, setup.identifier_id);
    let id = entry.id;
    setup.provider.create(entry).await.unwrap();

    let result = setup
        .provider
        .update(id, UpdateTrustEntryRequest::default())
        .await;
    assert!(result.is_ok());

    let found = setup
        .provider
        .get(id, &TrustEntryRelations::default())
        .await
        .unwrap();
    assert_eq!(found.state, TrustEntryStateEnum::Active);
    assert_eq!(found.metadata, Vec::<u8>::new());
}
