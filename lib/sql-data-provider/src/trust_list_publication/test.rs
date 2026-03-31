use std::sync::Arc;

use one_core::model::list_filter::{ComparisonType, ListFilterValue, ValueComparison};
use one_core::model::list_query::ListPagination;
use one_core::model::organisation::{Organisation, OrganisationRelations};
use one_core::model::trust_list_publication::{
    TrustListPublication, TrustListPublicationFilterValue, TrustListPublicationListQuery,
    TrustListPublicationRelations, UpdateTrustListPublicationRequest,
};
use one_core::model::trust_list_role::TrustListRoleEnum;
use one_core::repository::certificate_repository::MockCertificateRepository;
use one_core::repository::error::DataLayerError;
use one_core::repository::identifier_repository::MockIdentifierRepository;
use one_core::repository::key_repository::MockKeyRepository;
use one_core::repository::organisation_repository::MockOrganisationRepository;
use one_core::repository::trust_list_publication_repository::TrustListPublicationRepository;
use sea_orm::DatabaseConnection;
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::TrustListPublicationProvider;
use crate::test_utilities::*;
use crate::transaction_context::TransactionManagerImpl;

struct TestSetup {
    pub db: DatabaseConnection,
    pub provider: TrustListPublicationProvider,
    pub org_id: shared_types::OrganisationId,
    pub identifier_id: shared_types::IdentifierId,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;
    let org_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();
    let identifier_id =
        insert_identifier(&db, "testIdentifier", Uuid::new_v4(), None, org_id, false)
            .await
            .unwrap();
    TestSetup {
        provider: TrustListPublicationProvider {
            db: TransactionManagerImpl::new(db.clone()),
            organisation_repository: Arc::new(MockOrganisationRepository::default()),
            identifier_repository: Arc::new(MockIdentifierRepository::default()),
            key_repository: Arc::new(MockKeyRepository::default()),
            certificate_repository: Arc::new(MockCertificateRepository::default()),
        },
        db,
        org_id,
        identifier_id,
    }
}

fn dummy_trust_list_publication(
    org_id: shared_types::OrganisationId,
    identifier_id: shared_types::IdentifierId,
) -> TrustListPublication {
    let id = Uuid::new_v4().into();
    TrustListPublication {
        id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: format!("test-publication-{id}"),
        role: TrustListRoleEnum::Issuer,
        r#type: "LOTE".into(),
        metadata: vec![],
        deleted_at: None,
        content: Vec::new(),
        sequence_number: 0,
        organisation_id: org_id,
        identifier_id,
        key_id: None,
        certificate_id: None,
        organisation: None,
        identifier: None,
        key: None,
        certificate: None,
    }
}

#[tokio::test]
async fn test_create_trust_list_publication() {
    let TestSetup {
        provider,
        org_id,
        identifier_id,
        ..
    } = setup().await;

    let publication = dummy_trust_list_publication(org_id, identifier_id);
    let id = publication.id;

    let result = provider.create(publication).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), id);
}

#[tokio::test]
async fn test_get_trust_list_publication_missing() {
    let TestSetup { provider, .. } = setup().await;

    let result = provider
        .get(
            Uuid::new_v4().into(),
            &TrustListPublicationRelations::default(),
        )
        .await;
    assert!(matches!(result, Ok(None)));
}

#[tokio::test]
async fn test_get_trust_list_publication_success() {
    let TestSetup {
        provider,
        org_id,
        identifier_id,
        ..
    } = setup().await;

    let publication = dummy_trust_list_publication(org_id, identifier_id);
    let id = publication.id;
    provider.create(publication.clone()).await.unwrap();

    let result = provider
        .get(id, &TrustListPublicationRelations::default())
        .await;

    assert!(result.is_ok());
    let found = result.unwrap().unwrap();
    assert_eq!(found.id, id);
    assert_eq!(found.name, publication.name);
    assert_eq!(found.role, TrustListRoleEnum::Issuer);
    assert_eq!(found.r#type, "LOTE".into());
}

#[tokio::test]
async fn test_delete_trust_list_publication() {
    let TestSetup {
        provider,
        org_id,
        identifier_id,
        ..
    } = setup().await;

    let publication = dummy_trust_list_publication(org_id, identifier_id);
    let id = publication.id;
    provider.create(publication).await.unwrap();

    let result = provider.delete(id).await;
    assert!(result.is_ok());

    let get_result = provider
        .get(id, &TrustListPublicationRelations::default())
        .await;
    assert!(matches!(get_result, Ok(None)));
}

#[tokio::test]
async fn test_list_trust_list_publications() {
    let TestSetup {
        provider,
        org_id,
        identifier_id,
        ..
    } = setup().await;

    let pub1 = dummy_trust_list_publication(org_id, identifier_id);
    let pub2 = {
        let mut p = dummy_trust_list_publication(org_id, identifier_id);
        p.name = "second-publication".to_string();
        p.role = TrustListRoleEnum::Verifier;
        p
    };
    provider.create(pub1).await.unwrap();
    provider.create(pub2).await.unwrap();

    let result = provider
        .list(TrustListPublicationListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_items, 2);
    assert_eq!(list.total_pages, 1);
    assert_eq!(list.values.len(), 2);
}

#[tokio::test]
async fn test_list_trust_list_publications_with_name_filter() {
    let TestSetup {
        provider,
        org_id,
        identifier_id,
        ..
    } = setup().await;

    let pub1 = dummy_trust_list_publication(org_id, identifier_id);
    let pub2 = {
        let mut p = dummy_trust_list_publication(org_id, identifier_id);
        p.name = "other-publication".to_string();
        p
    };
    provider.create(pub1).await.unwrap();
    provider.create(pub2).await.unwrap();

    let result = provider
        .list(TrustListPublicationListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            filtering: Some(
                TrustListPublicationFilterValue::Name(
                    one_core::model::list_filter::StringMatch::equals("other-publication"),
                )
                .condition(),
            ),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_items, 1);
    assert_eq!(list.values[0].name, "other-publication");
}

#[tokio::test]
async fn test_list_trust_list_publications_with_organisation_filter() {
    let TestSetup {
        db,
        provider,
        org_id,
        identifier_id,
    } = setup().await;

    let other_org_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();

    let pub1 = dummy_trust_list_publication(org_id, identifier_id);
    let pub2 = dummy_trust_list_publication(other_org_id, identifier_id);
    provider.create(pub1).await.unwrap();
    provider.create(pub2).await.unwrap();

    let result = provider
        .list(TrustListPublicationListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            filtering: Some(TrustListPublicationFilterValue::OrganisationId(org_id).condition()),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_items, 1);
    assert_eq!(list.values[0].organisation_id, org_id);
}

#[tokio::test]
async fn test_list_trust_list_publications_with_type_filter() {
    let TestSetup {
        provider,
        org_id,
        identifier_id,
        ..
    } = setup().await;

    let pub1 = dummy_trust_list_publication(org_id, identifier_id);
    provider.create(pub1).await.unwrap();

    let result = provider
        .list(TrustListPublicationListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            filtering: Some(TrustListPublicationFilterValue::Type(vec!["LOTE".into()]).condition()),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_items, 1);
    assert_eq!(list.values[0].r#type, "LOTE".into());
}

#[tokio::test]
async fn test_list_trust_list_publications_with_role_filter() {
    let TestSetup {
        provider,
        org_id,
        identifier_id,
        ..
    } = setup().await;

    let pub1 = dummy_trust_list_publication(org_id, identifier_id); // role = Issuer
    let pub2 = {
        let mut p = dummy_trust_list_publication(org_id, identifier_id);
        p.role = TrustListRoleEnum::Verifier;
        p
    };
    provider.create(pub1).await.unwrap();
    provider.create(pub2).await.unwrap();

    let result = provider
        .list(TrustListPublicationListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            filtering: Some(
                TrustListPublicationFilterValue::Role(vec![TrustListRoleEnum::Issuer]).condition(),
            ),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_items, 1);
    assert_eq!(list.values[0].role, TrustListRoleEnum::Issuer);
}

#[tokio::test]
async fn test_list_trust_list_publications_filter_by_created_date() {
    let TestSetup {
        provider,
        org_id,
        identifier_id,
        ..
    } = setup().await;

    let pub1 = dummy_trust_list_publication(org_id, identifier_id);
    provider.create(pub1).await.unwrap();

    let result = provider
        .list(TrustListPublicationListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            filtering: Some(
                TrustListPublicationFilterValue::CreatedDate(ValueComparison {
                    comparison: ComparisonType::GreaterThan,
                    value: get_dummy_date(),
                })
                .condition(),
            ),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    // dummy_date is 2005, created_date is set to dummy_date, so nothing is after it
    assert_eq!(list.total_items, 0);
}

#[tokio::test]
async fn test_list_trust_list_publications_filter_by_last_modified() {
    let TestSetup {
        provider,
        org_id,
        identifier_id,
        ..
    } = setup().await;

    let publication = dummy_trust_list_publication(org_id, identifier_id);
    let id = publication.id;
    provider.create(publication).await.unwrap();

    // Update to bump last_modified to now
    provider
        .update(
            id,
            UpdateTrustListPublicationRequest {
                content: Some(b"updated".to_vec()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let result = provider
        .list(TrustListPublicationListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            filtering: Some(
                TrustListPublicationFilterValue::LastModified(ValueComparison {
                    comparison: ComparisonType::GreaterThan,
                    value: get_dummy_date(),
                })
                .condition(),
            ),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    // The updated publication has last_modified = now() which is after dummy_date
    assert_eq!(list.total_items, 1);
}

#[tokio::test]
async fn test_list_trust_list_publications_pagination() {
    let TestSetup {
        provider,
        org_id,
        identifier_id,
        ..
    } = setup().await;

    for i in 0..5 {
        let mut pub_item = dummy_trust_list_publication(org_id, identifier_id);
        pub_item.name = format!("publication-{i}");
        provider.create(pub_item).await.unwrap();
    }

    let result = provider
        .list(TrustListPublicationListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 2,
            }),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_items, 5);
    assert_eq!(list.total_pages, 3);
    assert_eq!(list.values.len(), 2);
}

#[tokio::test]
async fn test_update_trust_list_publication_content_and_sequence_number() {
    let TestSetup {
        provider,
        org_id,
        identifier_id,
        ..
    } = setup().await;

    let publication = dummy_trust_list_publication(org_id, identifier_id);
    let id = publication.id;
    provider.create(publication.clone()).await.unwrap();

    let new_content = b"trust list content".to_vec();
    let result = provider
        .update(
            id,
            UpdateTrustListPublicationRequest {
                content: Some(new_content.clone()),
                sequence_number: Some(42),
            },
        )
        .await;
    assert!(result.is_ok());

    let found = provider
        .get(id, &TrustListPublicationRelations::default())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.content, new_content);
    assert_eq!(found.sequence_number, 42);
    assert_eq!(found.name, publication.name);
}

#[tokio::test]
async fn test_get_trust_list_publication_with_organisation_relation() {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let org_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();

    let identifier_id =
        insert_identifier(&db, "test identifier", Uuid::new_v4(), None, org_id, false)
            .await
            .unwrap();

    let mut mock_org_repo = MockOrganisationRepository::default();
    mock_org_repo
        .expect_get_organisation()
        .returning(move |id, _relations| {
            Ok(Some(Organisation {
                id: *id,
                name: "test-org".to_string(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                deactivated_at: None,
                wallet_provider: None,
                wallet_provider_issuer: None,
            }))
        });

    let provider = TrustListPublicationProvider {
        db: TransactionManagerImpl::new(db.clone()),
        organisation_repository: Arc::new(mock_org_repo),
        identifier_repository: Arc::new(MockIdentifierRepository::default()),
        key_repository: Arc::new(MockKeyRepository::default()),
        certificate_repository: Arc::new(MockCertificateRepository::default()),
    };

    let publication = dummy_trust_list_publication(org_id, identifier_id);
    let id = publication.id;
    provider.create(publication).await.unwrap();

    let result = provider
        .get(
            id,
            &TrustListPublicationRelations {
                organisation: Some(OrganisationRelations::default()),
                ..Default::default()
            },
        )
        .await;

    assert!(result.is_ok());
    let found = result.unwrap().unwrap();
    assert!(found.organisation.is_some());
    assert_eq!(found.organisation.unwrap().name, "test-org");
}

#[tokio::test]
async fn test_update_trust_list_publication_not_found() {
    let TestSetup { provider, .. } = setup().await;

    let result = provider
        .update(
            Uuid::new_v4().into(),
            UpdateTrustListPublicationRequest {
                content: Some(b"updated".to_vec()),
                sequence_number: Some(2),
            },
        )
        .await;

    assert!(matches!(result, Err(DataLayerError::RecordNotUpdated)));
}

#[tokio::test]
async fn test_update_trust_list_publication_noop() {
    let TestSetup {
        provider,
        org_id,
        identifier_id,
        ..
    } = setup().await;

    let publication = dummy_trust_list_publication(org_id, identifier_id);
    let id = publication.id;
    provider.create(publication.clone()).await.unwrap();

    let result = provider
        .update(id, UpdateTrustListPublicationRequest::default())
        .await;
    assert!(result.is_ok());

    let found = provider
        .get(id, &TrustListPublicationRelations::default())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.name, publication.name);
    assert_eq!(found.role, TrustListRoleEnum::Issuer);
    assert_eq!(found.sequence_number, 0);
    assert_eq!(found.metadata, Vec::<u8>::new());
}
