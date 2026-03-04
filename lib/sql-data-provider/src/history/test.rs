use one_core::model::common::SortDirection;
use one_core::model::credential::CredentialStateEnum;
use one_core::model::history::{
    GetHistoryList, History, HistoryAction, HistoryEntityType, HistoryFilterValue,
    HistoryListQuery, HistorySearchEnum, HistorySource, IssuerStatsQuery,
    OrganisationOperationsCount, OrganisationStats, OrganisationTimelines,
    SortableIssuerStatisticsColumn, StatsBySchemaFilterValue, TimeSeriesPoint,
};
use one_core::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, ValueComparison,
};
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::model::organisation::Organisation;
use one_core::repository::history_repository::HistoryRepository;
use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};
use shared_types::{
    ClaimId, CredentialId, CredentialSchemaId, DidId, EntityId, IdentifierId, KeyId,
    OrganisationId, ProofId, ProofSchemaId,
};
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::entity::credential::CredentialRole;
use crate::entity::credential_schema::KeyStorageSecurity;
use crate::entity::history;
use crate::entity::key_did::KeyRole;
use crate::entity::proof::ProofRole;
use crate::history::HistoryProvider;
use crate::test_utilities::*;
use crate::transaction_context::TransactionManagerImpl;

struct TestSetup {
    pub provider: HistoryProvider,
    pub organisation: Organisation,
    pub db: DatabaseConnection,
    pub key_id: KeyId,
    pub identifier_id: IdentifierId,
    pub credential_schema_id: CredentialSchemaId,
    pub proof_schema_id: ProofSchemaId,
    pub credential_id: EntityId,
    pub proof_id: EntityId,
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
        "initial_schema",
        "JWT",
        None,
        Some(KeyStorageSecurity::Basic),
    )
    .await
    .unwrap();

    let did_id = insert_did_key(
        &db,
        "issuer / verifier",
        Uuid::new_v4(),
        "did:key:123456".parse().unwrap(),
        "KEY",
        organisation_id,
    )
    .await
    .unwrap();
    let key_id = insert_key_to_database(
        &db,
        "initial key ED25519".to_string(),
        vec![],
        vec![],
        None,
        organisation_id,
    )
    .await
    .unwrap();

    insert_key_did(&db, did_id, key_id, KeyRole::AssertionMethod)
        .await
        .unwrap();

    let identifier_id = insert_identifier(
        &db,
        "issuer / verifier",
        Uuid::new_v4(),
        Some(did_id),
        organisation_id,
        false,
    )
    .await
    .unwrap();

    let credential = insert_credential(
        &db,
        &credential_schema_id,
        CredentialStateEnum::Created,
        "OPENID4VCI_DRAFT13",
        identifier_id,
        None,
        None,
        Uuid::new_v4().into(),
        CredentialRole::Issuer,
    )
    .await
    .unwrap();
    let proof_schema_id = insert_proof_schema_with_claims_to_database(
        &db,
        None,
        vec![],
        organisation_id,
        "initial proof schema",
    )
    .await
    .unwrap();

    let proof_id = insert_proof_request_to_database(
        &db,
        identifier_id,
        &proof_schema_id,
        key_id,
        None,
        None,
        None,
        ProofRole::Verifier,
    )
    .await
    .unwrap();

    TestSetup {
        provider: HistoryProvider {
            db: TransactionManagerImpl::new(db.clone()),
        },
        organisation: dummy_organisation(Some(organisation_id)),
        db,
        key_id,
        identifier_id,
        credential_schema_id,
        proof_id: proof_id.into(),
        credential_id: credential.id.into(),
        proof_schema_id,
    }
}

struct TestSetupWithCredentialsSchemaAndProof {
    pub provider: HistoryProvider,
    pub organisation: Organisation,
    pub credential_schema_id: CredentialSchemaId,
    pub credential_schema_name: &'static str,
    pub did_id: DidId,
    pub did_name: &'static str,
    pub did_value: &'static str,
    pub claim_schema_name: &'static str,
    pub claim_value: &'static str,
    pub credential_id: CredentialId,
    pub proof_schema_id: ProofSchemaId,
}

async fn setup_with_credential_schema_and_proof() -> TestSetupWithCredentialsSchemaAndProof {
    let TestSetup {
        provider,
        organisation,
        db,
        ..
    } = setup_empty().await;

    insert_history(
        &db,
        HistoryAction::Created.into(),
        organisation.id.into(),
        HistoryEntityType::Organisation.into(),
        organisation.id,
        organisation.name.clone(),
    )
    .await
    .unwrap();

    let credential_schema_name = "schema";
    let credential_schema_id = insert_credential_schema_to_database(
        &db,
        None,
        organisation.id,
        credential_schema_name,
        "JWT",
        None,
        Some(KeyStorageSecurity::Basic),
    )
    .await
    .unwrap();
    insert_history(
        &db,
        HistoryAction::Created.into(),
        credential_schema_id.into(),
        HistoryEntityType::CredentialSchema.into(),
        organisation.id,
        credential_schema_name.to_string(),
    )
    .await
    .unwrap();

    let did_name = "issuer";
    let did_value = "did:key:123";
    let did_id = insert_did_key(
        &db,
        did_name,
        Uuid::new_v4(),
        did_value.parse().unwrap(),
        "KEY",
        organisation.id,
    )
    .await
    .unwrap();
    insert_history(
        &db,
        HistoryAction::Created.into(),
        did_id.into(),
        HistoryEntityType::Did.into(),
        organisation.id,
        did_name.to_string(),
    )
    .await
    .unwrap();

    let key_id = insert_key_to_database(
        &db,
        "ED25519".to_string(),
        vec![],
        vec![],
        None,
        organisation.id,
    )
    .await
    .unwrap();
    insert_history(
        &db,
        HistoryAction::Created.into(),
        key_id.into(),
        HistoryEntityType::Key.into(),
        organisation.id,
        "key".to_string(),
    )
    .await
    .unwrap();

    insert_key_did(&db, did_id, key_id, KeyRole::AssertionMethod)
        .await
        .unwrap();

    let identifier_id = insert_identifier(
        &db,
        "issuer",
        Uuid::new_v4(),
        Some(did_id),
        organisation.id,
        false,
    )
    .await
    .unwrap();

    let credential = insert_credential(
        &db,
        &credential_schema_id,
        CredentialStateEnum::Created,
        "OPENID4VCI_DRAFT13",
        identifier_id,
        None,
        None,
        Uuid::new_v4().into(),
        CredentialRole::Issuer,
    )
    .await
    .unwrap();
    insert_history(
        &db,
        HistoryAction::Issued.into(),
        credential.id.into(),
        HistoryEntityType::Credential.into(),
        organisation.id,
        credential_schema_name.to_string(),
    )
    .await
    .unwrap();

    let claim_schema_name = "test";
    let new_claim_schemas: Vec<ClaimInsertInfo> = (0..2)
        .map(|i| ClaimInsertInfo {
            id: Uuid::new_v4().into(),
            key: claim_schema_name,
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

    let claim_value = "claim_value";
    let claims = vec![(
        Uuid::new_v4().into(),
        new_claim_schemas[0].id,
        credential.id,
        Some(claim_value.as_bytes().to_vec()),
        new_claim_schemas[0].key.to_string(),
        false,
    )];
    insert_many_claims_to_database(&db, claims.as_slice())
        .await
        .unwrap();

    let proof_schema_name = "proof schema";
    let proof_schema_id = insert_proof_schema_with_claims_to_database(
        &db,
        None,
        vec![&claim_input],
        organisation.id,
        proof_schema_name,
    )
    .await
    .unwrap();

    insert_history(
        &db,
        HistoryAction::Created.into(),
        proof_schema_id.into(),
        HistoryEntityType::ProofSchema.into(),
        organisation.id,
        proof_schema_name.to_string(),
    )
    .await
    .unwrap();

    let proof_id = insert_proof_request_to_database(
        &db,
        identifier_id,
        &proof_schema_id,
        key_id,
        None,
        None,
        None,
        ProofRole::Verifier,
    )
    .await
    .unwrap();
    let proof_claim: Vec<(ProofId, ClaimId)> = vec![(proof_id.to_owned(), claims[0].0)];
    insert_many_proof_claim_to_database(&db, proof_claim.as_slice())
        .await
        .unwrap();

    insert_history(
        &db,
        HistoryAction::Created.into(),
        proof_id.into(),
        HistoryEntityType::Proof.into(),
        organisation.id,
        proof_schema_name.to_string(),
    )
    .await
    .unwrap();

    TestSetupWithCredentialsSchemaAndProof {
        provider,
        organisation,
        credential_schema_id,
        credential_schema_name,
        did_id,
        did_name,
        did_value,
        claim_schema_name,
        claim_value,
        credential_id: credential.id,
        proof_schema_id,
    }
}

fn history_list_query_with_filter(
    organisation_id: OrganisationId,
    value: HistoryFilterValue,
) -> HistoryListQuery {
    HistoryListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 999,
        }),
        sorting: None,
        filtering: Some(ListFilterCondition::And(vec![
            ListFilterCondition::Value(HistoryFilterValue::OrganisationIds(vec![organisation_id])),
            ListFilterCondition::Value(value),
        ])),
        include: None,
    }
}

fn assert_result(expected_count: i32, result: GetHistoryList) {
    let expected_pages = if expected_count > 0 { 1 } else { 0 };
    assert_eq!(expected_pages, result.total_pages);
    assert_eq!(expected_count as u64, result.total_items);
    assert_eq!(expected_count as usize, result.values.len());
}

#[tokio::test]
async fn test_create_history() {
    let TestSetup {
        provider,
        organisation,
        ..
    } = setup_empty().await;

    let id = Uuid::new_v4().into();
    let result = provider
        .create_history(History {
            id,
            created_date: get_dummy_date(),
            action: HistoryAction::Created,
            name: "test_key".to_string(),
            source: HistorySource::Core,
            target: None,
            entity_id: Some(Uuid::new_v4().into()),
            entity_type: HistoryEntityType::Key,
            metadata: None,
            organisation_id: Some(organisation.id),
            user: Some("testUser".to_string()),
        })
        .await;

    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(id, response);
}

#[tokio::test]
async fn test_get_history_list_simple() {
    let TestSetup {
        provider,
        organisation,
        db,
        ..
    } = setup_empty().await;

    let count = 20;
    for _ in 0..count {
        insert_history(
            &db,
            HistoryAction::Created.into(),
            Uuid::new_v4().into(),
            HistoryEntityType::Organisation.into(),
            organisation.id,
            organisation.name.clone(),
        )
        .await
        .unwrap();
    }

    let result = provider
        .get_history_list(HistoryListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: count,
            }),
            sorting: None,
            filtering: Some(ListFilterCondition::Value(
                HistoryFilterValue::OrganisationIds(vec![organisation.id]),
            )),
            include: None,
        })
        .await
        .unwrap();

    assert_result(count as i32, result);
}

#[tokio::test]
async fn test_get_history_list_schema_joins_credentials() {
    let TestSetup {
        provider,
        organisation,
        db,
        ..
    } = setup_empty().await;

    insert_history(
        &db,
        HistoryAction::Created.into(),
        organisation.id.into(),
        HistoryEntityType::Organisation.into(),
        organisation.id,
        organisation.name.clone(),
    )
    .await
    .unwrap();

    let credential_schema_id = insert_credential_schema_to_database(
        &db,
        None,
        organisation.id,
        "schema",
        "JWT",
        None,
        Some(KeyStorageSecurity::Basic),
    )
    .await
    .unwrap();
    insert_history(
        &db,
        HistoryAction::Created.into(),
        credential_schema_id.into(),
        HistoryEntityType::CredentialSchema.into(),
        organisation.id,
        organisation.name.clone(),
    )
    .await
    .unwrap();

    let did_id = insert_did_key(
        &db,
        "issuer",
        Uuid::new_v4(),
        "did:key:123".parse().unwrap(),
        "KEY",
        organisation.id,
    )
    .await
    .unwrap();

    let identifier_id = insert_identifier(
        &db,
        "issuer",
        Uuid::new_v4(),
        Some(did_id),
        organisation.id,
        false,
    )
    .await
    .unwrap();
    insert_history(
        &db,
        HistoryAction::Created.into(),
        did_id.into(),
        HistoryEntityType::Did.into(),
        organisation.id,
        organisation.name.clone(),
    )
    .await
    .unwrap();

    let credentials_count = 10;
    for _ in 0..credentials_count {
        let credential = insert_credential(
            &db,
            &credential_schema_id,
            CredentialStateEnum::Created,
            "OPENID4VCI_DRAFT13",
            identifier_id,
            None,
            None,
            Uuid::new_v4().into(),
            CredentialRole::Issuer,
        )
        .await
        .unwrap();
        insert_history(
            &db,
            HistoryAction::Issued.into(),
            credential.id.into(),
            HistoryEntityType::Credential.into(),
            organisation.id,
            organisation.name.clone(),
        )
        .await
        .unwrap();
    }

    let result = provider
        .get_history_list(history_list_query_with_filter(
            organisation.id,
            HistoryFilterValue::CredentialSchemaId(credential_schema_id),
        ))
        .await
        .unwrap();

    let expected_count = credentials_count + /* credential schema event */ 1;
    assert_result(expected_count, result);
}

#[tokio::test]
async fn test_get_history_list_joins_schema_credential_claim_proof_and_proof_schema() {
    let TestSetupWithCredentialsSchemaAndProof {
        provider,
        organisation,
        credential_id,
        credential_schema_id,
        proof_schema_id,
        ..
    } = setup_with_credential_schema_and_proof().await;

    let result = provider
        .get_history_list(history_list_query_with_filter(
            organisation.id,
            HistoryFilterValue::CredentialSchemaId(credential_schema_id),
        ))
        .await
        .unwrap();

    let expected_count = /* create(credential_schema, credential, proof) */ 3;
    assert_eq!(1, result.total_pages);
    assert_eq!(expected_count as u64, result.total_items);
    assert_eq!(expected_count as usize, result.values.len());

    let result = provider
        .get_history_list(history_list_query_with_filter(
            organisation.id,
            HistoryFilterValue::CredentialId(credential_id),
        ))
        .await
        .unwrap();

    let expected_count = /* create(credential, proof) */ 2;
    assert_result(expected_count, result);

    let result = provider
        .get_history_list(history_list_query_with_filter(
            organisation.id,
            HistoryFilterValue::ProofSchemaId(ProofSchemaId::from(Uuid::from(proof_schema_id))),
        ))
        .await
        .unwrap();

    let expected_count = /* create(proof_schema, proof) */ 2;
    assert_result(expected_count, result);
}

#[tokio::test]
async fn test_get_history_list_entity_of_another_type_should_not_get_fetched() {
    let TestSetupWithCredentialsSchemaAndProof {
        provider,
        organisation,
        did_id,
        credential_schema_id,
        ..
    } = setup_with_credential_schema_and_proof().await;

    let should_be_empty = provider
        .get_history_list(history_list_query_with_filter(
            organisation.id,
            HistoryFilterValue::IdentifierId(Uuid::from(credential_schema_id).into()),
        ))
        .await
        .unwrap();
    assert_result(0, should_be_empty);

    let should_be_empty = provider
        .get_history_list(history_list_query_with_filter(
            organisation.id,
            HistoryFilterValue::CredentialId(CredentialId::from(Uuid::from(did_id))),
        ))
        .await
        .unwrap();
    assert_result(0, should_be_empty);

    let should_be_empty = provider
        .get_history_list(history_list_query_with_filter(
            organisation.id,
            HistoryFilterValue::CredentialSchemaId(CredentialSchemaId::from(Uuid::from(did_id))),
        ))
        .await
        .unwrap();
    assert_result(0, should_be_empty);
}

#[tokio::test]
async fn test_get_history_list_search_query() {
    let TestSetupWithCredentialsSchemaAndProof {
        provider,
        organisation,
        credential_schema_name,
        did_name,
        did_value,
        claim_schema_name,
        claim_value,
        ..
    } = setup_with_credential_schema_and_proof().await;

    let search_by_credential_schema_name = provider
        .get_history_list(history_list_query_with_filter(
            organisation.id,
            HistoryFilterValue::SearchQuery(
                credential_schema_name.to_string(),
                HistorySearchEnum::CredentialSchemaName,
            ),
        ))
        .await
        .unwrap();
    assert_result(
        3, /* create schema, credential, proof */
        search_by_credential_schema_name,
    );

    let search_by_issuer_did_name = provider
        .get_history_list(history_list_query_with_filter(
            organisation.id,
            HistoryFilterValue::SearchQuery(did_name.to_string(), HistorySearchEnum::IssuerName),
        ))
        .await
        .unwrap();
    assert_result(
        2, /* create did, credential */
        search_by_issuer_did_name,
    );

    let search_by_verifier_did_name = provider
        .get_history_list(history_list_query_with_filter(
            organisation.id,
            HistoryFilterValue::SearchQuery(did_name.to_string(), HistorySearchEnum::VerifierName),
        ))
        .await
        .unwrap();
    assert_result(2 /* create did, proof */, search_by_verifier_did_name);

    let search_by_issuer_did_value = provider
        .get_history_list(history_list_query_with_filter(
            organisation.id,
            HistoryFilterValue::SearchQuery(did_value.to_string(), HistorySearchEnum::IssuerDid),
        ))
        .await
        .unwrap();
    assert_result(
        2, /* create did, credential */
        search_by_issuer_did_value,
    );

    let search_by_verifier_did_value = provider
        .get_history_list(history_list_query_with_filter(
            organisation.id,
            HistoryFilterValue::SearchQuery(did_value.to_string(), HistorySearchEnum::VerifierDid),
        ))
        .await
        .unwrap();
    assert_result(2 /* create did, proof */, search_by_verifier_did_value);

    let search_by_claim_value = provider
        .get_history_list(history_list_query_with_filter(
            organisation.id,
            HistoryFilterValue::SearchQuery(claim_value.to_string(), HistorySearchEnum::ClaimValue),
        ))
        .await
        .unwrap();
    assert_result(2 /* create credential, proof */, search_by_claim_value);

    let search_by_claim_schema_name = provider
        .get_history_list(history_list_query_with_filter(
            organisation.id,
            HistoryFilterValue::SearchQuery(
                claim_schema_name.to_string(),
                HistorySearchEnum::ClaimName,
            ),
        ))
        .await
        .unwrap();
    assert_result(
        2, /* create credential, proof */
        search_by_claim_schema_name,
    );
}

#[tokio::test]
async fn test_get_history_list_search_all_query() {
    let TestSetupWithCredentialsSchemaAndProof {
        provider,
        organisation,
        credential_schema_name,
        did_name,
        did_value,
        claim_schema_name,
        claim_value,
        ..
    } = setup_with_credential_schema_and_proof().await;

    let search_for_credential_schema_name = provider
        .get_history_list(history_list_query_with_filter(
            organisation.id,
            HistoryFilterValue::SearchQuery(
                credential_schema_name.to_string(),
                HistorySearchEnum::All,
            ),
        ))
        .await
        .unwrap();
    assert_result(
        3, /* create schema, credential, proof */
        search_for_credential_schema_name,
    );

    let search_for_issuer_did_name = provider
        .get_history_list(history_list_query_with_filter(
            organisation.id,
            HistoryFilterValue::SearchQuery(did_name.to_string(), HistorySearchEnum::All),
        ))
        .await
        .unwrap();
    assert_result(
        3, /* create did, credential, proof */
        search_for_issuer_did_name,
    );

    let search_for_verifier_did_name = provider
        .get_history_list(history_list_query_with_filter(
            organisation.id,
            HistoryFilterValue::SearchQuery(did_name.to_string(), HistorySearchEnum::All),
        ))
        .await
        .unwrap();
    assert_result(
        3, /* create did, credential, proof */
        search_for_verifier_did_name,
    );

    let search_for_issuer_did_value = provider
        .get_history_list(history_list_query_with_filter(
            organisation.id,
            HistoryFilterValue::SearchQuery(did_value.to_string(), HistorySearchEnum::All),
        ))
        .await
        .unwrap();
    assert_result(
        3, /* create did, credential, proof */
        search_for_issuer_did_value,
    );

    let search_for_verifier_did_value = provider
        .get_history_list(history_list_query_with_filter(
            organisation.id,
            HistoryFilterValue::SearchQuery(did_value.to_string(), HistorySearchEnum::All),
        ))
        .await
        .unwrap();
    assert_result(
        3, /* create did, credential, proof */
        search_for_verifier_did_value,
    );

    let search_for_claim_value = provider
        .get_history_list(history_list_query_with_filter(
            organisation.id,
            HistoryFilterValue::SearchQuery(claim_value.to_string(), HistorySearchEnum::All),
        ))
        .await
        .unwrap();
    assert_result(
        2, /* create credential, proof */
        search_for_claim_value,
    );

    let search_for_claim_schema_name = provider
        .get_history_list(history_list_query_with_filter(
            organisation.id,
            HistoryFilterValue::SearchQuery(claim_schema_name.to_string(), HistorySearchEnum::All),
        ))
        .await
        .unwrap();
    assert_result(
        2, /* create credential, proof */
        search_for_claim_schema_name,
    );
}

#[tokio::test]
async fn test_history_org_stats_empty_hourly() {
    let TestSetup {
        provider,
        organisation,
        ..
    } = setup_empty().await;

    let from = OffsetDateTime::now_utc();
    let to = from + Duration::days(1);
    let result = provider
        .organisation_stats(Some(from), to, organisation.id, true)
        .await
        .unwrap();

    // Start and end bucket with the same daily hour
    assert_zeroes(&result, 25);
}

#[tokio::test]
async fn test_history_org_stats_empty_daily() {
    let TestSetup {
        provider,
        organisation,
        ..
    } = setup_empty().await;

    let from = OffsetDateTime::now_utc();
    let to = from + Duration::days(30);
    let result = provider
        .organisation_stats(Some(from), to, organisation.id, true)
        .await
        .unwrap();

    // Start and end bucket with the same day
    assert_zeroes(&result, 31);
}

#[tokio::test]
async fn test_history_org_stats_empty_monthly() {
    let TestSetup {
        provider,
        organisation,
        ..
    } = setup_empty().await;

    let from = OffsetDateTime::now_utc();
    let to = from + Duration::days(365);
    let result = provider
        .organisation_stats(Some(from), to, organisation.id, true)
        .await
        .unwrap();

    // Start and end bucket with the same month
    assert_zeroes(&result, 13);
}

#[tokio::test]
async fn test_history_org_stats_empty_yearly() {
    let TestSetup {
        provider,
        organisation,
        ..
    } = setup_empty().await;

    let from = OffsetDateTime::now_utc();
    let to = from + Duration::days(4 * 365);
    let result = provider
        .organisation_stats(Some(from), to, organisation.id, true)
        .await
        .unwrap();

    // Start and end spans 5 years
    assert_zeroes(&result, 5);
}

#[tokio::test]
async fn test_history_org_stats_ignore_irrelevant() {
    let TestSetup {
        provider,
        organisation,
        db,
        credential_schema_id,
        identifier_id,
        proof_id,
        proof_schema_id,
        key_id,
        ..
    } = setup_empty().await;

    let holder_cred = insert_credential(
        &db,
        &credential_schema_id,
        CredentialStateEnum::Created,
        "OPENID4VCI_DRAFT13",
        identifier_id,
        None,
        None,
        Uuid::new_v4().into(),
        CredentialRole::Holder,
    )
    .await
    .unwrap();
    let holder_proof_id = insert_proof_request_to_database(
        &db,
        identifier_id,
        &proof_schema_id,
        key_id,
        None,
        None,
        None,
        ProofRole::Holder,
    )
    .await
    .unwrap();
    let org2_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();

    let org_id = organisation.id;
    let now = OffsetDateTime::now_utc();

    // Irrelevant: wrong action
    add_history(
        &db,
        HistoryEntityType::Proof,
        HistoryAction::Created,
        Some(proof_id),
        org_id,
        now,
    )
    .await;
    // Irrelevant: wrong role
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Issued,
        Some(holder_cred.id.into()),
        org_id,
        now,
    )
    .await;
    // Irrelevant: wrong role
    add_history(
        &db,
        HistoryEntityType::Proof,
        HistoryAction::Accepted,
        Some(holder_proof_id.into()),
        org_id,
        now,
    )
    .await;
    // Irrelevant: wrong entity
    add_history(
        &db,
        HistoryEntityType::TrustEntity,
        HistoryAction::Accepted,
        None,
        org_id,
        now,
    )
    .await;
    // Irrelevant: wrong org
    add_history(
        &db,
        HistoryEntityType::Proof,
        HistoryAction::Accepted,
        Some(proof_id),
        org2_id,
        now,
    )
    .await;
    // Irrelevant: too far into the future
    add_history(
        &db,
        HistoryEntityType::Proof,
        HistoryAction::Accepted,
        Some(proof_id),
        org_id,
        now + Duration::days(2),
    )
    .await;

    let from = now - Duration::days(1);
    let to = now + Duration::days(1);
    let result = provider
        .organisation_stats(Some(from), to, org_id, true)
        .await
        .unwrap();
    assert_zeroes(&result, 3);
}

#[tokio::test]
async fn test_history_org_stats_dummy_data() {
    let TestSetup {
        provider,
        organisation,
        db,
        credential_id,
        proof_id,
        ..
    } = setup_empty().await;
    let org_id = organisation.id;
    let now = OffsetDateTime::now_utc();

    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Offered,
        Some(credential_id),
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Issued,
        Some(credential_id),
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Rejected,
        Some(credential_id),
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Suspended,
        Some(credential_id),
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Reactivated,
        Some(credential_id),
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Revoked,
        Some(credential_id),
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Errored,
        Some(credential_id),
        org_id,
        now,
    )
    .await;

    add_history(
        &db,
        HistoryEntityType::Proof,
        HistoryAction::Pending,
        Some(proof_id),
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Proof,
        HistoryAction::Accepted,
        Some(proof_id),
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Proof,
        HistoryAction::Rejected,
        Some(proof_id),
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Proof,
        HistoryAction::Errored,
        Some(proof_id),
        org_id,
        now,
    )
    .await;

    let from = now - Duration::days(1);
    let to = now + Duration::days(1);
    let result = provider
        .organisation_stats(Some(from), to, org_id, true)
        .await
        .unwrap();
    assert_eq!(result.current.issuance_count, 1);
    assert_eq!(result.current.verification_count, 1);
    assert_eq!(result.current.credential_lifecycle_operation_count, 3);
    let previous = result.previous.unwrap();
    assert_eq!(previous.issuance_count, 0);
    assert_eq!(previous.verification_count, 0);
    assert_eq!(previous.credential_lifecycle_operation_count, 0);

    // Every operation exactly once in the middle of a three-day spanning stats window
    assert_timelines(&result.timelines, &[0, 1, 0]);
}

#[tokio::test]
async fn test_system_history_empty() {
    let TestSetup { provider, .. } = setup_empty().await;

    let from = OffsetDateTime::now_utc();
    let to = from + Duration::days(2 * 365);
    let result = provider.system_stats(Some(from), to, 5).await.unwrap();

    assert_eq!(result.current.issuance_count, 0);
    assert_eq!(result.current.verification_count, 0);
    assert_eq!(result.current.credential_lifecycle_operation_count, 0);
    assert_eq!(result.current.session_token_count, 0);
    assert_eq!(result.current.active_wallet_unit_count, 0);

    let previous = result.previous.unwrap();
    assert_eq!(previous.issuance_count, 0);
    assert_eq!(previous.verification_count, 0);
    assert_eq!(previous.credential_lifecycle_operation_count, 0);
    assert_eq!(previous.session_token_count, 0);
    assert_eq!(previous.active_wallet_unit_count, 0);

    assert!(result.top_verifiers.is_empty());
    assert!(result.top_issuers.is_empty());
}

#[tokio::test]
async fn test_system_history_stats_dummy_data() {
    let TestSetup {
        provider,
        organisation,
        db,
        credential_id,
        proof_id,
        ..
    } = setup_empty().await;
    let org_id = organisation.id;
    let now = OffsetDateTime::now_utc();

    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Offered,
        Some(credential_id),
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Issued,
        Some(credential_id),
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Rejected,
        Some(credential_id),
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Suspended,
        Some(credential_id),
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Reactivated,
        Some(credential_id),
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Revoked,
        Some(credential_id),
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Errored,
        Some(credential_id),
        org_id,
        now,
    )
    .await;

    add_history(
        &db,
        HistoryEntityType::Proof,
        HistoryAction::Accepted,
        Some(proof_id),
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::StsSession,
        HistoryAction::Created,
        None,
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::WalletUnit,
        HistoryAction::Created,
        None,
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::WalletUnit,
        HistoryAction::Activated,
        None,
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::WalletUnit,
        HistoryAction::Revoked,
        None,
        org_id,
        now,
    )
    .await;

    let from = now - Duration::days(1);
    let to = now + Duration::days(1);
    let result = provider.system_stats(Some(from), to, 5).await.unwrap();
    assert_eq!(result.current.issuance_count, 1);
    assert_eq!(result.current.verification_count, 1);
    assert_eq!(result.current.credential_lifecycle_operation_count, 3);
    assert_eq!(result.current.session_token_count, 1);
    assert_eq!(result.current.active_wallet_unit_count, 1); // one activated + one create - one revoked
    let previous = result.previous.unwrap();
    assert_eq!(previous.issuance_count, 0);
    assert_eq!(previous.verification_count, 0);
    assert_eq!(previous.credential_lifecycle_operation_count, 0);
    assert_eq!(previous.session_token_count, 0);
    assert_eq!(previous.active_wallet_unit_count, 0);
    assert_eq!(
        result.top_issuers,
        vec![OrganisationOperationsCount {
            organisation_id: org_id,
            previous: Some(0),
            current: 1,
        }]
    );
    assert_eq!(
        result.top_verifiers,
        vec![OrganisationOperationsCount {
            organisation_id: org_id,
            previous: Some(0),
            current: 1,
        }]
    );
}

#[tokio::test]
async fn test_system_history_stats_dummy_data_multiple_orgs() {
    let TestSetup {
        provider,
        organisation,
        db,
        credential_id,
        proof_id,
        ..
    } = setup_empty().await;
    let org_id = organisation.id;
    let org2_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();
    let now = OffsetDateTime::now_utc();

    // ignored because it is too old
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Issued,
        Some(credential_id),
        org_id,
        now - Duration::days(3),
    )
    .await;

    // prev window
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Issued,
        Some(credential_id),
        org_id,
        now - Duration::days(2),
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Suspended,
        Some(credential_id),
        org2_id,
        now - Duration::days(2),
    )
    .await;

    // current window
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Issued,
        Some(credential_id),
        org_id,
        now - Duration::days(1),
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Suspended,
        Some(credential_id),
        org2_id,
        now - Duration::days(1),
    )
    .await;

    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Issued,
        Some(credential_id),
        org_id,
        now,
    )
    .await;
    for _ in 0..10 {
        add_history(
            &db,
            HistoryEntityType::Credential,
            HistoryAction::Issued,
            Some(credential_id),
            org2_id,
            now,
        )
        .await;
    }
    for _ in 0..8 {
        add_history(
            &db,
            HistoryEntityType::Proof,
            HistoryAction::Accepted,
            Some(proof_id),
            org_id,
            now,
        )
        .await;
    }
    add_history(
        &db,
        HistoryEntityType::Proof,
        HistoryAction::Accepted,
        Some(proof_id),
        org2_id,
        now,
    )
    .await;

    // ignored because it is outside of current
    add_history(
        &db,
        HistoryEntityType::Proof,
        HistoryAction::Accepted,
        Some(proof_id),
        org2_id,
        now + Duration::days(1),
    )
    .await;

    let from = now - Duration::days(1);
    let to = now + Duration::days(1);
    let result = provider.system_stats(Some(from), to, 5).await.unwrap();
    assert_eq!(result.current.issuance_count, 12);
    assert_eq!(result.current.verification_count, 9);
    assert_eq!(result.current.credential_lifecycle_operation_count, 1);
    assert_eq!(result.current.session_token_count, 0);
    assert_eq!(result.current.active_wallet_unit_count, 0);
    let previous = result.previous.unwrap();
    assert_eq!(previous.issuance_count, 2);
    assert_eq!(previous.verification_count, 0);
    assert_eq!(previous.credential_lifecycle_operation_count, 1);
    assert_eq!(previous.session_token_count, 0);
    assert_eq!(previous.active_wallet_unit_count, 0);
    assert_eq!(
        result.top_issuers,
        vec![
            OrganisationOperationsCount {
                organisation_id: org2_id,
                previous: Some(0),
                current: 10,
            },
            OrganisationOperationsCount {
                organisation_id: org_id,
                previous: Some(2),
                current: 2,
            }
        ]
    );
    assert_eq!(
        result.top_verifiers,
        vec![
            OrganisationOperationsCount {
                organisation_id: org_id,
                previous: Some(0),
                current: 8,
            },
            OrganisationOperationsCount {
                organisation_id: org2_id,
                previous: Some(0),
                current: 1,
            }
        ]
    );
}

#[tokio::test]
async fn test_issuer_org_history_stats_dummy_data() {
    let day = Duration::days(1);
    let now = OffsetDateTime::now_utc();
    let TestSetup {
        provider,
        organisation,
        db,
        credential_id,
        identifier_id,
        credential_schema_id,
        ..
    } = setup_empty().await;
    let org_id = organisation.id;
    let credential_schema_id2 = insert_credential_schema_to_database(
        &db,
        None,
        org_id,
        "schema2",
        "JWT",
        None,
        Some(KeyStorageSecurity::Basic),
    )
    .await
    .unwrap();
    let credential2 = insert_credential(
        &db,
        &credential_schema_id2,
        CredentialStateEnum::Created,
        "OPENID4VCI_DRAFT13",
        identifier_id,
        None,
        None,
        Uuid::new_v4().into(),
        CredentialRole::Issuer,
    )
    .await
    .unwrap();

    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Issued,
        Some(credential_id),
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Revoked,
        Some(credential2.id.into()),
        org_id,
        now - Duration::hours(30),
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Suspended,
        Some(credential_id),
        org_id,
        now,
    )
    .await;
    for _ in 0..10 {
        add_history(
            &db,
            HistoryEntityType::Credential,
            HistoryAction::Suspended,
            Some(credential2.id.into()),
            org_id,
            now,
        )
        .await;
    }
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Reactivated,
        Some(credential2.id.into()),
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Revoked,
        Some(credential_id),
        org_id,
        now,
    )
    .await;
    for _ in 0..7 {
        add_history(
            &db,
            HistoryEntityType::Credential,
            HistoryAction::Errored,
            Some(credential_id),
            org_id,
            now,
        )
        .await;
    }

    let prev_start = now - 2 * day;
    let from = now - day;
    let to = now + day;
    let query = issuer_stats_query_with_filter(
        SortableIssuerStatisticsColumn::Suspended,
        org_id,
        Some(from),
        to,
    );
    let query_prev = issuer_stats_query_with_filter(
        SortableIssuerStatisticsColumn::Suspended,
        org_id,
        Some(prev_start),
        from,
    );
    let result = provider
        .issuer_stats(query, Some(query_prev))
        .await
        .unwrap();
    assert_eq!(result.total_items, 2);
    assert_eq!(result.total_pages, 1);
    assert_eq!(result.values[0].credential_schema_id, credential_schema_id2);
    assert_eq!(result.values[1].credential_schema_id, credential_schema_id);
    assert_eq!(result.values[0].current.suspended_count, 10);
    assert_eq!(result.values[1].current.suspended_count, 1);
    assert_eq!(result.values[0].current.error_count, 0);
    assert_eq!(result.values[1].current.error_count, 7);
    assert_eq!(result.values[0].previous.as_ref().unwrap().revoked_count, 1);
    assert_eq!(result.values[1].previous.as_ref().unwrap().revoked_count, 0);
}

fn issuer_stats_query_with_filter(
    sort: SortableIssuerStatisticsColumn,
    organisation_id: OrganisationId,
    from: Option<OffsetDateTime>,
    to: OffsetDateTime,
) -> IssuerStatsQuery {
    let to = StatsBySchemaFilterValue::From(ValueComparison {
        comparison: ComparisonType::LessThan,
        value: to,
    })
    .condition();

    let from = from.map(|t| {
        StatsBySchemaFilterValue::From(ValueComparison {
            comparison: ComparisonType::GreaterThanOrEqual,
            value: t,
        })
    });
    IssuerStatsQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 999,
        }),
        sorting: Some(ListSorting {
            column: sort,
            direction: Some(SortDirection::Descending),
        }),
        filtering: Some(to & from & StatsBySchemaFilterValue::OrganisationId(organisation_id)),
        include: None,
    }
}

async fn add_history(
    database: &DatabaseConnection,
    entity_type: HistoryEntityType,
    action: HistoryAction,
    entity_id: Option<EntityId>,
    organisation_id: OrganisationId,
    created_date: OffsetDateTime,
) {
    let id = Uuid::new_v4();
    history::ActiveModel {
        id: Set(id.into()),
        created_date: Set(created_date),
        action: Set(action.into()),
        name: Set("name".to_string()),
        entity_id: Set(entity_id),
        entity_type: Set(entity_type.into()),
        metadata: Set(None),
        organisation_id: Set(Some(organisation_id)),
        source: Set(history::HistorySource::Core),
        target: Set(None),
        user: Set(None),
    }
    .insert(database)
    .await
    .unwrap();
}

fn assert_zeroes(result: &OrganisationStats, expected_len: usize) {
    assert_eq!(result.current.issuance_count, 0);
    assert_eq!(result.current.verification_count, 0);
    assert_eq!(result.current.credential_lifecycle_operation_count, 0);
    let previous = result.previous.as_ref().unwrap();
    assert_eq!(previous.issuance_count, 0);
    assert_eq!(previous.verification_count, 0);
    assert_eq!(previous.credential_lifecycle_operation_count, 0);
    assert_zeroes_series(&result.timelines.issuer.offered, expected_len);
    assert_zeroes_series(&result.timelines.issuer.issued, expected_len);
    assert_zeroes_series(&result.timelines.issuer.rejected, expected_len);
    assert_zeroes_series(&result.timelines.issuer.suspended, expected_len);
    assert_zeroes_series(&result.timelines.issuer.reactivated, expected_len);
    assert_zeroes_series(&result.timelines.issuer.rejected, expected_len);
    assert_zeroes_series(&result.timelines.issuer.error, expected_len);
    assert_zeroes_series(&result.timelines.verifier.pending, expected_len);
    assert_zeroes_series(&result.timelines.verifier.accepted, expected_len);
    assert_zeroes_series(&result.timelines.verifier.rejected, expected_len);
    assert_zeroes_series(&result.timelines.verifier.error, expected_len);
}

fn assert_zeroes_series(data: &[TimeSeriesPoint], expected_len: usize) {
    assert_eq!(data.len(), expected_len);
    assert!(data.iter().all(|bucket| bucket.count == 0))
}

fn assert_timelines(result: &OrganisationTimelines, expected: &[usize]) {
    assert_counts(&result.issuer.offered, expected);
    assert_counts(&result.issuer.issued, expected);
    assert_counts(&result.issuer.rejected, expected);
    assert_counts(&result.issuer.suspended, expected);
    assert_counts(&result.issuer.reactivated, expected);
    assert_counts(&result.issuer.rejected, expected);
    assert_counts(&result.issuer.error, expected);
    assert_counts(&result.verifier.pending, expected);
    assert_counts(&result.verifier.accepted, expected);
    assert_counts(&result.verifier.rejected, expected);
    assert_counts(&result.verifier.error, expected);
}

fn assert_counts(actual: &[TimeSeriesPoint], expected: &[usize]) {
    assert_eq!(actual.iter().map(|p| p.count).collect::<Vec<_>>(), expected);
}
