use one_core::model::credential::CredentialStateEnum;
use one_core::model::history::{
    GetHistoryList, History, HistoryAction, HistoryEntityType, HistoryFilterValue,
    HistoryListQuery, HistorySearchEnum, HistorySource, OrganisationStats, TimeSeriesPoint,
};
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::list_query::ListPagination;
use one_core::model::organisation::Organisation;
use one_core::repository::history_repository::HistoryRepository;
use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};
use shared_types::{
    ClaimId, CredentialId, CredentialSchemaId, DidId, OrganisationId, ProofId, ProofSchemaId,
};
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::entity::credential_schema::KeyStorageSecurity;
use crate::entity::history;
use crate::entity::key_did::KeyRole;
use crate::history::HistoryProvider;
use crate::test_utilities::*;
use crate::transaction_context::TransactionManagerImpl;

struct TestSetup {
    pub provider: HistoryProvider,
    pub organisation: Organisation,
    pub db: sea_orm::DatabaseConnection,
}

async fn setup_empty() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();

    TestSetup {
        provider: HistoryProvider {
            db: TransactionManagerImpl::new(db.clone()),
        },
        organisation: dummy_organisation(Some(organisation_id)),
        db,
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
        .organisation_stats(from, to, organisation.id)
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
        .organisation_stats(from, to, organisation.id)
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
        .organisation_stats(from, to, organisation.id)
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
    let to = from + Duration::days(2 * 365);
    let result = provider
        .organisation_stats(from, to, organisation.id)
        .await
        .unwrap();

    // Start and end spans 3 years
    assert_zeroes(&result, 3);
}

#[tokio::test]
async fn test_history_org_stats_ignore_irrelevant() {
    let TestSetup {
        provider,
        organisation,
        db,
    } = setup_empty().await;
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
        org_id,
        now,
    )
    .await;
    // Irrelevant: wrong entity
    add_history(
        &db,
        HistoryEntityType::TrustEntity,
        HistoryAction::Accepted,
        org_id,
        now,
    )
    .await;
    // Irrelevant: wrong org
    add_history(
        &db,
        HistoryEntityType::TrustEntity,
        HistoryAction::Accepted,
        org2_id,
        now,
    )
    .await;
    // Irrelevant: too far into the future
    add_history(
        &db,
        HistoryEntityType::TrustEntity,
        HistoryAction::Accepted,
        org_id,
        now + Duration::days(2),
    )
    .await;

    let from = now - Duration::days(1);
    let to = now + Duration::days(1);
    let result = provider.organisation_stats(from, to, org_id).await.unwrap();
    assert_zeroes(&result, 3);
}

#[tokio::test]
async fn test_history_org_stats_dummy_data() {
    let TestSetup {
        provider,
        organisation,
        db,
    } = setup_empty().await;
    let org_id = organisation.id;
    let now = OffsetDateTime::now_utc();

    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Offered,
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Issued,
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Rejected,
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Suspended,
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Reactivated,
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Revoked,
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Credential,
        HistoryAction::Errored,
        org_id,
        now,
    )
    .await;

    add_history(
        &db,
        HistoryEntityType::Proof,
        HistoryAction::Pending,
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Proof,
        HistoryAction::Accepted,
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Proof,
        HistoryAction::Rejected,
        org_id,
        now,
    )
    .await;
    add_history(
        &db,
        HistoryEntityType::Proof,
        HistoryAction::Errored,
        org_id,
        now,
    )
    .await;

    let from = now - Duration::days(1);
    let to = now + Duration::days(1);
    let result = provider.organisation_stats(from, to, org_id).await.unwrap();
    assert_eq!(result.to.issuance_count, 1);
    assert_eq!(result.to.verification_count, 1);
    assert_eq!(result.to.credential_lifecycle_operation_count, 7);
    assert_eq!(result.from.issuance_count, 0);
    assert_eq!(result.from.verification_count, 0);
    assert_eq!(result.from.credential_lifecycle_operation_count, 0);

    // Every operation exactly once in the middle of a three-day spanning stats window
    assert_timelines(&result, &[0, 1, 0]);
}

async fn add_history(
    database: &DatabaseConnection,
    entity_type: HistoryEntityType,
    action: HistoryAction,
    organisation_id: OrganisationId,
    created_date: OffsetDateTime,
) {
    let id = Uuid::new_v4();
    history::ActiveModel {
        id: Set(id.into()),
        created_date: Set(created_date),
        action: Set(action.into()),
        name: Set(id.into()),
        entity_id: Set(None),
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
    assert_eq!(result.to.issuance_count, 0);
    assert_eq!(result.to.verification_count, 0);
    assert_eq!(result.to.credential_lifecycle_operation_count, 0);
    assert_eq!(result.from.issuance_count, 0);
    assert_eq!(result.from.verification_count, 0);
    assert_eq!(result.from.credential_lifecycle_operation_count, 0);
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

fn assert_timelines(result: &OrganisationStats, expected: &[usize]) {
    assert_counts(&result.timelines.issuer.offered, expected);
    assert_counts(&result.timelines.issuer.issued, expected);
    assert_counts(&result.timelines.issuer.rejected, expected);
    assert_counts(&result.timelines.issuer.suspended, expected);
    assert_counts(&result.timelines.issuer.reactivated, expected);
    assert_counts(&result.timelines.issuer.rejected, expected);
    assert_counts(&result.timelines.issuer.error, expected);
    assert_counts(&result.timelines.verifier.pending, expected);
    assert_counts(&result.timelines.verifier.accepted, expected);
    assert_counts(&result.timelines.verifier.rejected, expected);
    assert_counts(&result.timelines.verifier.error, expected);
}

fn assert_counts(actual: &[TimeSeriesPoint], expected: &[usize]) {
    assert_eq!(actual.iter().map(|p| p.count).collect::<Vec<_>>(), expected);
}
