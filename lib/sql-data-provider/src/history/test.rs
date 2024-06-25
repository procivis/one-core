use one_core::model::credential::CredentialStateEnum;
use one_core::model::history::{
    GetHistoryList, History, HistoryAction, HistoryEntityType, HistoryFilterValue,
    HistoryListQuery, HistorySearchEnum,
};
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::list_query::ListPagination;
use one_core::model::organisation::Organisation;
use one_core::repository::history_repository::HistoryRepository;
use shared_types::{
    ClaimId, ClaimSchemaId, CredentialId, CredentialSchemaId, DidId, OrganisationId, ProofId,
};
use uuid::Uuid;

use crate::entity::key_did::KeyRole;
use crate::history::HistoryProvider;
use crate::test_utilities::*;

struct TestSetup {
    pub provider: HistoryProvider,
    pub organisation: Organisation,
    pub db: sea_orm::DatabaseConnection,
}

async fn setup_empty() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None).await.unwrap();

    TestSetup {
        provider: HistoryProvider { db: db.clone() },
        organisation: Organisation {
            id: organisation_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        },
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
        "NONE",
    )
    .await
    .unwrap();
    insert_history(
        &db,
        HistoryAction::Created.into(),
        credential_schema_id.into(),
        HistoryEntityType::CredentialSchema.into(),
        organisation.id,
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
    )
    .await
    .unwrap();

    insert_key_did(&db, did_id, key_id, KeyRole::AssertionMethod)
        .await
        .unwrap();

    let credential_id = insert_credential(
        &db,
        &credential_schema_id,
        CredentialStateEnum::Created,
        "PROCIVIS_TEMPORARY",
        did_id.to_owned(),
        None,
    )
    .await
    .unwrap();
    insert_history(
        &db,
        HistoryAction::Issued.into(),
        credential_id.into(),
        HistoryEntityType::Credential.into(),
        organisation.id,
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
    let claims: Vec<(ClaimId, ClaimSchemaId, CredentialId, Vec<u8>, String)> = vec![(
        Uuid::new_v4().into(),
        new_claim_schemas[0].id,
        credential_id,
        claim_value.as_bytes().to_vec(),
        new_claim_schemas[0].key.to_string(),
    )];
    insert_many_claims_to_database(&db, claims.as_slice())
        .await
        .unwrap();

    let proof_schema_id = insert_proof_schema_with_claims_to_database(
        &db,
        None,
        vec![&claim_input],
        organisation.id,
        "proof schema",
    )
    .await
    .unwrap();

    insert_history(
        &db,
        HistoryAction::Created.into(),
        proof_schema_id.into(),
        HistoryEntityType::ProofSchema.into(),
        organisation.id,
    )
    .await
    .unwrap();

    let proof_id =
        insert_proof_request_to_database(&db, did_id, None, &proof_schema_id, key_id, None)
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
        credential_id,
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
            ListFilterCondition::Value(HistoryFilterValue::OrganisationId(organisation_id)),
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
            entity_id: Some(Uuid::new_v4().into()),
            entity_type: HistoryEntityType::Key,
            metadata: None,
            organisation: Some(organisation),
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
                HistoryFilterValue::OrganisationId(organisation.id),
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
    )
    .await
    .unwrap();

    let credential_schema_id =
        insert_credential_schema_to_database(&db, None, organisation.id, "schema", "JWT", "NONE")
            .await
            .unwrap();
    insert_history(
        &db,
        HistoryAction::Created.into(),
        credential_schema_id.into(),
        HistoryEntityType::CredentialSchema.into(),
        organisation.id,
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
    insert_history(
        &db,
        HistoryAction::Created.into(),
        did_id.into(),
        HistoryEntityType::Did.into(),
        organisation.id,
    )
    .await
    .unwrap();

    let credentials_count = 10;
    for _ in 0..credentials_count {
        let credential_id = insert_credential(
            &db,
            &credential_schema_id,
            CredentialStateEnum::Created,
            "PROCIVIS_TEMPORARY",
            did_id.to_owned(),
            None,
        )
        .await
        .unwrap();
        insert_history(
            &db,
            HistoryAction::Issued.into(),
            credential_id.into(),
            HistoryEntityType::Credential.into(),
            organisation.id,
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
async fn test_get_history_list_joins_schema_credential_claim_and_proof() {
    let TestSetupWithCredentialsSchemaAndProof {
        provider,
        organisation,
        credential_id,
        credential_schema_id,
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
            HistoryFilterValue::DidId(Uuid::from(credential_schema_id).into()),
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
