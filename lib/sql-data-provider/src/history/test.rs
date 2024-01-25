use uuid::Uuid;

use one_core::{
    model::{
        credential::CredentialStateEnum,
        history::{
            History, HistoryAction, HistoryEntityType, HistoryFilterValue, HistoryListQuery,
        },
        list_filter::ListFilterCondition,
        list_query::ListPagination,
        organisation::Organisation,
    },
    repository::history_repository::HistoryRepository,
};

use crate::{history::HistoryProvider, test_utilities::*};

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
            id: Uuid::parse_str(&organisation_id).unwrap(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        },
        db,
    }
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
            entity_id: Uuid::new_v4().into(),
            entity_type: HistoryEntityType::Key,
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
            organisation.id.to_owned().into(),
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
        })
        .await
        .unwrap();

    assert_eq!(1, result.total_pages);
    assert_eq!(count as u64, result.total_items);
    assert_eq!(count as usize, result.values.len());
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
        organisation.id.to_owned().into(),
        HistoryEntityType::Organisation.into(),
        organisation.id.to_owned().into(),
    )
    .await
    .unwrap();

    let credential_schema_id = insert_credential_schema_to_database(
        &db,
        None,
        &organisation.id.to_string(),
        "schema",
        "JWT",
        "NONE",
    )
    .await
    .unwrap();
    insert_history(
        &db,
        HistoryAction::Created.into(),
        Uuid::parse_str(&credential_schema_id).unwrap().into(),
        HistoryEntityType::CredentialSchema.into(),
        organisation.id.to_owned().into(),
    )
    .await
    .unwrap();

    let did_id = insert_did_key(
        &db,
        "issuer",
        Uuid::new_v4(),
        "did:key:123".parse().unwrap(),
        "KEY",
        &organisation.id.to_string(),
    )
    .await
    .unwrap();
    insert_history(
        &db,
        HistoryAction::Created.into(),
        did_id.into(),
        HistoryEntityType::Did.into(),
        organisation.id.to_owned().into(),
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
            Uuid::parse_str(&credential_id).unwrap().into(),
            HistoryEntityType::Credential.into(),
            organisation.id.to_owned().into(),
        )
        .await
        .unwrap();
    }

    let result = provider
        .get_history_list(HistoryListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 999,
            }),
            sorting: None,
            filtering: Some(ListFilterCondition::And(vec![
                ListFilterCondition::Value(HistoryFilterValue::OrganisationId(organisation.id)),
                ListFilterCondition::Value(HistoryFilterValue::CredentialSchemaId(
                    Uuid::parse_str(&credential_schema_id).unwrap(),
                )),
            ])),
        })
        .await
        .unwrap();

    let expected_count = credentials_count + /* credential schema event */ 1;
    assert_eq!(1, result.total_pages);
    assert_eq!(expected_count as u64, result.total_items);
    assert_eq!(expected_count as usize, result.values.len());
}

#[tokio::test]
async fn test_get_history_list_joins_schema_credential_claim_and_proof() {
    let TestSetup {
        provider,
        organisation,
        db,
        ..
    } = setup_empty().await;

    insert_history(
        &db,
        HistoryAction::Created.into(),
        organisation.id.to_owned().into(),
        HistoryEntityType::Organisation.into(),
        organisation.id.to_owned().into(),
    )
    .await
    .unwrap();

    let credential_schema_id = insert_credential_schema_to_database(
        &db,
        None,
        &organisation.id.to_string(),
        "schema",
        "JWT",
        "NONE",
    )
    .await
    .unwrap();
    insert_history(
        &db,
        HistoryAction::Created.into(),
        Uuid::parse_str(&credential_schema_id).unwrap().into(),
        HistoryEntityType::CredentialSchema.into(),
        organisation.id.to_owned().into(),
    )
    .await
    .unwrap();

    let did_id = insert_did_key(
        &db,
        "issuer",
        Uuid::new_v4(),
        "did:key:123".parse().unwrap(),
        "KEY",
        &organisation.id.to_string(),
    )
    .await
    .unwrap();
    insert_history(
        &db,
        HistoryAction::Created.into(),
        did_id.into(),
        HistoryEntityType::Did.into(),
        organisation.id.to_owned().into(),
    )
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
        Uuid::parse_str(&credential_id).unwrap().into(),
        HistoryEntityType::Credential.into(),
        organisation.id.to_owned().into(),
    )
    .await
    .unwrap();

    let claim_schema: Vec<(Uuid, &str, bool, u32, &str)> =
        vec![(Uuid::new_v4(), "test", false, 0, "STRING")];
    insert_many_claims_schema_to_database(&db, &credential_schema_id.to_string(), &claim_schema)
        .await
        .unwrap();

    let claims: Vec<(Uuid, Uuid, &str, Vec<u8>)> = vec![(
        Uuid::new_v4(),
        claim_schema[0].0.to_owned(),
        &credential_id,
        vec![],
    )];
    insert_many_claims_to_database(&db, claims.as_slice())
        .await
        .unwrap();

    let proof_schema_id = Uuid::parse_str(
        &insert_proof_schema_with_claims_to_database(
            &db,
            None,
            &claim_schema,
            &organisation.id.to_string(),
            "proof schema",
        )
        .await
        .unwrap(),
    )
    .unwrap();
    insert_history(
        &db,
        HistoryAction::Created.into(),
        proof_schema_id.into(),
        HistoryEntityType::ProofSchema.into(),
        organisation.id.to_owned().into(),
    )
    .await
    .unwrap();

    let proof_id = Uuid::parse_str(
        &insert_proof_request_to_database(&db, did_id, None, &proof_schema_id.to_string(), None)
            .await
            .unwrap(),
    )
    .unwrap();
    let proof_claim: Vec<(Uuid, Uuid)> = vec![(proof_id.to_owned(), claims[0].0.to_owned())];
    insert_many_proof_claim_to_database(&db, proof_claim.as_slice())
        .await
        .unwrap();

    insert_history(
        &db,
        HistoryAction::Created.into(),
        proof_id.into(),
        HistoryEntityType::Proof.into(),
        organisation.id.to_owned().into(),
    )
    .await
    .unwrap();

    let result = provider
        .get_history_list(HistoryListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 999,
            }),
            sorting: None,
            filtering: Some(ListFilterCondition::And(vec![
                ListFilterCondition::Value(HistoryFilterValue::OrganisationId(organisation.id)),
                ListFilterCondition::Value(HistoryFilterValue::CredentialSchemaId(
                    Uuid::parse_str(&credential_schema_id).unwrap(),
                )),
            ])),
        })
        .await
        .unwrap();

    let expected_count = /* create(credential_schema, credential, proof) */ 3;
    assert_eq!(1, result.total_pages);
    assert_eq!(expected_count as u64, result.total_items);
    assert_eq!(expected_count as usize, result.values.len());

    let result = provider
        .get_history_list(HistoryListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 999,
            }),
            sorting: None,
            filtering: Some(ListFilterCondition::And(vec![
                ListFilterCondition::Value(HistoryFilterValue::OrganisationId(organisation.id)),
                ListFilterCondition::Value(HistoryFilterValue::CredentialId(
                    Uuid::parse_str(&credential_id).unwrap(),
                )),
            ])),
        })
        .await
        .unwrap();

    let expected_count = /* create(credential, proof) */ 2;
    assert_eq!(1, result.total_pages);
    assert_eq!(expected_count as u64, result.total_items);
    assert_eq!(expected_count as usize, result.values.len());
}
