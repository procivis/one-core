use one_core::repository::DataRepository;
use sea_orm::{ActiveModelTrait, ColumnTrait, IntoActiveModel, QueryFilter};
use shared_types::{ClaimId, ProofId};
use similar_asserts::assert_eq;

use super::*;
use crate::entity::{claim, proof, proof_claim};

struct BatchSetup {
    db: DatabaseConnection,
    repositories: crate::DataLayer,
    parent: Credential,
    claim: Claim,
}

impl BatchSetup {
    async fn new() -> Self {
        Self::with_role(CredentialRole::Holder).await
    }

    async fn with_role(role: CredentialRole) -> Self {
        let TestSetup {
            db,
            credential_schema,
            identifier,
        } = setup_empty().await;
        let template = insert_credential(
            &db,
            &credential_schema.id,
            CredentialStateEnum::Accepted,
            "OPENID4VCI_FINAL1",
            identifier.id,
            None,
            None,
            Uuid::new_v4().into(),
            role.into(),
        )
        .await
        .unwrap();
        let mut row = credential::Entity::find_by_id(template.common().id)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .into_active_model();
        row.r#type = Set(credential::CredentialType::BatchParent);
        row.update(&db).await.unwrap();
        let repositories = crate::DataLayer::build(db.clone(), vec![]);
        let parent = {
            let mut updated_credential = repositories
                .get_credential_repository()
                .get_credential(&template.common().id)
                .await
                .unwrap();
            updated_credential.common_mut().id = Uuid::new_v4().into();
            *updated_credential.type_mut().unwrap() = CredentialType::BatchParent;
            updated_credential
        };
        repositories
            .get_credential_repository()
            .create_credential(parent.clone())
            .await
            .unwrap();
        let claim = Claim {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            value: Some("value".into()),
            path: "name".into(),
            selectively_disclosable: true,
            schema: credential_schema.claim_schemas.as_ref().await.unwrap()[0]
                .clone()
                .into(),
        };
        Self {
            db,
            repositories,
            parent,
            claim,
        }
    }

    fn item(&self, claims: Vec<Claim>) -> Credential {
        {
            let mut updated_credential = self.parent.clone();
            updated_credential.common_mut().id = Uuid::new_v4().into();
            *updated_credential.type_mut().unwrap() = CredentialType::BatchItem;
            *updated_credential.parent_mut().unwrap() = Some(self.parent.clone().into());
            *updated_credential.claims_mut().unwrap() = claims.into();
            updated_credential
        }
    }

    async fn create_item(&self, claims: Vec<Claim>) -> CredentialId {
        self.repositories
            .get_credential_repository()
            .create_credential(self.item(claims))
            .await
            .unwrap()
    }

    async fn claim_ids(&self, credential_id: CredentialId) -> HashSet<ClaimId> {
        self.repositories
            .get_claim_repository()
            .get_claims_for_credential(credential_id)
            .await
            .unwrap()
            .into_iter()
            .map(|claim| claim.id)
            .collect()
    }

    async fn proof(&self, references: &[(CredentialId, ClaimId)]) -> ProofId {
        let proof_id = Uuid::new_v4().into();
        proof::ActiveModel {
            id: Set(proof_id),
            created_date: Set(get_dummy_date()),
            last_modified: Set(get_dummy_date()),
            protocol: Set("OPENID4VP_FINAL1".into()),
            transport: Set("HTTP".into()),
            state: Set(proof::ProofRequestState::Accepted),
            role: Set(proof::ProofRole::Holder),
            ..Default::default()
        }
        .insert(&self.db)
        .await
        .unwrap();
        for &(credential_id, claim_id) in references {
            proof_claim::ActiveModel {
                proof_id: Set(proof_id),
                credential_id: Set(credential_id),
                claim_id: Set(claim_id),
            }
            .insert(&self.db)
            .await
            .unwrap();
        }
        proof_id
    }
}

#[rstest]
#[case::identical("same", true)]
#[case::different_timestamps("timestamps", true)]
#[case::different_value("value", false)]
#[case::case_sensitive_value("case", false)]
#[case::different_path("path", false)]
#[case::case_sensitive_path("path_case", false)]
#[case::different_schema("schema", false)]
#[case::different_disclosure("disclosure", false)]
#[case::null_and_empty("null_empty", false)]
#[case::two_nulls("null", true)]
#[tokio::test]
async fn reuse_requires_equal_claim_contents(#[case] difference: &str, #[case] reused: bool) {
    let setup = BatchSetup::new().await;
    let mut first = setup.claim.clone();
    let mut second = Claim {
        id: Uuid::new_v4().into(),
        created_date: first.created_date + Duration::days(1),
        ..first.clone()
    };
    match difference {
        "same" => {}
        "timestamps" => {
            second.created_date += Duration::days(1);
            second.last_modified += Duration::days(2);
        }
        "value" => second.value = Some("other".into()),
        "case" => second.value = Some("VALUE".into()),
        "path" => second.path = "name/0".into(),
        "path_case" => second.path = "NAME".into(),
        "schema" => {
            second.schema = setup
                .parent
                .common()
                .schema
                .as_ref()
                .await
                .unwrap()
                .claim_schemas
                .as_ref()
                .await
                .unwrap()[1]
                .clone()
                .into()
        }
        "disclosure" => second.selectively_disclosable = false,
        "null_empty" => {
            first.value = None;
            second.value = Some("".into());
        }
        "null" => {
            first.value = None;
            second.value = None;
        }
        _ => unreachable!(),
    }
    let first_item = setup.create_item(vec![first.clone()]).await;
    let second_item = setup.create_item(vec![second.clone()]).await;
    assert_eq!(setup.claim_ids(first_item).await, HashSet::from([first.id]));
    assert_eq!(
        setup.claim_ids(second_item).await,
        HashSet::from([if reused { first.id } else { second.id }])
    );
    assert_eq!(
        claim::Entity::find_by_id(second.id)
            .one(&setup.db)
            .await
            .unwrap()
            .is_none(),
        reused
    );
    assert!(setup.claim_ids(setup.parent.common().id).await.is_empty());
}

#[tokio::test]
async fn claims_are_not_reused_across_batches() {
    let setup = BatchSetup::new().await;
    let first = setup.create_item(vec![setup.claim.clone()]).await;
    let different = Claim {
        id: Uuid::new_v4().into(),
        ..setup.claim.clone()
    };
    let other_parent = {
        let mut updated_credential = setup.parent.clone();
        updated_credential.common_mut().id = Uuid::new_v4().into();
        updated_credential
    };
    setup
        .repositories
        .get_credential_repository()
        .create_credential(other_parent.clone())
        .await
        .unwrap();
    let item = {
        let mut updated_credential = setup.item(vec![different.clone()]);
        *updated_credential.parent_mut().unwrap() = Some(other_parent.into());
        updated_credential
    };
    let id = setup
        .repositories
        .get_credential_repository()
        .create_credential(item)
        .await
        .unwrap();
    assert_eq!(
        setup.claim_ids(first).await,
        HashSet::from([setup.claim.id])
    );
    assert_eq!(setup.claim_ids(id).await, HashSet::from([different.id]));
}

#[rstest]
#[case::holder(CredentialRole::Holder)]
#[case::issuer(CredentialRole::Issuer)]
#[case::verifier(CredentialRole::Verifier)]
#[tokio::test]
async fn single_credentials_do_not_reuse_batch_claims(#[case] role: CredentialRole) {
    let setup = BatchSetup::new().await;
    setup.create_item(vec![setup.claim.clone()]).await;
    let different = Claim {
        id: Uuid::new_v4().into(),
        ..setup.claim.clone()
    };
    let single = {
        let mut updated_credential = setup.item(vec![different.clone()]);
        *updated_credential.type_mut().unwrap() = CredentialType::Single;
        *updated_credential.parent_mut().unwrap() = None;
        updated_credential
    };
    let single = if role == CredentialRole::Verifier {
        let mut single = single;
        let format = single
            .common()
            .schema
            .as_ref()
            .await
            .unwrap()
            .formats
            .as_ref()
            .await
            .unwrap()[0]
            .clone();
        *single.format_mut().unwrap() = Some(format.into());
        one_core::service::test_utilities::verifier_credential(single).unwrap()
    } else if role == CredentialRole::Issuer {
        let mut single = single;
        let schema = single.common().schema.as_ref().await.unwrap().clone();
        let key_id = insert_key_to_database(
            &setup.db,
            "EDDSA".into(),
            vec![],
            vec![],
            None,
            schema.organisation.id(),
        )
        .await
        .unwrap();
        *single.key_mut().unwrap() = Some(one_core::model::relation::Related::new(
            key_id,
            setup.repositories.get_key_repository(),
        ));
        *single.format_mut().unwrap() =
            Some(schema.formats.as_ref().await.unwrap()[0].clone().into());
        one_core::service::test_utilities::issuer_credential(single).unwrap()
    } else {
        single
    };
    let id = setup
        .repositories
        .get_credential_repository()
        .create_credential(single)
        .await
        .unwrap();
    assert_eq!(setup.claim_ids(id).await, HashSet::from([different.id]));
}

#[tokio::test]
async fn refresh_reuses_common_claims_but_preserves_changed_metadata() {
    let setup = BatchSetup::new().await;
    let old_metadata = Claim {
        id: Uuid::new_v4().into(),
        path: "expiry".into(),
        value: Some("old".into()),
        ..setup.claim.clone()
    };
    let first = setup
        .create_item(vec![setup.claim.clone(), old_metadata.clone()])
        .await;
    let mut old_item = credential::Entity::find_by_id(first)
        .one(&setup.db)
        .await
        .unwrap()
        .unwrap()
        .into_active_model();
    old_item.deleted_at = Set(Some(get_dummy_date()));
    old_item.consumed_at = Set(Some(get_dummy_date()));
    old_item.update(&setup.db).await.unwrap();
    let new_metadata = Claim {
        id: Uuid::new_v4().into(),
        value: Some("new".into()),
        ..old_metadata.clone()
    };
    let next = setup
        .create_item(vec![
            Claim {
                id: Uuid::new_v4().into(),
                ..setup.claim.clone()
            },
            new_metadata.clone(),
        ])
        .await;
    assert_eq!(
        setup.claim_ids(first).await,
        HashSet::from([setup.claim.id, old_metadata.id])
    );
    assert_eq!(
        setup.claim_ids(next).await,
        HashSet::from([setup.claim.id, new_metadata.id])
    );
}

#[tokio::test]
async fn reuse_preserves_existing_proof_references() {
    let setup = BatchSetup::new().await;
    let first = setup.create_item(vec![setup.claim.clone()]).await;
    let proof_id = setup.proof(&[(first, setup.claim.id)]).await;
    let second = setup
        .create_item(vec![Claim {
            id: Uuid::new_v4().into(),
            ..setup.claim.clone()
        }])
        .await;
    assert_eq!(
        setup.claim_ids(second).await,
        HashSet::from([setup.claim.id])
    );
    let proof = setup
        .repositories
        .get_proof_repository()
        .get_proof(&proof_id, None)
        .await
        .unwrap();
    let inputs = proof.claims.as_ref().await.unwrap();
    assert_eq!(inputs[0].credential.id(), first);
    assert_eq!(inputs[0].claim.id, setup.claim.id);
}

#[tokio::test]
async fn concurrent_batch_items_share_claims() {
    let setup = BatchSetup::new().await;
    let batches = (0..4).map(|_| {
        (0..3)
            .map(|_| {
                setup.item(vec![Claim {
                    id: Uuid::new_v4().into(),
                    ..setup.claim.clone()
                }])
            })
            .collect()
    });
    let repository = setup.repositories.get_credential_repository();
    let results =
        futures::future::join_all(batches.map(|batch| repository.create_credentials(batch))).await;
    let mut ids = HashSet::new();
    for result in results {
        for credential_id in result.unwrap() {
            ids.extend(setup.claim_ids(credential_id).await);
        }
    }
    assert_eq!(ids.len(), 1);
}

#[tokio::test]
async fn reuse_does_not_hide_conflicting_requested_claim_ids() {
    let setup = BatchSetup::new().await;
    setup.create_item(vec![setup.claim.clone()]).await;
    let conflicting = Claim {
        id: Uuid::new_v4().into(),
        value: Some("different".into()),
        ..setup.claim.clone()
    };
    setup.create_item(vec![conflicting.clone()]).await;
    let request = setup.item(vec![Claim {
        id: conflicting.id,
        ..setup.claim.clone()
    }]);
    let requested_id = request.common().id;
    let result = setup
        .repositories
        .get_credential_repository()
        .create_credential(request)
        .await;
    assert!(matches!(result, Err(DataLayerError::AlreadyExists)));
    assert!(
        credential::Entity::find_by_id(requested_id)
            .one(&setup.db)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        claim::Entity::find_by_id(conflicting.id)
            .one(&setup.db)
            .await
            .unwrap()
            .unwrap()
            .value,
        Some(b"different".to_vec())
    );
}

#[rstest]
#[case::new_batch(false)]
#[case::refresh(true)]
#[tokio::test]
async fn bulk_creation_query_count_does_not_grow_per_item(#[case] refresh: bool) {
    use std::sync::Mutex;

    let mut counts = Vec::new();
    for size in [2, 20] {
        let mut setup = BatchSetup::new().await;
        if refresh {
            setup.create_item(vec![setup.claim.clone()]).await;
        } else {
            setup.parent.common_mut().id = Uuid::new_v4().into();
        }
        let statements = Arc::new(Mutex::new(Vec::new()));
        let captured = statements.clone();
        setup.db.set_metric_callback(move |info| {
            captured.lock().unwrap().push(info.statement.sql.clone());
        });
        setup.repositories = crate::DataLayer::build(setup.db.clone(), vec![]);
        let mut requests: Vec<_> = (0..size)
            .map(|_| {
                setup.item(vec![Claim {
                    id: Uuid::new_v4().into(),
                    ..setup.claim.clone()
                }])
            })
            .collect();
        if !refresh {
            // Input order does not have to follow foreign-key dependencies.
            requests.push(setup.parent.clone());
        }
        let expected_ids: Vec<_> = requests
            .iter()
            .map(|credential| credential.common().id)
            .collect();
        let ids = setup
            .repositories
            .get_credential_repository()
            .create_credentials(requests)
            .await
            .unwrap();
        assert_eq!(ids, expected_ids);
        {
            let statements = statements.lock().unwrap();
            counts.push((
                statements
                    .iter()
                    .filter(|sql| sql.starts_with("SELECT"))
                    .count(),
                statements
                    .iter()
                    .filter(|sql| sql.starts_with("INSERT"))
                    .count(),
            ));
            assert_eq!(
                statements
                    .iter()
                    .filter(|sql| sql.contains("credential_claim") && sql.contains("parent_id"))
                    .count(),
                usize::from(refresh),
            );
        }
        let mut claim_ids = HashSet::new();
        for id in ids.into_iter().filter(|id| *id != setup.parent.common().id) {
            claim_ids.extend(setup.claim_ids(id).await);
        }
        assert_eq!(claim_ids.len(), 1);
        if refresh {
            assert_eq!(claim_ids, HashSet::from([setup.claim.id]));
        }
        assert!(setup.claim_ids(setup.parent.common().id).await.is_empty());
    }
    assert!(counts[0].0 > 0 && counts[0].1 > 0);
    assert_eq!(
        counts[0], counts[1],
        "Queries should scale with chunks, not items"
    );
}

#[tokio::test]
async fn bulk_creation_crosses_all_insert_chunk_boundaries() {
    let mut setup = BatchSetup::new().await;
    setup.parent.common_mut().id = Uuid::new_v4().into();
    let mut requests: Vec<_> = (0..65)
        .map(|index| {
            let mut claims = vec![Claim {
                id: Uuid::new_v4().into(),
                ..setup.claim.clone()
            }];
            claims.extend((0..6).map(|field| Claim {
                id: Uuid::new_v4().into(),
                path: format!("metadata/{field}"),
                value: Some(format!("{index}-{field}")),
                ..setup.claim.clone()
            }));
            setup.item(claims)
        })
        .collect();
    requests.push(setup.parent.clone());
    let expected: Vec<_> = requests
        .iter()
        .map(|credential| credential.common().id)
        .collect();
    let ids = setup
        .repositories
        .get_credential_repository()
        .create_credentials(requests)
        .await
        .unwrap();
    assert_eq!(ids, expected);
    let mut stored = HashSet::new();
    for id in ids.into_iter().filter(|id| *id != setup.parent.common().id) {
        let claim_ids = setup.claim_ids(id).await;
        assert_eq!(claim_ids.len(), 7);
        stored.extend(claim_ids);
    }
    assert_eq!(stored.len(), 1 + 65 * 6);
    assert!(setup.claim_ids(setup.parent.common().id).await.is_empty());
}

#[rstest]
#[case::different_contents_for_one_id("id")]
#[case::different_claims_for_one_path("path")]
#[case::repeated_claim_id("repeated_id")]
#[case::repeated_claim_contents("repeated_contents")]
#[case::missing_claim_schema("schema")]
#[case::duplicate_credential_id("credential")]
#[tokio::test]
async fn bulk_creation_failure_leaves_no_credentials_or_claims(#[case] conflict: &str) {
    let mut setup = BatchSetup::new().await;
    setup.parent.common_mut().id = Uuid::new_v4().into();
    let first = setup.item(vec![setup.claim.clone()]);
    let mut second_claim = Claim {
        id: Uuid::new_v4().into(),
        ..setup.claim.clone()
    };
    match conflict {
        "id" => {
            second_claim.id = setup.claim.id;
            second_claim.value = Some("conflict".into());
        }
        "path" => second_claim.value = Some("conflict".into()),
        "repeated_id" => second_claim.id = setup.claim.id,
        "schema" => {
            let mut schema = second_claim.schema.as_ref().await.unwrap().clone();
            schema.id = Uuid::new_v4().into();
            second_claim.schema = schema.into();
        }
        "credential" | "repeated_contents" => {}
        _ => unreachable!(),
    }
    let mut second = setup.item(
        if matches!(conflict, "path" | "repeated_id" | "repeated_contents") {
            vec![setup.claim.clone(), second_claim]
        } else {
            vec![second_claim]
        },
    );
    if conflict == "credential" {
        second.common_mut().id = first.common().id;
    }
    let requests = vec![setup.parent.clone(), first, second];
    let requested_ids: Vec<_> = requests
        .iter()
        .map(|credential| credential.common().id)
        .collect();
    assert!(
        setup
            .repositories
            .get_credential_repository()
            .create_credentials(requests)
            .await
            .is_err()
    );
    assert!(
        credential::Entity::find()
            .filter(credential::Column::Id.is_in(requested_ids))
            .all(&setup.db)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        claim::Entity::find_by_id(setup.claim.id)
            .one(&setup.db)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn bulk_creation_keeps_batch_scopes_separate() {
    let setup = BatchSetup::new().await;
    let mut requests = Vec::new();
    let mut groups = Vec::new();
    for _ in 0..2 {
        let parent = {
            let mut updated_credential = setup.parent.clone();
            updated_credential.common_mut().id = Uuid::new_v4().into();
            updated_credential
        };
        let mut ids = Vec::new();
        for _ in 0..2 {
            let mut item = setup.item(vec![Claim {
                id: Uuid::new_v4().into(),
                ..setup.claim.clone()
            }]);
            *item.parent_mut().unwrap() = Some(parent.clone().into());
            ids.push(item.common().id);
            requests.push(item);
        }
        groups.push(ids);
        requests.push(parent);
    }
    let issuer_template = insert_credential(
        &setup.db,
        &setup.parent.common().schema.id(),
        CredentialStateEnum::Accepted,
        "OPENID4VCI_FINAL1",
        setup.parent.issuer_identifier().unwrap().id(),
        None,
        None,
        Uuid::new_v4().into(),
        credential::CredentialRole::Issuer,
    )
    .await
    .unwrap();
    let issuer_template = setup
        .repositories
        .get_credential_repository()
        .get_credential(&issuer_template.common().id)
        .await
        .unwrap();
    let issuer = {
        let mut issuer = issuer_template;
        issuer.common_mut().id = Uuid::new_v4().into();
        *issuer.claims_mut().unwrap() = vec![setup.claim.clone()].into();
        issuer
    };
    let issuer_id = issuer.common().id;
    requests.push(issuer);
    setup
        .repositories
        .get_credential_repository()
        .create_credentials(requests)
        .await
        .unwrap();
    let mut canonical_ids = HashSet::new();
    for group in groups {
        let first = setup.claim_ids(group[0]).await;
        assert_eq!(first, setup.claim_ids(group[1]).await);
        canonical_ids.extend(first);
    }
    canonical_ids.extend(setup.claim_ids(issuer_id).await);
    assert_eq!(canonical_ids.len(), 3);
    assert_eq!(
        setup.claim_ids(issuer_id).await,
        HashSet::from([setup.claim.id])
    );
}
