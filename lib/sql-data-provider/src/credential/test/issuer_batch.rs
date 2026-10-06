use one_core::model::credential::IssuerCredentialData;
use one_core::model::relation::Related;
use one_core::repository::DataRepository;
use sea_orm::{ActiveModelTrait, IntoActiveModel};
use similar_asserts::assert_eq;

use super::*;

fn batch_parent(single: Credential) -> (Credential, IssuerCredentialData) {
    let Credential::IssuerSingle {
        mut common,
        issuer,
        credential,
        ..
    } = single
    else {
        panic!("expected issuer single")
    };
    common.id = Uuid::new_v4().into();
    (
        Credential::IssuerBatchParent {
            common,
            issuer,
            webhook_url: Some("https://example.com/webhook".into()),
            subscriber_information: Some("shared metadata".into()),
            claims: Default::default(),
            suspend_end_date: Some(get_dummy_date() + Duration::days(1)),
        },
        credential,
    )
}

fn batch_item(parent: &Credential, credential: IssuerCredentialData) -> Credential {
    let Credential::IssuerBatchParent { common, issuer, .. } = parent else {
        panic!("expected issuer batch parent")
    };
    Credential::IssuerBatchItem {
        common: CredentialCommon {
            id: Uuid::new_v4().into(),
            ..common.clone()
        },
        issuer: issuer.clone(),
        parent: parent.clone().into(),
        credential,
    }
}

#[tokio::test]
async fn issuer_batch_round_trip_keeps_parent_and_item_data_separate() {
    let setup = setup_with_credential().await;
    let repositories = crate::DataLayer::build(setup.db.clone(), vec![]);
    let repository = repositories.get_credential_repository();
    let single = repository
        .get_credential(&setup.credential_id)
        .await
        .unwrap();
    let (mut parent, mut data) = batch_parent(single);
    let claim = Claim {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: Some("shared claim".into()),
        path: "key-0".into(),
        selectively_disclosable: false,
        schema: setup
            .credential_schema
            .claim_schemas
            .as_ref()
            .await
            .unwrap()[0]
            .clone()
            .into(),
    };
    let Credential::IssuerBatchParent { claims, .. } = &mut parent else {
        panic!("expected an issuer batch parent")
    };
    *claims = vec![claim.clone()].into();
    data.suspend_end_date = Some(get_dummy_date() + Duration::days(2));
    data.holder_identifier = Some(setup.identifier.clone().into());
    data.wallet_key_attestation_blob_id = data.credential_blob_id;
    data.wallet_instance_attestation_blob_id = data.credential_blob_id;
    let mut item = batch_item(&parent, data.clone());
    let Credential::IssuerBatchItem {
        parent: relation, ..
    } = &mut item
    else {
        unreachable!()
    };
    // A new parent can be supplied after its item, even when the relation is lazy.
    *relation = Related::new(parent.common().id, repository.clone());
    repository
        .create_credentials(vec![item.clone(), parent.clone()])
        .await
        .unwrap();
    let listed = repository
        .get_credential_list(CredentialListQuery {
            filtering: Some(
                CredentialFilterValue::CredentialIds(vec![parent.common().id, item.common().id])
                    .condition(),
            ),
            ..Default::default()
        })
        .await
        .unwrap();
    let loaded_parent = repository
        .get_credential(&parent.common().id)
        .await
        .unwrap();
    let loaded_item = repository.get_credential(&item.common().id).await.unwrap();
    for actual in listed.values.iter().chain([&loaded_parent, &loaded_item]) {
        let issuer = actual.issuer().unwrap();
        assert_eq!(
            issuer.data.identifier.as_ref().await.unwrap().id,
            setup.identifier.id
        );
        assert!(issuer.data.signing_key.as_ref().await.is_ok());
        match actual {
            Credential::IssuerBatchParent {
                webhook_url,
                subscriber_information,
                ..
            } => {
                assert_eq!(
                    actual.claims().unwrap().as_ref().await.unwrap()[0].id,
                    claim.id
                );
                assert_eq!(actual.suspend_end_date(), parent.suspend_end_date());
                assert_eq!(subscriber_information.as_deref(), Some("shared metadata"));
                assert_eq!(webhook_url.as_deref(), Some("https://example.com/webhook"));
                assert!(actual.format().is_none());
                assert!(actual.holder_identifier().is_none());
                assert!(actual.credential_blob_id().is_none());
            }
            Credential::IssuerBatchItem { credential, .. } => {
                assert_eq!(actual.parent().unwrap().id(), parent.common().id);
                assert_eq!(actual.format().unwrap().id(), data.format.id());
                assert_eq!(actual.suspend_end_date(), data.suspend_end_date);
                assert_eq!(actual.credential_blob_id(), data.credential_blob_id);
                assert_eq!(
                    credential.wallet_key_attestation_blob_id,
                    data.wallet_key_attestation_blob_id
                );
                assert_eq!(
                    credential.wallet_instance_attestation_blob_id,
                    data.wallet_instance_attestation_blob_id
                );
                assert_eq!(
                    actual.holder_identifier().as_ref().unwrap().id(),
                    setup.identifier.id
                );
                assert!(actual.claims().is_err());
            }
            _ => panic!("expected issuer batch variant"),
        }
    }
    assert!(
        repositories
            .get_claim_repository()
            .get_claims_for_credential(item.common().id)
            .await
            .unwrap()
            .is_empty()
    );
    let row = credential::Entity::find_by_id(parent.common().id)
        .one(&setup.db)
        .await
        .unwrap()
        .unwrap();
    assert!(row.format.is_none());
    assert!(row.credential_blob_id.is_none());
    assert!(row.wallet_key_attestation_blob_id.is_none());
    assert!(row.wallet_instance_attestation_blob_id.is_none());

    // Legacy parent rows may retain fields that only concrete credentials now own.
    credential::ActiveModel {
        id: Set(setup.credential_id),
        r#type: Set(credential::CredentialType::BatchParent),
        ..Default::default()
    }
    .update(&setup.db)
    .await
    .unwrap();
    let legacy_parent = repository
        .get_credential(&setup.credential_id)
        .await
        .unwrap();
    assert!(matches!(
        legacy_parent,
        Credential::IssuerBatchParent { .. }
    ));
    assert!(legacy_parent.format().is_none());
    assert!(legacy_parent.credential_blob_id().is_none());
}

#[rstest]
#[case::parent_issuer(credential::CredentialType::BatchParent, "issuer")]
#[case::parent_key(credential::CredentialType::BatchParent, "key")]
#[case::item_issuer(credential::CredentialType::BatchItem, "issuer")]
#[case::item_key(credential::CredentialType::BatchItem, "key")]
#[case::item_format(credential::CredentialType::BatchItem, "format")]
#[case::item_parent(credential::CredentialType::BatchItem, "parent")]
#[tokio::test]
async fn issuer_batch_rows_require_relations(
    #[case] kind: credential::CredentialType,
    #[case] missing: &str,
) {
    let setup = setup_with_credential().await;
    let repository = credential_repository(setup.db.clone(), None);
    let mut row = credential::Entity::find_by_id(setup.credential_id)
        .one(&setup.db)
        .await
        .unwrap()
        .unwrap()
        .into_active_model();
    row.r#type = Set(kind);
    // Use an existing ID to keep the FK valid; row mapping only validates required IDs.
    row.parent_id = Set(Some(setup.credential_id));
    match missing {
        "issuer" => row.issuer_identifier_id = Set(None),
        "key" => row.key_id = Set(None),
        "format" => row.format = Set(None),
        "parent" => row.parent_id = Set(None),
        _ => unreachable!(),
    }
    row.update(&setup.db).await.unwrap();
    assert!(matches!(
        repository.get_credential(&setup.credential_id).await,
        Err(DataLayerError::MappingError)
    ));
    assert!(matches!(
        repository
            .get_credential_list(CredentialListQuery::default())
            .await,
        Err(DataLayerError::MappingError)
    ));
}
