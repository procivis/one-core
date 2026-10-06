use assert2::let_assert;
use one_core::model::credential::{HolderBinding, HolderCredentialData, IssuerIdentity};
use one_core::repository::DataRepository;
use sea_orm::{ActiveModelTrait, ColumnTrait, IntoActiveModel, QueryFilter};
use similar_asserts::assert_eq;

use super::*;

#[rstest]
#[case::bound(true)]
#[case::unbound(false)]
#[tokio::test]
async fn holder_batch_round_trip_keeps_parent_and_item_data_separate(#[case] bound: bool) {
    let setup = setup_with_credential().await;
    let repositories = crate::DataLayer::build(setup.db.clone(), vec![]);
    let repository = repositories.get_credential_repository();
    let template = repository
        .get_credential(&setup.credential_id)
        .await
        .unwrap();
    let mut common = template.common().clone();
    common.id = Uuid::new_v4().into();
    common.state = CredentialStateEnum::Accepted;
    let parent = Credential::HolderBatchParent { common };
    let parent_id = parent.common().id;
    let claim = Claim {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: Some("holder batch value".into()),
        path: "key-0".into(),
        selectively_disclosable: true,
        schema: setup
            .credential_schema
            .claim_schemas
            .as_ref()
            .await
            .unwrap()[0]
            .clone()
            .into(),
    };
    let key = template.issuer().unwrap().data.signing_key.clone();
    let format = template.format().unwrap().clone();
    let mut common = parent.common().clone();
    common.id = Uuid::new_v4().into();
    common.interaction = None;
    let item = Credential::HolderBatchItem {
        common,
        parent: parent.clone().into(),
        consumed_at: Some(get_dummy_date()),
        credential: HolderCredentialData {
            issuer: IssuerIdentity {
                identifier: setup.identifier.clone().into(),
                certificate: None,
            },
            format: format.clone(),
            claims: vec![claim.clone()].into(),
            binding: bound.then(|| HolderBinding {
                identifier: setup.identifier.clone().into(),
                key: key.clone(),
            }),
            credential_blob_id: template.credential_blob_id(),
            embedded_disclosure_policy: Some("batch policy".into()),
        },
    };
    let item_id = item.common().id;
    // The repository must order inserts even when an item precedes its parent.
    repository
        .create_credentials(vec![item.clone(), parent.clone()])
        .await
        .unwrap();
    let row = credential::Entity::find_by_id(parent_id)
        .one(&setup.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.role, credential::CredentialRole::Holder);
    assert_eq!(row.r#type, credential::CredentialType::BatchParent);
    assert!(row.issuer_identifier_id.is_none());
    assert!(row.issuer_certificate_id.is_none());
    assert!(row.holder_identifier_id.is_none());
    assert!(row.key_id.is_none());
    assert!(row.format.is_none());
    assert!(row.parent_id.is_none());
    assert!(row.credential_blob_id.is_none());
    assert!(row.embedded_disclosure_policy.is_none());
    assert!(row.consumed_at.is_none());
    assert!(row.suspend_end_date.is_none());
    assert!(row.wallet_key_attestation_blob_id.is_none());
    assert!(row.wallet_instance_attestation_blob_id.is_none());
    assert!(row.webhook_url.is_none());
    assert!(row.subscriber_information.is_none());
    assert_eq!(
        crate::entity::credential_claim::Entity::find()
            .filter(crate::entity::credential_claim::Column::CredentialId.eq(parent_id))
            .all(&setup.db)
            .await
            .unwrap()
            .len(),
        0
    );

    let loaded_parent = repository.get_credential(&parent_id).await.unwrap();
    assert!(matches!(
        loaded_parent,
        Credential::HolderBatchParent { .. }
    ));
    assert!(loaded_parent.claims().is_err());
    assert_eq!(
        loaded_parent.common().schema.as_ref().await.unwrap().id,
        setup.credential_schema.id
    );

    let loaded_item = repository.get_credential(&item_id).await.unwrap();
    let listed = repository
        .get_credential_list(CredentialListQuery {
            filtering: Some(
                CredentialFilterValue::CredentialIds(vec![parent_id, item_id]).condition(),
            ),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(listed.values.len(), 2);
    assert!(
        listed
            .values
            .iter()
            .any(|value| matches!(value, Credential::HolderBatchParent { .. }))
    );
    for actual in listed
        .values
        .iter()
        .filter(|value| value.common().id == item_id)
        .chain([&loaded_item])
    {
        let_assert!(Credential::HolderBatchItem { consumed_at, .. } = actual);
        let holder = actual.holder().unwrap();
        let binding = holder.data.binding.as_ref();
        assert_eq!(
            actual.parent().unwrap().as_ref().await.unwrap().common().id,
            parent_id
        );
        assert_eq!(holder.data.claims.as_ref().await.unwrap()[0], claim);
        assert_eq!(
            holder.data.issuer.identifier.as_ref().await.unwrap().id,
            setup.identifier.id
        );
        assert_eq!(holder.data.format.as_ref().await.unwrap().id, format.id());
        assert_eq!(
            binding.map(|binding| binding.key.id()),
            bound.then_some(key.id())
        );
        assert_eq!(
            binding.map(|binding| binding.identifier.id()),
            bound.then_some(setup.identifier.id)
        );
        assert_eq!(actual.credential_blob_id(), item.credential_blob_id());
        assert_eq!(
            holder.data.embedded_disclosure_policy.as_deref(),
            Some("batch policy")
        );
        assert_eq!(*consumed_at, Some(get_dummy_date()));
    }
}

#[rstest]
#[case::missing_parent(true, false, false, false, false)]
#[case::missing_issuer(false, true, false, false, false)]
#[case::missing_format(false, false, true, false, false)]
#[case::identifier_without_key(false, false, false, true, false)]
#[case::key_without_identifier(false, false, false, false, true)]
#[tokio::test]
async fn invalid_holder_batch_item_rows_return_mapping_errors(
    #[case] missing_parent: bool,
    #[case] missing_issuer: bool,
    #[case] missing_format: bool,
    #[case] identifier_only: bool,
    #[case] key_only: bool,
) {
    let setup = setup_with_credential().await;
    let repositories = crate::DataLayer::build(setup.db.clone(), vec![]);
    let repository = repositories.get_credential_repository();
    let template = repository
        .get_credential(&setup.credential_id)
        .await
        .unwrap();
    let mut common = template.common().clone();
    common.id = Uuid::new_v4().into();
    let parent_id = repository
        .create_credential(Credential::HolderBatchParent { common })
        .await
        .unwrap();
    let mut row = credential::Entity::find_by_id(setup.credential_id)
        .one(&setup.db)
        .await
        .unwrap()
        .unwrap()
        .into_active_model();
    row.role = Set(credential::CredentialRole::Holder);
    row.r#type = Set(credential::CredentialType::BatchItem);
    row.parent_id = Set((!missing_parent).then_some(parent_id));
    if missing_issuer {
        row.issuer_identifier_id = Set(None);
    }
    if missing_format {
        row.format = Set(None);
    }
    if !key_only {
        row.key_id = Set(None);
    }
    row.holder_identifier_id = Set(identifier_only.then_some(setup.identifier.id));
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
