use one_core::model::credential::{HolderBinding, HolderCredentialData, IssuerIdentity};
use one_core::repository::DataRepository;
use sea_orm::{ActiveModelTrait, IntoActiveModel};
use similar_asserts::assert_eq;

use super::*;

#[rstest]
#[case::bound(true)]
#[case::unbound(false)]
#[tokio::test]
async fn holder_single_round_trip_preserves_data_and_relations(#[case] bound: bool) {
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
    let key = template.issuer().unwrap().data.signing_key.clone();
    let format = template.format().unwrap().clone();
    let claim = Claim {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: Some("holder value".into()),
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
    let request = Credential::HolderSingle {
        common,
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
            embedded_disclosure_policy: Some("policy".into()),
        },
    };
    let id = repository.create_credential(request.clone()).await.unwrap();
    let row = credential::Entity::find_by_id(id)
        .one(&setup.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.role, credential::CredentialRole::Holder);
    assert_eq!(row.r#type, credential::CredentialType::Single);
    assert_eq!(row.issuer_identifier_id, Some(setup.identifier.id));
    assert_eq!(row.format, Some(format.id()));
    assert_eq!(
        row.holder_identifier_id,
        bound.then_some(setup.identifier.id)
    );
    assert_eq!(row.key_id, bound.then_some(key.id()));
    assert_eq!(row.credential_blob_id, template.credential_blob_id());
    assert_eq!(row.embedded_disclosure_policy.as_deref(), Some("policy"));
    assert!(row.parent_id.is_none());
    assert!(row.consumed_at.is_none());
    assert!(row.suspend_end_date.is_none());
    assert!(row.wallet_key_attestation_blob_id.is_none());
    assert!(row.wallet_instance_attestation_blob_id.is_none());
    assert!(row.webhook_url.is_none());
    assert!(row.subscriber_information.is_none());

    let loaded = repository.get_credential(&id).await.unwrap();
    let listed = repository
        .get_credential_list(CredentialListQuery {
            filtering: Some(CredentialFilterValue::CredentialIds(vec![id]).condition()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(listed.values.len(), 1);
    for actual in listed.values.iter().chain([&loaded]) {
        assert!(matches!(actual, Credential::HolderSingle { .. }));
        let holder = actual.holder().unwrap();
        let binding = holder.data.binding.as_ref();
        assert_eq!(
            holder.data.issuer.identifier.as_ref().await.unwrap().id,
            setup.identifier.id
        );
        assert_eq!(holder.data.format.as_ref().await.unwrap().id, format.id());
        assert_eq!(holder.data.claims.as_ref().await.unwrap()[0], claim);
        assert_eq!(
            binding.map(|binding| binding.key.id()),
            bound.then_some(key.id())
        );
        assert_eq!(
            binding.map(|binding| binding.identifier.id()),
            bound.then_some(setup.identifier.id)
        );
        if bound {
            let binding = binding.unwrap();
            assert_eq!(binding.key.as_ref().await.unwrap().id, key.id());
            assert_eq!(
                binding.identifier.as_ref().await.unwrap().id,
                setup.identifier.id
            );
        }
        assert_eq!(actual.credential_blob_id(), request.credential_blob_id());
        assert_eq!(
            holder.data.embedded_disclosure_policy,
            request.holder().unwrap().data.embedded_disclosure_policy
        );
    }
    repository
        .update_credential(
            id,
            UpdateCredentialRequest {
                state: Some(CredentialStateEnum::Revoked),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        repository.get_credential(&id).await.unwrap().common().state,
        CredentialStateEnum::Revoked
    );
}

#[rstest]
#[case::missing_issuer(true, false, false, false)]
#[case::missing_format(false, true, false, false)]
#[case::identifier_without_key(false, false, true, false)]
#[case::key_without_identifier(false, false, false, true)]
#[tokio::test]
async fn invalid_holder_single_rows_return_mapping_errors(
    #[case] missing_issuer: bool,
    #[case] missing_format: bool,
    #[case] identifier_only: bool,
    #[case] key_only: bool,
) {
    let setup = setup_with_credential().await;
    let repository = credential_repository(setup.db.clone(), None);
    let mut row = credential::Entity::find_by_id(setup.credential_id)
        .one(&setup.db)
        .await
        .unwrap()
        .unwrap()
        .into_active_model();
    row.role = Set(credential::CredentialRole::Holder);
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
