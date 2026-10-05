use assert2::let_assert;
use one_core::repository::DataRepository;
use sea_orm::{ActiveModelTrait, IntoActiveModel};
use similar_asserts::assert_eq;

use super::*;

#[tokio::test]
async fn issuer_single_round_trip_preserves_data_and_relations() {
    let setup = setup_with_credential().await;
    let repositories = crate::DataLayer::build(setup.db.clone(), vec![]);
    let repository = repositories.get_credential_repository();
    let mut request = repository
        .get_credential(&setup.credential_id)
        .await
        .unwrap();
    request.common_mut().id = Uuid::new_v4().into();
    request.common_mut().state = CredentialStateEnum::Suspended;
    let claim = Claim {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: Some("issued value".into()),
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
    let_assert!(
        Credential::IssuerSingle {
            issuer,
            credential,
            claims,
            webhook_url,
            subscriber_information,
            ..
        } = &mut request
    );
    let key_id = issuer.signing_key.id();
    let format_id = credential.format.id();
    let blob_id = credential.credential_blob_id;
    credential.holder_identifier = Some(setup.identifier.clone().into());
    credential.wallet_key_attestation_blob_id = blob_id;
    credential.wallet_instance_attestation_blob_id = blob_id;
    *claims = vec![claim.clone()].into();
    *webhook_url = Some("https://example.com/credential".into());
    *subscriber_information = Some("opaque metadata".into());
    credential.suspend_end_date = Some(get_dummy_date() + Duration::days(1));
    let id = repository.create_credential(request.clone()).await.unwrap();

    let row = credential::Entity::find_by_id(id)
        .one(&setup.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.role, credential::CredentialRole::Issuer);
    assert_eq!(row.r#type, credential::CredentialType::Single);
    assert_eq!(row.key_id, Some(key_id));
    assert_eq!(row.format, Some(format_id));
    assert_eq!(row.issuer_identifier_id, Some(setup.identifier.id));
    assert_eq!(row.suspend_end_date, request.suspend_end_date());
    assert_eq!(row.webhook_url, *request.webhook_url());
    assert_eq!(
        row.subscriber_information,
        *request.subscriber_information()
    );
    assert_eq!(row.credential_blob_id, blob_id);
    assert_eq!(row.wallet_key_attestation_blob_id, blob_id);
    assert_eq!(row.wallet_instance_attestation_blob_id, blob_id);
    assert!(row.parent_id.is_none());
    assert!(row.consumed_at.is_none());
    assert!(row.embedded_disclosure_policy.is_none());

    let listed = repository
        .get_credential_list(CredentialListQuery {
            filtering: Some(CredentialFilterValue::CredentialIds(vec![id]).condition()),
            ..Default::default()
        })
        .await
        .unwrap();
    let loaded = repository.get_credential(&id).await.unwrap();
    for actual in listed.values.iter().chain([&loaded]) {
        assert!(matches!(actual, Credential::IssuerSingle { .. }));
        assert_eq!(actual.role(), CredentialRole::Issuer);
        assert_eq!(actual.r#type(), CredentialType::Single);
        assert_eq!(
            actual
                .issuer_identifier()
                .unwrap()
                .as_ref()
                .await
                .unwrap()
                .id,
            setup.identifier.id
        );
        assert_eq!(actual.key().unwrap().as_ref().await.unwrap().id, key_id);
        assert_eq!(
            actual.format().unwrap().as_ref().await.unwrap().id,
            format_id
        );
        assert_eq!(
            actual
                .holder_identifier()
                .as_ref()
                .unwrap()
                .as_ref()
                .await
                .unwrap()
                .id,
            setup.identifier.id
        );
        assert_eq!(
            actual.claims().unwrap().as_ref().await.unwrap()[0].id,
            claim.id
        );
        assert_eq!(actual.suspend_end_date(), request.suspend_end_date());
        assert_eq!(actual.webhook_url(), request.webhook_url());
        assert_eq!(
            actual.subscriber_information(),
            request.subscriber_information()
        );
        assert_eq!(actual.credential_blob_id(), blob_id);
        assert_eq!(actual.wallet_key_attestation_blob_id(), blob_id);
        assert_eq!(actual.wallet_instance_attestation_blob_id(), blob_id);
    }
    repository
        .update_credential(
            id,
            UpdateCredentialRequest {
                state: Some(CredentialStateEnum::Accepted),
                suspend_end_date: Clearable::ForceSet(None),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let resumed = repository.get_credential(&id).await.unwrap();
    assert_eq!(resumed.common().state, CredentialStateEnum::Accepted);
    assert!(resumed.suspend_end_date().is_none());
}

#[rstest]
#[case::missing_issuer(true, false, false)]
#[case::missing_key(false, true, false)]
#[case::missing_format(false, false, true)]
#[tokio::test]
async fn invalid_issuer_single_rows_return_mapping_errors(
    #[case] missing_issuer: bool,
    #[case] missing_key: bool,
    #[case] missing_format: bool,
) {
    let setup = setup_with_credential().await;
    let repository = credential_repository(setup.db.clone(), None);
    let mut row = credential::Entity::find_by_id(setup.credential_id)
        .one(&setup.db)
        .await
        .unwrap()
        .unwrap()
        .into_active_model();
    if missing_issuer {
        row.issuer_identifier_id = Set(None);
    }
    if missing_key {
        row.key_id = Set(None);
    }
    if missing_format {
        row.format = Set(None);
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

#[rstest]
#[case::single(CredentialType::Single)]
#[case::parent(CredentialType::BatchParent)]
#[case::item(CredentialType::BatchItem)]
#[tokio::test]
async fn generic_issuer_credentials_cannot_be_persisted(#[case] kind: CredentialType) {
    let setup = setup_with_credential().await;
    let repository = credential_repository(setup.db.clone(), None);
    // The raw fixture returns the old generic model, even though its stored relations are valid.
    let request = insert_credential(
        &setup.db,
        &setup.credential_schema.id,
        CredentialStateEnum::Created,
        "OPENID4VCI_FINAL1",
        setup.identifier.id,
        None,
        None,
        Uuid::new_v4().into(),
        credential::CredentialRole::Issuer,
    )
    .await
    .unwrap();
    let mut request = request;
    *request.type_mut().unwrap() = kind;
    request.common_mut().id = Uuid::new_v4().into();
    assert!(matches!(
        repository.create_credential(request.clone()).await,
        Err(DataLayerError::MappingError)
    ));
    assert!(
        credential::Entity::find_by_id(request.common().id)
            .one(&setup.db)
            .await
            .unwrap()
            .is_none()
    );
}
