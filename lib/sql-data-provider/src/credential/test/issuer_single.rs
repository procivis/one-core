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
    let expected_webhook_url = "https://example.com/credential";
    *webhook_url = Some(expected_webhook_url.into());
    let expected_subscriber_information = "opaque metadata";
    *subscriber_information = Some(expected_subscriber_information.into());
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
    assert_eq!(row.webhook_url.as_deref(), Some(expected_webhook_url));
    assert_eq!(
        row.subscriber_information.as_deref(),
        Some(expected_subscriber_information)
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
        let_assert!(
            Credential::IssuerSingle {
                issuer,
                credential,
                webhook_url,
                subscriber_information,
                claims,
                ..
            } = actual
        );
        assert_eq!(
            issuer.identifier.as_ref().await.unwrap().id,
            setup.identifier.id
        );
        assert_eq!(issuer.signing_key.as_ref().await.unwrap().id, key_id);
        assert_eq!(
            actual.format().unwrap().as_ref().await.unwrap().id,
            format_id
        );
        assert_eq!(
            credential
                .holder_identifier
                .as_ref()
                .unwrap()
                .as_ref()
                .await
                .unwrap()
                .id,
            setup.identifier.id
        );
        assert_eq!(claims.as_ref().await.unwrap()[0].id, claim.id);
        assert_eq!(actual.suspend_end_date(), request.suspend_end_date());
        assert_eq!(webhook_url.as_deref(), Some(expected_webhook_url));
        assert_eq!(
            subscriber_information.as_deref(),
            Some(expected_subscriber_information)
        );
        assert_eq!(credential.credential_blob_id, blob_id);
        assert_eq!(credential.wallet_key_attestation_blob_id, blob_id);
        assert_eq!(credential.wallet_instance_attestation_blob_id, blob_id);
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
