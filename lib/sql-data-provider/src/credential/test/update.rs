use one_core::model::credential::Clearable;
use sea_orm::{ActiveModelTrait, IntoActiveModel, ModelTrait};
use similar_asserts::assert_eq;

use super::*;

async fn create_variant(
    setup: &TestSetupWithCredential,
    repository: &impl CredentialRepository,
    role: CredentialRole,
    kind: CredentialType,
) -> CredentialId {
    let template = repository
        .get_credential(&setup.credential_id)
        .await
        .unwrap();
    let mut builder = CredentialBuilder {
        role,
        r#type: kind,
        claims: Default::default(),
        holder_identifier: Some(setup.identifier.clone().into()),
        ..template.into()
    };
    builder.common.id = Uuid::new_v4().into();
    if kind == CredentialType::BatchItem {
        let mut parent = builder.clone();
        parent.common.id = Uuid::new_v4().into();
        parent.r#type = CredentialType::BatchParent;
        let parent = parent.build();
        repository.create_credential(parent.clone()).await.unwrap();
        builder.parent = Some(parent.into());
    }
    repository.create_credential(builder.build()).await.unwrap()
}

async fn row(setup: &TestSetupWithCredential, id: CredentialId) -> credential::Model {
    credential::Entity::find_by_id(id)
        .one(&setup.db)
        .await
        .unwrap()
        .unwrap()
}

#[rstest]
#[case::issuer_single(
    CredentialRole::Issuer,
    CredentialType::Single,
    "issuer certificate holder key format blob key_attestation instance_attestation"
)]
#[case::issuer_parent(
    CredentialRole::Issuer,
    CredentialType::BatchParent,
    "issuer certificate key instance_attestation"
)]
#[case::issuer_item(
    CredentialRole::Issuer,
    CredentialType::BatchItem,
    "issuer certificate holder key format blob key_attestation"
)]
#[case::holder_single(
    CredentialRole::Holder,
    CredentialType::Single,
    "issuer certificate holder key format blob"
)]
#[case::holder_parent(CredentialRole::Holder, CredentialType::BatchParent, "")]
#[case::holder_item(
    CredentialRole::Holder,
    CredentialType::BatchItem,
    "issuer certificate holder key format blob consumed clear_consumed"
)]
#[case::verifier(
    CredentialRole::Verifier,
    CredentialType::Single,
    "issuer certificate holder format"
)]
#[tokio::test]
async fn patches_respect_variant_fields(
    #[case] role: CredentialRole,
    #[case] kind: CredentialType,
    #[case] allowed: &str,
) {
    use credential::Column;

    use crate::entity::certificate;

    let setup = setup_with_credential().await;
    let repository = credential_repository(setup.db.clone(), None);
    let id = create_variant(&setup, &repository, role, kind).await;
    let template = row(&setup, setup.credential_id).await;
    let certificate_id = Uuid::new_v4().into();
    certificate::ActiveModel {
        id: Set(certificate_id),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        expiry_date: Set(get_dummy_date()),
        name: Set("patch test".into()),
        chain: Set("chain".into()),
        fingerprint: Set("fingerprint".into()),
        state: Set(certificate::CertificateState::Active),
        roles: Set(None),
        identifier_id: Set(setup.identifier.id),
        key_id: Set(None),
        organisation_id: Set(setup.credential_schema.organisation.id()),
        deleted_at: Set(None),
    }
    .insert(&setup.db)
    .await
    .unwrap();
    let interaction_id = insert_interaction(
        &setup.db,
        &[],
        setup.credential_schema.organisation.id(),
        interaction::InteractionType::Issuance,
    )
    .await
    .unwrap();

    // Common patches must work for all seven variants, including both batch parents.
    let end = get_dummy_date() + Duration::days(1);
    repository
        .update_credential(
            id,
            UpdateCredentialRequest {
                interaction: Some(interaction_id),
                issuance_date: Some(get_dummy_date()),
                expires_at: Some(end),
                redirect_uri: Some(Some("https://example.com".into())),
                state: Some(CredentialStateEnum::Suspended {
                    suspend_end_date: Some(end),
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let stored = row(&setup, id).await;
    assert_eq!(stored.interaction_id, Some(interaction_id));
    assert_eq!(stored.issuance_date, Some(get_dummy_date()));
    assert_eq!(stored.expires_at, Some(end));
    assert_eq!(stored.redirect_uri.as_deref(), Some("https://example.com"));
    assert_eq!(stored.suspend_end_date, Some(end));

    let patches: Vec<(&str, UpdateCredentialRequest, Column, sea_orm::Value)> = vec![
        (
            "issuer",
            UpdateCredentialRequest {
                issuer_identifier_id: Some(setup.identifier.id),
                ..Default::default()
            },
            Column::IssuerIdentifierId,
            Some(setup.identifier.id).into(),
        ),
        (
            "certificate",
            UpdateCredentialRequest {
                issuer_certificate_id: Some(certificate_id),
                ..Default::default()
            },
            Column::IssuerCertificateId,
            Some(certificate_id).into(),
        ),
        (
            "holder",
            UpdateCredentialRequest {
                holder_identifier_id: Some(setup.identifier.id),
                ..Default::default()
            },
            Column::HolderIdentifierId,
            Some(setup.identifier.id).into(),
        ),
        (
            "key",
            UpdateCredentialRequest {
                key: template.key_id,
                ..Default::default()
            },
            Column::KeyId,
            template.key_id.into(),
        ),
        (
            "format",
            UpdateCredentialRequest {
                format: template.format,
                ..Default::default()
            },
            Column::Format,
            template.format.into(),
        ),
        (
            "blob",
            UpdateCredentialRequest {
                credential_blob_id: template.credential_blob_id,
                ..Default::default()
            },
            Column::CredentialBlobId,
            template.credential_blob_id.into(),
        ),
        (
            "key_attestation",
            UpdateCredentialRequest {
                wallet_key_attestation_blob_id: template.credential_blob_id,
                ..Default::default()
            },
            Column::WalletKeyAttestationBlobId,
            template.credential_blob_id.into(),
        ),
        (
            "instance_attestation",
            UpdateCredentialRequest {
                wallet_instance_attestation_blob_id: template.credential_blob_id,
                ..Default::default()
            },
            Column::WalletInstanceAttestationBlobId,
            template.credential_blob_id.into(),
        ),
        (
            "consumed",
            UpdateCredentialRequest {
                consumed_at: Clearable::ForceSet(Some(end)),
                ..Default::default()
            },
            Column::ConsumedAt,
            Some(end).into(),
        ),
        (
            "clear_consumed",
            UpdateCredentialRequest {
                consumed_at: Clearable::ForceSet(None),
                ..Default::default()
            },
            Column::ConsumedAt,
            Option::<time::OffsetDateTime>::None.into(),
        ),
    ];
    for (name, mut patch, column, expected) in patches {
        let before = row(&setup, id).await;
        // A rejected variant field must also prevent otherwise valid changes in the same patch.
        patch.state = Some(CredentialStateEnum::Accepted);
        patch.redirect_uri = Some(None);
        let result = repository.update_credential(id, patch).await;
        let after = row(&setup, id).await;
        if allowed.split_whitespace().any(|field| field == name) {
            result.unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(after.get(column), expected, "{name}");
            assert_eq!(after.state, credential::CredentialState::Accepted);
            assert!(after.suspend_end_date.is_none());
            assert!(after.redirect_uri.is_none());
            repository.get_credential(&id).await.unwrap();
        } else {
            assert!(
                matches!(result, Err(DataLayerError::IncorrectParameters(_))),
                "{name}: {result:?}"
            );
            assert_eq!(
                after, before,
                "rejected patch {name} must not change any column"
            );
        }
    }
}

#[rstest]
#[case::single(CredentialType::Single)]
#[case::item(CredentialType::BatchItem)]
#[tokio::test]
async fn holder_binding_is_validated_after_merging(#[case] kind: CredentialType) {
    let setup = setup_with_credential().await;
    let repository = credential_repository(setup.db.clone(), None);
    let id = create_variant(&setup, &repository, CredentialRole::Holder, kind).await;
    let mut unbound = row(&setup, id).await.into_active_model();
    let key = row(&setup, id).await.key_id.unwrap();
    unbound.holder_identifier_id = Set(None);
    unbound.key_id = Set(None);
    unbound.update(&setup.db).await.unwrap();
    let before = row(&setup, id).await;
    for patch in [
        UpdateCredentialRequest {
            holder_identifier_id: Some(setup.identifier.id),
            ..Default::default()
        },
        UpdateCredentialRequest {
            key: Some(key),
            ..Default::default()
        },
    ] {
        let error = repository.update_credential(id, patch).await.unwrap_err();
        assert!(matches!(error, DataLayerError::IncorrectParameters(_)));
        assert!(
            error
                .to_string()
                .contains("Holder identifier and key must both be present or absent")
        );
        assert_eq!(row(&setup, id).await, before);
    }
    // Neither binding field is required for an unrelated patch to an unbound credential.
    repository
        .update_credential(
            id,
            UpdateCredentialRequest {
                state: Some(CredentialStateEnum::Accepted),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    // A complete binding can be added atomically; either component can then be patched alone.
    for patch in [
        UpdateCredentialRequest {
            holder_identifier_id: Some(setup.identifier.id),
            key: Some(key),
            ..Default::default()
        },
        UpdateCredentialRequest {
            holder_identifier_id: Some(setup.identifier.id),
            ..Default::default()
        },
        UpdateCredentialRequest {
            key: Some(key),
            ..Default::default()
        },
    ] {
        repository.update_credential(id, patch).await.unwrap();
        let loaded = repository.get_credential(&id).await.unwrap();
        let binding = loaded.holder().unwrap().data.binding.as_ref().unwrap();
        assert_eq!(binding.identifier.id(), setup.identifier.id);
        assert_eq!(binding.key.id(), key);
    }
}

#[rstest]
#[case::issuer_missing_issuer(
    CredentialRole::Issuer,
    CredentialType::Single,
    credential::Column::IssuerIdentifierId
)]
#[case::issuer_missing_key(
    CredentialRole::Issuer,
    CredentialType::Single,
    credential::Column::KeyId
)]
#[case::issuer_missing_format(
    CredentialRole::Issuer,
    CredentialType::Single,
    credential::Column::Format
)]
#[case::issuer_item_missing_parent(
    CredentialRole::Issuer,
    CredentialType::BatchItem,
    credential::Column::ParentId
)]
#[case::issuer_parent_missing_key(
    CredentialRole::Issuer,
    CredentialType::BatchParent,
    credential::Column::KeyId
)]
#[case::holder_missing_issuer(
    CredentialRole::Holder,
    CredentialType::Single,
    credential::Column::IssuerIdentifierId
)]
#[case::holder_missing_format(
    CredentialRole::Holder,
    CredentialType::Single,
    credential::Column::Format
)]
#[case::holder_item_missing_parent(
    CredentialRole::Holder,
    CredentialType::BatchItem,
    credential::Column::ParentId
)]
#[case::verifier_missing_issuer(
    CredentialRole::Verifier,
    CredentialType::Single,
    credential::Column::IssuerIdentifierId
)]
#[case::verifier_missing_format(
    CredentialRole::Verifier,
    CredentialType::Single,
    credential::Column::Format
)]
#[tokio::test]
async fn resulting_model_must_have_required_fields(
    #[case] role: CredentialRole,
    #[case] kind: CredentialType,
    #[case] column: credential::Column,
) {
    let setup = setup_with_credential().await;
    let repository = credential_repository(setup.db.clone(), None);
    let id = create_variant(&setup, &repository, role, kind).await;
    let mut corrupt = row(&setup, id).await.into_active_model();
    corrupt.set(column, Option::<String>::None.into());
    corrupt.update(&setup.db).await.unwrap();
    let before = row(&setup, id).await;
    let result = repository
        .update_credential(
            id,
            UpdateCredentialRequest {
                state: Some(CredentialStateEnum::Accepted),
                ..Default::default()
            },
        )
        .await;
    assert!(matches!(
        result,
        Err(DataLayerError::IncorrectParameters(_))
    ));
    assert_eq!(row(&setup, id).await, before);
}

#[tokio::test]
async fn patch_can_repair_a_missing_required_field() {
    let setup = setup_with_credential().await;
    let repository = credential_repository(setup.db.clone(), None);
    let mut corrupt = row(&setup, setup.credential_id).await.into_active_model();
    corrupt.issuer_identifier_id = Set(None);
    corrupt.update(&setup.db).await.unwrap();
    repository
        .update_credential(
            setup.credential_id,
            UpdateCredentialRequest {
                issuer_identifier_id: Some(setup.identifier.id),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    repository
        .get_credential(&setup.credential_id)
        .await
        .unwrap();
}

#[tokio::test]
async fn patch_preserves_ignored_legacy_columns() {
    let setup = setup_with_credential().await;
    let repository = credential_repository(setup.db.clone(), None);
    // Legacy issuer parents may retain concrete credential columns that the model ignores.
    let mut legacy = row(&setup, setup.credential_id).await.into_active_model();
    legacy.r#type = Set(credential::CredentialType::BatchParent);
    legacy.update(&setup.db).await.unwrap();
    let before = row(&setup, setup.credential_id).await;
    repository
        .update_credential(
            setup.credential_id,
            UpdateCredentialRequest {
                state: Some(CredentialStateEnum::Accepted),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let after = row(&setup, setup.credential_id).await;
    assert_eq!(after.format, before.format);
    assert_eq!(after.credential_blob_id, before.credential_blob_id);
    assert_eq!(after.state, credential::CredentialState::Accepted);
    repository
        .get_credential(&setup.credential_id)
        .await
        .unwrap();
}

#[tokio::test]
async fn patch_participates_in_callers_transaction() {
    let setup = setup_with_credential().await;
    let repository = credential_repository(setup.db.clone(), None);
    let before = row(&setup, setup.credential_id).await;
    let result = TransactionManagerImpl::new(setup.db.clone())
        .tx(async {
            // A rejected nested patch must leave the surrounding transaction usable.
            let result = repository
                .update_credential(
                    setup.credential_id,
                    UpdateCredentialRequest {
                        consumed_at: Clearable::ForceSet(Some(get_dummy_date())),
                        ..Default::default()
                    },
                )
                .await;
            assert!(matches!(
                result,
                Err(DataLayerError::IncorrectParameters(_))
            ));
            repository
                .update_credential(
                    setup.credential_id,
                    UpdateCredentialRequest {
                        state: Some(CredentialStateEnum::Accepted),
                        ..Default::default()
                    },
                )
                .await?;
            assert_eq!(
                repository
                    .get_credential(&setup.credential_id)
                    .await?
                    .common()
                    .state,
                CredentialStateEnum::Accepted
            );
            Err::<(), _>(DataLayerError::IncorrectParameters(anyhow::anyhow!(
                "rollback outer transaction"
            )))
        })
        .await
        .unwrap();
    assert!(result.is_err());
    assert_eq!(row(&setup, setup.credential_id).await, before);
}

#[tokio::test]
async fn patch_missing_credential_returns_record_not_updated() {
    let setup = setup_with_credential().await;
    let repository = credential_repository(setup.db.clone(), None);
    let result = repository
        .update_credential(Uuid::new_v4().into(), UpdateCredentialRequest::default())
        .await;
    assert!(matches!(result, Err(DataLayerError::RecordNotUpdated(_))));
}
