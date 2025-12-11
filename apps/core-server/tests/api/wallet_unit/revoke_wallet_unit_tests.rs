use one_core::model::identifier::IdentifierType;
use one_core::model::key::PublicKeyJwk;
use one_core::model::organisation::UpdateOrganisationRequest;
use one_core::model::revocation_list::{
    RevocationListEntityId, RevocationListEntryStatus, RevocationListPurpose,
    RevocationListRelations, StatusListType,
};
use one_core::model::wallet_unit::{WalletUnitRelations, WalletUnitStatus};
use one_core::model::wallet_unit_attested_key::{
    WalletUnitAttestedKey, WalletUnitAttestedKeyRelations, WalletUnitAttestedKeyRevocationInfo,
};
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::fixtures::TestingIdentifierParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::eddsa_testing_params;
use crate::utils::db_clients::wallet_units::TestWalletUnit;

#[tokio::test]
async fn test_revoke_wallet_unit_success() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    let local_key = context.db.keys.create(&org, eddsa_testing_params()).await;

    let identifier = context
        .db
        .identifiers
        .create(
            &org,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::Key),
                key: Some(local_key),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .organisations
        .update(UpdateOrganisationRequest {
            id: org.id,
            name: None,
            deactivate: None,
            wallet_provider: None,
            wallet_provider_issuer: Some(Some(identifier.id)),
        })
        .await;

    let wallet_unit_id = Uuid::new_v4().into();
    let wallet_unit_attested_key_id = Uuid::new_v4().into();

    let revocation_list = context
        .db
        .revocation_lists
        .create(
            identifier,
            RevocationListPurpose::RevocationAndSuspension,
            None,
            Some(StatusListType::TokenStatusList),
        )
        .await;

    let wallet_unit = context
        .db
        .wallet_units
        .create(
            org,
            TestWalletUnit {
                id: Some(wallet_unit_id),
                status: Some(WalletUnitStatus::Active),
                attested_keys: Some(vec![WalletUnitAttestedKey {
                    id: wallet_unit_attested_key_id,
                    wallet_unit_id,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    expiration_date: OffsetDateTime::now_utc() + Duration::days(1),
                    public_key_jwk: public_key_jwk(),
                    revocation: Some(WalletUnitAttestedKeyRevocationInfo {
                        revocation_list: revocation_list.clone(),
                        revocation_list_index: 0,
                    }),
                }]),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .revocation_lists
        .create_entry(
            revocation_list.id,
            RevocationListEntityId::WalletUnitAttestedKey(wallet_unit_attested_key_id),
            0,
        )
        .await;

    // WHEN
    let resp = context.api.wallet_units.revoke(&wallet_unit.id).await;

    // THEN
    assert_eq!(resp.status(), 204);

    let wallet_unit = context
        .db
        .wallet_units
        .get(
            wallet_unit.id,
            &WalletUnitRelations {
                organisation: None,
                attested_keys: Some(WalletUnitAttestedKeyRelations {
                    revocation: Some(RevocationListRelations::default()),
                }),
            },
        )
        .await
        .unwrap();
    assert_eq!(wallet_unit.status, WalletUnitStatus::Revoked);

    let revocation_list_entry = context
        .db
        .revocation_lists
        .get_entries(revocation_list.id)
        .await;
    assert_eq!(revocation_list_entry.len(), 1);
    assert_eq!(
        revocation_list_entry[0].status,
        RevocationListEntryStatus::Revoked
    );
}

fn public_key_jwk() -> PublicKeyJwk {
    let key_pair = Ecdsa.generate_key().unwrap();
    key_pair.key.public_key_as_jwk().unwrap()
}
