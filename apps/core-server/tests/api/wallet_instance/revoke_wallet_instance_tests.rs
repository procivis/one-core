use one_core::model::identifier::IdentifierType;
use one_core::model::instance::InstanceStatus;
use one_core::model::managed_instance_attested_key::ManagedInstanceAttestedKey;
use one_core::model::organisation::UpdateOrganisationRequest;
use one_core::model::revocation_list::{
    RevocationListEntityId, RevocationListEntryState, RevocationListPurpose,
};
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use similar_asserts::assert_eq;
use standardized_types::jwk::PublicJwk;
use time::Duration;
use uuid::Uuid;

use crate::fixtures::TestingIdentifierParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::eddsa_testing_params;
use crate::utils::db_clients::managed_instances::TestWalletInstance;
use crate::utils::db_clients::revocation_lists::TestingRevocationListParams;

#[tokio::test]
async fn test_revoke_wallet_instance_success() {
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
        .update(
            &org.id,
            UpdateOrganisationRequest {
                wallet_provider_issuer: Some(Some(identifier.id)),
                ..Default::default()
            },
        )
        .await;

    let wallet_unit_id = Uuid::new_v4().into();
    let wallet_unit_attested_key_id = Uuid::new_v4().into();

    let revocation_list = context
        .db
        .revocation_lists
        .create(
            identifier,
            Some(TestingRevocationListParams {
                purpose: Some(RevocationListPurpose::RevocationAndSuspension),
                r#type: Some("TOKENSTATUSLIST".into()),
                ..Default::default()
            }),
        )
        .await;

    let wallet_unit = context
        .db
        .managed_instances
        .create(
            org,
            TestWalletInstance {
                id: Some(wallet_unit_id),
                status: Some(InstanceStatus::Active),
                attested_keys: Some(vec![ManagedInstanceAttestedKey {
                    id: wallet_unit_attested_key_id,
                    instance_id: wallet_unit_id,
                    created_date: one_core::clock::now_utc(),
                    last_modified: one_core::clock::now_utc(),
                    expiration_date: one_core::clock::now_utc() + Duration::days(1),
                    public_key_jwk: public_key_jwk(),
                    revocation: None,
                }]),
                ..Default::default()
            },
        )
        .await;

    let revocation_entry_id = context
        .db
        .revocation_lists
        .create_entry(
            revocation_list.id,
            RevocationListEntityId::WalletUnitAttestedKey(wallet_unit_attested_key_id),
            Some(0),
        )
        .await;

    // WHEN
    let resp = context.api.wallet_units.revoke(&wallet_unit.id).await;

    // THEN
    assert_eq!(resp.status(), 204);

    let wallet_unit = context
        .db
        .managed_instances
        .get(wallet_unit.id)
        .await
        .unwrap();
    assert_eq!(wallet_unit.status, InstanceStatus::Revoked);

    let attested_keys = wallet_unit.attested_keys.as_ref().await.unwrap();
    assert_eq!(attested_keys.len(), 1);
    let attested_key_revocation = attested_keys[0]
        .revocation
        .as_ref()
        .unwrap()
        .as_ref()
        .await
        .unwrap()
        .to_owned();
    assert_eq!(attested_key_revocation.id, revocation_entry_id);
    assert_eq!(attested_key_revocation.revocation_list_index, 0);
    assert_eq!(
        attested_key_revocation.revocation_list.id(),
        revocation_list.id
    );

    let revocation_list_entry = context
        .db
        .revocation_lists
        .get_entries(revocation_list.id)
        .await;
    assert_eq!(revocation_list_entry.len(), 1);
    assert_eq!(
        revocation_list_entry[0].state,
        RevocationListEntryState::Revoked
    );
}

fn public_key_jwk() -> PublicJwk {
    let key_pair = Ecdsa.generate_key().unwrap();
    key_pair.key.public_key_as_jwk().unwrap()
}
