use one_core::model::identifier::IdentifierType;
use one_core::model::instance::InstanceStatus;
use one_core::model::managed_instance_attestation::ManagedInstanceAttestation;
use one_core::model::organisation::UpdateOrganisationRequest;
use one_core::model::revocation_list::{
    RevocationListEntityId, RevocationListEntryState, RevocationListPurpose,
};
use one_core::model::wallet_attestation::AttestationType;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use shared_types::{ManagedInstanceAttestationId, ManagedInstanceId};
use similar_asserts::assert_eq;
use time::Duration;

use crate::fixtures::TestingIdentifierParams;
use crate::fixtures::wallet_provider::{
    create_key_possession_proof, create_wallet_unit_attestation_issuer_identifier,
};
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

    let wallet_unit_id = ManagedInstanceId::new();
    let wallet_unit_attested_key_id = ManagedInstanceAttestationId::new();

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
                attestations: Some(vec![ManagedInstanceAttestation {
                    id: wallet_unit_attested_key_id,
                    instance_id: wallet_unit_id,
                    created_date: one_core::clock::now_utc(),
                    last_modified: one_core::clock::now_utc(),
                    expiration_date: one_core::clock::now_utc() + Duration::days(1),
                    r#type: AttestationType::KeyAttestation,
                    attestation_content_hash: None,
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
            RevocationListEntityId::KeyAttestation(wallet_unit_attested_key_id),
            Some(0),
        )
        .await;

    // WHEN
    let resp = context.api.managed_instances.revoke(&wallet_unit.id).await;

    // THEN
    assert_eq!(resp.status(), 204);

    let wallet_unit = context
        .db
        .managed_instances
        .get(wallet_unit.id)
        .await
        .unwrap();
    assert_eq!(wallet_unit.status, InstanceStatus::Revoked);

    let attestations = wallet_unit.attestations.as_ref().await.unwrap();
    assert_eq!(attestations.len(), 1);
    let attested_key_revocation = attestations[0]
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

/// Issuing attestations to a wallet unit while it is revoked must neither deadlock nor leave
/// unrevoked attestations behind:
/// - issuance locks the wallet unit row and then adds status list entries (a foreign key lock on
///   the list), so the revocation must lock the wallet unit row before any status list as well
/// - an issuance that waited for the revocation must see the revoked status and issue nothing
#[tokio::test]
async fn test_concurrent_attestation_issuance_and_revocation_do_not_deadlock() {
    const WALLET_UNIT_COUNT: usize = 5;

    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    create_wallet_unit_attestation_issuer_identifier(&context, &org).await;
    let base_url = context.config.app.core_base_url.clone();

    let mut wallet_units = vec![];
    for _ in 0..WALLET_UNIT_COUNT {
        let holder_key_pair = Ecdsa.generate_key().unwrap();
        let wallet_unit = context
            .db
            .managed_instances
            .create(
                org.clone(),
                TestWalletInstance {
                    public_key: Some(holder_key_pair.key.public_key_as_jwk().unwrap()),
                    ..Default::default()
                },
            )
            .await;

        // a first attestation puts the wallet unit on the issuer's status list
        let resp = context
            .api
            .wallet_provider
            .issue_attestation(
                wallet_unit.id,
                &create_key_possession_proof(&holder_key_pair, base_url.clone()).await,
                vec![
                    create_key_possession_proof(&Ecdsa.generate_key().unwrap(), base_url.clone())
                        .await,
                ],
                vec![],
            )
            .await;
        assert_eq!(resp.status(), 200);

        wallet_units.push((wallet_unit.id, holder_key_pair));
    }

    let mut requests = vec![];
    for (wallet_unit_id, holder_key_pair) in &wallet_units {
        let auth_pop = create_key_possession_proof(holder_key_pair, base_url.clone()).await;
        let wia_pop =
            create_key_possession_proof(&Ecdsa.generate_key().unwrap(), base_url.clone()).await;
        requests.push((*wallet_unit_id, auth_pop, wia_pop));
    }

    // WHEN
    let (issuances, revocations) = futures::future::join(
        futures::future::join_all(requests.iter().map(|(id, auth_pop, wia_pop)| {
            context.api.wallet_provider.issue_attestation(
                *id,
                auth_pop,
                vec![wia_pop.to_owned()],
                vec![],
            )
        })),
        futures::future::join_all(
            wallet_units
                .iter()
                .map(|(id, _)| context.api.managed_instances.revoke(id)),
        ),
    )
    .await;

    // THEN
    for response in revocations {
        assert_eq!(response.status(), 204);
    }
    for response in issuances {
        // issued before the revocation, or rejected because the wallet unit is revoked
        if response.status() != 200 {
            assert_eq!(response.status(), 400);
            assert_eq!(response.json_value().await["code"], "BR_0261");
        }
    }

    // every attestation, including those issued concurrently, is revoked
    for (wallet_unit_id, _) in &wallet_units {
        let wallet_unit = context
            .db
            .managed_instances
            .get(*wallet_unit_id)
            .await
            .unwrap();
        assert_eq!(wallet_unit.status, InstanceStatus::Revoked);

        for attestation in wallet_unit.attestations.as_ref().await.unwrap().iter() {
            let revocation = attestation
                .revocation
                .as_ref()
                .unwrap()
                .as_ref()
                .await
                .unwrap()
                .to_owned();
            let entry = context
                .db
                .revocation_lists
                .get_entries(revocation.revocation_list.id())
                .await
                .into_iter()
                .find(|entry| entry.index == Some(revocation.revocation_list_index))
                .unwrap();
            assert_eq!(
                entry.state,
                RevocationListEntryState::Revoked,
                "attestation {} of wallet unit {wallet_unit_id} is not revoked",
                attestation.id
            );
        }
    }
}
