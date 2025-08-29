use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use one_crypto::encryption::encrypt_data;
use secrecy::SecretSlice;
use similar_asserts::assert_eq;

use crate::fixtures::TestingKeyParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::wallet_unit_attestations::TestWalletUnitAttestation;

#[tokio::test]
async fn holder_refresh_wallet_unit_successfully() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;

    let holder_key_pair = Ecdsa.generate_key().unwrap();
    let internal_storage_encryption_key = SecretSlice::from(
        hex::decode("93d9182795f0d1bec61329fc2d18c4b4c1b7e65e69e20ec30a2101a9875fff7e").unwrap(), // has to match config keyStorage.INTERNAL.params.private.encryption
    );
    let holder_private_key_reference =
        encrypt_data(&holder_key_pair.private, &internal_storage_encryption_key).unwrap();

    let holder_key = context
        .db
        .keys
        .create(
            &org,
            TestingKeyParams {
                key_type: Some("ECDSA".to_string()),
                storage_type: Some("INTERNAL".to_string()),
                public_key: Some(holder_key_pair.public.clone()),
                key_reference: Some(holder_private_key_reference),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .wallet_unit_attestations
        .create(TestWalletUnitAttestation {
            organisation: Some(org.clone()),
            key: Some(holder_key.clone()),
            ..Default::default()
        })
        .await;

    // when
    let resp = context.api.wallet_units.holder_attestations(org.id).await;

    // then
    assert_eq!(resp.status(), 200);
}
