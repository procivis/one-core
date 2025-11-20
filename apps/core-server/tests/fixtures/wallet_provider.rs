use one_core::model::did::{KeyRole, RelatedKey};
use one_core::model::identifier::{IdentifierState, IdentifierType};
use one_core::model::organisation::{Organisation, UpdateOrganisationRequest};
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use one_core::provider::key_algorithm::model::GeneratedKey;
use one_crypto::encryption::encrypt_data;
use secrecy::SecretSlice;

use crate::fixtures::jwt::signed_jwt;
use crate::fixtures::{TestingDidParams, TestingIdentifierParams, TestingKeyParams};
use crate::utils::context::TestContext;

pub(crate) async fn create_key_possession_proof(key: &GeneratedKey, aud: String) -> String {
    signed_jwt(key, "ES256", Some(aud), None, None, (), None).await
}

pub(crate) async fn create_wallet_unit_attestation_issuer_identifier(
    context: &TestContext,
    org: &Organisation,
) {
    let issuer_key_pair = Ecdsa.generate_key().unwrap();
    let internal_storage_encryption_key = SecretSlice::from(
        hex::decode("93d9182795f0d1bec61329fc2d18c4b4c1b7e65e69e20ec30a2101a9875fff7e").unwrap(), // has to match config keyStorage.INTERNAL.params.private.encryption
    );
    let issuer_private_key_reference =
        encrypt_data(&issuer_key_pair.private, &internal_storage_encryption_key).unwrap();

    let issuer_key = context
        .db
        .keys
        .create(
            org,
            TestingKeyParams {
                key_type: Some("ECDSA".to_string()),
                storage_type: Some("INTERNAL".to_string()),
                public_key: Some(issuer_key_pair.public.clone()),
                key_reference: Some(issuer_private_key_reference),
                ..Default::default()
            },
        )
        .await;
    let issuer_did = context
        .db
        .dids
        .create(
            Some(org.to_owned()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: issuer_key.to_owned(),
                    reference: "1".to_string(),
                }]),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            org,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::Did),
                state: Some(IdentifierState::Active),
                did: Some(issuer_did),
                is_remote: Some(false),
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
            wallet_provider: Some(Some("PROCIVIS_ONE".to_string())),
            wallet_provider_issuer: Some(Some(identifier.id)),
        })
        .await;
}
