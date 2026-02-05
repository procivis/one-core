use anyhow::anyhow;
use one_crypto::jwe::Header;
use standardized_types::jwa::EncryptionAlgorithm;
use standardized_types::jwk::{JwkUse, PublicJwk};

use crate::provider::key_algorithm::provider::{KeyAlgorithmProvider, ParsedKey};
use crate::provider::verification_protocol::openid4vp::model::{
    JwePayload, OpenID4VPClientMetadata,
};

pub(crate) async fn build_jwe(
    payload: JwePayload,
    verifier_key: PublicJwk,
    holder_nonce: &str,
    nonce: &str, // nonce from the authorization request object
    encryption_algorithm: EncryptionAlgorithm,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> anyhow::Result<String> {
    let payload = payload.try_into_json_base64_encode()?;
    let ParsedKey { algorithm_type, .. } = key_algorithm_provider.parse_jwk(&verifier_key)?;
    let algorithm = key_algorithm_provider
        .key_algorithm_from_type(algorithm_type)
        .ok_or(anyhow!("Algorithm not found"))?;

    let key_id = verifier_key
        .kid()
        .ok_or(anyhow!("Missing verifier key id"))?
        .to_string();
    let private_key = algorithm.generate_key()?;
    let key_agreement = private_key
        .key
        .key_agreement()
        .ok_or(anyhow!("Key agreement not set"))?;
    let shared_secret = key_agreement
        .private()
        .ok_or(anyhow!("Private key not set"))?
        .shared_secret(&verifier_key)
        .await?;
    let local_jwk = key_agreement.public().as_jwk().map_err(|e| anyhow!(e))?;

    Ok(one_crypto::jwe::build_jwe(
        &payload,
        Header {
            key_id,
            agreement_partyuinfo: Some(holder_nonce.to_owned()),
            agreement_partyvinfo: Some(nonce.to_owned()),
        },
        shared_secret,
        local_jwk,
        encryption_algorithm,
    )?)
}

pub(crate) fn ec_key_from_metadata(metadata: OpenID4VPClientMetadata) -> Option<PublicJwk> {
    let jwks = match metadata {
        OpenID4VPClientMetadata::Draft(metadata) => metadata.jwks,
        OpenID4VPClientMetadata::Final1_0(metadata) => metadata.jwks,
    };

    jwks.into_iter().flat_map(|jwk| jwk.keys).find(|key| {
        matches!(&key,
            PublicJwk::Ec(key) | PublicJwk::Okp(key) if key.r#use == Some(JwkUse::Encryption)
        )
    })
}
