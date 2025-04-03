use anyhow::anyhow;
use one_crypto::jwe::Header;

use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::verification_protocol::openid4vp_draft20::model::{
    AuthorizationEncryptedResponseContentEncryptionAlgorithm, JwePayload, OpenID4VPClientMetadata,
    OpenID4VPClientMetadataJwkDTO,
};
use crate::service::key::dto::PublicKeyJwkDTO;

pub(crate) async fn build_jwe(
    payload: JwePayload,
    verifier_key: OpenID4VPClientMetadataJwkDTO,
    holder_nonce: &str,
    nonce: &str, // nonce from the authorization request object
    encryption_algorithm: AuthorizationEncryptedResponseContentEncryptionAlgorithm,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> anyhow::Result<String> {
    let payload = payload.try_into_json_base64_encode()?;

    let jwk = verifier_key.jwk.clone().into();
    let parsed_key = key_algorithm_provider.parse_jwk(&jwk)?;
    let algorithm = key_algorithm_provider
        .key_algorithm_from_id(&parsed_key.algorithm_id)
        .ok_or(anyhow!("Algorithm not found"))?;
    let public_key_jwk = parsed_key
        .key
        .key_agreement()
        .ok_or(anyhow!("Key agreement not set on parsed JWK"))?
        .public()
        .as_jwk()?;

    let private_key = algorithm.generate_key()?;
    let key_agreement = private_key
        .key
        .key_agreement()
        .ok_or(anyhow!("Key agreement not set"))?;
    let shared_secret = key_agreement
        .private()
        .ok_or(anyhow!("Private key not set"))?
        .shared_secret(&public_key_jwk)
        .await?;
    let local_jwk = key_agreement.public().as_jwk().map_err(|e| anyhow!(e))?;

    Ok(one_crypto::jwe::build_jwe(
        &payload,
        Header {
            key_id: verifier_key.key_id.to_string(),
            agreement_partyuinfo: holder_nonce.to_owned(),
            agreement_partyvinfo: nonce.to_owned(),
        },
        shared_secret,
        local_jwk,
        encryption_algorithm.into(),
    )?)
}

pub(crate) fn ec_key_from_metadata(
    metadata: OpenID4VPClientMetadata,
) -> Option<OpenID4VPClientMetadataJwkDTO> {
    metadata
        .jwks.keys
        .into_iter()
        .find(|key| {
            matches!(&key.jwk,
                PublicKeyJwkDTO::Ec(key) | PublicKeyJwkDTO::Okp(key) if key.r#use.as_deref() == Some("enc")
            )
        })
}
