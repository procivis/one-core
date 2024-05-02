use anyhow::{anyhow, bail, Context};
use josekit::{
    jwe::{
        alg::ecdh_es::{EcdhEsJweAlgorithm, EcdhEsJweEncrypter},
        JweHeader,
    },
    jwk::Jwk,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::provider::{did_method::dto::PublicKeyJwkDTO, key_algorithm::eddsa::JwkEddsaExt};

use super::{
    dto::{
        AuthorizationEncryptedResponseAlgorithm,
        AuthorizationEncryptedResponseContentEncryptionAlgorithm, OpenID4VPClientMetadata,
        OpenID4VPClientMetadataJwkDTO,
    },
    model::JwePayload,
};

pub(crate) fn build_jwe(
    payload: JwePayload,
    client_metadata: OpenID4VPClientMetadata,
    mdoc_generated_nonce: &str,
    nonce: &str, // nonce from the authorization request object
) -> anyhow::Result<String> {
    let payload = payload.try_into_json_base64_encode()?;

    let (header, encrypter) = build_ecdh_es_encrypter(client_metadata, mdoc_generated_nonce, nonce)
        .context("Failed to build ecdh-es encrypter")?;

    josekit::jwe::serialize_compact(payload.as_bytes(), &header, &encrypter)
        .context("JWE serialization failed")
}

pub(crate) fn generate_nonce() -> String {
    let mut rng = ChaCha20Rng::from_entropy();

    rng.gen::<[u8; 32]>().map(char::from).into_iter().collect()
}

fn build_ecdh_es_encrypter(
    verifier_metadata: OpenID4VPClientMetadata,
    mdoc_generated_nonce: &str,
    nonce: &str,
) -> anyhow::Result<(JweHeader, EcdhEsJweEncrypter)> {
    match verifier_metadata
        .authorization_encrypted_response_alg
        .as_ref()
        .zip(verifier_metadata.authorization_encrypted_response_enc.as_ref())
    {
        None => return Err(anyhow!("Verifier must provide `authorization_encrypted_response_alg` and `authorization_encrypted_response_enc` parameters when for encrypted authorization response")),
        Some((AuthorizationEncryptedResponseAlgorithm::EcdhEs, AuthorizationEncryptedResponseContentEncryptionAlgorithm::A256GCM)) => {}
    }

    let key = key_from_verifier_metadata(verifier_metadata)?;

    let mut header = JweHeader::new();
    header.set_key_id(key.key_id.to_string());
    header.set_content_encryption(
        AuthorizationEncryptedResponseContentEncryptionAlgorithm::A256GCM.to_string(),
    );
    // apu param
    header.set_agreement_partyuinfo(mdoc_generated_nonce);
    // apv param
    header.set_agreement_partyvinfo(nonce);

    let jwk = build_jwk(key)?;

    // the encrypter will set the correct "alg" and "epk" parameters when constructing the JWE
    let encrypter = EcdhEsJweAlgorithm::EcdhEs.encrypter_from_jwk(&jwk)?;

    Ok((header, encrypter))
}

fn build_jwk(key: OpenID4VPClientMetadataJwkDTO) -> anyhow::Result<Jwk> {
    match key.jwk {
        PublicKeyJwkDTO::Rsa(_) | PublicKeyJwkDTO::Oct(_) | PublicKeyJwkDTO::Mlwe(_) => {
            bail!("Unsupported key type for MDOC proof verification, must be EC or OKP")
        }
        PublicKeyJwkDTO::Ec(ec) => {
            let mut jwk = Jwk::new("EC");
            jwk.set_curve(ec.crv);
            jwk.set_parameter("x", Some(ec.x.into()))?;
            jwk.set_parameter("y", ec.y.map(Into::into))?;

            Ok(jwk)
        }
        PublicKeyJwkDTO::Okp(okp) => {
            let mut jwk = Jwk::new("OKP");
            jwk.set_curve(okp.crv);
            jwk.set_parameter("x", Some(okp.x.into()))?;

            if let Some("Ed25519") = jwk.curve() {
                jwk = jwk
                    .into_x25519()
                    .context("Cannot convert Ed25519 into X25519")?;
            }

            Ok(jwk)
        }
    }
}

fn key_from_verifier_metadata(
    metadata: OpenID4VPClientMetadata,
) -> anyhow::Result<OpenID4VPClientMetadataJwkDTO> {
    metadata
        .jwks
        .into_iter()
        .find(|key| {
            matches!(&key.jwk,
                PublicKeyJwkDTO::Ec(key) | PublicKeyJwkDTO::Okp(key) if key.r#use.as_deref() == Some("enc")
            )
        })
        .ok_or(anyhow!(
            "verifier metadata is missing EC or OKP key with `enc=use` parameter",
        ))
}
