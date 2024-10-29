use anyhow::{anyhow, bail};
use one_crypto::jwe::{Header, RemoteJwk};
use x509_parser::nom::AsBytes;

use crate::provider::exchange_protocol::openid4vc::model::{
    AuthorizationEncryptedResponseAlgorithm, JwePayload, OpenID4VPClientMetadata,
    OpenID4VPClientMetadataJwkDTO,
};
use crate::service::key::dto::PublicKeyJwkDTO;

pub(crate) fn build_jwe(
    payload: JwePayload,
    verifier_metadata: OpenID4VPClientMetadata,
    mdoc_generated_nonce: &str,
    nonce: &str, // nonce from the authorization request object
) -> anyhow::Result<String> {
    let payload = payload.try_into_json_base64_encode()?;

    match verifier_metadata
        .authorization_encrypted_response_alg
        .as_ref()
        .zip(verifier_metadata.authorization_encrypted_response_enc.as_ref())
    {
        None => return Err(anyhow!("Verifier must provide `authorization_encrypted_response_alg` and `authorization_encrypted_response_enc` parameters when for encrypted authorization response")),
        Some((AuthorizationEncryptedResponseAlgorithm::EcdhEs, _)) => {}
    }

    let key = key_from_verifier_metadata(&verifier_metadata)?;

    Ok(one_crypto::jwe::build_jwe(
        payload.as_bytes(),
        Header {
            key_id: key.key_id.to_string(),
            agreement_partyuinfo: mdoc_generated_nonce.to_owned(),
            agreement_partyvinfo: nonce.to_owned(),
        },
        convert_jwk(key.jwk)?,
    )?)
}

fn convert_jwk(key: PublicKeyJwkDTO) -> anyhow::Result<RemoteJwk> {
    match key {
        PublicKeyJwkDTO::Ec(ec) => Ok(RemoteJwk {
            kty: "EC".to_string(),
            crv: ec.crv,
            x: ec.x,
            y: ec.y,
        }),
        PublicKeyJwkDTO::Okp(okp) => Ok(RemoteJwk {
            kty: "OKP".to_string(),
            crv: okp.crv,
            x: okp.x,
            y: None,
        }),
        _ => {
            bail!("Unsupported key type for MDOC proof verification, must be EC or OKP")
        }
    }
}

fn key_from_verifier_metadata(
    metadata: &OpenID4VPClientMetadata,
) -> anyhow::Result<OpenID4VPClientMetadataJwkDTO> {
    metadata
        .jwks
        .iter()
        .find(|key| {
            matches!(&key.jwk,
                PublicKeyJwkDTO::Ec(key) | PublicKeyJwkDTO::Okp(key) if key.r#use.as_deref() == Some("enc")
            )
        })
        .ok_or(anyhow!(
            "verifier metadata is missing EC or OKP key with `enc=use` parameter",
        ))
        .cloned()
}
