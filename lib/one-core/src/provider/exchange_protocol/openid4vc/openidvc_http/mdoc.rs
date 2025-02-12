use anyhow::{anyhow, bail};
use one_crypto::jwe::{Header, RemoteJwk};
use x509_parser::nom::AsBytes;

use crate::model::key::PublicKeyJwk;
use crate::provider::exchange_protocol::openid4vc::model::{
    AuthorizationEncryptedResponseAlgorithm, JwePayload, OpenID4VPClientMetadata,
    OpenID4VPClientMetadataJwkDTO,
};
use crate::provider::key_algorithm::provider::{KeyAlgorithmProvider, ParsedKey};
use crate::service::key::dto::PublicKeyJwkDTO;

pub(crate) async fn build_jwe(
    payload: JwePayload,
    verifier_metadata: OpenID4VPClientMetadata,
    mdoc_generated_nonce: &str,
    nonce: &str, // nonce from the authorization request object
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
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

    let jwk = key.jwk.clone().into();

    let ParsedKey { algorithm_id, .. } = key_algorithm_provider.parse_jwk(&jwk)?;
    let algorithm = key_algorithm_provider
        .key_algorithm_from_id(&algorithm_id)
        .ok_or(anyhow!("Algorithm not found"))?;
    let private_key = algorithm.generate_key()?;

    let key_agreement = private_key
        .key
        .key_agreement()
        .ok_or(anyhow!("Key agreement not set"))?;
    let shared_secret = key_agreement
        .private()
        .ok_or(anyhow!("Private key not set"))?
        .shared_secret(&convert_jwk(jwk)?)
        .await?;
    let local_jwk = key_agreement.public().as_jwk().map_err(|e| anyhow!(e))?;

    Ok(one_crypto::jwe::build_jwe(
        payload.as_bytes(),
        Header {
            key_id: key.key_id.to_string(),
            agreement_partyuinfo: mdoc_generated_nonce.to_owned(),
            agreement_partyvinfo: nonce.to_owned(),
        },
        shared_secret,
        local_jwk,
    )?)
}

fn convert_jwk(key: PublicKeyJwk) -> anyhow::Result<RemoteJwk> {
    match key {
        PublicKeyJwk::Ec(ec) => Ok(RemoteJwk {
            kty: "EC".to_string(),
            crv: ec.crv,
            x: ec.x,
            y: ec.y,
        }),
        PublicKeyJwk::Okp(okp) => Ok(RemoteJwk {
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

#[cfg(test)]
mod test {
    use one_crypto::jwe::RemoteJwk;

    use crate::provider::key_algorithm::es256::Es256;
    use crate::provider::key_algorithm::KeyAlgorithm;

    #[tokio::test]
    async fn test_generate_key() {
        let es256_alg = Es256 {};
        let key = es256_alg.generate_key().unwrap();

        let recipient_jwk = RemoteJwk {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: "KRJIXU-pyEcHURRRQ54jTh9PTTmBYog57rQD1uCsvwo".to_string(),
            y: Some("d31DZcRSqaxAUGBt70HB7uCZdufA6uKdL6BvAzUhbJU".to_string()),
        };

        // verify if it succeeds for given JWK
        let _shared_secret = key
            .key
            .key_agreement()
            .unwrap()
            .private()
            .unwrap()
            .shared_secret(&recipient_jwk)
            .await
            .unwrap();

        let remote_jwk = key.key.key_agreement().unwrap().public().as_jwk().unwrap();
        assert_eq!("EC", remote_jwk.kty);
        assert_eq!("P-256", remote_jwk.crv);
    }

    #[tokio::test]
    async fn test_generate_ed25519() {
        let eddsa = crate::provider::key_algorithm::eddsa::Eddsa {};
        let key = eddsa.generate_key().unwrap();

        let recipient_jwk = RemoteJwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x: "0yErlKcMCx5DG6zmgoUnnFvLBEQuuYWQSYILwV2O9TM".to_string(),
            y: None,
        };

        // verify if it succeeds for given JWK
        let _shared_secret = key
            .key
            .key_agreement()
            .unwrap()
            .private()
            .unwrap()
            .shared_secret(&recipient_jwk)
            .await
            .unwrap();

        let remote_jwk = key.key.key_agreement().unwrap().public().as_jwk().unwrap();
        assert_eq!("OKP", remote_jwk.kty);
        assert_eq!("X25519", remote_jwk.crv);
    }
}
