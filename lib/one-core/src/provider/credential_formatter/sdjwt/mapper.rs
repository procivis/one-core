use anyhow::Context;
use rand::seq::SliceRandom;

use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::model::Presentation;
use crate::provider::credential_formatter::sdjwt::model::{Sdvp, VcClaim};
use crate::provider::credential_formatter::vcdm::{VcdmCredential, VcdmCredentialSubject};

pub(crate) fn vc_from_credential(
    credential: VcdmCredential,
    digests: Vec<String>,
    algorithm: &str,
) -> Result<VcClaim, FormatterError> {
    let digests: Vec<String> = {
        let mut digests = digests;
        let mut rng = rand::thread_rng();
        digests.shuffle(&mut rng);
        digests
    };

    let mut credential = credential;
    credential.credential_subject = vec![VcdmCredentialSubject {
        id: None,
        claims: indexmap::indexmap! {
          "_sd".to_string() => serde_json::json!(digests)
        },
    }];

    Ok(VcClaim {
        digests: vec![],
        vc: credential.into(),
        hash_alg: Some(algorithm.to_owned()),
    })
}

impl TryFrom<Jwt<Sdvp>> for Presentation {
    type Error = anyhow::Error;

    fn try_from(jwt: Jwt<Sdvp>) -> Result<Self, Self::Error> {
        Ok(Presentation {
            id: jwt.payload.jwt_id,
            issued_at: jwt.payload.issued_at,
            expires_at: jwt.payload.expires_at,
            issuer_did: jwt
                .payload
                .issuer
                .map(|did| did.parse().context("did parsing error"))
                .transpose()
                .map_err(|e| FormatterError::Failed(e.to_string()))?,
            nonce: jwt.payload.custom.nonce,
            credentials: jwt.payload.custom.vp.verifiable_credential,
        })
    }
}
