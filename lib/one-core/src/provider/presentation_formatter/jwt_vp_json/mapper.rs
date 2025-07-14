use anyhow::Context;

use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{IdentifierDetails, Presentation};
use crate::provider::presentation_formatter::jwt_vp_json::model::{VP, VerifiableCredential};
use crate::util::jwt::Jwt;

impl TryFrom<Jwt<VP>> for Presentation {
    type Error = FormatterError;

    fn try_from(jwt: Jwt<VP>) -> Result<Self, Self::Error> {
        let credentials = jwt
            .payload
            .custom
            .vp
            .verifiable_credential
            .into_iter()
            .map(|vc| match vc {
                VerifiableCredential::Enveloped(enveloped) => {
                    let (_type, token) = enveloped.id.split_once(',').ok_or(
                        FormatterError::CouldNotExtractPresentation(
                            "Enveloped VP id missing delimiter".to_string(),
                        ),
                    )?;
                    Ok(token.to_string())
                }
                VerifiableCredential::Token(token) => Ok(token),
            })
            .collect::<Result<Vec<_>, FormatterError>>()?;

        Ok(Presentation {
            id: jwt.payload.jwt_id,
            issued_at: jwt.payload.issued_at,
            expires_at: jwt.payload.expires_at,
            issuer: jwt
                .payload
                .issuer
                .map(|did| did.parse().context("did parsing error"))
                .transpose()
                .map_err(|e| Self::Error::Failed(e.to_string()))?
                .map(IdentifierDetails::Did),
            nonce: jwt.payload.custom.nonce,
            credentials,
        })
    }
}
