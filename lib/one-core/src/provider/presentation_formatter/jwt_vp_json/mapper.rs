use crate::error::ContextWithErrorCode;
use crate::proto::jwt::Jwt;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::presentation_formatter::jwt_vp_json::model::{VP, VerifiableCredential};
use crate::provider::presentation_formatter::model::ExtractedPresentation;

impl TryFrom<Jwt<VP>> for ExtractedPresentation {
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

        let issuer = Some(match (jwt.payload.issuer, jwt.header.jwk) {
            (None, Some(jwk)) => IdentifierDetails::Key(jwk),
            (Some(issuer), None) => IdentifierDetails::Did(
                issuer
                    .parse()
                    .map_err(DidMethodError::DidValueError)
                    .error_while("parsing issuer DID")?,
            ),
            (None, None) => {
                return Err(FormatterError::MissingIssuer);
            }
            (Some(_), Some(_)) => {
                return Err(FormatterError::CouldNotVerify(
                    "Both jwk and issuer defined".to_string(),
                ));
            }
        });

        Ok(ExtractedPresentation {
            id: jwt.payload.jwt_id,
            issued_at: jwt.payload.issued_at,
            expires_at: jwt.payload.expires_at,
            issuer,
            nonce: jwt.payload.custom.nonce,
            credentials,
        })
    }
}
