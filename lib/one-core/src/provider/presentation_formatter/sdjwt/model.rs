use serde::{Deserialize, Serialize};

use crate::error::ContextWithErrorCode;
use crate::proto::jwt::Jwt;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::presentation_formatter::model::ExtractedPresentation;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Sdvp {
    pub vp: VPContent,
    pub nonce: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VPContent {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub r#type: Vec<String>,
    #[serde(rename = "_sd_jwt")]
    pub verifiable_credential: Vec<String>,
}

impl TryFrom<Jwt<Sdvp>> for ExtractedPresentation {
    type Error = FormatterError;

    fn try_from(jwt: Jwt<Sdvp>) -> Result<Self, Self::Error> {
        Ok(ExtractedPresentation {
            id: jwt.payload.jwt_id,
            issued_at: jwt.payload.issued_at,
            expires_at: jwt.payload.expires_at,
            issuer: jwt
                .payload
                .issuer
                .map(|did| did.parse())
                .transpose()
                .map_err(DidMethodError::DidValueError)
                .error_while("parsing issuer DID")?
                .map(IdentifierDetails::Did),
            nonce: jwt.payload.custom.nonce,
            credentials: jwt.payload.custom.vp.verifiable_credential,
        })
    }
}
