use crate::provider::credential_formatter::AuthenticationFn;
use crate::service::error::ServiceError;
use crate::{
    model::did::Did,
    provider::credential_formatter::{
        error::FormatterError,
        jwt::{model::JWTPayload, Jwt},
    },
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofContent {
    #[serde(rename = "aud")]
    pub audience: String,
}

pub struct OpenID4VCIProofJWTFormatter {}

impl OpenID4VCIProofJWTFormatter {
    pub async fn verify_proof(content: &str) -> Result<Jwt<ProofContent>, ServiceError> {
        // TODO: Later it will be necessary to verify with nonce
        Ok(Jwt::build_from_token(content, None).await?)
    }
    pub async fn format_proof(
        issuer_url: String,
        holder_did: &Did,
        algorithm: String,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        let content = ProofContent {
            audience: issuer_url,
        };

        let payload = JWTPayload {
            issuer: None,
            jwt_id: None,
            subject: None,
            custom: content,
            issued_at: Some(OffsetDateTime::now_utc()),
            expires_at: None,
            invalid_before: None,
            nonce: None,
        };

        let jwt = Jwt::new(
            "openid4vci-proof+jwt".to_owned(),
            algorithm,
            Some(holder_did.did.to_owned()),
            payload,
        );

        jwt.tokenize(auth_fn).await
    }
}
