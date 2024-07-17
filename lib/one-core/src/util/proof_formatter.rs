use crate::model::did::Did;
use crate::service::error::ServiceError;
use one_providers::credential_formatter::{
    error::FormatterError,
    imp::jwt::{model::JWTPayload, Jwt},
    model::AuthenticationFn,
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
            Some(holder_did.did.to_string()),
            payload,
        );

        jwt.tokenize(auth_fn).await
    }
}
