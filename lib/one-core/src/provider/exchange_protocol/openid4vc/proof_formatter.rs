use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::model::did::Did;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt::model::JWTPayload;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::service::key::dto::PublicKeyJwkDTO;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofContent {
    #[serde(rename = "aud")]
    pub audience: String,
}

pub struct OpenID4VCIProofJWTFormatter {}

impl OpenID4VCIProofJWTFormatter {
    pub async fn verify_proof(content: &str) -> Result<Jwt<ProofContent>, FormatterError> {
        Jwt::build_from_token(content, None).await
    }
    pub async fn format_proof(
        issuer_url: String,
        holder_did: &Did,
        jwk: Option<PublicKeyJwkDTO>,
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
            vc_type: None,
        };

        let key_id = match jwk {
            Some(_) => None,
            None => Some(holder_did.did.to_string()),
        };

        let jwt: Jwt<ProofContent> = Jwt::new(
            "openid4vci-proof+jwt".to_owned(),
            algorithm,
            key_id,
            jwk,
            payload,
        );

        jwt.tokenize(auth_fn).await
    }
}
