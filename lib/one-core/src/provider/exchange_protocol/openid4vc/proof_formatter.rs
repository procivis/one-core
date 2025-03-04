use time::OffsetDateTime;

use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt::model::JWTPayload;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::service::key::dto::PublicKeyJwkDTO;

pub struct OpenID4VCIProofJWTFormatter {}

impl OpenID4VCIProofJWTFormatter {
    pub async fn verify_proof(content: &str) -> Result<Jwt<()>, FormatterError> {
        Jwt::build_from_token(content, None).await
    }

    pub async fn format_proof(
        issuer_url: String,
        holder_key_id: Option<String>,
        jwk: Option<PublicKeyJwkDTO>,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        let payload = JWTPayload {
            issuer: None,
            jwt_id: None,
            subject: None,
            audience: Some(vec![issuer_url]),
            custom: (),
            issued_at: Some(OffsetDateTime::now_utc()),
            expires_at: None,
            invalid_before: None,
            vc_type: None,
            proof_of_possession_key: None,
        };

        let key_id = match jwk {
            Some(_) => None,
            None => holder_key_id,
        };

        let jwt = Jwt::new(
            "openid4vci-proof+jwt".to_owned(),
            auth_fn.jose_alg().ok_or(FormatterError::CouldNotFormat(
                "Invalid key algorithm".to_string(),
            ))?,
            key_id,
            jwk,
            payload,
        );

        jwt.tokenize(Some(auth_fn)).await
    }
}
