use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[cfg(test)]
mod test;

mod mapper;
mod model;

use crate::{
    provider::credential_formatter::{jwt::Jwt, jwt_formatter::mapper::format_vc},
    service::credential::dto::CredentialDetailResponseDTO,
};

use self::model::{VPContent, VC, VP};

use super::{
    error::FormatterError,
    jwt::{model::JWTPayload, AuthenticationFn, VerificationFn},
    model::{CredentialPresentation, CredentialStatus, DetailCredential, PresentationCredential},
    CredentialFormatter,
};

pub struct JWTFormatter {}

impl CredentialFormatter for JWTFormatter {
    fn format_credentials(
        &self,
        credential: &CredentialDetailResponseDTO,
        credential_status: Option<CredentialStatus>,
        holder_did: &str,
        algorithm: &str,
        additional_context: Vec<String>,
        additional_types: Vec<String>,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        let vc = format_vc(
            credential,
            credential_status,
            additional_context,
            additional_types,
        );

        let now = OffsetDateTime::now_utc();
        let valid_for = time::Duration::days(365 * 2);

        let payload = JWTPayload {
            issued_at: Some(now),
            expires_at: now.checked_add(valid_for),
            invalid_before: now.checked_sub(Duration::seconds(30)),
            issuer: credential.issuer_did.clone(),
            subject: Some(holder_did.to_owned()),
            jwt_id: Some(credential.id.to_string()),
            custom: vc,
            nonce: None,
        };

        let jwt = Jwt::new("JWT".to_owned(), algorithm.to_owned(), None, payload);

        jwt.tokenize(auth_fn)
    }

    fn extract_credentials(
        &self,
        token: &str,
        verify_fn: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        // Build fails if verification fails
        let jwt: Jwt<VC> = Jwt::build_from_token(token, verify_fn)?;

        Ok(jwt.into())
    }

    fn format_presentation(
        &self,
        tokens: &[PresentationCredential],
        holder_did: &str,
        algorithm: &str,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        let vp: VP = format_payload(tokens);

        let now = OffsetDateTime::now_utc();
        let valid_for = time::Duration::minutes(5);

        let payload = JWTPayload {
            issued_at: Some(now),
            expires_at: now.checked_add(valid_for),
            invalid_before: now.checked_sub(Duration::seconds(30)),
            issuer: Some(holder_did.to_owned()),
            subject: Some(holder_did.to_owned()),
            jwt_id: Some(Uuid::new_v4().to_string()),
            custom: vp,
            nonce: None,
        };

        let jwt = Jwt::new("JWT".to_owned(), algorithm.to_owned(), None, payload);

        jwt.tokenize(auth_fn)
    }

    fn extract_presentation(
        &self,
        token: &str,
        verify_fn: VerificationFn,
    ) -> Result<CredentialPresentation, FormatterError> {
        // Build fails if verification fails
        let jwt: Jwt<VP> = Jwt::build_from_token(token, verify_fn)?;

        Ok(CredentialPresentation {
            id: jwt.payload.jwt_id,
            issued_at: jwt.payload.issued_at,
            expires_at: jwt.payload.expires_at,
            issuer_did: jwt.payload.issuer,
            credentials: jwt.payload.custom.vp.verifiable_credential,
        })
    }
}

fn format_payload(credentials: &[PresentationCredential]) -> VP {
    VP {
        vp: VPContent {
            context: vec!["https://www.w3.org/2018/credentials/v1".to_owned()],
            r#type: vec!["VerifiablePresentation".to_owned()],
            verifiable_credential: credentials.iter().map(|fc| fc.token.clone()).collect(),
        },
    }
}

impl JWTFormatter {}
