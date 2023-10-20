use self::model::{CredentialSubject, VCContent, VC};
use super::{
    error::FormatterError,
    jwt::{model::JWTPayload, AuthenticationFn},
};
use crate::{model::did::Did, provider::credential_formatter::jwt::Jwt};
use time::OffsetDateTime;

mod model;

pub struct StatusList2021JWTFormatter {}

impl StatusList2021JWTFormatter {
    pub fn format_status_list(
        revocation_list_url: String,
        issuer_did: &Did,
        encoded_list: String,
        algorithm: String,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        let subject = format!("{}#list", revocation_list_url);
        let vc = VC {
            vc: VCContent {
                context: vec![
                    "https://www.w3.org/2018/credentials/v1".to_string(),
                    "https://w3id.org/vc/status-list/2021/v1".to_string(),
                ],
                id: revocation_list_url.to_owned(),
                r#type: vec![
                    "VerifiableCredential".to_string(),
                    "StatusList2021Credential".to_string(),
                ],
                issuer: issuer_did.did.to_owned(),
                issued: OffsetDateTime::now_utc(),
                credential_subject: CredentialSubject {
                    id: subject.to_owned(),
                    r#type: "StatusList2021".to_string(),
                    status_purpose: "revocation".to_string(),
                    encoded_list,
                },
            },
        };

        let payload = JWTPayload {
            issuer: Some(issuer_did.did.to_owned()),
            jwt_id: Some(revocation_list_url),
            subject: Some(subject),
            custom: vc,
            issued_at: None,
            expires_at: None,
            invalid_before: None,
            nonce: None,
        };

        let jwt = Jwt::new("JWT".to_owned(), algorithm, None, payload);

        jwt.tokenize(auth_fn)
    }
}
