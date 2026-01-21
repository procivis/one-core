use serde_json::json;
use time::OffsetDateTime;
use url::Url;

use super::JWTFormatter;
use super::model::{TokenStatusListContent, TokenStatusListSubject, VcClaim};
use crate::mapper::x509::pem_chain_into_x5c;
use crate::model::certificate::CertificateState;
use crate::model::identifier::{Identifier, IdentifierType};
use crate::proto::jwt::model::JWTPayload;
use crate::proto::jwt::{Jwt, JwtPublicKeyInfo};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{AuthenticationFn, Issuer};
use crate::provider::credential_formatter::vcdm::{VcdmCredential, VcdmCredentialSubject};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::provider::revocation::token_status_list::util::PREFERRED_ENTRY_SIZE;

impl JWTFormatter {
    pub(super) async fn format_bitstring_status_list(
        &self,
        revocation_list_url: String,
        issuer_identifier: &Identifier,
        encoded_list: String,
        jose_alg: String,
        auth_fn: AuthenticationFn,
        status_purpose: StatusPurpose,
    ) -> Result<String, FormatterError> {
        if issuer_identifier.r#type != IdentifierType::Did {
            return Err(FormatterError::Failed(
                "Unsupported identifier type".to_string(),
            ));
        }

        let issuer_did = issuer_identifier
            .did
            .as_ref()
            .ok_or(FormatterError::Failed(
                "Identifier of type DID has no related DID".to_string(),
            ))?;

        let issuer = Issuer::Url(
            issuer_identifier
                .as_url()
                .ok_or(FormatterError::Failed("Invalid issuer DID".to_string()))?,
        );

        let revocation_list_url: Url = revocation_list_url
            .parse()
            .map_err(|_| FormatterError::Failed("Invalid revocation list url".to_string()))?;

        let credential_id = revocation_list_url.clone();

        let credential_subject_id = {
            let mut url = revocation_list_url;
            url.set_fragment(Some("list"));
            url
        };

        let credential_subject = VcdmCredentialSubject::new([
            ("type", json!("BitstringStatusList")),
            ("statusPurpose", json!(status_purpose)),
            ("encodedList", json!(encoded_list)),
        ])?
        .with_id(credential_subject_id.clone());

        let vc = VcdmCredential::new_v2(issuer, credential_subject)
            .add_type("BitstringStatusListCredential".to_string())
            .with_id(credential_id);

        let vc_claim = VcClaim { vc: vc.into() };

        let payload = JWTPayload {
            issuer: Some(issuer_did.did.to_string()),
            subject: Some(credential_subject_id.to_string()),
            custom: vc_claim,
            issued_at: Some(OffsetDateTime::now_utc()),
            ..Default::default()
        };

        let jwt = Jwt::new("JWT".to_owned(), jose_alg, None, None, payload);

        jwt.tokenize(Some(&*auth_fn)).await
    }

    pub(super) async fn format_token_status_list(
        &self,
        revocation_list_url: String,
        issuer_identifier: &Identifier,
        encoded_list: String,
        jose_alg: String,
        auth_fn: AuthenticationFn,
        key_alg_provider: &dyn KeyAlgorithmProvider,
    ) -> Result<String, FormatterError> {
        let (issuer, public_key_info) = match issuer_identifier.r#type {
            IdentifierType::Did => {
                let issuer_did = issuer_identifier
                    .did
                    .as_ref()
                    .ok_or(FormatterError::Failed(
                        "Identifier of type DID has no related DID".to_string(),
                    ))?;

                (Some(issuer_did.did.to_string()), None)
            }
            IdentifierType::Certificate => {
                let certificates =
                    issuer_identifier
                        .certificates
                        .as_ref()
                        .ok_or(FormatterError::Failed(
                            "Identifier of type Certificate has no related Certificates"
                                .to_string(),
                        ))?;

                let certificate = certificates
                    .iter()
                    .filter(|c| c.state == CertificateState::Active)
                    .find(|c| {
                        c.key
                            .as_ref()
                            .is_some_and(|key| key.public_key == auth_fn.get_public_key())
                    })
                    .ok_or(FormatterError::Failed(
                        "Valid certificate not found".to_string(),
                    ))?;

                (
                    None,
                    Some(JwtPublicKeyInfo::X5c(
                        pem_chain_into_x5c(&certificate.chain)
                            .map_err(|e| FormatterError::Failed(e.to_string()))?,
                    )),
                )
            }
            IdentifierType::Key => {
                let key = issuer_identifier
                    .key
                    .as_ref()
                    .ok_or(FormatterError::Failed(
                        "Identifier of type Key missing related key".to_string(),
                    ))?;

                let key_alg = key.key_algorithm_type().ok_or_else(|| {
                    FormatterError::Failed(format!("Invalid key type {}", key.key_type))
                })?;

                let key = key_alg_provider
                    .key_algorithm_from_type(key_alg)
                    .ok_or_else(|| {
                        FormatterError::Failed(format!("Missing key algorithm {key_alg}"))
                    })?
                    .reconstruct_key(&key.public_key, None, None)
                    .map_err(|e| FormatterError::Failed(e.to_string()))?
                    .public_key_as_jwk()
                    .map_err(|e| FormatterError::Failed(e.to_string()))?;

                (None, Some(JwtPublicKeyInfo::Jwk(key)))
            }
            IdentifierType::CertificateAuthority => {
                return Err(FormatterError::Failed(format!(
                    "Invalid issuer identifier type {}",
                    issuer_identifier.r#type
                )));
            }
        };

        let content = TokenStatusListContent {
            status_list: TokenStatusListSubject {
                bits: PREFERRED_ENTRY_SIZE,
                value: encoded_list,
            },
        };

        let payload = JWTPayload {
            issuer,
            subject: Some(revocation_list_url),
            custom: content,
            issued_at: Some(OffsetDateTime::now_utc()),
            ..Default::default()
        };

        let jwt = Jwt::new(
            "statuslist+jwt".to_owned(),
            jose_alg,
            auth_fn.get_key_id(),
            public_key_info,
            payload,
        );

        jwt.tokenize(Some(&*auth_fn)).await
    }
}
