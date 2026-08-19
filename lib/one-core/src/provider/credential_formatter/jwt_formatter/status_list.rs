use serde_json::json;
use url::Url;

use super::JWTFormatter;
use super::model::{TokenStatusListContent, TokenStatusListSubject, VcClaim};
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::pem_chain_into_x5c;
use crate::proto::jwt::model::JWTPayload;
use crate::proto::jwt::{Jwt, JwtPublicKeyInfo};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{AuthenticationFn, Issuer};
use crate::provider::credential_formatter::vcdm::{VcdmCredential, VcdmCredentialSubject};
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::util::key_selection::SelectedKey;

impl JWTFormatter {
    pub(super) async fn format_bitstring_status_list(
        &self,
        revocation_list_url: String,
        issuer: SelectedKey,
        encoded_list: String,
        jose_alg: String,
        auth_fn: AuthenticationFn,
        status_purpose: StatusPurpose,
    ) -> Result<String, FormatterError> {
        let SelectedKey::Did { did, .. } = issuer else {
            return Err(FormatterError::CouldNotFormat(
                "Status list issuer must be a DID".to_string(),
            ));
        };
        let did_value = &did.did;

        let revocation_list_url: Url = revocation_list_url.parse()?;

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

        let vc = VcdmCredential::new_v2(
            Issuer::Url(did_value.clone().into_url()),
            credential_subject,
        )
        .add_type("BitstringStatusListCredential".to_string())
        .with_id(credential_id);

        let payload = JWTPayload {
            issuer: Some(did_value.to_string()),
            subject: Some(credential_subject_id.to_string()),
            custom: VcClaim { vc: vc.into() },
            issued_at: Some(crate::clock::now_utc()),
            ..Default::default()
        };

        let jwt = Jwt::new("JWT".to_owned(), jose_alg, None, None, payload);

        Ok(jwt
            .tokenize(Some(&*auth_fn))
            .await
            .error_while("creating JWT bitstring status list token")?)
    }

    pub(super) async fn format_token_status_list(
        &self,
        revocation_list_url: String,
        issuer: SelectedKey,
        encoded_list: String,
        jose_alg: String,
        auth_fn: AuthenticationFn,
        bits: usize,
    ) -> Result<String, FormatterError> {
        let (issuer, public_key_info) = match issuer {
            SelectedKey::Did { did, .. } => (Some(did.did.to_string()), None),
            SelectedKey::Certificate { certificate, .. } => (
                None,
                Some(JwtPublicKeyInfo::X5c(
                    pem_chain_into_x5c(&certificate.chain).error_while("parsing PEM chain")?,
                )),
            ),
            SelectedKey::Key(key) => {
                let key = self
                    .key_algorithm_provider
                    .key_algorithm_from_key(&key)
                    .error_while("getting key algorithm")?
                    .reconstruct_key(&key.public_key, None, None)
                    .error_while("reconstructing key")?
                    .public_key_as_jwk()
                    .error_while("getting JWK")?;

                (None, Some(JwtPublicKeyInfo::Jwk(key)))
            }
        };

        let content = TokenStatusListContent {
            status_list: TokenStatusListSubject {
                bits,
                value: encoded_list,
            },
        };

        let payload = JWTPayload {
            issuer,
            subject: Some(revocation_list_url),
            custom: content,
            issued_at: Some(crate::clock::now_utc()),
            ..Default::default()
        };

        let jwt = Jwt::new(
            "statuslist+jwt".to_owned(),
            jose_alg,
            auth_fn.get_key_id(),
            public_key_info,
            payload,
        );

        Ok(jwt
            .tokenize(Some(&*auth_fn))
            .await
            .error_while("creating JWT token status list")?)
    }
}
