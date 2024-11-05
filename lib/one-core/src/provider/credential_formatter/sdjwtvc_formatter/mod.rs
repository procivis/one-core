//! SD-JWT VC implementation.
//
// https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html

#[cfg(test)]
mod test;

use std::sync::Arc;

use async_trait::async_trait;
use one_crypto::CryptoProvider;
use serde::Deserialize;
use shared_types::DidValue;

use super::json_ld::model::ContextType;
use crate::model::did::Did;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, CredentialData, CredentialPresentation, DetailCredential,
    ExtractPresentationCtx, FormatPresentationCtx, FormatterCapabilities, Presentation,
    VerificationFn,
};
use crate::provider::credential_formatter::sdjwt::model::Sdvp;
use crate::provider::credential_formatter::sdjwt::{
    extract_credentials_internal, format_sdjwt_credentials, prepare_sd_presentation,
};
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;

pub struct SDJWTVCFormatter {
    pub crypto: Arc<dyn CryptoProvider>,
    params: Params,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub leeway: u64,
    pub embed_layout_properties: bool,
}

#[async_trait]
impl CredentialFormatter for SDJWTVCFormatter {
    async fn format_credentials(
        &self,
        credential: CredentialData,
        holder_did: &Option<DidValue>,
        algorithm: &str,
        additional_context: Vec<ContextType>,
        additional_types: Vec<String>,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        let schema_id = credential.schema.id.to_owned();
        format_sdjwt_credentials(
            credential,
            holder_did,
            algorithm,
            additional_context,
            additional_types,
            auth_fn,
            &*self.crypto,
            self.params.embed_layout_properties,
            self.params.leeway,
            "vc+sd-jwt".to_string(),
            schema_id,
        )
        .await
    }

    async fn format_bitstring_status_list(
        &self,
        _revocation_list_url: String,
        _issuer_did: &Did,
        _encoded_list: String,
        _algorithm: String,
        _auth_fn: AuthenticationFn,
        _status_purpose: StatusPurpose,
    ) -> Result<String, FormatterError> {
        Err(FormatterError::Failed(
            "Cannot format BitstringStatusList with SD-JWT VC formatter".to_string(),
        ))
    }

    async fn extract_credentials(
        &self,
        token: &str,
        verification: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        extract_credentials_internal(token, Some(verification), &*self.crypto).await
    }

    async fn format_credential_presentation(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        prepare_sd_presentation(credential, &*self.crypto)
    }

    async fn extract_credentials_unverified(
        &self,
        token: &str,
    ) -> Result<DetailCredential, FormatterError> {
        extract_credentials_internal(token, None, &*self.crypto).await
    }

    async fn format_presentation(
        &self,
        _credentials: &[String],
        _holder_did: &DidValue,
        _algorithm: &str,
        _auth_fn: AuthenticationFn,
        _context: FormatPresentationCtx,
    ) -> Result<String, FormatterError> {
        // for presentation the JWT formatter is used
        unreachable!()
    }

    async fn extract_presentation(
        &self,
        token: &str,
        verification: VerificationFn,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        // Build fails if verification fails
        let jwt: Jwt<Sdvp> = Jwt::build_from_token(token, Some(verification)).await?;

        Ok(jwt.into())
    }

    async fn extract_presentation_unverified(
        &self,
        token: &str,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        let jwt: Jwt<Sdvp> = Jwt::build_from_token(token, None).await?;

        Ok(jwt.into())
    }

    fn get_leeway(&self) -> u64 {
        self.params.leeway
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            signing_key_algorithms: vec![
                "EDDSA".to_owned(),
                "ES256".to_owned(),
                "DILITHIUM".to_owned(),
            ],
            allowed_schema_ids: vec![],
            datatypes: vec![
                "STRING".to_string(),
                "BOOLEAN".to_string(),
                "EMAIL".to_string(),
                "DATE".to_string(),
                "STRING".to_string(),
                "COUNT".to_string(),
                "BIRTH_DATE".to_string(),
                "NUMBER".to_string(),
                "PICTURE".to_string(),
                "OBJECT".to_string(),
                "ARRAY".to_string(),
            ],
            features: vec!["SELECTIVE_DISCLOSURE".to_string()],
            selective_disclosure: vec!["ANY_LEVEL".to_string()],
            issuance_did_methods: vec![
                "KEY".to_string(),
                "WEB".to_string(),
                "JWK".to_string(),
                "X509".to_string(),
            ],
            issuance_exchange_protocols: vec!["OPENID4VC".to_string()],
            proof_exchange_protocols: vec![],
            revocation_methods: vec!["NONE".to_string()],
            verification_key_algorithms: vec![],
            verification_key_storages: vec![],
            forbidden_claim_names: vec!["0".to_string()],
        }
    }
}

impl SDJWTVCFormatter {
    pub fn new(params: Params, crypto: Arc<dyn CryptoProvider>) -> Self {
        Self { params, crypto }
    }
}
