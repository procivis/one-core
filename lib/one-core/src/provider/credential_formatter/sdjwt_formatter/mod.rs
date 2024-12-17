//! SD-JWT implementation.
//
// https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html

use std::sync::Arc;

use async_trait::async_trait;
use one_crypto::CryptoProvider;
use serde::Deserialize;
use shared_types::DidValue;
use time::Duration;

use crate::model::did::Did;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt::model::JWTPayload;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, CredentialData, CredentialPresentation, CredentialSubject, DetailCredential,
    ExtractPresentationCtx, Features, FormatPresentationCtx, FormatterCapabilities, Presentation,
    SelectiveDisclosure, VerificationFn,
};
use crate::provider::credential_formatter::{sdjwt, CredentialFormatter, StatusListType};
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;

#[cfg(test)]
mod test;

use super::json_ld::model::ContextType;
use crate::provider::credential_formatter::sdjwt::disclosures::{
    compute_object_disclosures, extract_claims_from_disclosures, parse_token, to_hashmap,
};
use crate::provider::credential_formatter::sdjwt::mapper::{
    claims_to_json_object, unpack_arrays, vc_from_credential,
};
use crate::provider::credential_formatter::sdjwt::model::*;
use crate::provider::credential_formatter::sdjwt::{model, prepare_sd_presentation};

pub struct SDJWTFormatter {
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
impl CredentialFormatter for SDJWTFormatter {
    async fn format_credentials(
        &self,
        credential: CredentialData,
        holder_did: &Option<DidValue>,
        additional_context: Vec<ContextType>,
        additional_types: Vec<String>,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        format_credentials(
            credential,
            holder_did,
            additional_context,
            additional_types,
            auth_fn,
            &*self.crypto,
            self.params.embed_layout_properties,
            self.params.leeway,
            "SD_JWT".to_string(),
            None,
        )
        .await
    }

    async fn format_status_list(
        &self,
        _revocation_list_url: String,
        _issuer_did: &Did,
        _encoded_list: String,
        _algorithm: String,
        _auth_fn: AuthenticationFn,
        _status_purpose: StatusPurpose,
        _status_list_type: StatusListType,
    ) -> Result<String, FormatterError> {
        Err(FormatterError::Failed(
            "Cannot format StatusList with SD-JWT formatter".to_string(),
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
        prepare_sd_presentation(credential)
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
            features: vec![
                Features::SelectiveDisclosure,
                Features::SupportsCredentialDesign,
            ],
            selective_disclosure: vec![SelectiveDisclosure::AnyLevel],
            issuance_did_methods: vec![
                "KEY".to_string(),
                "WEB".to_string(),
                "JWK".to_string(),
                "X509".to_string(),
            ],
            issuance_exchange_protocols: vec!["OPENID4VC".to_string()],
            proof_exchange_protocols: vec!["OPENID4VC".to_string()],
            revocation_methods: vec![
                "NONE".to_string(),
                "BITSTRINGSTATUSLIST".to_string(),
                "LVVC".to_string(),
            ],
            verification_key_algorithms: vec![
                "EDDSA".to_string(),
                "ES256".to_string(),
                "DILITHIUM".to_string(),
            ],
            verification_key_storages: vec![
                "INTERNAL".to_string(),
                "AZURE_VAULT".to_string(),
                "SECURE_ELEMENT".to_string(),
            ],
            forbidden_claim_names: vec!["0".to_string()],
        }
    }
}

impl SDJWTFormatter {
    pub fn new(params: Params, crypto: Arc<dyn CryptoProvider>) -> Self {
        Self { params, crypto }
    }
}

pub(super) async fn extract_credentials_internal(
    token: &str,
    verification: Option<VerificationFn>,
    crypto: &dyn CryptoProvider,
) -> Result<DetailCredential, FormatterError> {
    let model::DecomposedToken { disclosures, jwt } = parse_token(token)?;

    let jwt: Jwt<Sdvc> = Jwt::build_from_token(jwt, verification).await?;
    let digests = jwt.payload.custom.vc.credential_subject.digests;

    let hasher =
        crypto.get_hasher(&jwt.payload.custom.hash_alg.unwrap_or("sha-256".to_string()))?;

    let claims = extract_claims_from_disclosures(digests, disclosures, &*hasher)?;

    Ok(DetailCredential {
        id: jwt.payload.jwt_id,
        valid_from: jwt.payload.issued_at,
        valid_until: jwt.payload.expires_at,
        update_at: None,
        invalid_before: jwt.payload.invalid_before,
        issuer_did: jwt.payload.issuer.map(DidValue::from),
        subject: jwt.payload.subject.map(DidValue::from),
        claims: CredentialSubject {
            values: to_hashmap(unpack_arrays(&claims)?)?,
        },
        status: jwt.payload.custom.vc.credential_status,
        credential_schema: jwt.payload.custom.vc.credential_schema,
    })
}

pub(super) fn format_hashed_credential(
    credential: CredentialData,
    algorithm: &str,
    additional_context: Vec<ContextType>,
    additional_types: Vec<String>,
    crypto: &dyn CryptoProvider,
    embed_layout_properties: bool,
) -> Result<(Sdvc, Vec<String>), FormatterError> {
    let nested = claims_to_json_object(&credential.claims)?;
    let hasher = crypto.get_hasher("sha-256")?;
    let (disclosures, digests) = compute_object_disclosures(&nested, &*hasher)?;

    let vc = vc_from_credential(
        credential,
        digests,
        additional_context,
        additional_types,
        algorithm,
        embed_layout_properties,
    )?;

    Ok((vc, disclosures))
}

#[allow(clippy::too_many_arguments)]
pub async fn format_credentials(
    credential: CredentialData,
    holder_did: &Option<DidValue>,
    additional_context: Vec<ContextType>,
    additional_types: Vec<String>,
    auth_fn: AuthenticationFn,
    crypto: &dyn CryptoProvider,
    embed_layout_properties: bool,
    leeway: u64,
    token_type: String,
    vc_type: Option<String>,
) -> Result<String, FormatterError> {
    let issuer = credential.issuer_did.to_did_value().to_string();
    let id = credential.id.clone();
    let issued_at = credential.issuance_date;
    let expires_at = issued_at.checked_add(credential.valid_for);

    let (vc, disclosures) = format_hashed_credential(
        credential,
        "sha-256",
        additional_context,
        additional_types,
        crypto,
        embed_layout_properties,
    )?;

    let payload = JWTPayload {
        issued_at: Some(issued_at),
        expires_at,
        invalid_before: issued_at.checked_sub(Duration::seconds(leeway as i64)),
        subject: holder_did.as_ref().map(|did| did.to_string()),
        issuer: Some(issuer),
        jwt_id: id,
        custom: vc,
        vc_type,
        proof_of_possession_key: None,
    };

    let key_id = auth_fn.get_key_id();
    let jwt = Jwt::new(
        token_type,
        auth_fn.get_key_type().to_owned(),
        key_id,
        None,
        payload,
    );

    let jwt_token = jwt.tokenize(Some(auth_fn)).await?;

    let sdjwt = sdjwt::serialize(jwt_token, disclosures);

    Ok(sdjwt)
}
