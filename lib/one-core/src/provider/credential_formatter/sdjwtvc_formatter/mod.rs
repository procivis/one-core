//! SD-JWT VC implementation.
//
// https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html

mod disclosures;
mod model;

#[cfg(test)]
mod test;

use std::sync::Arc;

use async_trait::async_trait;
use one_crypto::CryptoProvider;
use serde::Deserialize;
use shared_types::{CredentialSchemaId, DidValue};
use time::Duration;

use super::json_ld::model::ContextType;
use crate::model::did::Did;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt::model::JWTPayload;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, CredentialData, CredentialPresentation, CredentialSubject, DetailCredential,
    ExtractPresentationCtx, Features, FormatPresentationCtx, FormatterCapabilities, Presentation,
    SelectiveDisclosure, VerificationFn,
};
use crate::provider::credential_formatter::sdjwt::disclosures::{
    extract_disclosures, sort_published_claims_by_indices, to_hashmap,
};
use crate::provider::credential_formatter::sdjwt::mapper::{
    nest_claims_to_json, tokenize_claims, unpack_arrays,
};
use crate::provider::credential_formatter::sdjwt::model::{DecomposedToken, Sdvp};
use crate::provider::credential_formatter::sdjwt::prepare_sd_presentation;
use crate::provider::credential_formatter::sdjwtvc_formatter::disclosures::{
    extract_claims_from_disclosures, gather_disclosures,
};
use crate::provider::credential_formatter::sdjwtvc_formatter::model::SDJWTVCVc;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::service::credential_schema::dto::CreateCredentialSchemaRequestDTO;

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
        _additional_context: Vec<ContextType>,
        _additional_types: Vec<String>,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        let schema_id =
            credential.schema.id.clone().ok_or_else(|| {
                FormatterError::Failed("Missing credential schema id".to_string())
            })?;

        format_credentials(
            credential,
            holder_did,
            algorithm,
            auth_fn,
            &*self.crypto,
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
            features: vec![
                Features::SelectiveDisclosure,
                Features::RequiresSchemaId,
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
            proof_exchange_protocols: vec![],
            revocation_methods: vec!["NONE".to_string()],
            verification_key_algorithms: vec![],
            verification_key_storages: vec![],
            forbidden_claim_names: vec!["0".to_string()],
        }
    }

    fn credential_schema_id(
        &self,
        _id: CredentialSchemaId,
        request: &CreateCredentialSchemaRequestDTO,
        core_base_url: &str,
    ) -> Result<String, FormatterError> {
        request
            .schema_id
            .clone()
            .map(|schema_id| format!("{core_base_url}/ssi/v1/vct/{schema_id}"))
            .ok_or(FormatterError::Failed("Missing schema_id".to_string()))
    }
}

impl SDJWTVCFormatter {
    pub fn new(params: Params, crypto: Arc<dyn CryptoProvider>) -> Self {
        Self { params, crypto }
    }
}

pub(super) async fn extract_credentials_internal(
    token: &str,
    verification: Option<VerificationFn>,
    crypto: &dyn CryptoProvider,
) -> Result<DetailCredential, FormatterError> {
    let DecomposedToken {
        deserialized_disclosures,
        jwt,
    } = extract_disclosures(token)?;

    let jwt: Jwt<SDJWTVCVc> = Jwt::build_from_token(jwt, verification).await?;

    let hasher =
        crypto.get_hasher(&jwt.payload.custom.hash_alg.unwrap_or("sha-256".to_string()))?;

    let selective_disclosure_hashes = &jwt.payload.custom.disclosures;
    let public_claims = &jwt.payload.custom.public_claims;

    let claims = extract_claims_from_disclosures(
        &deserialized_disclosures,
        public_claims.clone(),
        selective_disclosure_hashes,
        &*hasher,
    )?;

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
        status: vec![],
        credential_schema: None,
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn format_credentials(
    credential: CredentialData,
    holder_did: &Option<DidValue>,
    algorithm: &str,
    auth_fn: AuthenticationFn,
    crypto: &dyn CryptoProvider,
    leeway: u64,
    token_type: String,
    vc_type: String,
) -> Result<String, FormatterError> {
    let (vc, disclosures) = format_hashed_credential(&credential, "sha-256", crypto)?;

    let issuer = credential.issuer_did.to_did_value().to_string();
    let id = credential.id;
    let issued_at = credential.issuance_date;
    let expires_at = issued_at.checked_add(credential.valid_for);

    let payload = JWTPayload {
        issued_at: Some(issued_at),
        expires_at,
        invalid_before: issued_at.checked_sub(Duration::seconds(leeway as i64)),
        subject: holder_did.as_ref().map(|did| did.to_string()),
        issuer: Some(issuer),
        jwt_id: id,
        custom: vc,
        nonce: None,
        vc_type: Some(vc_type),
        proof_of_possession_key: None,
    };

    let key_id = auth_fn.get_key_id();
    let jwt = Jwt::new(token_type, algorithm.to_owned(), key_id, None, payload);

    let mut token = jwt.tokenize(Some(auth_fn)).await?;

    let disclosures_token = tokenize_claims(disclosures)?;

    token.push_str(&disclosures_token);
    token.push('~'); // SD-JWT VC requires additional '~' at the end for Key Binding JWT

    Ok(token)
}

pub(super) fn format_hashed_credential(
    credential: &CredentialData,
    algorithm: &str,
    crypto: &dyn CryptoProvider,
) -> Result<(SDJWTVCVc, Vec<String>), FormatterError> {
    let nested = nest_claims_to_json(&sort_published_claims_by_indices(&credential.claims))?;
    let (disclosures, sd_section) = gather_disclosures(&nested, algorithm, crypto)?;

    let vc = vc_from_credential(&sd_section, algorithm)?;

    Ok((vc, disclosures))
}

pub(crate) fn vc_from_credential(
    sd_section: &[String],
    algorithm: &str,
) -> Result<SDJWTVCVc, FormatterError> {
    let mut hashed_claims: Vec<String> = sd_section.to_vec();
    hashed_claims.sort_unstable();

    Ok(SDJWTVCVc {
        disclosures: hashed_claims,
        hash_alg: Some(algorithm.to_owned()),
        public_claims: Default::default(),
    })
}
