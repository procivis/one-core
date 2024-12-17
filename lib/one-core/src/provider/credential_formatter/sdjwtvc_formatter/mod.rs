//! SD-JWT VC implementation.
//
// https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html

mod disclosures;
pub(crate) mod model;

#[cfg(test)]
mod test;

use std::sync::Arc;

use async_trait::async_trait;
use one_crypto::CryptoProvider;
use serde::Deserialize;
use shared_types::{CredentialSchemaId, DidValue};
use time::Duration;
use url::Url;

use super::json_ld::model::ContextType;
use super::sdjwt;
use crate::model::did::Did;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt::model::JWTPayload;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, CredentialData, CredentialPresentation, CredentialSubject, DetailCredential,
    ExtractPresentationCtx, Features, FormatPresentationCtx, FormatterCapabilities, Presentation,
    SelectiveDisclosure, VerificationFn,
};
use crate::provider::credential_formatter::sdjwt::disclosures::{parse_token, to_hashmap};
use crate::provider::credential_formatter::sdjwt::mapper::{claims_to_json_object, unpack_arrays};
use crate::provider::credential_formatter::sdjwt::model::{DecomposedToken, Sdvp};
use crate::provider::credential_formatter::sdjwt::prepare_sd_presentation;
use crate::provider::credential_formatter::sdjwtvc_formatter::disclosures::extract_claims_from_disclosures;
use crate::provider::credential_formatter::sdjwtvc_formatter::model::{
    SDJWTVCStatus, SDJWTVCStatusList, SDJWTVCVc,
};
use crate::provider::credential_formatter::{CredentialFormatter, StatusListType};
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::provider::revocation::token_status_list::credential_status_from_sdjwt_status;
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
            auth_fn,
            &*self.crypto,
            self.params.leeway,
            "vc+sd-jwt".to_string(),
            schema_id,
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
            "Cannot format StatusList with SD-JWT VC formatter".to_string(),
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
            revocation_methods: vec!["NONE".to_string(), "TOKENSTATUSLIST".to_string()],
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
        let Some(schema_id) = request.schema_id.as_ref() else {
            return Err(FormatterError::Failed("Missing schema_id".to_string()));
        };

        let mut url = Url::parse(core_base_url)
            .map_err(|error| FormatterError::Failed(format!("Invalid base URL: {error}")))?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| FormatterError::Failed("Invalid base URL".to_string()))?;
            let organisation_id = request.organisation_id.to_string();
            // /ssi/vct/v1/:organisation_id/:schema_id
            segments.extend(["ssi", "vct", "v1", &organisation_id, schema_id]);
        }

        Ok(url.to_string())
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
    let DecomposedToken { disclosures, jwt } = parse_token(token)?;

    let jwt: Jwt<SDJWTVCVc> = Jwt::build_from_token(jwt, verification).await?;

    let hasher =
        crypto.get_hasher(&jwt.payload.custom.hash_alg.unwrap_or("sha-256".to_string()))?;

    let selective_disclosure_hashes = &jwt.payload.custom.disclosures;
    let public_claims = &jwt.payload.custom.public_claims;

    let claims = extract_claims_from_disclosures(
        &disclosures,
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
        status: credential_status_from_sdjwt_status(&jwt.payload.custom.status),
        credential_schema: None,
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn format_credentials(
    credential: CredentialData,
    holder_did: &Option<DidValue>,
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
        vc_type: Some(vc_type),
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

    let token = jwt.tokenize(Some(auth_fn)).await?;
    let sdjwt = sdjwt::serialize(token, disclosures);

    Ok(sdjwt)
}

pub(super) fn format_hashed_credential(
    credential: &CredentialData,
    algorithm: &str,
    crypto: &dyn CryptoProvider,
) -> Result<(SDJWTVCVc, Vec<String>), FormatterError> {
    let nested = claims_to_json_object(&credential.claims)?;
    let hasher = crypto.get_hasher("sha-256")?;

    let (disclosures, sd_section) =
        sdjwt::disclosures::compute_object_disclosures(&nested, &*hasher)?;
    let status = credential.status.first().and_then(|status| {
        let obj: serde_json::Value = status
            .additional_fields
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        serde_json::from_value(obj).ok()
    });

    let vc = vc_from_credential(sd_section, algorithm, status)?;

    Ok((vc, disclosures))
}

pub(crate) fn vc_from_credential(
    mut hashed_claims: Vec<String>,
    algorithm: &str,
    status: Option<SDJWTVCStatusList>,
) -> Result<SDJWTVCVc, FormatterError> {
    hashed_claims.sort_unstable();

    Ok(SDJWTVCVc {
        disclosures: hashed_claims,
        hash_alg: Some(algorithm.to_owned()),
        status: status.map(|status| SDJWTVCStatus {
            status_list: status,
        }),
        public_claims: Default::default(),
    })
}
