//! SD-JWT VC implementation.
//
// https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html

pub(crate) mod model;

#[cfg(test)]
mod test;

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use model::SdJwtVcStatus;
use one_crypto::CryptoProvider;
use sdjwt::format_credential;
use serde::Deserialize;
use serde_json::Value;
use shared_types::{CredentialSchemaId, DidValue};
use time::Duration;
use url::Url;

use super::model::{
    CredentialData, CredentialStatus, FormattedPresentation, HolderBindingCtx, PublishedClaim,
};
use super::sdjwt;
use super::sdjwt::model::KeyBindingPayload;
use super::vcdm::VcdmCredential;
use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::config::core_config::{
    DatatypeConfig, DatatypeType, DidType, IdentifierType, IssuanceProtocolType, KeyAlgorithmType,
    KeyStorageType, RevocationType, VerificationProtocolType,
};
use crate::model::credential_schema::CredentialSchema;
use crate::model::identifier::Identifier;
use crate::provider::caching_loader::vct::VctTypeMetadataFetcher;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, CredentialPresentation, CredentialSubject, DetailCredential,
    ExtractPresentationCtx, Features, FormatPresentationCtx, FormatterCapabilities, Presentation,
    SelectiveDisclosure, VerificationFn,
};
use crate::provider::credential_formatter::sdjwt::disclosures::parse_token;
use crate::provider::credential_formatter::sdjwt::model::{DecomposedToken, SdJwtFormattingInputs};
use crate::provider::credential_formatter::sdjwt::{
    SdJwtHolderBindingParams, prepare_sd_presentation,
};
use crate::provider::credential_formatter::sdjwtvc_formatter::model::SdJwtVc;
use crate::provider::credential_formatter::{CredentialFormatter, StatusListType};
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::provider::revocation::token_status_list::credential_status_from_sdjwt_status;
use crate::service::certificate::validator::CertificateValidator;
use crate::service::credential_schema::dto::CreateCredentialSchemaRequestDTO;
use crate::util::jwt::Jwt;
use crate::util::jwt::model::JWTPayload;

const JPEG_DATA_URI_PREFIX: &str = "data:image/jpeg;base64,";

pub struct SDJWTVCFormatter {
    crypto: Arc<dyn CryptoProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    vct_type_metadata_cache: Arc<dyn VctTypeMetadataFetcher>,
    certificate_validator: Arc<dyn CertificateValidator>,
    datatype_config: DatatypeConfig,
    http_client: Arc<dyn HttpClient>,
    params: Params,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub leeway: u64,
    pub embed_layout_properties: bool,
    // Toggles SWIYU quirks, specifically the malformed `cnf` claim
    #[serde(default)]
    pub swiyu_mode: bool,
}

#[async_trait]
impl CredentialFormatter for SDJWTVCFormatter {
    async fn format_credential(
        &self,
        credential_data: CredentialData,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        const HASH_ALG: &str = "sha-256";
        // todo: here we need sdjwt-vc specific data model instead of using vcdm
        let vcdm = credential_data.vcdm;

        let schema_id = vcdm
            .credential_schema
            .as_ref()
            .and_then(|schemas| schemas.first())
            .map(|schema| schema.id.to_owned())
            .ok_or_else(|| FormatterError::Failed("Missing credential schema id".to_string()))?;

        let inputs = SdJwtFormattingInputs {
            holder_did: credential_data.holder_did,
            holder_key_id: credential_data.holder_key_id,
            leeway: self.params.leeway,
            token_type: "vc+sd-jwt".to_string(),
            swiyu_proof_of_possession: self.params.swiyu_mode,
            issuer_certificate: credential_data.issuer_certificate,
        };

        let vct_integrity = self
            .vct_type_metadata_cache
            .get(&schema_id)
            .await
            .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?
            .and_then(|item| item.integrity);

        let status = vcdm.credential_status.clone();
        let payload_from_digests = |digests: Vec<String>| {
            sdjwt_vc_from_credential(status, digests, HASH_ALG, schema_id, vct_integrity)
        };
        let claims = self.credential_to_claims(&vcdm, &credential_data.claims)?;
        format_credential(
            vcdm,
            claims,
            inputs,
            auth_fn,
            &*self.crypto.get_hasher(HASH_ALG)?,
            &*self.did_method_provider,
            payload_from_digests,
        )
        .await
    }

    async fn format_status_list(
        &self,
        _revocation_list_url: String,
        _issuer_identifier: &Identifier,
        _encoded_list: String,
        _algorithm: KeyAlgorithmType,
        _auth_fn: AuthenticationFn,
        _status_purpose: StatusPurpose,
        _status_list_type: StatusListType,
    ) -> Result<String, FormatterError> {
        Err(FormatterError::Failed(
            "Cannot format StatusList with SD-JWT VC formatter".to_string(),
        ))
    }

    async fn extract_credentials<'a>(
        &self,
        token: &str,
        credential_schema: Option<&'a CredentialSchema>,
        verification: VerificationFn,
        holder_binding_ctx: Option<HolderBindingCtx>,
    ) -> Result<DetailCredential, FormatterError> {
        let (credential, _) = self
            .extract_credentials_internal(
                token,
                credential_schema,
                Some(verification),
                &*self.crypto,
                holder_binding_ctx,
                Duration::seconds(self.get_leeway() as i64),
            )
            .await?;

        Ok(credential)
    }

    async fn format_credential_presentation(
        &self,
        credential: CredentialPresentation,
        holder_binding_ctx: Option<HolderBindingCtx>,
        holder_binding_fn: Option<AuthenticationFn>,
    ) -> Result<String, FormatterError> {
        let DecomposedToken { jwt, .. } = parse_token(&credential.token)?;
        let jwt: Jwt<SdJwtVc> = Jwt::build_from_token(jwt, None, None).await?;
        let hasher = self
            .crypto
            .get_hasher(&jwt.payload.custom.hash_alg.unwrap_or("sha-256".to_string()))?;

        prepare_sd_presentation(credential, &*hasher, holder_binding_ctx, holder_binding_fn).await
    }

    async fn extract_credentials_unverified<'a>(
        &self,
        token: &str,
        credential_schema: Option<&'a CredentialSchema>,
    ) -> Result<DetailCredential, FormatterError> {
        let (credential, _) = self
            .extract_credentials_internal(
                token,
                credential_schema,
                None,
                &*self.crypto,
                None,
                Duration::seconds(self.get_leeway() as i64),
            )
            .await?;

        Ok(credential)
    }

    async fn format_presentation(
        &self,
        _credentials: &[String],
        _holder_did: &DidValue,
        _algorithm: KeyAlgorithmType,
        _auth_fn: AuthenticationFn,
        _context: FormatPresentationCtx,
    ) -> Result<FormattedPresentation, FormatterError> {
        unimplemented!()
    }

    async fn extract_presentation(
        &self,
        _token: &str,
        _verification: VerificationFn,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        unimplemented!()
    }

    async fn extract_presentation_unverified(
        &self,
        _token: &str,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        unimplemented!()
    }

    fn get_leeway(&self) -> u64 {
        self.params.leeway
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        let mut datatypes = vec![
            "STRING".to_string(),
            "BOOLEAN".to_string(),
            "EMAIL".to_string(),
            "DATE".to_string(),
            "STRING".to_string(),
            "COUNT".to_string(),
            "BIRTH_DATE".to_string(),
            "NUMBER".to_string(),
        ];
        let mut issuance_exchange_protocols = vec![];
        let mut issuance_did_methods = vec![DidType::WebVh];
        let mut issuance_identifier_types = vec![IdentifierType::Did];
        let mut proof_exchange_protocols =
            vec![VerificationProtocolType::OpenId4VpProximityDraft00];
        let mut verification_identifier_types = vec![IdentifierType::Did];
        let mut signing_algorithms = vec![KeyAlgorithmType::Ecdsa];

        if self.params.swiyu_mode {
            datatypes.push("SWIYU_PICTURE".to_string());
            issuance_exchange_protocols.push(IssuanceProtocolType::OpenId4VciDraft13Swiyu);
            proof_exchange_protocols.push(VerificationProtocolType::OpenId4VpDraft20Swiyu)
        } else {
            datatypes.extend_from_slice(&[
                "PICTURE".to_string(),
                "OBJECT".to_string(),
                "ARRAY".to_string(),
            ]);
            issuance_did_methods.extend_from_slice(&[DidType::Key, DidType::Web, DidType::Jwk]);
            issuance_exchange_protocols.push(IssuanceProtocolType::OpenId4VciDraft13);
            issuance_identifier_types.push(IdentifierType::Certificate);
            proof_exchange_protocols.extend_from_slice(&[
                VerificationProtocolType::OpenId4VpDraft20,
                VerificationProtocolType::OpenId4VpDraft25,
            ]);
            verification_identifier_types.push(IdentifierType::Certificate);
            signing_algorithms
                .extend_from_slice(&[KeyAlgorithmType::Eddsa, KeyAlgorithmType::Dilithium]);
        }

        FormatterCapabilities {
            signing_key_algorithms: signing_algorithms.clone(),
            allowed_schema_ids: vec![],
            datatypes,
            features: vec![
                Features::SelectiveDisclosure,
                Features::RequiresSchemaId,
                Features::SupportsCredentialDesign,
            ],
            selective_disclosure: vec![SelectiveDisclosure::AnyLevel],
            issuance_did_methods,
            issuance_exchange_protocols,
            proof_exchange_protocols,
            revocation_methods: vec![RevocationType::None, RevocationType::TokenStatusList],
            verification_key_algorithms: signing_algorithms.clone(),
            verification_key_storages: vec![
                KeyStorageType::Internal,
                KeyStorageType::AzureVault,
                KeyStorageType::SecureElement,
            ],
            forbidden_claim_names: vec!["0".to_string()],
            issuance_identifier_types,
            verification_identifier_types,
            holder_identifier_types: vec![IdentifierType::Did],
            holder_key_algorithms: signing_algorithms,
            holder_did_methods: vec![DidType::Web, DidType::Key, DidType::Jwk, DidType::WebVh],
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

        if request.external_schema {
            return Ok(schema_id.to_string());
        }

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
    pub fn new(
        params: Params,
        crypto: Arc<dyn CryptoProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        vct_type_metadata_cache: Arc<dyn VctTypeMetadataFetcher>,
        certificate_validator: Arc<dyn CertificateValidator>,
        datatype_config: DatatypeConfig,
        http_client: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            params,
            crypto,
            did_method_provider,
            vct_type_metadata_cache,
            certificate_validator,
            datatype_config,
            http_client,
        }
    }

    async fn extract_credentials_internal(
        &self,
        token: &str,
        credential_schema: Option<&CredentialSchema>,
        verification: Option<VerificationFn>,
        crypto: &dyn CryptoProvider,
        holder_binding_ctx: Option<HolderBindingCtx>,
        leeway: Duration,
    ) -> Result<(DetailCredential, Option<JWTPayload<KeyBindingPayload>>), FormatterError> {
        let params = SdJwtHolderBindingParams {
            holder_binding_context: holder_binding_ctx,
            leeway,
            skip_holder_binding_aud_check: self.params.swiyu_mode, // skip holder binding aud check for SWIYU as aud is randomly populated
        };
        let (mut jwt, proof_of_key_possession, issuer): (Jwt<SdJwtVc>, _, _) =
            Jwt::build_from_token_with_disclosures(
                token,
                crypto,
                verification.as_ref(),
                params,
                Some(&*self.certificate_validator),
                &*self.http_client,
            )
            .await?;

        // SWIYU credentials don't encode image claims with the data uri prefix
        if self.params.swiyu_mode {
            if let Some(claim_schemas) =
                credential_schema.and_then(|schema| schema.claim_schemas.as_ref())
            {
                for claim_schema in claim_schemas {
                    let Some(fields) = self
                        .datatype_config
                        .get_fields(&claim_schema.schema.data_type)
                        .ok()
                    else {
                        continue;
                    };
                    if fields.r#type == DatatypeType::File {
                        let path = claim_schema.schema.key.split(NESTED_CLAIM_MARKER).collect();
                        post_process_claims(path, &mut jwt.payload.custom.public_claims, |value| {
                            format!("{JPEG_DATA_URI_PREFIX}{value}")
                        })
                    }
                }
            }
        }

        let subject = jwt
            .payload
            .subject
            .map(|did| DidValue::from_str(&did))
            .transpose()
            .map_err(|e| FormatterError::Failed(e.to_string()))?;

        Ok((
            DetailCredential {
                id: jwt.payload.jwt_id,
                valid_from: jwt.payload.issued_at,
                valid_until: jwt.payload.expires_at,
                update_at: None,
                invalid_before: jwt.payload.invalid_before,
                issuer,
                subject,
                claims: CredentialSubject {
                    claims: HashMap::from_iter(jwt.payload.custom.public_claims),
                    id: None,
                },
                status: credential_status_from_sdjwt_status(&jwt.payload.custom.status),
                credential_schema: None,
            },
            proof_of_key_possession,
        ))
    }

    fn credential_to_claims(
        &self,
        credential: &VcdmCredential,
        published_claims: &[PublishedClaim],
    ) -> Result<Value, FormatterError> {
        let mut claims = credential
            .credential_subject
            .first()
            .map(|cs| {
                let object = serde_json::Map::from_iter(cs.claims.clone());
                serde_json::Value::Object(object)
            })
            .ok_or_else(|| {
                FormatterError::Failed("Credential is missing credential subject".to_string())
            })?;
        let Some(object_claim) = claims.as_object_mut() else {
            return Ok(claims);
        };

        if self.params.swiyu_mode {
            // Remove data uri prefix from image claim values when formatting for SWIYU
            for published_claim in published_claims.iter().filter(|claim| {
                let Some(ref data_type) = claim.datatype else {
                    return false;
                };
                let Some(fields) = self.datatype_config.get_fields(data_type).ok() else {
                    return false;
                };
                fields.r#type == DatatypeType::File
            }) {
                let path = published_claim.key.split(NESTED_CLAIM_MARKER).collect();
                post_process_claims(path, object_claim, |value| {
                    value.trim_start_matches(JPEG_DATA_URI_PREFIX).to_string()
                });
            }
        }

        Ok(claims)
    }
}

fn post_process_claims(
    mut path: Vec<&str>,
    claims: &mut serde_json::Map<String, Value>,
    process: impl Fn(&str) -> String,
) {
    let Some(current) = path.pop() else { return };
    let Some(current_value) = claims.get_mut(current) else {
        return;
    };

    if path.is_empty() {
        let Some(str_value) = current_value.as_str() else {
            return;
        };
        let processed_value = process(str_value);
        claims.insert(current.to_string(), Value::String(processed_value));
    } else {
        let Some(map_value) = current_value.as_object_mut() else {
            return;
        };
        post_process_claims(path, map_value, process)
    }
}

fn sdjwt_vc_from_credential(
    credential_status: Vec<CredentialStatus>,
    mut hashed_claims: Vec<String>,
    algorithm: &str,
    vc_type: String,
    vct_integrity: Option<String>,
) -> Result<SdJwtVc, FormatterError> {
    hashed_claims.sort_unstable();

    let status = credential_status.first().and_then(|status| {
        let obj: Value = status
            .additional_fields
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        serde_json::from_value(obj).ok()
    });

    Ok(SdJwtVc {
        digests: hashed_claims,
        hash_alg: Some(algorithm.to_owned()),
        status: status.map(|status| SdJwtVcStatus {
            status_list: status,
            custom_claims: Default::default(),
        }),
        public_claims: Default::default(),
        vc_type,
        vct_integrity,
    })
}
