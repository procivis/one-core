//! SD-JWT VC implementation.
//
// https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html

pub(crate) mod model;

#[cfg(test)]
mod test;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use model::{SdJwtVc, SdJwtVcCredential, SdJwtVcStatus};
use one_crypto::get_hasher;
use proc_macros::Provider;
use sdjwt::format_credential;
use serde::Deserialize;
use serde_json::Value;
use serde_with::{DurationSeconds, serde_as};
use shared_types::{
    CredentialFormat, CredentialSchemaId, OrganisationId, RevocationMethodId, SerializedCredential,
};
use standardized_types::iana::HashAlgorithm;
use time::Duration;
use uuid::Uuid;

use super::error::FormatterError;
use super::json_claims::{parse_claims, prepare_identifier};
use super::mapper::{default_2_years, first_certificate, to_format_with_mappings};
use super::model::{
    AuthenticationFn, CredentialClaim, CredentialClaimValue, CredentialData,
    CredentialPresentation, CredentialStatus, DetailCredential, Features, FormatterCapabilities,
    IdentifierDetails, IssuedClaimValue, ParsedCredential, SelectiveDisclosure, TokenVerifier,
    VerificationFn,
};
use super::sdjwt::disclosures::{
    SELECTIVE_DISCLOSURE_ARRAY_MARKER, SELECTIVE_DISCLOSURE_MARKER, parse_token,
};
use super::sdjwt::model::{DecomposedToken, SdJwtFormattingInputs};
use super::sdjwt::{parse_holder_identifier, prepare_sd_presentation};
use super::{CredentialFormatter, MetadataClaimSchema, sdjwt};
use crate::config::core_config::{
    DatatypeConfig, DatatypeType, DidType, IdentifierType, IssuanceProtocolType, KeyAlgorithmType,
    KeyStorageType, RevocationType, VerificationProtocolType,
};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::model::credential::{CredentialCommon, CredentialStateEnum};
use crate::model::credential_schema::CredentialSchema;
use crate::model::organisation::Organisation;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::http_client::HttpClient;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::jwt_metadata_claims;
use crate::provider::caching_loader::vct::VctTypeMetadataFetcher;
use crate::provider::data_type::provider::DataTypeProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::provider_directory::InitializationError;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::provider::revocation::token_status_list::credential_status_from_sdjwt_status;
use crate::util::key_selection::SelectedKey;

const JPEG_DATA_URI_PREFIX: &str = "data:image/jpeg;base64,";
const PNG_DATA_URI_PREFIX: &str = "data:image/png;base64,";

#[derive(Provider)]
pub struct SDJWTVCFormatter {
    base_url: Option<Arc<str>>,
    config_id: CredentialFormat,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    vct_type_metadata_cache: Arc<dyn VctTypeMetadataFetcher>,
    certificate_validator: Arc<dyn CertificateValidator>,
    datatype_config: DatatypeConfig,
    http_client: Arc<dyn HttpClient>,
    data_type_provider: Arc<dyn DataTypeProvider>,
    params: Params,
}

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    leeway_seconds: Duration,
    #[expect(unused)]
    embed_layout_properties: bool,
    // Toggles SWIYU quirks, specifically the malformed `cnf` claim
    #[serde(default)]
    swiyu_mode: bool,
    #[serde(default = "default_sd_array_elements")]
    sd_array_elements: bool,
    #[serde_as(as = "DurationSeconds<i64>")]
    #[serde(default = "default_2_years")]
    expiration_seconds: Duration,
    revocation_method: Option<RevocationMethodId>,
}

fn default_sd_array_elements() -> bool {
    true
}

#[async_trait]
impl CredentialFormatter for SDJWTVCFormatter {
    async fn parse_credential(
        &self,
        credential: &SerializedCredential,
        organisation: Organisation,
        verification: Box<dyn TokenVerifier>,
    ) -> Result<ParsedCredential, FormatterError> {
        let now = crate::clock::now_utc();

        let (parsed_credential, issuer, _): (Jwt<SdJwtVc>, _, _) =
            Jwt::build_from_token_with_disclosures(
                credential,
                Some(&verification),
                Some(&*self.certificate_validator),
                &*self.http_client,
            )
            .await?;

        let holder_identifier = parse_holder_identifier(
            &organisation,
            &parsed_credential,
            self.key_algorithm_provider.as_ref(),
            self.did_method_provider.as_ref(),
        )?;

        let revocation_method = parsed_credential
            .payload
            .custom
            .status
            .as_ref()
            .map(|_| RevocationType::TokenStatusList);

        let credential_id = Uuid::new_v4().into();
        let vct = parsed_credential.payload.custom.vc_type.clone();

        // Get metadata claims first (includes vct and standard JWT claims)
        let metadata_claims = parsed_credential
            .get_metadata_claims()
            .error_while("getting metadata claims")?;

        // Parse claims from public_claims
        let (mut claims, mut claim_schemas) = parse_claims(
            parsed_credential.payload.custom.public_claims,
            self.data_type_provider.as_ref(),
        )
        .await?;

        // Add parsed metadata claims
        let (metadata_claims, metadata_claim_schemas) =
            parse_claims(metadata_claims, self.data_type_provider.as_ref()).await?;
        claims.extend(metadata_claims);
        claim_schemas.extend(metadata_claim_schemas);

        let credential_schema_id = Uuid::new_v4().into();
        let format = to_format_with_mappings(
            self.config_id.clone(),
            credential_schema_id,
            vct.clone(),
            &claim_schemas,
            now,
        );
        let schema = CredentialSchema {
            expiration: None,
            ecosystem: None,
            id: credential_schema_id,
            deleted_at: None,
            created_date: now,
            last_modified: now,
            // Will be overridden based on issuer metadata
            name: vct,
            wallet_attestation: Default::default(),
            layout_properties: None,
            imported_source_url: "".to_string(),
            allow_suspension: false,
            claim_schemas: claim_schemas.into(),
            organisation: organisation.clone().into(),
            transaction_code: None,
            formats: vec![format.clone()].into(),
            batch_size: None,
            allow_revocation: revocation_method.is_some(),
            translations: Default::default(),
            embedded_disclosure_policy: None,
        };

        let issuer_identifier = prepare_identifier(
            &issuer,
            self.key_algorithm_provider.as_ref(),
            self.did_method_provider.as_ref(),
            organisation.to_owned(),
        )?;

        Ok(ParsedCredential {
            common: CredentialCommon {
                expires_at: parsed_credential.payload.expires_at,
                ecosystem: None,
                id: credential_id,
                created_date: now,
                issuance_date: parsed_credential.payload.issued_at,
                last_modified: now,
                deleted_at: None,
                protocol: "".to_string(),
                redirect_uri: None,
                state: CredentialStateEnum::Accepted,
                profile: None,
                schema: schema.into(),
                interaction: None,
            },
            claims: claims.into(),
            issuer: crate::model::credential::IssuerIdentity {
                certificate: first_certificate(&issuer_identifier).await?.map(Into::into),
                identifier: issuer_identifier.into(),
            },
            holder_identifier: holder_identifier.map(Into::into),
            format: format.into(),
        })
    }

    async fn format_credential(
        &self,
        credential_data: CredentialData,
        auth_fn: AuthenticationFn,
    ) -> Result<SerializedCredential, FormatterError> {
        let Some(base_url) = self.base_url.as_deref() else {
            return Err(
                InitializationError::MissingDependency("base_url".to_string())
                    .error_while("missing base_url")
                    .into(),
            );
        };
        const HASH_ALG: HashAlgorithm = HashAlgorithm::Sha256;
        let SdJwtVcCredential {
            vct,
            issuer,
            valid_until,
            credential_status,
            mut claims,
        } = credential_data.credential.into_sd_jwt_vc()?;

        if self.params.swiyu_mode {
            for claim in claims.values_mut() {
                strip_swiyu_picture_prefix(claim);
            }
        }
        let claims = Value::from(IssuedClaimValue::Object(claims));

        let token_type = if self.params.swiyu_mode {
            // SWIYU still uses the old typ
            "vc+sd-jwt".to_string()
        } else {
            "dc+sd-jwt".to_string()
        };
        let inputs = SdJwtFormattingInputs {
            issuer,
            id: None,
            valid_from: crate::clock::now_utc(),
            valid_until,
            holder_identifier: credential_data.holder_identifier,
            holder_key_id: credential_data.holder_key_id,
            token_type,
            issuer_certificate: credential_data.issuer_certificate,
        };

        let vct_integrity = self
            .vct_type_metadata_cache
            .get(&vct)
            .await
            .error_while("getting VCT")?
            .and_then(|item| item.integrity);

        let payload_from_digests = |digests: Vec<String>| {
            sdjwt_vc_from_credential(credential_status, digests, HASH_ALG, vct, vct_integrity)
        };
        format_credential(
            claims,
            inputs,
            auth_fn,
            &*get_hasher(HASH_ALG)?,
            &*self.did_method_provider,
            &*self.key_algorithm_provider,
            payload_from_digests,
            self.params.sd_array_elements,
            base_url,
        )
        .await
    }

    async fn format_status_list<'a>(
        &self,
        _revocation_list_url: String,
        _issuer: SelectedKey,
        _encoded_list: String,
        _algorithm: KeyAlgorithmType,
        _auth_fn: AuthenticationFn,
        _status_purpose: StatusPurpose,
        _status_list_type: RevocationType,
    ) -> Result<Vec<u8>, FormatterError> {
        Err(FormatterError::CouldNotFormat(
            "Cannot format StatusList with SD-JWT VC formatter".to_string(),
        ))
    }

    async fn extract_credentials<'a>(
        &self,
        token: &SerializedCredential,
        credential_schema: Option<&'a CredentialSchema>,
        verification: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        self.extract_credentials_internal(token, credential_schema, Some(verification))
            .await
    }

    async fn prepare_selective_disclosure(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        let DecomposedToken { jwt, .. } = parse_token(&credential.token)?;
        let jwt: Jwt<SdJwtVc> = Jwt::build_from_token(jwt, None, None)
            .await
            .error_while("parsing SD-JWT-VC token")?;
        let hasher = get_hasher(
            jwt.payload
                .custom
                .hash_alg
                .as_deref()
                .unwrap_or("sha-256")
                .try_into()?,
        )?;

        prepare_sd_presentation(credential, &*hasher, &self.user_claims_path()).await
    }

    async fn extract_credentials_unverified<'a>(
        &self,
        token: &SerializedCredential,
        credential_schema: Option<&'a CredentialSchema>,
    ) -> Result<DetailCredential, FormatterError> {
        self.extract_credentials_internal(token, credential_schema, None)
            .await
    }

    fn get_leeway(&self) -> Duration {
        self.params.leeway_seconds
    }

    fn get_default_expiration(&self) -> Duration {
        self.params.expiration_seconds
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
            "EAA_CATEGORY".to_string(),
            "OBJECT".to_string(),
            "ARRAY".to_string(),
        ];
        let issuance_exchange_protocols = vec![IssuanceProtocolType::OpenId4VciFinal1_0];
        let mut issuance_did_methods = vec![DidType::Tdw, DidType::Webvh];
        let mut issuance_identifier_types = vec![IdentifierType::Did];
        let mut proof_exchange_protocols =
            vec![VerificationProtocolType::OpenId4VpProximityDraft00];
        let mut verification_identifier_types = vec![IdentifierType::Did];
        let mut signing_algorithms = vec![KeyAlgorithmType::Ecdsa];
        let mut features = vec![
            Features::SelectiveDisclosure,
            Features::SupportsSchemaId,
            Features::SupportsCredentialDesign,
        ];

        if !self.params.swiyu_mode {
            features.push(Features::SupportsCombinedPresentation);
            features.push(Features::SupportsTxCode);
            features.push(Features::SupportsTransactionData);
        }

        if self.params.swiyu_mode {
            datatypes.push("SWIYU_PICTURE".to_string());
            proof_exchange_protocols.push(VerificationProtocolType::OpenId4VpFinal1_0Swiyu)
        } else {
            datatypes.extend_from_slice(&["PICTURE".to_string()]);
            issuance_did_methods.extend_from_slice(&[DidType::Key, DidType::Web, DidType::Jwk]);
            issuance_identifier_types.push(IdentifierType::Certificate);
            proof_exchange_protocols
                .extend_from_slice(&[VerificationProtocolType::OpenId4VpFinal1_0]);
            verification_identifier_types.push(IdentifierType::Certificate);
            signing_algorithms
                .extend_from_slice(&[KeyAlgorithmType::Eddsa, KeyAlgorithmType::MlDsa]);
        }

        let metadata_keys: Vec<_> = self
            .get_metadata_claims()
            .into_iter()
            .map(|c| c.key)
            .collect();

        FormatterCapabilities {
            signing_key_algorithms: signing_algorithms.clone(),
            datatypes,
            features,
            selective_disclosure: vec![SelectiveDisclosure::AnyLevel],
            issuance_did_methods,
            issuance_exchange_protocols,
            proof_exchange_protocols,
            revocation_methods: vec![RevocationType::TokenStatusList],
            verification_key_algorithms: signing_algorithms.clone(),
            verification_key_storages: vec![
                KeyStorageType::Internal,
                KeyStorageType::AzureVault,
                KeyStorageType::SecureElement,
            ],
            forbidden_claim_technical_keys: vec![
                SELECTIVE_DISCLOSURE_MARKER.to_string(),
                SELECTIVE_DISCLOSURE_ARRAY_MARKER.to_string(),
            ],
            forbidden_root_claim_technical_keys: [
                metadata_keys,
                vec!["_sd_alg".to_string(), "status".to_string()],
            ]
            .concat(),
            issuance_identifier_types,
            verification_identifier_types,
            holder_identifier_types: vec![IdentifierType::Did, IdentifierType::Key],
            holder_key_algorithms: signing_algorithms,
            holder_did_methods: vec![
                DidType::Web,
                DidType::Key,
                DidType::Jwk,
                DidType::Tdw,
                DidType::Webvh,
            ],
        }
    }

    fn credential_schema_id<'a>(
        &self,
        id: CredentialSchemaId,
        organisation_id: OrganisationId,
        ecosystem_schema_id: Option<&'a str>,
        core_base_url: &'a str,
        format: &CredentialFormat,
    ) -> Result<String, FormatterError> {
        Ok(match ecosystem_schema_id {
            Some(ecosystem_schema_id) => ecosystem_schema_id.to_string(),
            None => format!("{core_base_url}/ssi/vct/v2/{organisation_id}/{id}/{format}"),
        })
    }

    fn get_metadata_claims(&self) -> Vec<MetadataClaimSchema> {
        // specific SD-JWT VC claims
        let mut sd_jwt_vc_claims = vec![MetadataClaimSchema {
            key: "vct".to_string(),
            data_type: "STRING".to_string(),
            array: false,
            required: true,
        }];

        if self.params.swiyu_mode {
            sd_jwt_vc_claims.push(MetadataClaimSchema {
                key: "vct_metadata_uri".to_string(),
                data_type: "STRING".to_string(),
                array: false,
                required: false,
            });
            sd_jwt_vc_claims.push(MetadataClaimSchema {
                key: "vct_metadata_uri#integrity".to_string(),
                data_type: "STRING".to_string(),
                array: false,
                required: false,
            });
        }

        [jwt_metadata_claims(), sd_jwt_vc_claims].concat()
    }

    fn user_claims_path(&self) -> Vec<String> {
        vec![]
    }

    fn revocation_method_id(&self) -> Option<&RevocationMethodId> {
        self.params.revocation_method.as_ref()
    }

    fn config_name(&self) -> &CredentialFormat {
        &self.config_id
    }
}

impl SDJWTVCFormatter {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        base_url: Option<Arc<str>>,
        config_id: CredentialFormat,
        params: serde_json::Value,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        vct_type_metadata_cache: Arc<dyn VctTypeMetadataFetcher>,
        certificate_validator: Arc<dyn CertificateValidator>,
        datatype_config: DatatypeConfig,
        http_client: Arc<dyn HttpClient>,
        data_type_provider: Arc<dyn DataTypeProvider>,
    ) -> Result<Self, InitializationError> {
        let params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_id.to_string(),
                source: err,
            })?;
        Ok(Self {
            base_url,
            config_id,
            params,
            did_method_provider,
            key_algorithm_provider,
            vct_type_metadata_cache,
            certificate_validator,
            datatype_config,
            http_client,
            data_type_provider,
        })
    }

    async fn extract_credentials_internal(
        &self,
        token: &SerializedCredential,
        credential_schema: Option<&CredentialSchema>,
        verification: Option<VerificationFn>,
    ) -> Result<DetailCredential, FormatterError> {
        let (mut jwt, issuer, _): (Jwt<SdJwtVc>, _, _) = Jwt::build_from_token_with_disclosures(
            token,
            verification.as_ref(),
            Some(&*self.certificate_validator),
            &*self.http_client,
        )
        .await?;

        // SWIYU credentials don't encode image claims with the data uri prefix
        if self.params.swiyu_mode
            && let Some(credential_schema) = credential_schema
        {
            let claim_schemas = credential_schema.claim_schemas.as_ref().await?;
            for claim_schema in &claim_schemas {
                let Some(fields) = self
                    .datatype_config
                    .get_fields(&claim_schema.data_type)
                    .ok()
                else {
                    continue;
                };
                if fields.r#type == DatatypeType::SwiyuPicture {
                    let path = claim_schema.key.split(NESTED_CLAIM_MARKER).collect();
                    post_process_claims(path, &mut jwt.payload.custom.public_claims, |value| {
                        // PNG magic bytes base64 (aligned to not be affected by padding)
                        if value.starts_with("iVBORw0K") {
                            format!("{PNG_DATA_URI_PREFIX}{value}")
                        } else {
                            format!("{JPEG_DATA_URI_PREFIX}{value}")
                        }
                    })
                }
            }
        }

        let metadata_claims = jwt
            .get_metadata_claims()
            .error_while("getting metadata claims")?;
        let subject = jwt
            .payload
            .proof_of_possession_key
            .map(|holder_key| IdentifierDetails::Key(holder_key.jwk.jwk().clone()));

        let mut claims = jwt.payload.custom.public_claims;
        claims.extend(metadata_claims);
        Ok(DetailCredential {
            issuance_date: jwt.payload.issued_at,
            valid_from: jwt.payload.issued_at,
            valid_until: jwt.payload.expires_at,
            update_at: None,
            invalid_before: jwt.payload.invalid_before,
            issuer,
            subject,
            claims,
            status: credential_status_from_sdjwt_status(&jwt.payload.custom.status),
        })
    }
}

/// SWIYU credentials don't encode image claims with the data uri prefix
fn strip_swiyu_picture_prefix(claim: &mut IssuedClaimValue) {
    match claim {
        IssuedClaimValue::SwiyuPicture(value) => {
            *value = value
                .trim_start_matches(JPEG_DATA_URI_PREFIX)
                .trim_start_matches(PNG_DATA_URI_PREFIX)
                .to_string();
        }
        IssuedClaimValue::Object(claims) => {
            claims.values_mut().for_each(strip_swiyu_picture_prefix)
        }
        IssuedClaimValue::Array(claims) => claims.iter_mut().for_each(strip_swiyu_picture_prefix),
        _ => {}
    }
}

fn post_process_claims(
    path: Vec<&str>,
    claims: &mut HashMap<String, CredentialClaim>,
    process: impl Fn(&str) -> String,
) {
    let Some((current, remaining_path)) = path.split_first() else {
        return;
    };
    let Some(current_value) = claims.get_mut(*current) else {
        return;
    };

    post_process_claim_value_at_path(&mut current_value.value, remaining_path, &process);
}

fn post_process_claim_value_at_path(
    value: &mut CredentialClaimValue,
    path: &[&str],
    process: &impl Fn(&str) -> String,
) {
    let Some((current, remaining_path)) = path.split_first() else {
        post_process_claim_value(value, process);
        return;
    };

    if let Some(map_value) = value.as_object_mut() {
        let Some(current_value) = map_value.get_mut(*current) else {
            return;
        };
        post_process_claim_value_at_path(&mut current_value.value, remaining_path, process);
    } else if let Some(array_value) = value.as_array_mut() {
        for claim in array_value {
            post_process_claim_value_at_path(&mut claim.value, path, process);
        }
    }
}

fn post_process_claim_value(value: &mut CredentialClaimValue, process: &impl Fn(&str) -> String) {
    if let Some(str_value) = value.as_str() {
        *value = CredentialClaimValue::String(process(str_value));
    } else if let Some(map_value) = value.as_object_mut() {
        for claim in map_value.values_mut() {
            post_process_claim_value(&mut claim.value, process);
        }
    } else if let Some(array_value) = value.as_array_mut() {
        for claim in array_value {
            post_process_claim_value(&mut claim.value, process);
        }
    }
}

fn sdjwt_vc_from_credential(
    credential_status: Vec<CredentialStatus>,
    mut hashed_claims: Vec<String>,
    algorithm: HashAlgorithm,
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
        hash_alg: Some(algorithm.to_string()),
        status: status.map(|status| SdJwtVcStatus {
            status_list: status,
            custom_claims: Default::default(),
        }),
        public_claims: Default::default(),
        vc_type,
        vct_integrity,
    })
}
