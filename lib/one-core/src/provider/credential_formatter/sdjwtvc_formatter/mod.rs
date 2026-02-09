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
use model::{SdJwtVc, SdJwtVcStatus};
use one_crypto::CryptoProvider;
use sdjwt::format_credential;
use serde::Deserialize;
use serde_json::Value;
use shared_types::{CredentialSchemaId, DidValue};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::error::FormatterError;
use super::json_claims::{parse_claims, prepare_identifier};
use super::model::{
    AuthenticationFn, CredentialClaim, CredentialClaimValue, CredentialData,
    CredentialPresentation, CredentialStatus, CredentialSubject, DetailCredential, Features,
    FormatterCapabilities, HolderBindingCtx, IdentifierDetails, PublishedClaim,
    SelectiveDisclosure, VerificationFn,
};
use super::sdjwt::disclosures::parse_token;
use super::sdjwt::model::{DecomposedToken, KeyBindingPayload, SdJwtFormattingInputs};
use super::sdjwt::{SdJwtHolderBindingParams, prepare_sd_presentation};
use super::vcdm::VcdmCredential;
use super::{CredentialFormatter, MetadataClaimSchema, sdjwt};
use crate::config::core_config::{
    DatatypeConfig, DatatypeType, DidType, IdentifierType, IssuanceProtocolType, KeyAlgorithmType,
    KeyStorageType, RevocationType, VerificationProtocolType,
};
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{CredentialSchema, LayoutType};
use crate::model::identifier::Identifier;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::http_client::HttpClient;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::{JWTPayload, jwt_metadata_claims};
use crate::provider::caching_loader::vct::VctTypeMetadataFetcher;
use crate::provider::data_type::provider::DataTypeProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::provider::revocation::token_status_list::credential_status_from_sdjwt_status;
use crate::service::credential_schema::dto::CreateCredentialSchemaRequestDTO;

const JPEG_DATA_URI_PREFIX: &str = "data:image/jpeg;base64,";

pub struct SDJWTVCFormatter {
    crypto: Arc<dyn CryptoProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    vct_type_metadata_cache: Arc<dyn VctTypeMetadataFetcher>,
    certificate_validator: Arc<dyn CertificateValidator>,
    datatype_config: DatatypeConfig,
    http_client: Arc<dyn HttpClient>,
    data_type_provider: Arc<dyn DataTypeProvider>,
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
    #[serde(default = "default_sd_array_elements")]
    pub sd_array_elements: bool,
    #[serde(default)]
    ecosystem_schema_ids: Vec<String>,
}

fn default_sd_array_elements() -> bool {
    true
}

#[async_trait]
impl CredentialFormatter for SDJWTVCFormatter {
    async fn parse_credential(&self, credential: &str) -> Result<Credential, FormatterError> {
        let now = OffsetDateTime::now_utc();

        let (parsed_credential, _, issuer): (Jwt<SdJwtVc>, _, _) =
            Jwt::build_from_token_with_disclosures(
                credential,
                &*self.crypto,
                None,
                SdJwtHolderBindingParams {
                    holder_binding_context: None,
                    leeway: Duration::seconds(self.get_leeway() as i64),
                    skip_holder_binding_aud_check: true,
                },
                Some(&*self.certificate_validator),
                &*self.http_client,
            )
            .await?;

        let revocation_method = parsed_credential
            .payload
            .custom
            .status
            .as_ref()
            .map(|_| RevocationType::TokenStatusList);

        let credential_id = Uuid::new_v4().into();
        let vct = parsed_credential.payload.custom.vc_type.clone();

        // Get metadata claims first (includes vct and standard JWT claims)
        let metadata_claims = parsed_credential.get_metadata_claims()?;

        // Parse claims from public_claims
        let (mut claims, mut claim_schemas) = parse_claims(
            parsed_credential.payload.custom.public_claims,
            self.data_type_provider.as_ref(),
            credential_id,
        )?;

        // Add parsed metadata claims
        let (metadata_claims, metadata_claim_schemas) = parse_claims(
            metadata_claims,
            self.data_type_provider.as_ref(),
            credential_id,
        )?;
        claims.extend(metadata_claims);
        claim_schemas.extend(metadata_claim_schemas);

        let schema = CredentialSchema {
            id: Uuid::new_v4().into(),
            deleted_at: None,
            created_date: now,
            last_modified: now,
            // Will be overridden based on issuer metadata
            name: vct.clone(),
            format: "".into(), // Will be overridden based on config priority
            revocation_method: revocation_method.map(|v| v.to_string().into()),
            key_storage_security: None,
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: vct,
            imported_source_url: "".to_string(),
            allow_suspension: false,
            requires_wallet_instance_attestation: false,
            claim_schemas: Some(claim_schemas),
            organisation: None,
            transaction_code: None,
        };

        let issuer_identifier = prepare_identifier(&issuer, self.key_algorithm_provider.as_ref())?;
        let holder_identifier = parsed_credential
            .payload
            .subject
            .map(|did| DidValue::from_str(&did))
            .transpose()
            .map_err(|e| FormatterError::Failed(e.to_string()))?
            .map(IdentifierDetails::Did)
            .map(|details| prepare_identifier(&details, self.key_algorithm_provider.as_ref()))
            .transpose()?;

        Ok(Credential {
            id: credential_id,
            created_date: now,
            issuance_date: parsed_credential.payload.issued_at,
            last_modified: now,
            deleted_at: None,
            protocol: "".to_string(),
            redirect_uri: None,
            role: CredentialRole::Holder,
            state: CredentialStateEnum::Accepted,
            suspend_end_date: None,
            profile: None,
            credential_blob_id: None,
            wallet_unit_attestation_blob_id: None,
            wallet_instance_attestation_blob_id: None,
            claims: Some(claims),
            issuer_certificate: issuer_identifier
                .certificates
                .as_ref()
                .and_then(|certs| certs.first().cloned()),
            issuer_identifier: Some(issuer_identifier),
            holder_identifier,
            schema: Some(schema),
            interaction: None,
            key: None,
        })
    }

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

        let token_type = if self.params.swiyu_mode {
            // SWIYU still uses the old typ
            "vc+sd-jwt".to_string()
        } else {
            "dc+sd-jwt".to_string()
        };
        let inputs = SdJwtFormattingInputs {
            holder_identifier: credential_data.holder_identifier,
            holder_key_id: credential_data.holder_key_id,
            leeway: self.params.leeway,
            token_type,
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
            &*self.key_algorithm_provider,
            payload_from_digests,
            self.params.sd_array_elements,
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
        _status_list_type: RevocationType,
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

    async fn prepare_selective_disclosure(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        let DecomposedToken { jwt, .. } = parse_token(&credential.token)?;
        let jwt: Jwt<SdJwtVc> = Jwt::build_from_token(jwt, None, None).await?;
        let hasher = self
            .crypto
            .get_hasher(&jwt.payload.custom.hash_alg.unwrap_or("sha-256".to_string()))?;

        prepare_sd_presentation(credential, &*hasher, &self.user_claims_path()).await
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
        let mut features = vec![
            Features::SelectiveDisclosure,
            Features::SupportsSchemaId,
            Features::RequiresSchemaIdForExternal,
            Features::SupportsCredentialDesign,
        ];

        if !self.params.swiyu_mode {
            features.push(Features::SupportsCombinedPresentation);
            features.push(Features::SupportsTxCode);
        }

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
            issuance_exchange_protocols.push(IssuanceProtocolType::OpenId4VciFinal1_0);
            issuance_identifier_types.push(IdentifierType::Certificate);
            proof_exchange_protocols.extend_from_slice(&[
                VerificationProtocolType::OpenId4VpDraft20,
                VerificationProtocolType::OpenId4VpDraft25,
                VerificationProtocolType::OpenId4VpFinal1_0,
            ]);
            verification_identifier_types.push(IdentifierType::Certificate);
            signing_algorithms
                .extend_from_slice(&[KeyAlgorithmType::Eddsa, KeyAlgorithmType::MlDsa]);
        }

        FormatterCapabilities {
            signing_key_algorithms: signing_algorithms.clone(),
            allowed_schema_ids: vec![],
            ecosystem_schema_ids: self.params.ecosystem_schema_ids.to_owned(),
            datatypes,
            features,
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
            holder_identifier_types: vec![IdentifierType::Did, IdentifierType::Key],
            holder_key_algorithms: signing_algorithms,
            holder_did_methods: vec![DidType::Web, DidType::Key, DidType::Jwk, DidType::WebVh],
        }
    }

    fn credential_schema_id(
        &self,
        id: CredentialSchemaId,
        request: &CreateCredentialSchemaRequestDTO,
        core_base_url: &str,
    ) -> Result<String, FormatterError> {
        Ok(
            match (request.external_schema, request.schema_id.as_ref()) {
                (_, Some(schema_id)) => schema_id.to_string(),
                (false, None) => format!(
                    "{core_base_url}/ssi/vct/v1/{}/{id}",
                    request.organisation_id
                ),
                _ => {
                    return Err(FormatterError::Failed(
                        "Invalid combination schema_id/external".to_string(),
                    ));
                }
            },
        )
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
}

impl SDJWTVCFormatter {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        params: Params,
        crypto: Arc<dyn CryptoProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        vct_type_metadata_cache: Arc<dyn VctTypeMetadataFetcher>,
        certificate_validator: Arc<dyn CertificateValidator>,
        datatype_config: DatatypeConfig,
        http_client: Arc<dyn HttpClient>,
        data_type_provider: Arc<dyn DataTypeProvider>,
    ) -> Self {
        Self {
            params,
            crypto,
            did_method_provider,
            key_algorithm_provider,
            vct_type_metadata_cache,
            certificate_validator,
            datatype_config,
            http_client,
            data_type_provider,
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
        if self.params.swiyu_mode
            && let Some(claim_schemas) =
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
                if fields.r#type == DatatypeType::SwiyuPicture {
                    let path = claim_schema.schema.key.split(NESTED_CLAIM_MARKER).collect();
                    post_process_claims(path, &mut jwt.payload.custom.public_claims, |value| {
                        format!("{JPEG_DATA_URI_PREFIX}{value}")
                    })
                }
            }
        }

        let metadata_claims = jwt.get_metadata_claims()?;
        let subject = jwt
            .payload
            .subject
            .map(|did| DidValue::from_str(&did))
            .transpose()
            .map_err(|e| FormatterError::Failed(e.to_string()))?
            .map(IdentifierDetails::Did);

        let mut claims = CredentialSubject {
            claims: jwt.payload.custom.public_claims,
            id: None,
        };
        claims.claims.extend(metadata_claims);
        Ok((
            DetailCredential {
                id: jwt.payload.jwt_id,
                issuance_date: jwt.payload.issued_at,
                valid_from: jwt.payload.issued_at,
                valid_until: jwt.payload.expires_at,
                update_at: None,
                invalid_before: jwt.payload.invalid_before,
                issuer,
                subject,
                claims,
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
        let claims = credential
            .credential_subject
            .first()
            .map(|cs| cs.claims.clone())
            .ok_or_else(|| {
                FormatterError::Failed("Credential is missing credential subject".to_string())
            })?;

        let mut claims = HashMap::from_iter(claims);

        if self.params.swiyu_mode {
            // Remove data uri prefix from image claim values when formatting for SWIYU
            for published_claim in published_claims.iter().filter(|claim| {
                let Some(ref data_type) = claim.datatype else {
                    return false;
                };
                let Some(fields) = self.datatype_config.get_fields(data_type).ok() else {
                    return false;
                };
                fields.r#type == DatatypeType::SwiyuPicture
            }) {
                let path = published_claim.key.split(NESTED_CLAIM_MARKER).collect();
                post_process_claims(path, &mut claims, |value| {
                    value.trim_start_matches(JPEG_DATA_URI_PREFIX).to_string()
                });
            }
        }
        Ok(Value::Object(serde_json::Map::from_iter(
            claims
                .into_iter()
                .map(|(key, value)| (key, serde_json::Value::from(value.value))),
        )))
    }
}

fn post_process_claims(
    mut path: Vec<&str>,
    claims: &mut HashMap<String, CredentialClaim>,
    process: impl Fn(&str) -> String,
) {
    let Some(current) = path.pop() else { return };
    let Some(current_value) = claims.get_mut(current) else {
        return;
    };

    if path.is_empty() {
        let Some(str_value) = current_value.value.as_str() else {
            return;
        };
        current_value.value = CredentialClaimValue::String(process(str_value));
    } else {
        let Some(map_value) = current_value.value.as_object_mut() else {
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
