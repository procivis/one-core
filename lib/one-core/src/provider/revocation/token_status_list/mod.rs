//! Token Status List implementation.
//! https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-03

use std::collections::HashMap;
use std::sync::Arc;

use resolver::{StatusListCacheEntry, StatusListResolver};
use serde::{Deserialize, Serialize};
use shared_types::{CredentialId, IdentifierId};

use crate::model::credential::{Credential, CredentialStateEnum};
use crate::model::did::{KeyFilter, KeyRole};
use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::revocation_list::{StatusListCredentialFormat, StatusListType};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::jwt::Jwt;
use crate::proto::key_verification::KeyVerification;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt_formatter::model::TokenStatusListContent;
use crate::provider::credential_formatter::model::{
    CredentialStatus, IdentifierDetails, TokenVerifier,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::credential_formatter::sdjwtvc_formatter::model::SdJwtVcStatus;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::model::{
    CredentialAdditionalData, CredentialDataByRole, CredentialRevocationInfo,
    CredentialRevocationState, JsonLdContext, Operation, RevocationListId,
    RevocationMethodCapabilities, RevocationUpdate,
};
use crate::provider::revocation::token_status_list::model::RevocationUpdateData;
use crate::provider::revocation::token_status_list::resolver::StatusListCachingLoader;
use crate::provider::revocation::token_status_list::util::{
    PREFERRED_ENTRY_SIZE, calculate_preferred_token_size,
};
use crate::util::params::convert_params;

pub mod model;
pub mod resolver;
pub mod util;

#[cfg(test)]
mod test;

pub(crate) const URI_KEY: &str = "uri";
pub(crate) const INDEX_KEY: &str = "idx";
const CREDENTIAL_STATUS_TYPE: &str = "TokenStatusListEntry";

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub format: StatusListCredentialFormat,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            format: StatusListCredentialFormat::Jwt,
        }
    }
}

pub struct TokenStatusList {
    pub core_base_url: Option<String>,
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    pub did_method_provider: Arc<dyn DidMethodProvider>,
    pub key_provider: Arc<dyn KeyProvider>,
    pub caching_loader: StatusListCachingLoader,
    pub formatter_provider: Arc<dyn CredentialFormatterProvider>,
    pub certificate_validator: Arc<dyn CertificateValidator>,
    resolver: Arc<StatusListResolver>,
    params: Params,
}

impl TokenStatusList {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        core_base_url: Option<String>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_provider: Arc<dyn KeyProvider>,
        caching_loader: StatusListCachingLoader,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        client: Arc<dyn HttpClient>,
        params: Option<Params>,
    ) -> Result<Self, RevocationError> {
        let params = params.unwrap_or_default();

        if params.format != StatusListCredentialFormat::Jwt {
            return Err(RevocationError::ValidationError(
                "Token revocation format must be JWT".to_string(),
            ));
        }

        Ok(Self {
            core_base_url,
            key_algorithm_provider,
            did_method_provider,
            key_provider,
            caching_loader,
            formatter_provider,
            certificate_validator,
            resolver: Arc::new(StatusListResolver::new(client)),
            params,
        })
    }
}

#[async_trait::async_trait]
impl RevocationMethod for TokenStatusList {
    fn get_status_type(&self) -> String {
        CREDENTIAL_STATUS_TYPE.to_string()
    }

    async fn add_issued_credential(
        &self,
        credential: &Credential,
        additional_data: Option<CredentialAdditionalData>,
    ) -> Result<(Option<RevocationUpdate>, Vec<CredentialRevocationInfo>), RevocationError> {
        let data = additional_data.ok_or(RevocationError::MappingError(
            "additional_data is None".to_string(),
        ))?;

        let issuer_identifier =
            credential
                .issuer_identifier
                .as_ref()
                .ok_or(RevocationError::MappingError(
                    "issuer identifier is None".to_string(),
                ))?;

        let index_on_status_list = self.get_credential_index_on_revocation_list(
            &data.credentials_by_issuer_identifier,
            &credential.id,
            &issuer_identifier.id,
        )?;

        let revocation_info = vec![CredentialRevocationInfo {
            credential_status: self.create_credential_status(
                &data.revocation_list_id,
                index_on_status_list,
                "revocation",
            )?,
        }];

        Ok((None, revocation_info))
    }

    async fn mark_credential_as(
        &self,
        credential: &Credential,
        new_state: CredentialRevocationState,
        additional_data: Option<CredentialAdditionalData>,
    ) -> Result<RevocationUpdate, RevocationError> {
        let additional_data = additional_data.ok_or(RevocationError::MappingError(
            "additional_data is None".to_string(),
        ))?;

        self.mark_credential_as_impl(credential, new_state, additional_data)
            .await
    }

    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        issuer_details: &IdentifierDetails,
        _additional_credential_data: Option<CredentialDataByRole>,
        force_refresh: bool,
    ) -> Result<CredentialRevocationState, RevocationError> {
        if credential_status.r#type != CREDENTIAL_STATUS_TYPE {
            return Err(RevocationError::ValidationError(format!(
                "Invalid credential status type: {}",
                credential_status.r#type
            )));
        }

        let list_url = credential_status
            .additional_fields
            .get(URI_KEY)
            .and_then(|url| url.as_str())
            .ok_or(RevocationError::ValidationError(
                "Missing status list url".to_string(),
            ))?;

        let list_index = credential_status
            .additional_fields
            .get(INDEX_KEY)
            .and_then(|index| index.as_str())
            .ok_or(RevocationError::ValidationError(
                "Missing status list index".to_string(),
            ))?;
        let list_index: usize = list_index
            .parse()
            .map_err(|_| RevocationError::ValidationError("Invalid list index".to_string()))?;

        let (content, _media_type) = &self
            .caching_loader
            .get(list_url, self.resolver.clone(), force_refresh)
            .await?;

        let response: StatusListCacheEntry = serde_json::from_slice(content)?;

        let response_content = String::from_utf8(response.content)?;
        let key_verification: Box<dyn TokenVerifier> = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
            certificate_validator: self.certificate_validator.clone(),
        });

        // TODO: ONE-6158 validate issuer certificate/CA of status-list is trusted

        let issuer_did = if let IdentifierDetails::Did(issuer_did) = issuer_details {
            Some(issuer_did.to_owned())
        } else {
            None
        };

        let jwt: Jwt<TokenStatusListContent> =
            Jwt::build_from_token(&response_content, Some(&key_verification), issuer_did).await?;

        Ok(util::extract_state_from_token(
            &jwt.payload.custom.status_list,
            list_index,
        )?)
    }

    fn get_capabilities(&self) -> RevocationMethodCapabilities {
        RevocationMethodCapabilities {
            operations: vec![Operation::Revoke, Operation::Suspend],
        }
    }

    fn get_params(&self) -> Result<serde_json::Value, RevocationError> {
        convert_params(self.params.clone()).map_err(RevocationError::from)
    }

    fn get_json_ld_context(&self) -> Result<JsonLdContext, RevocationError> {
        Ok(JsonLdContext::default())
    }
}

impl TokenStatusList {
    fn get_formatter_for_issuance(&self) -> Result<Arc<dyn CredentialFormatter>, RevocationError> {
        let format = self.params.format.to_string();

        self.formatter_provider
            .get_credential_formatter(&format)
            .ok_or(RevocationError::FormatterNotFound(format))
    }

    fn get_credential_index_on_revocation_list(
        &self,
        credentials_by_issuer_did: &[Credential],
        credential_id: &CredentialId,
        issuer_identifier_id: &IdentifierId,
    ) -> Result<usize, RevocationError> {
        let index = credentials_by_issuer_did
            .iter()
            .position(|credential| credential.id == *credential_id)
            .ok_or(RevocationError::MissingCredentialIndexOnRevocationList(
                *credential_id,
                *issuer_identifier_id,
            ))?;

        Ok(index)
    }

    fn create_credential_status(
        &self,
        revocation_list_id: &RevocationListId,
        index_on_status_list: usize,
        purpose: &str,
    ) -> Result<CredentialStatus, RevocationError> {
        create_credential_status(
            &self.core_base_url,
            revocation_list_id,
            index_on_status_list,
            purpose,
        )
    }

    async fn mark_credential_as_impl(
        &self,
        credential: &Credential,
        new_revocation_value: CredentialRevocationState,
        data: CredentialAdditionalData,
    ) -> Result<RevocationUpdate, RevocationError> {
        let list_id = data.revocation_list_id;

        let issuer_identifier =
            credential
                .issuer_identifier
                .as_ref()
                .ok_or(RevocationError::MappingError(
                    "issuer identifier is None".to_string(),
                ))?;

        let encoded_list = generate_token_from_credentials(
            &data.credentials_by_issuer_identifier,
            Some(TokenCredentialInfo {
                credential_id: credential.id,
                value: new_revocation_value,
            }),
        )
        .await?;

        let list_credential = format_status_list_credential(
            &list_id,
            issuer_identifier,
            encoded_list,
            &*self.key_provider,
            &self.key_algorithm_provider,
            &self.core_base_url,
            &*self.get_formatter_for_issuance()?,
        )
        .await?;

        Ok(RevocationUpdate {
            status_type: self.get_status_type(),
            data: serde_json::to_vec(&RevocationUpdateData {
                id: list_id,
                value: list_credential.as_bytes().to_vec(),
            })?,
        })
    }
}

fn create_credential_status(
    core_base_url: &Option<String>,
    revocation_list_id: &RevocationListId,
    index_on_status_list: usize,
    purpose: &str,
) -> Result<CredentialStatus, RevocationError> {
    let revocation_list_url = get_revocation_list_url(revocation_list_id, core_base_url)?;
    Ok(CredentialStatus {
        id: Some(
            uuid::Uuid::new_v4()
                .urn()
                .to_string()
                .parse()
                .map_err(|e| {
                    RevocationError::ValidationError(format!("Failed to parse URL: `{e}`"))
                })?,
        ),
        r#type: CREDENTIAL_STATUS_TYPE.to_string(),
        status_purpose: Some(purpose.to_string()),
        additional_fields: HashMap::from([
            (URI_KEY.to_string(), revocation_list_url.into()),
            (
                INDEX_KEY.to_string(),
                index_on_status_list.to_string().into(),
            ),
        ]),
    })
}

pub(crate) fn credential_status_from_sdjwt_status(
    sd_jwt_status: &Option<SdJwtVcStatus>,
) -> Vec<CredentialStatus> {
    match sd_jwt_status {
        None => vec![],
        Some(value) => {
            vec![CredentialStatus {
                id: None,
                r#type: CREDENTIAL_STATUS_TYPE.to_string(),
                status_purpose: Some("revocation".to_string()),
                additional_fields: HashMap::from([
                    (
                        URI_KEY.to_string(),
                        serde_json::Value::String(value.status_list.uri.to_string()),
                    ),
                    (
                        INDEX_KEY.to_string(),
                        serde_json::Value::String(value.status_list.index.to_string()),
                    ),
                ]),
            }]
        }
    }
}

pub(crate) struct TokenCredentialInfo {
    pub credential_id: CredentialId,
    pub value: CredentialRevocationState,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn format_status_list_credential(
    revocation_list_id: &RevocationListId,
    issuer_identifier: &Identifier,
    encoded_list: String,
    key_provider: &dyn KeyProvider,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    core_base_url: &Option<String>,
    formatter: &dyn CredentialFormatter,
) -> Result<String, RevocationError> {
    let revocation_list_url = get_revocation_list_url(revocation_list_id, core_base_url)?;

    let key = issuer_identifier
        .find_matching_key(&KeyFilter::role_filter(KeyRole::AssertionMethod))
        .map_err(|_| RevocationError::KeyWithRoleNotFound(KeyRole::AssertionMethod))?
        .ok_or(RevocationError::KeyWithRoleNotFound(
            KeyRole::AssertionMethod,
        ))?;

    let key_id = if issuer_identifier.r#type == IdentifierType::Did {
        let issuer_did = issuer_identifier
            .did
            .as_ref()
            .ok_or(RevocationError::MappingError(
                "issuer did is None".to_string(),
            ))?;

        let key = issuer_did
            .find_key(&key.id, &KeyFilter::role_filter(KeyRole::AssertionMethod))
            .map_err(|_| RevocationError::KeyWithRoleNotFound(KeyRole::AssertionMethod))?
            .ok_or(RevocationError::KeyWithRoleNotFound(
                KeyRole::AssertionMethod,
            ))?;

        Some(issuer_did.verification_method_id(key))
    } else {
        None
    };

    let auth_fn =
        key_provider.get_signature_provider(key, key_id, key_algorithm_provider.clone())?;

    let algorithm = key
        .key_algorithm_type()
        .ok_or(FormatterError::CouldNotFormat(format!(
            "Unsupported algorithm: {}",
            key.key_type
        )))?;

    let status_list = formatter
        .format_status_list(
            revocation_list_url,
            issuer_identifier,
            encoded_list,
            algorithm,
            auth_fn,
            StatusPurpose::Revocation,
            StatusListType::TokenStatusList,
        )
        .await?;

    Ok(status_list)
}

pub(crate) async fn generate_token_from_credentials(
    credentials_by_issuer_did: &[Credential],
    additionally_changed_credential: Option<TokenCredentialInfo>,
) -> Result<String, RevocationError> {
    let states = credentials_by_issuer_did
        .iter()
        .map(|credential| {
            if let Some(changed_credential) = additionally_changed_credential.as_ref()
                && changed_credential.credential_id == credential.id
            {
                return Ok(changed_credential.value.clone());
            }

            Ok(credential_state_into_revocation_state(credential.state))
        })
        .collect::<Result<Vec<_>, RevocationError>>()?;

    let preferred_token_size = calculate_preferred_token_size(states.len(), PREFERRED_ENTRY_SIZE);
    util::generate_token(states, PREFERRED_ENTRY_SIZE, preferred_token_size)
        .map_err(RevocationError::from)
}

fn credential_state_into_revocation_state(
    credential_state: CredentialStateEnum,
) -> CredentialRevocationState {
    match credential_state {
        CredentialStateEnum::Revoked => CredentialRevocationState::Revoked,
        CredentialStateEnum::Suspended => CredentialRevocationState::Suspended {
            suspend_end_date: None,
        },
        _ => CredentialRevocationState::Valid,
    }
}

fn get_revocation_list_url(
    revocation_list_id: &RevocationListId,
    core_base_url: &Option<String>,
) -> Result<String, RevocationError> {
    Ok(format!(
        "{}/ssi/revocation/v1/list/{}",
        core_base_url.as_ref().ok_or(RevocationError::MappingError(
            "Host URL not specified".to_string()
        ))?,
        revocation_list_id
    ))
}
