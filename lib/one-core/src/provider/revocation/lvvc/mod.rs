//! LVVC implementation.
//! https://eprint.iacr.org/2022/1658.pdf

use std::collections::HashMap;
use std::ops::Sub;
use std::sync::Arc;

use holder_fetch::holder_get_lvvc;
use serde::{Deserialize, Serialize};
use serde_with::DurationSeconds;
use shared_types::DidValue;
use time::{Duration, OffsetDateTime};
use url::Url;
use util::get_lvvc_credential_subject;
use uuid::Uuid;
use uuid::fmt::Urn;

use self::dto::LvvcStatus;
use self::mapper::{create_status_claims, status_from_lvvc_claims};
use crate::model::credential::Credential;
use crate::provider::credential_formatter::model::{
    CredentialData, CredentialStatus, Issuer, IssuerDetails,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::credential_formatter::vcdm::{
    ContextType, VcdmCredential, VcdmCredentialSubject,
};
use crate::provider::credential_formatter::{CredentialFormatter, nest_claims};
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::lvvc::dto::Lvvc;
use crate::provider::revocation::model::{
    CredentialAdditionalData, CredentialDataByRole, CredentialRevocationInfo,
    CredentialRevocationState, JsonLdContext, Operation, RevocationMethodCapabilities,
    RevocationUpdate, VerifierCredentialData,
};
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::util::params::convert_params;

pub mod dto;
pub(crate) mod holder_fetch;
pub mod mapper;
pub mod util;

#[cfg(test)]
mod test;

#[serde_with::serde_as]
#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    /// issued LVVC credential expiration duration
    #[serde_as(as = "DurationSeconds<i64>")]
    pub credential_expiry: time::Duration,

    /// time limit whether to reuse an old LVVC or issue a new one
    #[serde_as(as = "DurationSeconds<i64>")]
    pub minimum_refresh_time: time::Duration,

    /// custom JSON-LD context inside the issued LVVC (defaults to /ssi/context/v1/lvvc.json)
    pub json_ld_context_url: Option<String>,
}

pub struct LvvcProvider {
    core_base_url: Option<String>,
    credential_formatter: Arc<dyn CredentialFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    client: Arc<dyn HttpClient>,
    params: Params,
}

#[allow(clippy::too_many_arguments)]
impl LvvcProvider {
    pub fn new(
        core_base_url: Option<String>,
        credential_formatter: Arc<dyn CredentialFormatterProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        client: Arc<dyn HttpClient>,
        params: Params,
    ) -> Self {
        Self {
            core_base_url,
            credential_formatter,
            did_method_provider,
            validity_credential_repository,
            key_provider,
            key_algorithm_provider,
            client,
            params,
        }
    }

    fn get_base_url(&self) -> Result<&String, RevocationError> {
        self.core_base_url.as_ref().ok_or_else(|| {
            RevocationError::MappingError("LVVC issuance is missing core base_url".to_string())
        })
    }

    fn formatter(
        &self,
        credential: &Credential,
    ) -> Result<Arc<dyn CredentialFormatter>, RevocationError> {
        let format = credential
            .schema
            .as_ref()
            .map(|schema| schema.format.as_str())
            .ok_or(RevocationError::MappingError(
                "credential_schema is None".to_string(),
            ))?;

        let formatter = self
            .credential_formatter
            .get_formatter(format)
            .ok_or_else(|| RevocationError::FormatterNotFound(format.to_owned()))?;

        Ok(formatter)
    }

    async fn create_lvvc_with_status(
        &self,
        credential: &Credential,
        status: LvvcStatus,
    ) -> Result<RevocationUpdate, RevocationError> {
        Ok(RevocationUpdate {
            status_type: self.get_status_type(),
            data: serde_json::to_vec(
                &create_lvvc_with_status(
                    credential,
                    status,
                    &self.core_base_url,
                    self.params.credential_expiry,
                    self.formatter(credential)?,
                    self.key_provider.clone(),
                    self.key_algorithm_provider.clone(),
                    self.did_method_provider.clone(),
                    self.get_json_ld_context()?,
                )
                .await?,
            )?,
        })
    }

    async fn check_revocation_status_as_holder(
        &self,
        credential: &Credential,
        credential_status: &CredentialStatus,
        force_refresh: bool,
    ) -> Result<CredentialRevocationState, RevocationError> {
        let lvvc = holder_get_lvvc(
            credential,
            credential_status,
            &*self.validity_credential_repository,
            &*self.key_provider,
            &self.key_algorithm_provider,
            &*self.did_method_provider,
            &*self.client,
            &self.params,
            force_refresh,
        )
        .await?;

        let lvvc_credential_content = std::str::from_utf8(&lvvc.credential)
            .map_err(|e| RevocationError::MappingError(e.to_string()))?;

        let formatter = self.formatter(credential)?;

        let lvvc = formatter
            .extract_credentials_unverified(lvvc_credential_content, None)
            .await?;

        let status = status_from_lvvc_claims(&lvvc.claims.claims)?;
        Ok(match status {
            LvvcStatus::Accepted => CredentialRevocationState::Valid,
            LvvcStatus::Revoked => CredentialRevocationState::Revoked,
            LvvcStatus::Suspended { suspend_end_date } => {
                CredentialRevocationState::Suspended { suspend_end_date }
            }
        })
    }

    fn check_revocation_status_as_verifier(
        &self,
        issuer_did: &DidValue,
        data: VerifierCredentialData,
    ) -> Result<CredentialRevocationState, RevocationError> {
        let credential_id = data
            .credential
            .id
            .as_ref()
            .ok_or(RevocationError::ValidationError(
                "credential id missing".to_string(),
            ))?;

        let lvvc = data
            .extracted_lvvcs
            .iter()
            .find(|lvvc| get_lvvc_credential_subject(lvvc).is_some_and(|id| id == credential_id))
            .ok_or(RevocationError::ValidationError(
                "no matching LVVC found among credentials".to_string(),
            ))?;

        let IssuerDetails::Did(ref lvvc_issuer_did) = lvvc.issuer else {
            return Err(RevocationError::ValidationError(
                "LVVC issuer DID missing".to_string(),
            ));
        };

        if issuer_did != lvvc_issuer_did {
            return Err(RevocationError::ValidationError(
                "LVVC issuer DID is not equal to issuer DID".to_string(),
            ));
        }

        let lvvc_issued_at = lvvc.valid_from.ok_or(RevocationError::ValidationError(
            "LVVC issued_at missing".to_string(),
        ))?;

        if let Some(validity_constraint) = data.proof_input.validity_constraint {
            let now = OffsetDateTime::now_utc();

            if now.sub(Duration::seconds(validity_constraint)) > lvvc_issued_at {
                return Err(RevocationError::ValidationError(
                    "LVVC has expired".to_string(),
                ));
            }
        }

        let status = status_from_lvvc_claims(&lvvc.claims.claims)?;
        Ok(match status {
            LvvcStatus::Accepted => CredentialRevocationState::Valid,
            LvvcStatus::Revoked => CredentialRevocationState::Revoked,
            LvvcStatus::Suspended { suspend_end_date } => {
                CredentialRevocationState::Suspended { suspend_end_date }
            }
        })
    }

    fn get_json_ld_context_url(&self) -> Result<Option<String>, RevocationError> {
        if let Some(json_ld_params_context_url) = &self.params.json_ld_context_url {
            return Ok(Some(json_ld_params_context_url.to_string()));
        }
        Ok(Some(format!(
            "{}/ssi/context/v1/lvvc.json",
            self.get_base_url()?
        )))
    }
}

#[async_trait::async_trait]
impl RevocationMethod for LvvcProvider {
    fn get_status_type(&self) -> String {
        "LVVC".to_string()
    }

    async fn add_issued_credential(
        &self,
        credential: &Credential,
        _additional_data: Option<CredentialAdditionalData>,
    ) -> Result<(Option<RevocationUpdate>, Vec<CredentialRevocationInfo>), RevocationError> {
        let base_url = self.get_base_url()?;

        Ok((
            Some(
                self.create_lvvc_with_status(credential, LvvcStatus::Accepted)
                    .await?,
            ),
            vec![CredentialRevocationInfo {
                credential_status: CredentialStatus {
                    id: Some(
                        format!("{base_url}/ssi/revocation/v1/lvvc/{}", credential.id)
                            .parse()
                            .map_err(|e| {
                                RevocationError::ValidationError(format!(
                                    "Failed to parse URL: `{e}`"
                                ))
                            })?,
                    ),
                    r#type: self.get_status_type(),
                    status_purpose: None,
                    additional_fields: HashMap::new(),
                },
            }],
        ))
    }

    async fn mark_credential_as(
        &self,
        credential: &Credential,
        new_state: CredentialRevocationState,
        _additional_data: Option<CredentialAdditionalData>,
    ) -> Result<RevocationUpdate, RevocationError> {
        match new_state {
            CredentialRevocationState::Revoked => {
                self.create_lvvc_with_status(credential, LvvcStatus::Revoked)
                    .await
            }
            CredentialRevocationState::Valid => {
                self.create_lvvc_with_status(credential, LvvcStatus::Accepted)
                    .await
            }
            CredentialRevocationState::Suspended { suspend_end_date } => {
                self.create_lvvc_with_status(credential, LvvcStatus::Suspended { suspend_end_date })
                    .await
            }
        }
    }

    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        issuer_details: &IssuerDetails,
        additional_credential_data: Option<CredentialDataByRole>,
        force_refresh: bool,
    ) -> Result<CredentialRevocationState, RevocationError> {
        let IssuerDetails::Did(issuer_did) = issuer_details else {
            return Err(RevocationError::ValidationError(
                "issuer did is missing".to_string(),
            ));
        };

        let additional_credential_data = additional_credential_data.ok_or(
            RevocationError::ValidationError("additional_credential_data is None".to_string()),
        )?;

        match additional_credential_data {
            CredentialDataByRole::Holder(credential) => {
                self.check_revocation_status_as_holder(
                    &credential,
                    credential_status,
                    force_refresh,
                )
                .await
            }
            CredentialDataByRole::Verifier(data) => {
                self.check_revocation_status_as_verifier(issuer_did, *data)
            }
        }
    }

    fn get_capabilities(&self) -> RevocationMethodCapabilities {
        RevocationMethodCapabilities {
            operations: vec![Operation::Revoke, Operation::Suspend],
        }
    }

    fn get_json_ld_context(&self) -> Result<JsonLdContext, RevocationError> {
        Ok(JsonLdContext {
            revokable_credential_type: "LvvcCredential".to_string(),
            revokable_credential_subject: "Lvvc".to_string(),
            url: self.get_json_ld_context_url()?,
        })
    }

    fn get_params(&self) -> Result<serde_json::Value, RevocationError> {
        convert_params(self.params.clone()).map_err(RevocationError::from)
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn create_lvvc_with_status(
    credential: &Credential,
    status: LvvcStatus,
    core_base_url: &Option<String>,
    credential_expiry: time::Duration,
    formatter: Arc<dyn CredentialFormatter>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    json_ld_context: JsonLdContext,
) -> Result<Lvvc, RevocationError> {
    let base_url = core_base_url.as_ref().ok_or_else(|| {
        RevocationError::MappingError("LVVC issuance is missing core base_url".to_string())
    })?;
    let issuer_did = credential
        .issuer_identifier
        .as_ref()
        .ok_or_else(|| {
            RevocationError::MappingError("LVVC issuance is missing issuer identifier".to_string())
        })?
        .did
        .as_ref()
        .ok_or_else(|| {
            RevocationError::MappingError("LVVC issuance is missing issuer DID".to_string())
        })?;

    let key = credential
        .key
        .as_ref()
        .ok_or_else(|| RevocationError::MappingError("LVVC issuance is missing key".to_string()))?
        .to_owned();

    let did_document = did_method_provider.resolve(&issuer_did.did).await?;
    let assertion_methods = did_document
        .assertion_method
        .ok_or(RevocationError::MappingError(
            "Missing assertion_method keys".to_owned(),
        ))?;

    let issuer_jwk_key_id = match assertion_methods
        .iter()
        .find(|id| id.contains(&key.id.to_string()))
        .cloned()
    {
        Some(id) => id,
        None => assertion_methods
            .first()
            .ok_or(RevocationError::MappingError(
                "Missing first assertion_method key".to_owned(),
            ))?
            .to_owned(),
    };

    let auth_fn = key_provider.get_signature_provider(
        &key.to_owned(),
        Some(issuer_jwk_key_id),
        key_algorithm_provider,
    )?;

    let lvvc_credential_id = Uuid::new_v4();
    let credential_id = format!("{base_url}/ssi/lvvc/v1/{lvvc_credential_id}")
        .parse::<Url>()
        .map_err(|err| RevocationError::ValidationError(format!("Invalid credential id: {err}")))?;

    let issuer = Issuer::Url(issuer_did.did.clone().into_url());

    let credential_subject_id: Url = Urn::from_uuid(credential.id.into())
        .to_string()
        .parse()
        .map_err(|err| {
            RevocationError::ValidationError(format!("Invalid credential subject id: {err}"))
        })?;

    let claims = create_status_claims(&status)?;
    let claims = nest_claims(claims)
        .map_err(|err| RevocationError::ValidationError(format!("Invalid claims: {err}")))?;

    let credential_subject = VcdmCredentialSubject::new(claims).with_id(credential_subject_id);

    let lvvc_context = json_ld_context
        .url
        .map(|ctx| {
            ctx.parse().map(ContextType::Url).map_err(|_| {
                RevocationError::MappingError("Invalid JSON-LD context URL".to_string())
            })
        })
        .transpose()?;

    let vcdm = VcdmCredential::new_v2(issuer, credential_subject)
        .add_context(lvvc_context)
        .add_type(json_ld_context.revokable_credential_type)
        .with_id(credential_id)
        .with_valid_from(OffsetDateTime::now_utc())
        .with_valid_until(OffsetDateTime::now_utc() + credential_expiry);

    let credential_data = CredentialData {
        vcdm,
        claims: vec![],
        holder_did: None,
        holder_key_id: None,
        issuer_certificate: None,
    };

    let formatted_credential = formatter
        .format_credential(credential_data, auth_fn)
        .await?;

    let lvvc_credential = Lvvc {
        id: lvvc_credential_id,
        created_date: OffsetDateTime::now_utc(),
        credential: formatted_credential.into_bytes(),
        linked_credential_id: credential.id.into(),
    };

    Ok(lvvc_credential)
}
