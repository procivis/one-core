//! LVVC implementation.
//! https://eprint.iacr.org/2022/1658.pdf

use std::collections::HashMap;
use std::ops::Sub;
use std::sync::Arc;

use holder_fetch::holder_get_lvvc;
use serde::{Deserialize, Serialize};
use serde_with::DurationSeconds;
use shared_types::{DidValue, RevocationListEntryId};
use time::{Duration, OffsetDateTime};
use url::Url;
use util::get_lvvc_credential_subject;
use uuid::Uuid;
use uuid::fmt::Urn;

use self::dto::LvvcStatus;
use self::mapper::{create_status_claims, status_from_lvvc_claims};
use crate::model::certificate::Certificate;
use crate::model::credential::Credential;
use crate::model::did::{KeyFilter, KeyRole};
use crate::model::identifier::Identifier;
use crate::model::wallet_unit_attested_key::{
    WalletUnitAttestedKey, WalletUnitAttestedKeyRevocationInfo,
};
use crate::proto::http_client::HttpClient;
use crate::provider::credential_formatter::model::{
    CredentialData, CredentialStatus, IdentifierDetails, Issuer,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::credential_formatter::vcdm::{
    ContextType, VcdmCredential, VcdmCredentialSubject,
};
use crate::provider::credential_formatter::{CredentialFormatter, nest_claims};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::lvvc::dto::Lvvc;
use crate::provider::revocation::model::{
    CredentialDataByRole, CredentialRevocationInfo, JsonLdContext, Operation,
    RevocationMethodCapabilities, RevocationState, VerifierCredentialData,
};
use crate::repository::validity_credential_repository::ValidityCredentialRepository;

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

    pub leeway: u64,

    /// custom JSON-LD context inside the issued LVVC (defaults to /ssi/context/v1/lvvc.json)
    pub json_ld_context_url: Option<String>,
}

pub struct LvvcProvider {
    core_base_url: Option<String>,
    credential_formatter: Arc<dyn CredentialFormatterProvider>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    client: Arc<dyn HttpClient>,
    params: Params,
}

impl LvvcProvider {
    pub fn new(
        core_base_url: Option<String>,
        credential_formatter: Arc<dyn CredentialFormatterProvider>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        client: Arc<dyn HttpClient>,
        params: Params,
    ) -> Self {
        Self {
            core_base_url,
            credential_formatter,
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
            .map(|schema| &schema.format)
            .ok_or(RevocationError::MappingError(
                "credential_schema is None".to_string(),
            ))?;

        let formatter = self
            .credential_formatter
            .get_credential_formatter(format)
            .ok_or_else(|| RevocationError::FormatterNotFound(format.to_string()))?;

        Ok(formatter)
    }

    async fn create_lvvc_with_status(
        &self,
        credential: &Credential,
        status: LvvcStatus,
    ) -> Result<Lvvc, RevocationError> {
        create_lvvc_with_status(
            credential,
            status,
            &self.core_base_url,
            self.params.credential_expiry,
            self.formatter(credential)?,
            self.key_provider.clone(),
            self.key_algorithm_provider.clone(),
            self.get_json_ld_context()?,
        )
        .await
    }

    async fn check_revocation_status_as_holder(
        &self,
        credential: &Credential,
        credential_status: &CredentialStatus,
        force_refresh: bool,
    ) -> Result<RevocationState, RevocationError> {
        let lvvc = holder_get_lvvc(
            credential,
            credential_status,
            &*self.validity_credential_repository,
            &*self.key_provider,
            &self.key_algorithm_provider,
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
            LvvcStatus::Accepted => RevocationState::Valid,
            LvvcStatus::Revoked => RevocationState::Revoked,
            LvvcStatus::Suspended { suspend_end_date } => {
                RevocationState::Suspended { suspend_end_date }
            }
        })
    }

    fn check_revocation_status_as_verifier(
        &self,
        issuer_did: &DidValue,
        data: VerifierCredentialData,
    ) -> Result<RevocationState, RevocationError> {
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

        let IdentifierDetails::Did(ref lvvc_issuer_did) = lvvc.issuer else {
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
            LvvcStatus::Accepted => RevocationState::Valid,
            LvvcStatus::Revoked => RevocationState::Revoked,
            LvvcStatus::Suspended { suspend_end_date } => {
                RevocationState::Suspended { suspend_end_date }
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
    ) -> Result<Vec<CredentialRevocationInfo>, RevocationError> {
        let base_url = self.get_base_url()?;

        let id = format!("{base_url}/ssi/revocation/v1/lvvc/{}", credential.id)
            .parse()
            .map_err(|e| RevocationError::ValidationError(format!("Failed to parse URL: `{e}`")))?;

        let lvvc = self
            .create_lvvc_with_status(credential, LvvcStatus::Accepted)
            .await?;

        self.validity_credential_repository
            .insert(lvvc.into())
            .await?;

        Ok(vec![CredentialRevocationInfo {
            credential_status: CredentialStatus {
                id: Some(id),
                r#type: self.get_status_type(),
                status_purpose: None,
                additional_fields: HashMap::new(),
            },
            serial: None,
        }])
    }

    async fn mark_credential_as(
        &self,
        credential: &Credential,
        new_state: RevocationState,
    ) -> Result<(), RevocationError> {
        let lvvc = match new_state {
            RevocationState::Revoked => {
                self.create_lvvc_with_status(credential, LvvcStatus::Revoked)
                    .await
            }
            RevocationState::Valid => {
                self.create_lvvc_with_status(credential, LvvcStatus::Accepted)
                    .await
            }
            RevocationState::Suspended { suspend_end_date } => {
                self.create_lvvc_with_status(credential, LvvcStatus::Suspended { suspend_end_date })
                    .await
            }
        }?;

        self.validity_credential_repository
            .insert(lvvc.into())
            .await?;

        Ok(())
    }

    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        issuer_details: &IdentifierDetails,
        additional_credential_data: Option<CredentialDataByRole>,
        force_refresh: bool,
    ) -> Result<RevocationState, RevocationError> {
        let IdentifierDetails::Did(issuer_did) = issuer_details else {
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

    async fn add_issued_attestation(
        &self,
        _attestation: &WalletUnitAttestedKey,
    ) -> Result<CredentialRevocationInfo, RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "Attestations not supported".to_string(),
        ))
    }

    async fn get_attestation_revocation_info(
        &self,
        _key_info: &WalletUnitAttestedKeyRevocationInfo,
    ) -> Result<CredentialRevocationInfo, RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "Attestations not supported".to_string(),
        ))
    }

    async fn update_attestation_entries(
        &self,
        _keys: Vec<WalletUnitAttestedKeyRevocationInfo>,
        _new_state: RevocationState,
    ) -> Result<(), RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "Attestations not supported".to_string(),
        ))
    }

    async fn add_signature(
        &self,
        _signature_type: String,
        _issuer: &Identifier,
        _certificate: &Option<Certificate>,
    ) -> Result<(RevocationListEntryId, CredentialRevocationInfo), RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "Signatures not supported".to_string(),
        ))
    }

    async fn revoke_signature(
        &self,
        _signature_id: RevocationListEntryId,
    ) -> Result<(), RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "Signatures not supported".to_string(),
        ))
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
}

#[expect(clippy::too_many_arguments)]
pub(crate) async fn create_lvvc_with_status(
    credential: &Credential,
    status: LvvcStatus,
    core_base_url: &Option<String>,
    credential_expiry: time::Duration,
    formatter: Arc<dyn CredentialFormatter>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
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

    let related_did_key = issuer_did
        .find_key(&key.id, &KeyFilter::role_filter(KeyRole::AssertionMethod))
        .map_err(|e| RevocationError::MappingError(e.to_string()))?
        .ok_or_else(|| {
            RevocationError::MappingError("LVVC issuance is missing related key".to_string())
        })?;

    let issuer_jwk_key_id = issuer_did.verification_method_id(related_did_key);

    let auth_fn = key_provider.get_signature_provider(
        &key,
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

    let credential_subject = VcdmCredentialSubject::new(claims)?.with_id(credential_subject_id);

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
        holder_identifier: None,
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
        linked_credential_id: credential.id,
    };

    Ok(lvvc_credential)
}
