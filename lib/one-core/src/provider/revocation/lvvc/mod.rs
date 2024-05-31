use std::collections::HashMap;
use std::ops::Sub;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_with::DurationSeconds;
use shared_types::{CredentialId, DidValue};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::{
    CredentialDataByRole, CredentialRevocationInfo, CredentialRevocationState, JsonLdContext,
    RevocationMethodCapabilities, VerifierCredentialData,
};
use crate::model::credential::{
    Credential, CredentialRelations, CredentialStateEnum, CredentialStateRelations,
};
use crate::model::did::{DidRelations, KeyRole};
use crate::model::key::KeyRelations;
use crate::model::lvvc::Lvvc;
use crate::provider::credential_formatter::jwt::model::JWTPayload;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::model::CredentialStatus;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::credential_formatter::{
    CredentialData, CredentialFormatter, CredentialSchemaData,
};
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::exchange_protocol::ExchangeProtocolError;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::lvvc_repository::LvvcRepository;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError,
};
use crate::service::ssi_issuer::dto::IssuerResponseDTO;

pub mod dto;
pub mod mapper;

use self::dto::LvvcStatus;
use self::mapper::{create_id_claim, create_status_claims, status_from_lvvc_claims};

#[serde_with::serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub credential_expiry: time::Duration,
    pub json_ld_context_url: Option<String>,
}

pub struct LvvcProvider {
    core_base_url: Option<String>,
    credential_repository: Arc<dyn CredentialRepository>,
    lvvc_repository: Arc<dyn LvvcRepository>,
    credential_formatter: Arc<dyn CredentialFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    client: reqwest::Client,
    params: Params,
}

#[allow(clippy::too_many_arguments)]
impl LvvcProvider {
    pub(crate) fn new(
        core_base_url: Option<String>,
        credential_repository: Arc<dyn CredentialRepository>,
        lvvc_repository: Arc<dyn LvvcRepository>,
        credential_formatter: Arc<dyn CredentialFormatterProvider>,
        key_provider: Arc<dyn KeyProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        client: reqwest::Client,
        params: Params,
    ) -> Self {
        Self {
            core_base_url,
            credential_repository,
            lvvc_repository,
            credential_formatter,
            key_provider,
            did_method_provider,
            client,
            params,
        }
    }

    fn get_base_url(&self) -> Result<&String, ServiceError> {
        self.core_base_url.as_ref().ok_or_else(|| {
            ServiceError::MappingError("LVVC issuance is missing core base_url".to_string())
        })
    }

    fn formatter(
        &self,
        credential: &Credential,
    ) -> Result<Arc<dyn CredentialFormatter>, ServiceError> {
        let format = credential
            .schema
            .as_ref()
            .map(|schema| schema.format.as_str())
            .ok_or(BusinessLogicError::MissingCredentialSchema)?;

        let formatter = self
            .credential_formatter
            .get_formatter(format)
            .ok_or_else(|| MissingProviderError::Formatter(format.to_owned()))?;

        Ok(formatter)
    }

    async fn create_lvvc_with_status(
        &self,
        credential: &Credential,
        status: LvvcStatus,
    ) -> Result<(), ServiceError> {
        create_lvvc_with_status(
            credential,
            status,
            &self.core_base_url,
            self.params.credential_expiry,
            self.formatter(credential)?,
            self.lvvc_repository.clone(),
            self.key_provider.clone(),
            self.did_method_provider.clone(),
            self.get_json_ld_context()?,
        )
        .await
        .map(|_| ())
    }

    async fn check_revocation_status_as_holder(
        &self,
        credential_id: &CredentialId,
        credential_status: &CredentialStatus,
    ) -> Result<CredentialRevocationState, ServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    holder_did: Some(DidRelations {
                        keys: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(EntityNotFoundError::Credential(credential_id.to_owned()))?;

        let bearer_token = prepare_bearer_token(&credential, self.key_provider.clone()).await?;

        let lvvc_check_url = &credential_status.id;
        let response: IssuerResponseDTO = self
            .client
            .get(lvvc_check_url)
            .bearer_auth(bearer_token)
            .send()
            .await
            .map_err(ExchangeProtocolError::HttpRequestError)?
            .error_for_status()
            .map_err(ExchangeProtocolError::HttpRequestError)?
            .json()
            .await
            .map_err(ExchangeProtocolError::HttpRequestError)?;

        let formatter = self
            .credential_formatter
            .get_formatter(&response.format)
            .ok_or(MissingProviderError::Formatter(response.format))?;

        let lvvc = formatter
            .extract_credentials_unverified(&response.credential)
            .await?;

        let status = status_from_lvvc_claims(&lvvc.claims.values)?;
        Ok(match status {
            LvvcStatus::Accepted => CredentialRevocationState::Valid,
            LvvcStatus::Revoked => CredentialRevocationState::Revoked,
            LvvcStatus::Suspended { suspend_end_date } => {
                CredentialRevocationState::Suspended { suspend_end_date }
            }
        })
    }

    async fn check_revocation_status_as_issuer(
        &self,
        credential_id: &CredentialId,
    ) -> Result<CredentialRevocationState, ServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations::default()),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(EntityNotFoundError::Credential(credential_id.to_owned()))?;

        let states = credential
            .state
            .ok_or(ServiceError::MappingError("state is None".to_string()))?;
        let latest_state = states
            .first()
            .ok_or(ServiceError::MappingError("state is missing".to_string()))?;

        Ok(match latest_state.state {
            CredentialStateEnum::Accepted => CredentialRevocationState::Valid,
            CredentialStateEnum::Revoked => CredentialRevocationState::Revoked,
            CredentialStateEnum::Suspended => CredentialRevocationState::Suspended {
                suspend_end_date: latest_state.suspend_end_date,
            },
            _ => {
                return Err(BusinessLogicError::InvalidCredentialState {
                    state: latest_state.state.to_owned(),
                }
                .into());
            }
        })
    }

    fn check_revocation_status_as_verifier(
        &self,
        issuer_did: &DidValue,
        data: VerifierCredentialData,
    ) -> Result<CredentialRevocationState, ServiceError> {
        let credential_id = data
            .credential
            .id
            .as_ref()
            .ok_or(ServiceError::ValidationError(
                "credential id missing".to_string(),
            ))?;

        let lvvc = data
            .extracted_lvvcs
            .iter()
            .find(|lvvc| {
                if let Some((_, id)) = lvvc.claims.values.iter().find(|(key, _)| *key == "id") {
                    *id == *credential_id
                } else {
                    false
                }
            })
            .ok_or(ServiceError::ValidationError(
                "no matching LVVC found among credentials".to_string(),
            ))?;

        let lvvc_issuer_did = lvvc
            .issuer_did
            .as_ref()
            .ok_or(ServiceError::ValidationError(
                "LVVC issuer DID missing".to_string(),
            ))?;

        if issuer_did != lvvc_issuer_did {
            return Err(ServiceError::ValidationError(
                "LVVC issuer DID is not equal to issuer DID".to_string(),
            ));
        }

        let lvvc_issued_at = lvvc.issued_at.ok_or(ServiceError::ValidationError(
            "LVVC issued_at missing".to_string(),
        ))?;

        if let Some(validity_constraint) = data.proof_input.validity_constraint {
            let now = OffsetDateTime::now_utc();

            if now.sub(Duration::seconds(validity_constraint)) > lvvc_issued_at {
                return Err(ServiceError::ValidationError(
                    "LVVC has expired".to_string(),
                ));
            }
        }

        let status = status_from_lvvc_claims(&lvvc.claims.values)?;
        Ok(match status {
            LvvcStatus::Accepted => CredentialRevocationState::Valid,
            LvvcStatus::Revoked => CredentialRevocationState::Revoked,
            LvvcStatus::Suspended { suspend_end_date } => {
                CredentialRevocationState::Suspended { suspend_end_date }
            }
        })
    }

    fn get_json_ld_context_url(&self) -> Result<Option<String>, ServiceError> {
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

    fn get_capabilities(&self) -> RevocationMethodCapabilities {
        RevocationMethodCapabilities {
            operations: vec!["REVOKE".to_string(), "SUSPEND".to_string()],
        }
    }

    async fn add_issued_credential(
        &self,
        credential: &Credential,
    ) -> Result<Vec<CredentialRevocationInfo>, ServiceError> {
        let base_url = self.get_base_url()?;

        self.create_lvvc_with_status(credential, LvvcStatus::Accepted)
            .await?;

        Ok(vec![CredentialRevocationInfo {
            credential_status: CredentialStatus {
                id: format!("{base_url}/ssi/revocation/v1/lvvc/{}", credential.id),
                r#type: self.get_status_type(),
                status_purpose: None,
                additional_fields: HashMap::new(),
            },
        }])
    }

    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        issuer_did: &DidValue,
        additional_credential_data: Option<CredentialDataByRole>,
    ) -> Result<CredentialRevocationState, ServiceError> {
        let additional_credential_data = additional_credential_data.ok_or(
            ServiceError::ValidationError("additional_credential_data is None".to_string()),
        )?;

        match additional_credential_data {
            CredentialDataByRole::Holder(credential_id) => {
                self.check_revocation_status_as_holder(&credential_id, credential_status)
                    .await
            }
            CredentialDataByRole::Issuer(credential_id) => {
                self.check_revocation_status_as_issuer(&credential_id).await
            }
            CredentialDataByRole::Verifier(data) => {
                self.check_revocation_status_as_verifier(issuer_did, *data)
            }
        }
    }

    async fn mark_credential_as(
        &self,
        credential: &Credential,
        new_state: CredentialRevocationState,
    ) -> Result<(), ServiceError> {
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

    fn get_json_ld_context(&self) -> Result<JsonLdContext, ServiceError> {
        Ok(JsonLdContext {
            revokable_credential_type: "LvvcCredential".to_string(),
            revokable_credential_subject: "Lvvc".to_string(),
            url: self.get_json_ld_context_url()?,
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_lvvc_with_status(
    credential: &Credential,
    status: LvvcStatus,
    core_base_url: &Option<String>,
    credential_expiry: time::Duration,
    formatter: Arc<dyn CredentialFormatter>,
    lvvc_repository: Arc<dyn LvvcRepository>,
    key_provider: Arc<dyn KeyProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    json_ld_context: JsonLdContext,
) -> Result<Lvvc, ServiceError> {
    let base_url = core_base_url.as_ref().ok_or_else(|| {
        ServiceError::MappingError("LVVC issuance is missing core base_url".to_string())
    })?;
    let issuer_did = credential.issuer_did.as_ref().ok_or_else(|| {
        ServiceError::MappingError("LVVC issuance is missing issuer DID".to_string())
    })?;
    let holder_did = credential.holder_did.as_ref().ok_or_else(|| {
        ServiceError::MappingError("LVVC issuance is missing holder DID".to_string())
    })?;
    let schema = credential.schema.as_ref().ok_or_else(|| {
        ServiceError::MappingError("LVVC issuance is missing credential schema".to_string())
    })?;

    let key = credential
        .key
        .as_ref()
        .ok_or_else(|| ServiceError::MappingError("LVVC issuance is missing key".to_string()))?;

    let did_document = did_method_provider.resolve(&issuer_did.did).await?;
    let assertion_methods = did_document
        .assertion_method
        .ok_or(ServiceError::MappingError(
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
            .ok_or(ServiceError::MappingError(
                "Missing first assertion_method key".to_owned(),
            ))?
            .to_owned(),
    };

    let auth_fn = key_provider.get_signature_provider(key, Some(issuer_jwk_key_id))?;

    let lvvc_credential_id = Uuid::new_v4();
    let mut claims = vec![create_id_claim(base_url, credential.id)];
    claims.extend(create_status_claims(&status)?);

    let credential_data = CredentialData {
        id: format!("{base_url}/ssi/lvvc/v1/{lvvc_credential_id}"),
        issuance_date: OffsetDateTime::now_utc(),
        valid_for: credential_expiry,
        claims,
        issuer_did: issuer_did.did.to_owned(),
        status: vec![],
        schema: CredentialSchemaData {
            id: None,
            context: None,
            r#type: None,
            name: schema.name.to_owned(),
        },
    };

    let formatted_credential = formatter
        .format_credentials(
            credential_data,
            &holder_did.did,
            &key.key_type,
            vec![],
            vec![json_ld_context.revokable_credential_type],
            auth_fn,
            json_ld_context.url,
            Some(json_ld_context.revokable_credential_subject),
        )
        .await?;

    let lvvc_credential = Lvvc {
        id: lvvc_credential_id,
        created_date: OffsetDateTime::now_utc(),
        credential: formatted_credential.into_bytes(),
        linked_credential_id: credential.id,
    };

    lvvc_repository.insert(lvvc_credential.to_owned()).await?;

    Ok(lvvc_credential)
}

pub(crate) async fn prepare_bearer_token(
    credential: &Credential,
    key_provider: Arc<dyn KeyProvider>,
) -> Result<String, ServiceError> {
    let holder_did = credential
        .holder_did
        .as_ref()
        .ok_or(ServiceError::MappingError("holder_did is None".to_string()))?;
    let keys = holder_did
        .keys
        .as_ref()
        .ok_or(ServiceError::MappingError("keys is None".to_string()))?;
    let authentication_key = keys
        .iter()
        .find(|key| key.role == KeyRole::Authentication)
        .ok_or(ServiceError::MappingError(
            "No authentication keys found for holder DID".to_string(),
        ))?;

    let payload = JWTPayload {
        custom: BearerTokenPayload {
            timestamp: OffsetDateTime::now_utc().unix_timestamp(),
        },
        ..Default::default()
    };

    let signer = key_provider.get_signature_provider(&authentication_key.key, None)?;
    let bearer_token = Jwt::new("JWT".to_string(), "HS256".to_string(), None, payload)
        .tokenize(signer)
        .await?;

    Ok(bearer_token)
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct BearerTokenPayload {
    pub timestamp: i64,
}
