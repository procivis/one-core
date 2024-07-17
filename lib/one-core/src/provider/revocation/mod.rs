use one_providers::credential_formatter::model::{CredentialStatus, DetailCredential};
use serde::Serialize;
use shared_types::{CredentialId, DidValue};
use strum_macros::Display;
use time::OffsetDateTime;

use crate::model::credential::Credential;
use crate::model::proof_schema::ProofInputSchema;
use crate::service::error::ServiceError;

pub mod bitstring_status_list;
pub mod lvvc;
pub mod none;
pub mod provider;
pub mod status_list_2021;

#[derive(Clone, Default, Serialize)]
pub struct RevocationMethodCapabilities {
    pub operations: Vec<String>,
}

pub struct CredentialRevocationInfo {
    pub credential_status: CredentialStatus,
}

#[derive(Debug, Clone)]
pub struct VerifierCredentialData {
    pub credential: DetailCredential,
    pub extracted_lvvcs: Vec<DetailCredential>,
    pub proof_input: ProofInputSchema,
}

#[derive(Clone)]
pub enum CredentialDataByRole {
    Holder(CredentialId),
    Issuer(CredentialId),
    Verifier(Box<VerifierCredentialData>),
}

#[derive(Clone, Debug, Display, PartialEq)]
pub enum CredentialRevocationState {
    Valid,
    Revoked,
    Suspended {
        suspend_end_date: Option<OffsetDateTime>,
    },
}

#[derive(Debug, Default)]
pub struct JsonLdContext {
    pub revokable_credential_type: String,
    pub revokable_credential_subject: String,
    pub url: Option<String>,
}

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait RevocationMethod: Send + Sync {
    fn get_status_type(&self) -> String;

    async fn add_issued_credential(
        &self,
        credential: &Credential,
    ) -> Result<Vec<CredentialRevocationInfo>, ServiceError>;

    async fn mark_credential_as(
        &self,
        credential: &Credential,
        new_state: CredentialRevocationState,
    ) -> Result<(), ServiceError>;

    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        issuer_did: &DidValue,
        additional_credential_data: Option<CredentialDataByRole>,
    ) -> Result<CredentialRevocationState, ServiceError>;

    fn get_capabilities(&self) -> RevocationMethodCapabilities;

    fn get_json_ld_context(&self) -> Result<JsonLdContext, ServiceError>;
}
