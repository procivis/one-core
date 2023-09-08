use crate::{
    utils::{run_sync, TimestampFormat},
    OneCore,
};
pub use one_core::error::OneCoreError;
use one_core::repository::data_provider::{
    DetailCredentialClaimResponse, ListCredentialSchemaResponse,
};

pub use one_core::repository::error::DataLayerError;

use one_core::service::credential::dto::CredentialSchemaResponseDTO;
use one_core::service::credential::CredentialService;
use one_core::service::error::ServiceError;

use crate::utils::dto::CredentialState;

pub struct CredentialSchema {
    pub id: String,
    pub created_date: String,
    pub last_modified: String,
    pub name: String,
    pub organisation_id: String,
    pub format: String,
    pub revocation_method: String,
}

impl From<ListCredentialSchemaResponse> for CredentialSchema {
    fn from(value: ListCredentialSchemaResponse) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            name: value.name,
            organisation_id: value.organisation_id.to_string(),
            format: value.format,
            revocation_method: value.revocation_method,
        }
    }
}

impl From<CredentialSchemaResponseDTO> for CredentialSchema {
    fn from(value: CredentialSchemaResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            name: value.name,
            organisation_id: value.organisation_id.to_string(),
            format: value.format,
            revocation_method: value.revocation_method,
        }
    }
}

pub struct Claim {
    pub id: String,
    pub key: String,
    pub data_type: String,
    pub value: String,
}

impl From<DetailCredentialClaimResponse> for Claim {
    fn from(value: DetailCredentialClaimResponse) -> Self {
        Self {
            id: value.schema.id,
            key: value.schema.key,
            data_type: value.schema.datatype,
            value: value.value,
        }
    }
}

pub struct Credential {
    pub id: String,
    pub created_date: String,
    pub issuance_date: String,
    pub last_modified: String,
    pub issuer_did: Option<String>,
    pub state: CredentialState,
    pub claims: Vec<Claim>,
    pub schema: CredentialSchema,
}

async fn get_credentials(data_layer: &CredentialService) -> Result<Vec<Credential>, ServiceError> {
    let response = data_layer.get_all_credential_list().await?;
    Ok(response
        .into_iter()
        .map(|credential| credential.into())
        .collect())
}

impl OneCore {
    pub fn get_credentials(&self) -> Result<Vec<Credential>, ServiceError> {
        run_sync(async { get_credentials(&self.inner.credential_service).await })
    }
}
