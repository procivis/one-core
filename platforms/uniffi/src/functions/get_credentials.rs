use std::sync::Arc;

use crate::{
    utils::{run_sync, TimestampFormat},
    OneCore,
};
pub use one_core::error::OneCoreError;
use one_core::repository::data_provider::{
    DataProvider, DetailCredentialClaimResponse, DetailCredentialResponse, Format,
    ListCredentialSchemaResponse,
};

pub use one_core::repository::error::DataLayerError;

pub use one_core::repository::data_provider::{CredentialState, RevocationMethod};
pub type CredentialFormat = Format;

pub struct CredentialSchema {
    pub id: String,
    pub created_date: String,
    pub last_modified: String,
    pub name: String,
    pub organisation_id: String,
    pub format: CredentialFormat,
    pub revocation_method: RevocationMethod,
}

impl From<ListCredentialSchemaResponse> for CredentialSchema {
    fn from(value: ListCredentialSchemaResponse) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            name: value.name,
            organisation_id: value.organisation_id,
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

impl From<DetailCredentialResponse> for Credential {
    fn from(value: DetailCredentialResponse) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            issuance_date: value.issuance_date.format_timestamp(),
            issuer_did: value.issuer_did,
            state: value.state,
            claims: value.claims.into_iter().map(|claim| claim.into()).collect(),
            schema: value.schema.into(),
        }
    }
}

async fn get_credentials(
    data_layer: Arc<dyn DataProvider + Sync + Send>,
) -> Result<Vec<Credential>, DataLayerError> {
    let response = data_layer.get_all_credentials().await;
    response.map(|list| {
        list.into_iter()
            .map(|credential| credential.into())
            .collect()
    })
}

impl OneCore {
    pub fn get_credentials(&self) -> Result<Vec<Credential>, DataLayerError> {
        run_sync(async { get_credentials(self.inner.data_layer.clone()).await })
    }
}
