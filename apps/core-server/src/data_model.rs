use one_core::{
    data_model::{ConnectIssuerResponse, ConnectVerifierResponse, ProofClaimSchema},
    repository::data_provider::{CredentialClaimSchemaResponse, EntityResponse},
};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::endpoint::credential_schema::dto::CredentialClaimSchemaResponseRestDTO;
use crate::{endpoint, serialize::front_time};

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct EntityResponseDTO {
    pub id: String,
}

impl From<one_core::repository::data_provider::EntityResponse> for EntityResponseDTO {
    fn from(value: EntityResponse) -> Self {
        Self { id: value.id }
    }
}

impl From<CredentialClaimSchemaResponse> for CredentialClaimSchemaResponseRestDTO {
    fn from(value: CredentialClaimSchemaResponse) -> Self {
        Self {
            id: value.id.parse().unwrap(),
            created_date: value.created_date,
            last_modified: value.last_modified,
            key: value.key,
            datatype: value.datatype,
        }
    }
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct PostSsiIssuerConnectQuery {
    pub protocol: String,
    pub credential: Uuid,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct PostSsiVerifierConnectQuery {
    pub protocol: String,
    pub proof: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConnectRequestDTO {
    pub did: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConnectIssuerResponseDTO {
    pub credential: String,
    pub format: String,
}

impl From<ConnectIssuerResponse> for ConnectIssuerResponseDTO {
    fn from(value: ConnectIssuerResponse) -> Self {
        Self {
            credential: value.credential,
            format: value.format,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConnectVerifierResponseDTO {
    pub claims: Vec<ProofClaimResponseDTO>,
}

impl From<ConnectVerifierResponse> for ConnectVerifierResponseDTO {
    fn from(value: ConnectVerifierResponse) -> Self {
        Self {
            claims: value.claims.into_iter().map(|item| item.into()).collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProofClaimResponseDTO {
    pub id: String,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub credential_schema: endpoint::credential_schema::dto::CredentialSchemaResponseRestDTO,
}

impl From<ProofClaimSchema> for ProofClaimResponseDTO {
    fn from(value: ProofClaimSchema) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            key: value.key,
            datatype: value.datatype,
            required: value.required,
            credential_schema: value.credential_schema.into(),
        }
    }
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct ProofRequestQueryParams {
    pub proof: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct HandleInvitationRequestDTO {
    pub url: String,
}
