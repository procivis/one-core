use one_core::model::common::EntityShareResponseDTO;
use one_core::model::credential::SortableCredentialColumn;
use one_core::service::credential::dto::{
    CreateCredentialRequestDTO, CredentialDetailResponseDTO, CredentialListItemResponseDTO,
    CredentialStateEnum, DetailCredentialClaimResponseDTO, DetailCredentialSchemaResponseDTO,
};

use crate::dto::common::EntityShareResponseRestDTO;
use crate::endpoint::credential::dto::{
    CreateCredentialRequestRestDTO, CredentialDetailClaimResponseRestDTO,
    CredentialDetailSchemaResponseRestDTO, CredentialListItemResponseRestDTO,
    CredentialStateRestEnum, GetCredentialResponseRestDTO, SortableCredentialColumnRestEnum,
};

impl From<CredentialDetailResponseDTO> for GetCredentialResponseRestDTO {
    fn from(value: CredentialDetailResponseDTO) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            issuance_date: value.issuance_date,
            state: value.state.into(),
            last_modified: value.last_modified,
            schema: value.schema.into(),
            issuer_did: value.issuer_did,
            claims: value.claims.into_iter().map(|claim| claim.into()).collect(),
        }
    }
}

impl From<CredentialStateEnum> for CredentialStateRestEnum {
    fn from(value: CredentialStateEnum) -> Self {
        match value {
            CredentialStateEnum::Created => CredentialStateRestEnum::Created,
            CredentialStateEnum::Pending => CredentialStateRestEnum::Pending,
            CredentialStateEnum::Offered => CredentialStateRestEnum::Offered,
            CredentialStateEnum::Accepted => CredentialStateRestEnum::Accepted,
            CredentialStateEnum::Rejected => CredentialStateRestEnum::Rejected,
            CredentialStateEnum::Revoked => CredentialStateRestEnum::Revoked,
            CredentialStateEnum::Error => CredentialStateRestEnum::Error,
        }
    }
}

impl From<DetailCredentialClaimResponseDTO> for CredentialDetailClaimResponseRestDTO {
    fn from(value: DetailCredentialClaimResponseDTO) -> Self {
        Self {
            schema: value.schema.into(),
            value: value.value,
        }
    }
}

impl From<SortableCredentialColumnRestEnum>
    for one_core::model::credential::SortableCredentialColumn
{
    fn from(value: SortableCredentialColumnRestEnum) -> Self {
        match value {
            SortableCredentialColumnRestEnum::CreatedDate => SortableCredentialColumn::CreatedDate,
            SortableCredentialColumnRestEnum::SchemaName => SortableCredentialColumn::SchemaName,
            SortableCredentialColumnRestEnum::IssuerDid => SortableCredentialColumn::IssuerDid,
            SortableCredentialColumnRestEnum::State => SortableCredentialColumn::State,
        }
    }
}

impl From<CredentialListItemResponseDTO> for CredentialListItemResponseRestDTO {
    fn from(value: CredentialListItemResponseDTO) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            issuance_date: value.issuance_date,
            state: value.state.into(),
            last_modified: value.last_modified,
            schema: value.schema.into(),
            issuer_did: value.issuer_did,
        }
    }
}

impl From<DetailCredentialSchemaResponseDTO> for CredentialDetailSchemaResponseRestDTO {
    fn from(value: DetailCredentialSchemaResponseDTO) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
            organisation_id: value.organisation_id,
        }
    }
}

impl From<CreateCredentialRequestRestDTO> for CreateCredentialRequestDTO {
    fn from(value: CreateCredentialRequestRestDTO) -> Self {
        Self {
            credential_schema_id: value.credential_schema_id,
            issuer_did: value.issuer_did,
            transport: value.transport,
            claim_values: value
                .claim_values
                .into_iter()
                .map(|claim| claim.into())
                .collect(),
        }
    }
}

pub(crate) fn share_credentials_to_entity_share_response(
    value: EntityShareResponseDTO,
    base_url: &str,
) -> EntityShareResponseRestDTO {
    let protocol = &value.transport;
    EntityShareResponseRestDTO {
        url: format!(
            "{}/ssi/temporary-issuer/v1/connect?protocol={}&credential={}",
            base_url, protocol, value.id
        ),
    }
}
