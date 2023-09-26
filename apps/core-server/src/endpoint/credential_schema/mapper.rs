use crate::endpoint::credential_schema::dto::{
    CreateCredentialSchemaRequestRestDTO, CreateCredentialSchemaResponseRestDTO,
    CredentialClaimSchemaRequestRestDTO, CredentialClaimSchemaResponseRestDTO,
    CredentialSchemaListValueResponseRestDTO, CredentialSchemaResponseRestDTO,
    SortableCredentialSchemaColumnRestEnum,
};
use one_core::service::credential_schema::dto::{
    CreateCredentialSchemaRequestDTO, CreateCredentialSchemaResponseDTO, CredentialClaimSchemaDTO,
    CredentialClaimSchemaRequestDTO, CredentialSchemaDetailResponseDTO,
    CredentialSchemaListItemResponseDTO,
};

impl From<CredentialSchemaListItemResponseDTO> for CredentialSchemaListValueResponseRestDTO {
    fn from(value: CredentialSchemaListItemResponseDTO) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
        }
    }
}

impl From<CredentialSchemaDetailResponseDTO> for CredentialSchemaResponseRestDTO {
    fn from(value: CredentialSchemaDetailResponseDTO) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
            organisation_id: value.organisation_id,
            claims: value.claims.into_iter().map(|claim| claim.into()).collect(),
        }
    }
}

impl From<CredentialClaimSchemaDTO> for CredentialClaimSchemaResponseRestDTO {
    fn from(value: CredentialClaimSchemaDTO) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            key: value.key,
            datatype: value.datatype,
            required: value.required,
        }
    }
}

impl From<CreateCredentialSchemaRequestRestDTO> for CreateCredentialSchemaRequestDTO {
    fn from(value: CreateCredentialSchemaRequestRestDTO) -> Self {
        CreateCredentialSchemaRequestDTO {
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
            organisation_id: value.organisation_id,
            claims: value.claims.into_iter().map(|claim| claim.into()).collect(),
        }
    }
}

impl From<CreateCredentialSchemaResponseDTO> for CreateCredentialSchemaResponseRestDTO {
    fn from(value: CreateCredentialSchemaResponseDTO) -> Self {
        CreateCredentialSchemaResponseRestDTO {
            id: value.id.to_string(),
        }
    }
}

impl From<CredentialClaimSchemaRequestRestDTO> for CredentialClaimSchemaRequestDTO {
    fn from(value: CredentialClaimSchemaRequestRestDTO) -> Self {
        CredentialClaimSchemaRequestDTO {
            key: value.key,
            datatype: value.datatype,
            required: value.required,
        }
    }
}

impl From<SortableCredentialSchemaColumnRestEnum>
    for one_core::model::credential_schema::SortableCredentialSchemaColumn
{
    fn from(value: SortableCredentialSchemaColumnRestEnum) -> Self {
        match value {
            SortableCredentialSchemaColumnRestEnum::Name => {
                one_core::model::credential_schema::SortableCredentialSchemaColumn::Name
            }
            SortableCredentialSchemaColumnRestEnum::Format => {
                one_core::model::credential_schema::SortableCredentialSchemaColumn::Format
            }
            SortableCredentialSchemaColumnRestEnum::CreatedDate => {
                one_core::model::credential_schema::SortableCredentialSchemaColumn::CreatedDate
            }
        }
    }
}
