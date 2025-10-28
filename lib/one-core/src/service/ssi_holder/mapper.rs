use one_dto_mapper::convert_inner;

use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaClaim, LayoutType};
use crate::service::credential::dto::DetailCredentialSchemaResponseDTO;
use crate::service::credential_schema::dto::CredentialClaimSchemaDTO;

impl From<DetailCredentialSchemaResponseDTO> for CredentialSchema {
    fn from(value: DetailCredentialSchemaResponseDTO) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            format: value.format,
            wallet_storage_type: value.wallet_storage_type,
            revocation_method: value.revocation_method,
            deleted_at: value.deleted_at,
            claim_schemas: None,
            organisation: None, // response organisation is intentionally ignored (holder sets its local organisation)
            layout_type: value.layout_type.unwrap_or(LayoutType::Card),
            layout_properties: convert_inner(value.layout_properties),
            schema_id: value.schema_id,
            imported_source_url: value.imported_source_url,
            allow_suspension: value.allow_suspension,
        }
    }
}

impl From<CredentialClaimSchemaDTO> for CredentialSchemaClaim {
    fn from(value: CredentialClaimSchemaDTO) -> Self {
        Self {
            schema: ClaimSchema {
                id: value.id,
                key: value.key,
                data_type: value.datatype,
                created_date: value.created_date,
                last_modified: value.last_modified,
                array: false,
                metadata: false,
            },
            required: value.required,
        }
    }
}
