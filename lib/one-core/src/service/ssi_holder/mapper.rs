use one_dto_mapper::convert_inner;

use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::Credential;
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaClaim, LayoutType};
use crate::model::did::{Did, KeyFilter};
use crate::model::key::Key;
use crate::service::credential::dto::DetailCredentialSchemaResponseDTO;
use crate::service::credential_schema::dto::CredentialClaimSchemaDTO;
use crate::service::error::ServiceError;

impl From<DetailCredentialSchemaResponseDTO> for CredentialSchema {
    fn from(value: DetailCredentialSchemaResponseDTO) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            format: value.format,
            key_storage_security: value.key_storage_security,
            revocation_method: value.revocation_method,
            deleted_at: value.deleted_at,
            claim_schemas: None,
            organisation: None, // response organisation is intentionally ignored (holder sets its local organisation)
            layout_type: value.layout_type.unwrap_or(LayoutType::Card),
            layout_properties: convert_inner(value.layout_properties),
            schema_id: value.schema_id,
            imported_source_url: value.imported_source_url,
            allow_suspension: value.allow_suspension,
            requires_app_attestation: false,
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

pub(super) fn holder_did_key_jwk_from_credential(
    credential: &Credential,
) -> Result<(Did, Key, String), ServiceError> {
    let holder_did = credential
        .holder_identifier
        .as_ref()
        .and_then(|id| id.did.clone())
        .ok_or(ServiceError::MappingError(
            "missing identifier did".to_string(),
        ))?;
    let key = credential
        .key
        .clone()
        .ok_or(ServiceError::MappingError("missing holder key".to_string()))?;

    // There should probably be a nicer error if a key is rotated out from a did
    let related_key =
        holder_did
            .find_key(&key.id, &KeyFilter::default())?
            .ok_or(ServiceError::MappingError(format!(
                "Failed to find key `{}` in keys of did `{}`",
                key.id, holder_did.id
            )))?;
    let holder_jwk_key_id = holder_did.verification_method_id(related_key);
    Ok((holder_did, key, holder_jwk_key_id))
}
