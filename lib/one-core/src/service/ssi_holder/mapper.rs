use one_dto_mapper::convert_inner;
use shared_types::KeyId;

use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::Credential;
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaClaim, LayoutType};
use crate::model::did::{Did, KeyFilter, KeyRole};
use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::key::Key;
use crate::service::credential::dto::DetailCredentialSchemaResponseDTO;
use crate::service::credential_schema::dto::CredentialClaimSchemaDTO;
use crate::service::error::{BusinessLogicError, ServiceError, ValidationError};

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
) -> Result<(Option<Did>, Key, Option<String>), ServiceError> {
    let key = credential
        .key
        .clone()
        .ok_or(ServiceError::MappingError("missing holder key".to_string()))?;

    let holder_identifier =
        credential
            .holder_identifier
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "missing holder identifier".to_string(),
            ))?;

    let (holder_did, holder_jwk_key_id) = if holder_identifier.r#type == IdentifierType::Did {
        let holder_did = holder_identifier
            .did
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "missing identifier did".to_string(),
            ))?
            .to_owned();

        // There should probably be a nicer error if a key is rotated out from a did
        let related_key = holder_did.find_key(&key.id, &KeyFilter::default())?.ok_or(
            ServiceError::MappingError(format!(
                "Failed to find key `{}` in keys of did `{}`",
                key.id, holder_did.id
            )),
        )?;
        let holder_jwk_key_id = holder_did.verification_method_id(related_key);

        (Some(holder_did), Some(holder_jwk_key_id))
    } else {
        (None, None)
    };

    Ok((holder_did, key, holder_jwk_key_id))
}

pub(super) fn select_holder_key(
    identifier: &Identifier,
    key_id: Option<KeyId>,
) -> Result<Key, ServiceError> {
    Ok(match identifier.r#type {
        IdentifierType::Key => {
            let key = identifier.key.to_owned().ok_or(ServiceError::MappingError(
                "Missing identifier key".to_string(),
            ))?;

            if let Some(key_id) = key_id
                && key_id != key.id
            {
                return Err(ValidationError::InvalidKey(
                    "Mismatch keyId of selected identifier".to_string(),
                )
                .into());
            }
            key
        }
        IdentifierType::Did => {
            let did = identifier.did.to_owned().ok_or(ServiceError::MappingError(
                "Missing identifier did".to_string(),
            ))?;

            let key_filter = KeyFilter::role_filter(KeyRole::Authentication);
            let selected_key = match key_id {
                Some(key_id) => did
                    .find_key(&key_id, &key_filter)?
                    .ok_or(ValidationError::KeyNotFound)?,
                None => {
                    did.find_first_matching_key(&key_filter)?
                        .ok_or(ValidationError::InvalidKey(
                            "No key with role authentication available".to_string(),
                        ))?
                }
            };
            selected_key.key.to_owned()
        }
        _ => {
            return Err(BusinessLogicError::IncompatibleHolderIdentifier.into());
        }
    })
}
