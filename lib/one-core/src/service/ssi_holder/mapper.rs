use shared_types::KeyId;

use super::error::HolderServiceError;
use crate::error::ContextWithErrorCode;
use crate::model::credential::Credential;
use crate::model::did::{Did, KeyRole};
use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::key::Key;
use crate::util::key_selection::KeyFilter;

pub(super) fn holder_did_key_jwk_from_credential(
    credential: &Credential,
) -> Result<(Option<Did>, Key, Option<String>), HolderServiceError> {
    let key = credential
        .key
        .clone()
        .ok_or(HolderServiceError::MappingError(
            "missing holder key".to_string(),
        ))?;

    let holder_identifier =
        credential
            .holder_identifier
            .as_ref()
            .ok_or(HolderServiceError::MappingError(
                "missing holder identifier".to_string(),
            ))?;

    let (holder_did, holder_jwk_key_id) = if holder_identifier.r#type == IdentifierType::Did {
        let holder_did = holder_identifier
            .did
            .as_ref()
            .ok_or(HolderServiceError::MappingError(
                "missing identifier did".to_string(),
            ))?
            .to_owned();

        // There should probably be a nicer error if a key is rotated out from a did
        let related_key = holder_did
            .find_key(&key.id, &KeyFilter::default())
            .error_while("finding key")?;
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
) -> Result<Key, HolderServiceError> {
    Ok(match identifier.r#type {
        IdentifierType::Key => {
            let key = identifier
                .key
                .to_owned()
                .ok_or(HolderServiceError::MappingError(
                    "Missing identifier key".to_string(),
                ))?;

            if let Some(key_id) = key_id
                && key_id != key.id
            {
                return Err(HolderServiceError::InvalidKey(
                    "Mismatch keyId of selected identifier".to_string(),
                ));
            }
            key
        }
        IdentifierType::Did => {
            let did = identifier
                .did
                .to_owned()
                .ok_or(HolderServiceError::MappingError(
                    "Missing identifier did".to_string(),
                ))?;

            let key_filter = KeyFilter::role_filter(KeyRole::Authentication);
            let selected_key = match key_id {
                Some(key_id) => did
                    .find_key(&key_id, &key_filter)
                    .error_while("finding key")?,
                None => did
                    .find_first_matching_key(&key_filter)
                    .error_while("finding matching key")?
                    .ok_or(HolderServiceError::InvalidKey(
                        "No key with role authentication available".to_string(),
                    ))?,
            };
            selected_key.key.to_owned()
        }
        _ => {
            return Err(HolderServiceError::IncompatibleHolderIdentifier);
        }
    })
}
