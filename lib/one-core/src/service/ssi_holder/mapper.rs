use shared_types::KeyId;

use super::error::HolderServiceError;
use crate::error::ContextWithErrorCode;
use crate::model::credential::HolderBinding;
use crate::model::did::{Did, KeyRole};
use crate::model::identifier::{Identifier, IdentifierData};
use crate::model::key::Key;
use crate::util::key_selection::KeyFilter;

pub(super) async fn holder_did_key_jwk_from_binding(
    binding: &HolderBinding,
) -> Result<(Option<Did>, Key, Option<String>), HolderServiceError> {
    let key = binding.key.as_ref().await?.to_owned();
    let holder_identifier = binding.identifier.as_ref().await?;

    let (holder_did, holder_jwk_key_id) =
        if let IdentifierData::Did(holder_did) = &holder_identifier.data {
            let holder_did = holder_did.as_ref().await?.to_owned();

            // There should probably be a nicer error if a key is rotated out from a did
            let related_key = holder_did
                .find_key(&key.id, &KeyFilter::default())
                .await
                .error_while("finding key")?;
            let holder_jwk_key_id = holder_did.verification_method_id(&related_key);

            (Some(holder_did), Some(holder_jwk_key_id))
        } else {
            (None, None)
        };

    Ok((holder_did, key, holder_jwk_key_id))
}

pub(super) async fn select_holder_key(
    identifier: &Identifier,
    key_id: Option<KeyId>,
) -> Result<Key, HolderServiceError> {
    Ok(match &identifier.data {
        IdentifierData::Key(key) => {
            let key = key.as_ref().await?.to_owned();

            if let Some(key_id) = key_id
                && key_id != key.id
            {
                return Err(HolderServiceError::InvalidKey(
                    "Mismatch keyId of selected identifier".to_string(),
                ));
            }
            key
        }
        IdentifierData::Did(did) => {
            let did = did.as_ref().await?;

            let key_filter = KeyFilter::did_role(KeyRole::Authentication);
            let selected_key = match key_id {
                Some(key_id) => did
                    .find_key(&key_id, &key_filter)
                    .await
                    .error_while("finding key")?,
                None => did
                    .find_first_matching_key(&key_filter)
                    .await
                    .error_while("finding matching key")?
                    .ok_or(HolderServiceError::InvalidKey(
                        "No key with role authentication available".to_string(),
                    ))?,
            };
            selected_key.key
        }
        _ => {
            return Err(HolderServiceError::IncompatibleHolderIdentifier);
        }
    })
}
