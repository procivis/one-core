//! Selection of the keys an identifier can use for ECDH-ES key agreement.

use standardized_types::jwk::{JwkUse, PublicJwk};

use crate::error::{ContextWithErrorCode, NestedError};
use crate::model::did::KeyRole;
use crate::model::identifier::Identifier;
use crate::model::key::Key;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::util::key_selection::{KeyFilter, KeySelectionError};

/// A key of an identifier that can be used as the static recipient key of an ECDH-ES key
/// agreement, together with the public JWK to advertise for it.
pub(crate) struct KeyAgreementKey {
    pub key: Key,
    pub jwk: PublicJwk,
}

/// Lists the keys of `identifier` that can actually perform ECDH.
/// Returns an empty list rather than an error when the identifier has no such key.
pub(crate) async fn key_agreement_keys(
    identifier: &Identifier,
    key_provider: &dyn KeyProvider,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<Vec<KeyAgreementKey>, NestedError> {
    let candidates = match identifier
        .list_keys(Some(KeyFilter::did_role(KeyRole::KeyAgreement)), None)
        .await
    {
        Ok(keys) => keys,
        // an identifier without a usable key simply cannot do key agreement
        Err(
            KeySelectionError::NoKeyMatchingFilter { .. }
            | KeySelectionError::NoMatchingCertificate { .. }
            | KeySelectionError::RemoteIdentifier
            | KeySelectionError::DidDeactivated { .. },
        ) => return Ok(vec![]),
        Err(error) => return Err(error).error_while("listing identifier keys"),
    };

    let mut result = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let key = candidate.key();

        // the key storage has to be able to derive a shared secret with this key
        let supported = key_provider
            .get_key_storage(&key.storage_type)?
            .key_handle(key)
            .error_while("getting key handle")?
            .key_agreement()
            .and_then(|key_agreement| key_agreement.private())
            .is_some();
        if !supported {
            continue;
        }

        // the JWK has to be derived from the key agreement handle: for EdDSA the key agreement
        // public key is the X25519 conversion, not the Ed25519 point returned for signing
        let Some(mut jwk) = key_algorithm_provider
            .key_algorithm_from_key(key)
            .error_while("getting key algorithm")?
            .reconstruct_key(&key.public_key, None, Some(JwkUse::Encryption))
            .error_while("reconstructing key agreement key")?
            .key_agreement()
            .map(|key_agreement| key_agreement.public().as_jwk())
            .transpose()
            .error_while("creating key agreement JWK")?
        else {
            continue;
        };
        jwk.set_kid(key.id.to_string());

        result.push(KeyAgreementKey {
            key: key.to_owned(),
            jwk,
        });
    }

    Ok(result)
}
