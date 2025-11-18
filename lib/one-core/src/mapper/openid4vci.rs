use crate::provider::issuance_protocol::model::KeyStorageSecurityLevel;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::HolderInteractionData;

pub(crate) fn interaction_data_to_accepted_key_storage_security(
    data: &HolderInteractionData,
) -> Option<Vec<KeyStorageSecurityLevel>> {
    data.proof_types_supported.as_ref().and_then(|proof_types| {
        proof_types.get("jwt").and_then(|proof_type| {
            proof_type
                .key_attestations_required
                .as_ref()
                .map(|kar| kar.key_storage.clone())
        })
    })
}
