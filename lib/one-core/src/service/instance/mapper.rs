use shared_types::KeyId;

use super::dto::HolderInstanceResponseDTO;
use super::service::ProviderMetadata;
use crate::error::NestedError;
use crate::model::instance::{Instance, InstanceStatus};
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::provider::key_storage::model::StorageGeneratedKey;
use crate::service::key::dto::KeyListItemResponseDTO;
use crate::service::managed_instance::dto::WalletProviderMetadataResponseDTO;
use crate::service::verifier_provider::dto::VerifierProviderMetadataResponseDTO;

impl From<WalletProviderMetadataResponseDTO> for ProviderMetadata {
    fn from(value: WalletProviderMetadataResponseDTO) -> Self {
        Self {
            name: value.name,
            attestation: value.wallet_unit_attestation,
            user_authentication: value.user_authentication,
            ecosystems: value.ecosystems,
            credential_schemas: vec![],
            proof_schemas: vec![],
            access_certificate_provisioning_enabled: false,
            ecosystems_enforcement_enabled: value.feature_flags.ecosystems_enforcement_enabled,
        }
    }
}

impl From<VerifierProviderMetadataResponseDTO> for ProviderMetadata {
    fn from(value: VerifierProviderMetadataResponseDTO) -> Self {
        Self {
            name: value.name,
            attestation: value.verifier_app_attestation,
            user_authentication: value.user_authentication,
            ecosystems: value.ecosystems,
            credential_schemas: value.credential_schemas.unwrap_or_default(),
            proof_schemas: value.proof_schemas.unwrap_or_default(),
            access_certificate_provisioning_enabled: value
                .feature_flags
                .access_certificate_provisioning_enabled,
            ecosystems_enforcement_enabled: value.feature_flags.ecosystems_enforcement_enabled,
        }
    }
}

pub(super) fn key_from_generated_key(
    key_id: KeyId,
    key_storage_id: &str,
    key_type: &str,
    organisation: Organisation,
    generated_key: StorageGeneratedKey,
) -> Key {
    let now = crate::clock::now_utc();

    Key {
        id: key_id,
        created_date: now,
        last_modified: now,
        public_key: generated_key.public_key,
        name: format!("Wallet unit key {key_id}"),
        key_reference: generated_key.key_reference,
        storage_type: key_storage_id.to_string(),
        key_type: key_type.to_string(),
        organisation: organisation.into(),
    }
}

pub(super) async fn instance_to_detail_dto(
    value: Instance,
) -> Result<HolderInstanceResponseDTO, NestedError> {
    let authentication_key = match value.authentication_key {
        None => None,
        Some(key) => Some(KeyListItemResponseDTO::from(key.as_ref().await?.to_owned())),
    };
    Ok(HolderInstanceResponseDTO {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        role: value.role,
        provider_instance_id: value.provider_instance_id,
        provider_url: value.provider_url,
        provider_type: value.provider_type,
        provider_name: value.provider_name,
        status: value.status,
        authentication_key,
        user_nonce: (value.status == InstanceStatus::Pending)
            .then_some(value.user_nonce)
            .flatten(),
    })
}
