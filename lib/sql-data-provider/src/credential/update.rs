use anyhow::anyhow;
use one_core::repository::error::DataLayerError;
use sea_orm::{ActiveModelTrait, ActiveValue, IntoActiveModel, Iterable};

use crate::entity::credential::{ActiveModel, Column, CredentialRole, CredentialType, Model};

/// Merge only explicitly patched columns. In particular, leave ignored legacy columns intact.
/// The caller must also check that the result can be mapped to the domain model before writing.
pub(super) fn merge_patch(
    stored: Model,
    patch: ActiveModel,
) -> Result<ActiveModel, DataLayerError> {
    let role = stored.role;
    let kind = stored.r#type;
    let mut merged = stored.into_active_model();
    for column in Column::iter() {
        let ActiveValue::Set(value) = patch.get(column) else {
            continue;
        };
        if !allows_patch(column, role, kind) {
            return Err(DataLayerError::IncorrectParameters(anyhow!(
                "Cannot update {column:?} on {role:?} {kind:?} credential"
            )));
        }
        merged.set(column, value);
    }
    Ok(merged)
}

fn allows_patch(column: Column, role: CredentialRole, kind: CredentialType) -> bool {
    use CredentialRole::{Holder, Issuer, Verifier};
    use CredentialType::{BatchItem, BatchParent, Single};

    match column {
        Column::LastModified
        | Column::IssuanceDate
        | Column::ExpiresAt
        | Column::InteractionId
        | Column::RedirectUri
        | Column::State
        | Column::SuspendEndDate => true,
        Column::IssuerIdentifierId | Column::IssuerCertificateId => matches!(
            (role, kind),
            (Issuer, _) | (Holder, Single | BatchItem) | (Verifier, Single)
        ),
        Column::HolderIdentifierId | Column::Format => matches!(
            (role, kind),
            (Issuer | Holder, Single | BatchItem) | (Verifier, Single)
        ),
        Column::KeyId => matches!((role, kind), (Issuer, _) | (Holder, Single | BatchItem)),
        Column::CredentialBlobId => matches!((role, kind), (Issuer | Holder, Single | BatchItem)),
        Column::WalletKeyAttestationBlobId => matches!((role, kind), (Issuer, Single | BatchItem)),
        Column::WalletInstanceAttestationBlobId => {
            matches!((role, kind), (Issuer, Single | BatchParent))
        }
        Column::ConsumedAt => matches!((role, kind), (Holder, BatchItem)),
        // New patchable fields must explicitly declare which variants support them.
        _ => false,
    }
}
