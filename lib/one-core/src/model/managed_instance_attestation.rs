use proc_macros::Model;
use shared_types::{ManagedInstanceAttestationId, ManagedInstanceId, RevocationListEntryId};
use time::OffsetDateTime;

use super::wallet_attestation::AttestationType;
use crate::model::relation::Related;
use crate::model::revocation_list::RevocationList;

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct ManagedInstanceAttestation {
    #[model(id)]
    pub id: ManagedInstanceAttestationId,
    pub instance_id: ManagedInstanceId, // cannot be a relation, because managed instance defines a reverse relation already
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub expiration_date: OffsetDateTime,
    pub r#type: AttestationType,
    pub attestation_content_hash: Option<String>,

    // Relations
    pub revocation: Option<Related<ManagedInstanceAttestationRevocationInfo>>,
}

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct ManagedInstanceAttestationRevocationInfo {
    #[model(id)]
    pub id: RevocationListEntryId,
    pub revocation_list: Related<RevocationList>,
    pub revocation_list_index: usize,
}

#[derive(Clone, Debug, Default)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct UpdateManagedInstanceAttestationRequest {
    pub attestation_content_hash: Option<Option<String>>,
}
