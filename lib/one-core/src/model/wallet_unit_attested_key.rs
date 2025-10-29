use shared_types::{WalletUnitAttestedKeyId, WalletUnitId};
use time::OffsetDateTime;

use crate::model::key::PublicKeyJwk;
use crate::model::revocation_list::{RevocationList, RevocationListRelations};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletUnitAttestedKey {
    pub id: WalletUnitAttestedKeyId,
    pub wallet_unit_id: WalletUnitId, // cannot be a relation, because wallet unit defines a reverse relation already
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub expiration_date: OffsetDateTime,
    pub public_key_jwk: PublicKeyJwk,
    pub revocation_list_index: Option<i64>,

    // Relations:
    pub revocation_list: Option<RevocationList>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct WalletUnitAttestedKeyRelations {
    pub revocation_list: Option<RevocationListRelations>,
}
