use shared_types::WalletUnitId;
use time::OffsetDateTime;

pub struct WalletUnit {
    pub id: WalletUnitId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub last_issuance: OffsetDateTime,
    pub name: String,
    pub os: String,
    pub status: WalletUnitStatus,
    pub wallet_unit_type: String,
    pub public_key: String,
}

pub enum WalletUnitStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct WalletUnitRelations {}
