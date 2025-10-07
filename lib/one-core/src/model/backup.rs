use super::credential::Credential;
use super::did::Did;
use super::identifier::Identifier;
use super::key::Key;
use crate::model::history::History;
use crate::model::wallet_unit_attestation::WalletUnitAttestation;

#[derive(Debug, Clone)]
pub struct UnexportableEntities {
    pub credentials: Vec<Credential>,
    pub keys: Vec<Key>,
    pub dids: Vec<Did>,
    pub identifiers: Vec<Identifier>,
    pub histories: Vec<History>,
    pub wallet_unit_attestations: Vec<WalletUnitAttestation>,
    pub total_credentials: u64,
    pub total_keys: u64,
    pub total_dids: u64,
    pub total_identifiers: u64,
    pub total_histories: u64,
    pub total_wallet_unit_attestations: u64,
}

#[derive(Debug, Clone)]
pub struct Metadata {
    pub version: String,
}
