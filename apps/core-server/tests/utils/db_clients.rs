use identifiers::IdentifiersDB;
use one_core::repository::DataRepository;
use sql_data_provider::{DataLayer, DbConn};

use self::certificates::CertificatesDB;
use self::credential_schemas::CredentialSchemasDB;
use self::credentials::CredentialsDB;
use self::dids::DidsDB;
use self::histories::HistoriesDB;
use self::interactions::InteractionsDB;
use self::keys::KeysDB;
use self::organisations::OrganisationsDB;
use self::proof_schemas::ProofSchemasDB;
use self::proofs::ProofsDB;
use self::revocation_lists::RevocationListsDB;
use self::trust_anchors::TrustAnchorDB;
use self::trust_entities::TrustEntityDB;
use crate::utils::db_clients::blobs::BlobsDB;
use crate::utils::db_clients::holder_wallet_unit::HolderWalletUnitsDB;
use crate::utils::db_clients::remote_entity_cache::RemoteEntityCacheDB;
use crate::utils::db_clients::validity_credentials::ValidityCredentialsDB;
use crate::utils::db_clients::wallet_unit_attestations::WalletUnitAttestationsDB;
use crate::utils::db_clients::wallet_units::WalletUnitsDB;

pub mod blobs;
pub mod certificates;
pub mod credential_schemas;
pub mod credentials;
pub mod dids;
pub mod histories;
mod holder_wallet_unit;
pub mod identifiers;
pub mod interactions;
pub mod keys;
pub mod organisations;
pub mod proof_schemas;
pub mod proofs;
pub mod remote_entity_cache;
pub mod revocation_lists;
pub mod trust_anchors;
pub mod trust_entities;
pub mod validity_credentials;
pub mod wallet_unit_attestations;
pub mod wallet_units;

pub struct DbClient {
    pub organisations: OrganisationsDB,
    pub dids: DidsDB,
    pub certificates: CertificatesDB,
    pub identifiers: IdentifiersDB,
    pub credential_schemas: CredentialSchemasDB,
    pub credentials: CredentialsDB,
    pub histories: HistoriesDB,
    pub remote_entities: RemoteEntityCacheDB,
    pub keys: KeysDB,
    pub validity_credentials: ValidityCredentialsDB,
    pub revocation_lists: RevocationListsDB,
    pub proof_schemas: ProofSchemasDB,
    pub proofs: ProofsDB,
    pub interactions: InteractionsDB,
    pub trust_anchors: TrustAnchorDB,
    pub trust_entities: TrustEntityDB,
    pub blobs: BlobsDB,
    pub wallet_units: WalletUnitsDB,
    #[allow(unused)]
    pub holder_wallet_units: HolderWalletUnitsDB,
    #[allow(unused)]
    pub wallet_unit_attestations: WalletUnitAttestationsDB,
    pub db_conn: DbConn,
}

impl DbClient {
    pub fn new(db: DbConn) -> Self {
        let layer = DataLayer::build(db.clone(), vec![]);
        Self {
            db_conn: db,
            organisations: OrganisationsDB::new(layer.get_organisation_repository()),
            dids: DidsDB::new(layer.get_did_repository()),
            certificates: CertificatesDB::new(layer.get_certificate_repository()),
            identifiers: IdentifiersDB::new(layer.get_identifier_repository()),
            credential_schemas: CredentialSchemasDB::new(layer.get_credential_schema_repository()),
            credentials: CredentialsDB::new(layer.get_credential_repository()),
            histories: HistoriesDB::new(layer.get_history_repository()),
            remote_entities: RemoteEntityCacheDB::new(layer.get_remote_entity_cache_repository()),
            keys: KeysDB::new(layer.get_key_repository()),
            validity_credentials: ValidityCredentialsDB::new(
                layer.get_validity_credential_repository(),
            ),
            revocation_lists: RevocationListsDB::new(layer.get_revocation_list_repository()),
            proof_schemas: ProofSchemasDB::new(layer.get_proof_schema_repository()),
            proofs: ProofsDB::new(layer.get_proof_repository()),
            interactions: InteractionsDB::new(layer.get_interaction_repository()),
            trust_anchors: TrustAnchorDB::new(layer.get_trust_anchor_repository()),
            trust_entities: TrustEntityDB::new(layer.get_trust_entity_repository()),
            blobs: BlobsDB::new(layer.get_blob_repository()),
            wallet_units: WalletUnitsDB::new(layer.get_wallet_unit_repository()),
            holder_wallet_units: HolderWalletUnitsDB::new(
                layer.get_holder_wallet_unit_repository(),
            ),
            wallet_unit_attestations: WalletUnitAttestationsDB::new(
                layer.get_wallet_unit_attestation_repository(),
            ),
        }
    }
}
