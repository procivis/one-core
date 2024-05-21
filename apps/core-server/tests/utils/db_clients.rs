use crate::utils::db_clients::json_ld_context::JsonLdContextDB;
use crate::utils::db_clients::lvvcs::LvvcsDB;
use one_core::repository::DataRepository;
use sql_data_provider::{DataLayer, DbConn};

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

pub mod credential_schemas;
pub mod credentials;
pub mod dids;
pub mod histories;
pub mod interactions;
pub mod json_ld_context;
pub mod keys;
pub mod lvvcs;
pub mod organisations;
pub mod proof_schemas;
pub mod proofs;
pub mod revocation_lists;
pub mod trust_anchors;
pub mod trust_entities;

pub struct DbClient {
    pub organisations: OrganisationsDB,
    pub dids: DidsDB,
    pub credential_schemas: CredentialSchemasDB,
    pub credentials: CredentialsDB,
    pub histories: HistoriesDB,
    pub json_ld_contexts: JsonLdContextDB,
    pub keys: KeysDB,
    pub lvvcs: LvvcsDB,
    pub revocation_lists: RevocationListsDB,
    pub proof_schemas: ProofSchemasDB,
    pub proofs: ProofsDB,
    pub interactions: InteractionsDB,
    pub trust_anchors: TrustAnchorDB,
    pub trust_entities: TrustEntityDB,
}

impl DbClient {
    pub fn new(db: DbConn) -> Self {
        let layer = DataLayer::build(db, vec![]);
        Self {
            organisations: OrganisationsDB::new(layer.get_organisation_repository()),
            dids: DidsDB::new(layer.get_did_repository()),
            credential_schemas: CredentialSchemasDB::new(layer.get_credential_schema_repository()),
            credentials: CredentialsDB::new(layer.get_credential_repository()),
            histories: HistoriesDB::new(layer.get_history_repository()),
            json_ld_contexts: JsonLdContextDB::new(layer.get_json_ld_context_repository()),
            keys: KeysDB::new(layer.get_key_repository()),
            lvvcs: LvvcsDB::new(layer.get_lvvc_repository()),
            revocation_lists: RevocationListsDB::new(layer.get_revocation_list_repository()),
            proof_schemas: ProofSchemasDB::new(layer.get_proof_schema_repository()),
            proofs: ProofsDB::new(layer.get_proof_repository()),
            interactions: InteractionsDB::new(layer.get_interaction_repository()),
            trust_anchors: TrustAnchorDB::new(layer.get_trust_anchor_repository()),
            trust_entities: TrustEntityDB::new(layer.get_trust_entity_repository()),
        }
    }
}
