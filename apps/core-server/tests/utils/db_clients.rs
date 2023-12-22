use one_core::repository::DataRepository;
use sql_data_provider::{DataLayer, DbConn};

use self::credential_schemas::CredentialSchemasDB;
use self::credentials::CredentialsDB;
use self::dids::DidsDB;
use self::interactions::InteractionsDB;
use self::keys::KeysDB;
use self::organisations::OrganisationsDB;
use self::revocation_lists::RevocationListsDB;

pub mod credential_schemas;
pub mod credentials;
pub mod dids;
pub mod interactions;
pub mod keys;
pub mod organisations;
pub mod revocation_lists;

pub struct DbClient {
    pub organisations: OrganisationsDB,
    pub dids: DidsDB,
    pub credential_schemas: CredentialSchemasDB,
    pub credentials: CredentialsDB,
    pub keys: KeysDB,
    pub revocation_lists: RevocationListsDB,
    pub interactions: InteractionsDB,
}

impl DbClient {
    pub fn new(db: DbConn) -> Self {
        let layer = DataLayer::build(db);
        Self {
            organisations: OrganisationsDB::new(layer.get_organisation_repository()),
            dids: DidsDB::new(layer.get_did_repository()),
            credential_schemas: CredentialSchemasDB::new(layer.get_credential_schema_repository()),
            credentials: CredentialsDB::new(layer.get_credential_repository()),
            keys: KeysDB::new(layer.get_key_repository()),
            revocation_lists: RevocationListsDB::new(layer.get_revocation_list_repository()),
            interactions: InteractionsDB::new(layer.get_interaction_repository()),
        }
    }
}
