use identifier_trust_information::IdentifierTrustInformationDB;
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
use self::notifications::NotificationsDB;
use self::organisations::OrganisationsDB;
use self::proof_schemas::ProofSchemasDB;
use self::proofs::ProofsDB;
use self::revocation_lists::RevocationListsDB;
use self::trust_entry::TrustEntryDB;
use self::trust_list_publication::TrustListPublicationDB;
use self::trust_list_subscription::TrustListSubscriptionDB;
use crate::utils::db_clients::blobs::BlobsDB;
use crate::utils::db_clients::holder_wallet_instance::HolderWalletInstancesDB;
use crate::utils::db_clients::localized_text::LocalizedTextDB;
use crate::utils::db_clients::managed_instances::ManagedInstancesDB;
use crate::utils::db_clients::remote_entity_cache::RemoteEntityCacheDB;
use crate::utils::db_clients::trust_collections::TrustCollectionDB;
use crate::utils::db_clients::wallet_attestations::WalletAttestationsDB;

pub mod blobs;
pub mod certificates;
pub mod credential_schemas;
pub mod credentials;
pub mod dids;
pub mod histories;
pub mod holder_wallet_instance;
pub mod identifier_trust_information;
pub mod identifiers;
pub mod interactions;
pub mod keys;
pub mod localized_text;
pub mod managed_instances;
pub mod notifications;
pub mod organisations;
pub mod proof_schemas;
pub mod proofs;
pub mod remote_entity_cache;
pub mod revocation_lists;
pub mod trust_collections;
pub mod trust_entry;
pub mod trust_list_publication;
pub mod trust_list_subscription;
pub mod wallet_attestations;

pub struct DbClient {
    pub organisations: OrganisationsDB,
    pub dids: DidsDB,
    pub certificates: CertificatesDB,
    pub identifiers: IdentifiersDB,
    pub identifier_trust_information: IdentifierTrustInformationDB,
    pub credential_schemas: CredentialSchemasDB,
    pub credentials: CredentialsDB,
    pub histories: HistoriesDB,
    pub remote_entities: RemoteEntityCacheDB,
    pub keys: KeysDB,
    pub notifications: NotificationsDB,
    pub revocation_lists: RevocationListsDB,
    pub proof_schemas: ProofSchemasDB,
    pub proofs: ProofsDB,
    pub interactions: InteractionsDB,
    pub trust_list_publications: TrustListPublicationDB,
    pub trust_list_subscriptions: TrustListSubscriptionDB,
    pub trust_collections: TrustCollectionDB,
    pub trust_entries: TrustEntryDB,
    pub blobs: BlobsDB,
    pub managed_instances: ManagedInstancesDB,
    pub holder_wallet_units: HolderWalletInstancesDB,
    #[expect(unused)]
    pub wallet_attestations: WalletAttestationsDB,
    pub localized_text: LocalizedTextDB,
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
            identifier_trust_information: IdentifierTrustInformationDB::new(
                layer.get_identifier_trust_information_repository(),
            ),
            credential_schemas: CredentialSchemasDB::new(layer.get_credential_schema_repository()),
            credentials: CredentialsDB::new(layer.get_credential_repository()),
            histories: HistoriesDB::new(layer.get_history_repository()),
            remote_entities: RemoteEntityCacheDB::new(layer.get_remote_entity_cache_repository()),
            keys: KeysDB::new(layer.get_key_repository()),
            notifications: NotificationsDB::new(layer.get_notification_repository()),
            revocation_lists: RevocationListsDB::new(layer.get_revocation_list_repository()),
            proof_schemas: ProofSchemasDB::new(layer.get_proof_schema_repository()),
            proofs: ProofsDB::new(
                layer.get_proof_repository(),
                layer.get_credential_repository(),
            ),
            interactions: InteractionsDB::new(layer.get_interaction_repository()),
            trust_list_publications: TrustListPublicationDB::new(
                layer.get_trust_list_publication_repository(),
            ),
            trust_list_subscriptions: TrustListSubscriptionDB::new(
                layer.get_trust_list_subscription_repository(),
                layer.get_trust_collection_repository(),
            ),
            trust_entries: TrustEntryDB::new(layer.get_trust_entry_repository()),
            trust_collections: TrustCollectionDB::new(layer.get_trust_collection_repository()),
            blobs: BlobsDB::new(layer.get_blob_repository()),
            managed_instances: ManagedInstancesDB::new(layer.get_managed_instance_repository()),
            holder_wallet_units: HolderWalletInstancesDB::new(layer.get_instance_repository()),
            wallet_attestations: WalletAttestationsDB::new(
                layer.get_wallet_attestation_repository(),
            ),
            localized_text: LocalizedTextDB::new(layer.get_localized_text_repository()),
        }
    }
}
