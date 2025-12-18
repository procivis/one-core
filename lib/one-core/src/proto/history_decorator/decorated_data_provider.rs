use std::sync::Arc;

use super::certificate::CertificateHistoryDecorator;
use super::credential::CredentialHistoryDecorator;
use super::credential_schema::CredentialSchemaHistoryDecorator;
use super::did::DidHistoryDecorator;
use super::identifier::IdentifierHistoryDecorator;
use super::key::KeyHistoryDecorator;
use super::organisation::OrganisationHistoryDecorator;
use super::proof::ProofHistoryDecorator;
use super::proof_schema::ProofSchemaHistoryDecorator;
use super::trust_entity::TrustEntityHistoryDecorator;
use crate::proto::session_provider::SessionProvider;
use crate::proto::transaction_manager::TransactionManager;
use crate::repository::DataRepository;
use crate::repository::backup_repository::BackupRepository;
use crate::repository::blob_repository::BlobRepository;
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::claim_repository::ClaimRepository;
use crate::repository::claim_schema_repository::ClaimSchemaRepository;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::holder_wallet_unit_repository::HolderWalletUnitRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::repository::proof_schema_repository::ProofSchemaRepository;
use crate::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::repository::trust_anchor_repository::TrustAnchorRepository;
use crate::repository::trust_entity_repository::TrustEntityRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::repository::wallet_unit_attestation_repository::WalletUnitAttestationRepository;
use crate::repository::wallet_unit_attested_key_repository::WalletUnitAttestedKeyRepository;
use crate::repository::wallet_unit_repository::WalletUnitRepository;

struct DecoratedDataProvider {
    // for non-decorated repositories
    data_provider: Arc<dyn DataRepository>,

    // decorated repositories
    organisation_repository: Arc<dyn OrganisationRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    certificate_repository: Arc<dyn CertificateRepository>,
    credential_repository: Arc<dyn CredentialRepository>,
    key_repository: Arc<dyn KeyRepository>,
    did_repository: Arc<dyn DidRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    trust_entity_repository: Arc<dyn TrustEntityRepository>,
}

impl DataRepository for DecoratedDataProvider {
    // decorated
    fn get_organisation_repository(&self) -> Arc<dyn OrganisationRepository> {
        self.organisation_repository.clone()
    }
    fn get_did_repository(&self) -> Arc<dyn DidRepository> {
        self.did_repository.clone()
    }
    fn get_certificate_repository(&self) -> Arc<dyn CertificateRepository> {
        self.certificate_repository.clone()
    }
    fn get_credential_schema_repository(&self) -> Arc<dyn CredentialSchemaRepository> {
        self.credential_schema_repository.clone()
    }
    fn get_credential_repository(&self) -> Arc<dyn CredentialRepository> {
        self.credential_repository.clone()
    }
    fn get_identifier_repository(&self) -> Arc<dyn IdentifierRepository> {
        self.identifier_repository.clone()
    }
    fn get_key_repository(&self) -> Arc<dyn KeyRepository> {
        self.key_repository.clone()
    }
    fn get_proof_schema_repository(&self) -> Arc<dyn ProofSchemaRepository> {
        self.proof_schema_repository.clone()
    }
    fn get_proof_repository(&self) -> Arc<dyn ProofRepository> {
        self.proof_repository.clone()
    }
    fn get_trust_entity_repository(&self) -> Arc<dyn TrustEntityRepository> {
        self.trust_entity_repository.clone()
    }

    // non-decorated
    fn get_claim_repository(&self) -> Arc<dyn ClaimRepository> {
        self.data_provider.get_claim_repository()
    }
    fn get_claim_schema_repository(&self) -> Arc<dyn ClaimSchemaRepository> {
        self.data_provider.get_claim_schema_repository()
    }
    fn get_history_repository(&self) -> Arc<dyn HistoryRepository> {
        self.data_provider.get_history_repository()
    }
    fn get_interaction_repository(&self) -> Arc<dyn InteractionRepository> {
        self.data_provider.get_interaction_repository()
    }
    fn get_remote_entity_cache_repository(&self) -> Arc<dyn RemoteEntityCacheRepository> {
        self.data_provider.get_remote_entity_cache_repository()
    }
    fn get_revocation_list_repository(&self) -> Arc<dyn RevocationListRepository> {
        self.data_provider.get_revocation_list_repository()
    }
    fn get_validity_credential_repository(&self) -> Arc<dyn ValidityCredentialRepository> {
        self.data_provider.get_validity_credential_repository()
    }
    fn get_backup_repository(&self) -> Arc<dyn BackupRepository> {
        self.data_provider.get_backup_repository()
    }
    fn get_trust_anchor_repository(&self) -> Arc<dyn TrustAnchorRepository> {
        self.data_provider.get_trust_anchor_repository()
    }
    fn get_blob_repository(&self) -> Arc<dyn BlobRepository> {
        self.data_provider.get_blob_repository()
    }
    fn get_wallet_unit_repository(&self) -> Arc<dyn WalletUnitRepository> {
        self.data_provider.get_wallet_unit_repository()
    }
    fn get_holder_wallet_unit_repository(&self) -> Arc<dyn HolderWalletUnitRepository> {
        self.data_provider.get_holder_wallet_unit_repository()
    }
    fn get_wallet_unit_attestation_repository(&self) -> Arc<dyn WalletUnitAttestationRepository> {
        self.data_provider.get_wallet_unit_attestation_repository()
    }
    fn get_wallet_unit_attested_key_repository(&self) -> Arc<dyn WalletUnitAttestedKeyRepository> {
        self.data_provider.get_wallet_unit_attested_key_repository()
    }
    fn get_tx_manager(&self) -> Arc<dyn TransactionManager> {
        self.data_provider.get_tx_manager()
    }
}

pub(crate) fn decorate_data_provider(
    data_provider: Arc<dyn DataRepository>,
    session_provider: Arc<dyn SessionProvider>,
    core_base_url: Option<String>,
) -> Arc<dyn DataRepository> {
    let organisation_repository = Arc::new(OrganisationHistoryDecorator {
        inner: data_provider.get_organisation_repository(),
        history_repository: data_provider.get_history_repository(),
        session_provider: session_provider.clone(),
    });

    let credential_schema_repository = Arc::new(CredentialSchemaHistoryDecorator {
        history_repository: data_provider.get_history_repository(),
        inner: data_provider.get_credential_schema_repository(),
        session_provider: session_provider.clone(),
        core_base_url: core_base_url.clone(),
    });

    let proof_schema_repository = Arc::new(ProofSchemaHistoryDecorator {
        inner: data_provider.get_proof_schema_repository(),
        history_repository: data_provider.get_history_repository(),
        session_provider: session_provider.clone(),
        core_base_url,
    });

    let certificate_repository = Arc::new(CertificateHistoryDecorator {
        inner: data_provider.get_certificate_repository(),
        history_repository: data_provider.get_history_repository(),
        session_provider: session_provider.clone(),
        identifier_repository: data_provider.get_identifier_repository(),
    });

    let credential_repository = Arc::new(CredentialHistoryDecorator {
        inner: data_provider.get_credential_repository(),
        history_repository: data_provider.get_history_repository(),
        session_provider: session_provider.clone(),
    });

    let key_repository = Arc::new(KeyHistoryDecorator {
        inner: data_provider.get_key_repository(),
        history_repository: data_provider.get_history_repository(),
        session_provider: session_provider.clone(),
    });

    let did_repository = Arc::new(DidHistoryDecorator {
        inner: data_provider.get_did_repository(),
        history_repository: data_provider.get_history_repository(),
        session_provider: session_provider.clone(),
    });

    let identifier_repository = Arc::new(IdentifierHistoryDecorator {
        inner: data_provider.get_identifier_repository(),
        history_repository: data_provider.get_history_repository(),
        session_provider: session_provider.clone(),
    });

    let proof_repository = Arc::new(ProofHistoryDecorator {
        inner: data_provider.get_proof_repository(),
        history_repository: data_provider.get_history_repository(),
        session_provider: session_provider.clone(),
    });

    let trust_entity_repository = Arc::new(TrustEntityHistoryDecorator {
        inner: data_provider.get_trust_entity_repository(),
        history_repository: data_provider.get_history_repository(),
        session_provider,
    });

    Arc::new(DecoratedDataProvider {
        data_provider,
        organisation_repository,
        credential_schema_repository,
        proof_schema_repository,
        certificate_repository,
        credential_repository,
        key_repository,
        did_repository,
        identifier_repository,
        proof_repository,
        trust_entity_repository,
    })
}
