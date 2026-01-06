use std::sync::Arc;

use assert2::let_assert;
use dcql::DcqlQuery;
use mockall::Sequence;
use mockall::predicate::*;
use rstest::rstest;
use secrecy::SecretSlice;
use shared_types::ProofId;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use super::ProofService;
use super::dto::{
    CreateProofRequestDTO, GetProofQueryDTO, ProofClaimValueDTO, ProofFilterValue,
    ProposeProofRequestDTO, ScanToVerifyBarcodeTypeEnum, ScanToVerifyRequestDTO,
    ShareProofRequestDTO,
};
use crate::config::core_config::{
    CoreConfig, Fields, IdentifierType, KeyStorageType, TransportType, VerificationProtocolType,
};
use crate::model::certificate::CertificateRelations;
use crate::model::claim::{Claim, ClaimRelations};
use crate::model::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use crate::model::credential::{
    Credential, CredentialRelations, CredentialRole, CredentialStateEnum,
};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaRelations, KeyStorageSecurity,
    LayoutType,
};
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::history::GetHistoryList;
use crate::model::identifier::{Identifier, IdentifierRelations};
use crate::model::interaction::{
    Interaction, InteractionId, InteractionRelations, InteractionType,
};
use crate::model::key::{JwkUse, Key, PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListPagination;
use crate::model::organisation::OrganisationRelations;
use crate::model::proof::{
    GetProofList, Proof, ProofClaim, ProofClaimRelations, ProofRelations, ProofRole, ProofStateEnum,
};
use crate::model::proof_schema::{
    ProofInputClaimSchema, ProofInputSchema, ProofInputSchemaRelations, ProofSchema,
    ProofSchemaClaimRelations, ProofSchemaRelations,
};
use crate::proto::bluetooth_low_energy::ble_resource::BleWaiter;
use crate::proto::bluetooth_low_energy::low_level::ble_central::MockBleCentral;
use crate::proto::bluetooth_low_energy::low_level::ble_peripheral::MockBlePeripheral;
use crate::proto::bluetooth_low_energy::low_level::dto::DeviceInfo;
use crate::proto::certificate_validator::MockCertificateValidator;
use crate::proto::identifier_creator::MockIdentifierCreator;
use crate::proto::nfc::hce::{MockNfcHce, NfcHce};
use crate::proto::openid4vp_proof_validator::MockOpenId4VpProofValidator;
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::proto::session_provider::{NoSessionProvider, SessionProvider};
use crate::proto::transaction_manager::NoTransactionManager;
use crate::provider::blob_storage_provider::MockBlobStorageProvider;
use crate::provider::credential_formatter::model::FormatterCapabilities;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::credential_formatter::{CredentialFormatter, MockCredentialFormatter};
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::MockKeyStorage;
use crate::provider::key_storage::model::KeyStorageCapabilities;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::presentation_formatter::provider::MockPresentationFormatterProvider;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::provider::verification_protocol::MockVerificationProtocol;
use crate::provider::verification_protocol::dto::{
    ShareResponse, VerificationProtocolCapabilities,
};
use crate::provider::verification_protocol::openid4vp::final1_0::model::AuthorizationRequest;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::ble::BLEPeer;
use crate::provider::verification_protocol::openid4vp::proximity_draft00::ble::model::{
    BLEOpenID4VPInteractionDataVerifier, BLEVerifierProtocolData,
};
use crate::provider::verification_protocol::provider::MockVerificationProtocolProvider;
use crate::repository::certificate_repository::MockCertificateRepository;
use crate::repository::claim_repository::MockClaimRepository;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::did_repository::MockDidRepository;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::proof_repository::MockProofRepository;
use crate::repository::proof_schema_repository::MockProofSchemaRepository;
use crate::repository::validity_credential_repository::MockValidityCredentialRepository;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, ServiceError, ValidationError,
};
use crate::service::test_utilities::{
    dummy_identifier, dummy_organisation, generic_config, get_dummy_date,
};

#[derive(Default)]
struct Repositories {
    pub proof_repository: MockProofRepository,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub proof_schema_repository: MockProofSchemaRepository,
    pub did_repository: MockDidRepository,
    pub identifier_repository: MockIdentifierRepository,
    pub claim_repository: MockClaimRepository,
    pub credential_repository: MockCredentialRepository,
    pub credential_schema_repository: MockCredentialSchemaRepository,
    pub history_repository: MockHistoryRepository,
    pub interaction_repository: MockInteractionRepository,
    pub credential_formatter_provider: MockCredentialFormatterProvider,
    pub presentation_formatter_provider: MockPresentationFormatterProvider,
    pub revocation_method_provider: MockRevocationMethodProvider,
    pub protocol_provider: MockVerificationProtocolProvider,
    pub did_method_provider: MockDidMethodProvider,
    pub ble_peripheral: Option<MockBlePeripheral>,
    pub config: CoreConfig,
    pub organisation_repository: MockOrganisationRepository,
    pub validity_credential_repository: MockValidityCredentialRepository,
    pub certificate_validator: MockCertificateValidator,
    pub certificate_repository: MockCertificateRepository,
    pub key_repository: MockKeyRepository,
    pub blob_storage_provider: MockBlobStorageProvider,
    pub nfc_hce_provider: Option<MockNfcHce>,
    pub session_provider: Option<Arc<dyn SessionProvider>>,
    pub identifier_creator: MockIdentifierCreator,
    pub proof_validator: MockOpenId4VpProofValidator,
}

fn setup_service(repositories: Repositories) -> ProofService {
    ProofService::new(
        Arc::new(repositories.proof_repository),
        Arc::new(repositories.key_algorithm_provider),
        Arc::new(repositories.proof_schema_repository),
        Arc::new(repositories.did_repository),
        Arc::new(repositories.certificate_repository),
        Arc::new(repositories.identifier_repository),
        Arc::new(repositories.claim_repository),
        Arc::new(repositories.credential_repository),
        Arc::new(repositories.credential_schema_repository),
        Arc::new(repositories.history_repository),
        Arc::new(repositories.interaction_repository),
        Arc::new(repositories.credential_formatter_provider),
        Arc::new(repositories.presentation_formatter_provider),
        Arc::new(repositories.revocation_method_provider),
        Arc::new(repositories.protocol_provider),
        Arc::new(repositories.did_method_provider),
        repositories
            .ble_peripheral
            .map(|p| BleWaiter::new(Arc::new(MockBleCentral::new()), Arc::new(p))),
        Arc::new(repositories.config),
        Arc::new(repositories.organisation_repository),
        Arc::new(repositories.validity_credential_repository),
        Arc::new(repositories.certificate_validator),
        Arc::new(repositories.key_repository),
        Arc::new(repositories.blob_storage_provider),
        repositories.nfc_hce_provider.map(|m| {
            let m: Arc<dyn NfcHce> = Arc::new(m);
            m
        }),
        repositories
            .session_provider
            .unwrap_or(Arc::new(NoSessionProvider)),
        Arc::new(repositories.identifier_creator),
        Arc::new(NoTransactionManager),
        Arc::new(repositories.proof_validator),
    )
}

fn construct_proof_with_state(proof_id: &ProofId, state: ProofStateEnum) -> Proof {
    let requested_date = match state {
        ProofStateEnum::Pending
        | ProofStateEnum::Requested
        | ProofStateEnum::Accepted
        | ProofStateEnum::Rejected
        | ProofStateEnum::Error => Some(OffsetDateTime::now_utc()),
        _ => None,
    };

    let completed_date = match state {
        ProofStateEnum::Accepted | ProofStateEnum::Rejected => Some(OffsetDateTime::now_utc()),
        _ => None,
    };

    let key = Key {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        public_key: vec![],
        name: "key".to_string(),
        key_reference: None,
        storage_type: "INTERNAL".to_string(),
        key_type: "EDDSA".to_string(),
        organisation: None,
    };

    Proof {
        id: proof_id.to_owned(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        protocol: "OPENID4VP_DRAFT20".to_string(),
        transport: "HTTP".to_string(),
        redirect_uri: None,
        state,
        role: ProofRole::Verifier,
        requested_date,
        completed_date,
        schema: Some(ProofSchema {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            deleted_at: None,
            name: "".to_string(),
            expire_duration: 0,
            imported_source_url: None,
            organisation: Some(dummy_organisation(None)),
            input_schemas: None,
        }),
        claims: None,
        verifier_identifier: Some(Identifier {
            did: Some(Did {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "did".to_string(),
                organisation: Some(dummy_organisation(None)),
                did: "did:example:123".parse().unwrap(),
                did_type: DidType::Local,
                did_method: "KEY".to_string(),
                keys: Some(vec![RelatedKey {
                    role: KeyRole::KeyAgreement,
                    key: key.to_owned(),
                    reference: "1".to_string(),
                }]),
                deactivated: false,
                log: None,
            }),
            ..dummy_identifier()
        }),
        verifier_key: Some(key),
        verifier_certificate: None,
        interaction: None,
        profile: None,
        proof_blob_id: None,
        engagement: None,
    }
}

fn generic_proof_input_schema() -> ProofInputSchema {
    let now = OffsetDateTime::now_utc();

    ProofInputSchema {
        validity_constraint: None,
        claim_schemas: None,
        credential_schema: Some(CredentialSchema {
            id: Uuid::new_v4().into(),
            deleted_at: None,
            created_date: now,
            last_modified: now,
            name: "schema".to_string(),
            format: "JWT".into(),
            revocation_method: "NONE".to_string(),
            key_storage_security: None,
            imported_source_url: "CORE_URL".to_string(),
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: "".to_string(),
            claim_schemas: None,
            organisation: None,
            allow_suspension: true,
            requires_app_attestation: false,
        }),
    }
}

#[tokio::test]
async fn test_get_presentation_definition_proof_role_verifier() {
    let mut proof_repository = MockProofRepository::default();

    let proof = Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        protocol: "OPENID4VP_DRAFT20".to_string(),
        transport: "HTTP".to_string(),
        state: ProofStateEnum::Pending,
        redirect_uri: None,
        requested_date: Some(OffsetDateTime::now_utc()),
        completed_date: None,
        schema: Some(ProofSchema {
            id: Uuid::new_v4().into(),
            deleted_at: None,
            imported_source_url: Some("CORE_URL".to_string()),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "proof schema".to_string(),
            expire_duration: 0,
            organisation: Some(dummy_organisation(None)),
            input_schemas: Some(vec![ProofInputSchema {
                validity_constraint: None,
                claim_schemas: Some(vec![ProofInputClaimSchema {
                    schema: ClaimSchema {
                        id: Uuid::new_v4().into(),
                        key: "key_123".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                        array: false,
                        metadata: false,
                    },
                    required: true,
                    order: 0,
                }]),
                credential_schema: Some(CredentialSchema {
                    id: Uuid::new_v4().into(),
                    imported_source_url: "CORE_URL".to_string(),
                    deleted_at: None,
                    created_date: OffsetDateTime::now_utc(),
                    key_storage_security: Some(KeyStorageSecurity::Basic),
                    last_modified: OffsetDateTime::now_utc(),
                    name: "credential schema".to_string(),
                    format: "JWT".into(),
                    revocation_method: "NONE".to_string(),
                    claim_schemas: None,
                    organisation: None,
                    layout_type: LayoutType::Card,
                    layout_properties: None,
                    schema_id: "CredentialSchemaId".to_owned(),
                    allow_suspension: true,
                    requires_app_attestation: false,
                }),
            }]),
        }),
        claims: Some(vec![]),
        verifier_identifier: Some(Identifier {
            did: Some(Did {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "did".to_string(),
                did: "did:example:123".parse().unwrap(),
                did_type: DidType::Local,
                did_method: "KEY".to_string(),
                organisation: None,
                keys: None,
                deactivated: false,
                log: None,
            }),
            is_remote: false,
            ..dummy_identifier()
        }),
        verifier_key: None,
        verifier_certificate: None,
        interaction: None,
        role: ProofRole::Verifier,
        profile: None,
        proof_blob_id: None,
        engagement: None,
    };

    {
        let res_clone = proof.clone();
        let proof_id = proof.id;
        proof_repository
            .expect_get_proof()
            .once()
            .withf(move |id, _, _| id == &proof_id)
            .returning(move |_, _, _| Ok(Some(res_clone.clone())));
    }

    let mut protocol_provider = MockVerificationProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .returning(|_| Some(Arc::new(MockVerificationProtocol::default())));

    let service = setup_service(Repositories {
        proof_repository,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_proof_presentation_definition(&proof.id).await;

    assert!(result.is_err_and(|e| matches!(
        e,
        ServiceError::BusinessLogic(BusinessLogicError::InvalidProofRole { .. })
    )));
}

#[tokio::test]
async fn test_get_proof_exists() {
    let mut proof_repository = MockProofRepository::default();
    let mut history_repository = MockHistoryRepository::default();

    let proof = Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        protocol: "OPENID4VP_DRAFT20".to_string(),
        transport: "HTTP".to_string(),
        state: ProofStateEnum::Created,
        redirect_uri: None,
        requested_date: None,
        completed_date: None,
        schema: Some(ProofSchema {
            id: Uuid::new_v4().into(),
            imported_source_url: Some("CORE_URL".to_string()),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            deleted_at: None,
            name: "proof schema".to_string(),
            expire_duration: 0,
            organisation: Some(dummy_organisation(None)),
            input_schemas: Some(vec![ProofInputSchema {
                validity_constraint: None,
                claim_schemas: Some(vec![ProofInputClaimSchema {
                    schema: ClaimSchema {
                        id: Uuid::new_v4().into(),
                        key: "key".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                        array: false,
                        metadata: false,
                    },
                    required: true,
                    order: 0,
                }]),
                credential_schema: Some(CredentialSchema {
                    id: Uuid::new_v4().into(),
                    deleted_at: None,
                    created_date: OffsetDateTime::now_utc(),
                    key_storage_security: Some(KeyStorageSecurity::Basic),
                    imported_source_url: "CORE_URL".to_string(),
                    last_modified: OffsetDateTime::now_utc(),
                    name: "credential schema".to_string(),
                    format: "JWT".into(),
                    revocation_method: "NONE".to_string(),
                    claim_schemas: Some(vec![CredentialSchemaClaim {
                        schema: ClaimSchema {
                            id: Uuid::new_v4().into(),
                            key: "ClaimKey".to_owned(),
                            data_type: "STRING".to_owned(),
                            created_date: OffsetDateTime::now_utc(),
                            last_modified: OffsetDateTime::now_utc(),
                            array: false,
                            metadata: false,
                        },
                        required: true,
                    }]),
                    organisation: None,
                    layout_type: LayoutType::Card,
                    layout_properties: None,
                    schema_id: "CredentialSchemaId".to_owned(),
                    allow_suspension: true,
                    requires_app_attestation: false,
                }),
            }]),
        }),
        claims: Some(vec![]),
        verifier_identifier: Some(Identifier {
            did: Some(Did {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "did".to_string(),
                did: "did:example:123".parse().unwrap(),
                did_type: DidType::Local,
                did_method: "KEY".to_string(),
                organisation: None,
                keys: None,
                deactivated: false,
                log: None,
            }),
            ..dummy_identifier()
        }),
        verifier_key: None,
        verifier_certificate: None,
        interaction: None,
        role: ProofRole::Verifier,
        profile: None,
        proof_blob_id: None,
        engagement: None,
    };
    {
        let res_clone = proof.clone();
        proof_repository
            .expect_get_proof()
            .with(
                eq(proof.id.to_owned()),
                eq(ProofRelations {
                    schema: Some(ProofSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        proof_inputs: Some(ProofInputSchemaRelations {
                            claim_schemas: Some(ProofSchemaClaimRelations::default()),
                            credential_schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(ClaimSchemaRelations::default()),
                                organisation: None,
                            }),
                        }),
                    }),
                    claims: Some(ProofClaimRelations {
                        claim: ClaimRelations {
                            schema: Some(Default::default()),
                        },
                        credential: Some(CredentialRelations {
                            claims: Some(ClaimRelations {
                                schema: Some(Default::default()),
                            }),
                            schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(Default::default()),
                                organisation: Some(Default::default()),
                            }),
                            issuer_identifier: Some(IdentifierRelations {
                                did: Some(Default::default()),
                                ..Default::default()
                            }),
                            issuer_certificate: Some(CertificateRelations::default()),
                            holder_identifier: Some(IdentifierRelations {
                                did: Some(Default::default()),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                    }),
                    verifier_identifier: Some(IdentifierRelations {
                        organisation: Some(Default::default()),
                        ..Default::default()
                    }),
                    verifier_certificate: Some(CertificateRelations::default()),
                    interaction: Some(InteractionRelations {
                        organisation: Some(Default::default()),
                    }),
                    ..Default::default()
                }),
                eq(None),
            )
            .returning(move |_, _, _| Ok(Some(res_clone.clone())));
    }

    history_repository.expect_get_history_list().returning(|_| {
        Ok(GetHistoryList {
            values: vec![],
            total_pages: 1,
            total_items: 1,
        })
    });

    let service = setup_service(Repositories {
        proof_repository,
        history_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_proof(&proof.id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.id, proof.id);
    assert_eq!(result.protocol, proof.protocol);
}

#[tokio::test]
async fn test_get_proof_with_array_holder() {
    let mut proof_repository = MockProofRepository::default();
    let mut history_repository = MockHistoryRepository::default();

    let organisation = dummy_organisation(None);
    let claim_schema = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "key".to_string(),
        data_type: "STRING".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: true,
        metadata: false,
    };

    let credential_schema = CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        imported_source_url: "CORE_URL".to_string(),
        created_date: OffsetDateTime::now_utc(),
        key_storage_security: None,
        last_modified: OffsetDateTime::now_utc(),
        name: "credential schema".to_string(),
        format: "JWT".into(),
        revocation_method: "NONE".to_string(),
        claim_schemas: Some(vec![CredentialSchemaClaim {
            schema: claim_schema.clone(),
            required: true,
        }]),
        organisation: Some(organisation.clone()),
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: "CredentialSchemaId".to_owned(),
        allow_suspension: true,
        requires_app_attestation: false,
    };

    let credential = Credential {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        issuance_date: None,
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        protocol: "".into(),
        redirect_uri: None,
        role: CredentialRole::Holder,
        state: CredentialStateEnum::Accepted,
        suspend_end_date: None,
        claims: Some(vec![
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: None,
                path: "key".into(),
                selectively_disclosable: false,
                schema: Some(claim_schema.clone()),
            },
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: Some("foo1".into()),
                path: "key/0".into(),
                selectively_disclosable: false,
                schema: Some(claim_schema.clone()),
            },
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: Some("foo2".into()),
                path: "key/1".into(),
                selectively_disclosable: false,
                schema: Some(claim_schema.clone()),
            },
        ]),
        issuer_identifier: None,
        issuer_certificate: None,
        holder_identifier: None,
        schema: Some(credential_schema.clone()),
        interaction: None,
        key: None,
        profile: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_app_attestation_blob_id: None,
    };

    let proof = Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        protocol: "OPENID4VP_DRAFT20".to_string(),
        transport: "HTTP".to_string(),
        state: ProofStateEnum::Created,
        redirect_uri: None,
        requested_date: None,
        completed_date: None,
        schema: None,
        claims: Some(
            credential
                .claims
                .iter()
                .flatten()
                .map(|claim| ProofClaim {
                    claim: claim.clone(),
                    credential: Some(credential.clone()),
                })
                .collect(),
        ),
        verifier_identifier: Some(Identifier {
            did: Some(Did {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "did".to_string(),
                did: "did:example:123".parse().unwrap(),
                did_type: DidType::Local,
                did_method: "KEY".to_string(),
                organisation: None,
                keys: None,
                deactivated: false,
                log: None,
            }),
            organisation: Some(organisation.clone()),
            ..dummy_identifier()
        }),
        verifier_key: None,
        verifier_certificate: None,
        interaction: Some(Interaction {
            id: Uuid::new_v4(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            data: None,
            organisation: Some(organisation),
            nonce_id: None,
            interaction_type: InteractionType::Verification,
            expires_at: None,
        }),
        role: ProofRole::Holder,
        profile: None,
        proof_blob_id: None,
        engagement: None,
    };
    {
        let res_clone = proof.clone();
        proof_repository
            .expect_get_proof()
            .with(
                eq(proof.id.to_owned()),
                eq(ProofRelations {
                    schema: Some(ProofSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        proof_inputs: Some(ProofInputSchemaRelations {
                            claim_schemas: Some(ProofSchemaClaimRelations::default()),
                            credential_schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(ClaimSchemaRelations::default()),
                                organisation: None,
                            }),
                        }),
                    }),
                    claims: Some(ProofClaimRelations {
                        claim: ClaimRelations {
                            schema: Some(Default::default()),
                        },
                        credential: Some(CredentialRelations {
                            claims: Some(ClaimRelations {
                                schema: Some(Default::default()),
                            }),
                            schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(Default::default()),
                                organisation: Some(Default::default()),
                            }),
                            issuer_identifier: Some(IdentifierRelations {
                                did: Some(Default::default()),
                                ..Default::default()
                            }),
                            issuer_certificate: Some(CertificateRelations::default()),
                            holder_identifier: Some(IdentifierRelations {
                                did: Some(Default::default()),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                    }),
                    verifier_identifier: Some(IdentifierRelations {
                        organisation: Some(Default::default()),
                        ..Default::default()
                    }),
                    verifier_certificate: Some(CertificateRelations::default()),
                    interaction: Some(InteractionRelations {
                        organisation: Some(Default::default()),
                    }),
                    ..Default::default()
                }),
                eq(None),
            )
            .returning(move |_, _, _| Ok(Some(res_clone.clone())));
    }

    history_repository.expect_get_history_list().returning(|_| {
        Ok(GetHistoryList {
            values: vec![],
            total_pages: 1,
            total_items: 1,
        })
    });

    let service = setup_service(Repositories {
        proof_repository,
        history_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_proof(&proof.id).await.unwrap();
    assert_eq!(result.id, proof.id);

    assert_eq!(result.proof_inputs[0].claims[0].path, "key");

    let claims = match &result.proof_inputs[0].claims[0].value {
        Some(ProofClaimValueDTO::Claims(values)) => values,
        _ => panic!("not array field"),
    };

    assert_eq!(claims[0].path, "key/0");
    assert!(matches!(
        &claims[0].value,
        Some(ProofClaimValueDTO::Value(val)) if val == "foo1"
    ));
    assert_eq!(claims[1].path, "key/1");
    assert!(matches!(
        &claims[1].value,
        Some(ProofClaimValueDTO::Value(val)) if val == "foo2"
    ));
}

#[tokio::test]
async fn test_get_proof_with_array_in_object_holder() {
    let mut proof_repository = MockProofRepository::default();
    let mut history_repository = MockHistoryRepository::default();

    let organisation = dummy_organisation(None);
    let claim_schemas = vec![
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "key".to_string(),
                data_type: "OBJECT".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: false,
                metadata: false,
            },
            required: true,
        },
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "key/address".to_string(),
                data_type: "STRING".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: true,
                metadata: false,
            },
            required: true,
        },
    ];

    let credential_schema = CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        imported_source_url: "CORE_URL".to_string(),
        created_date: OffsetDateTime::now_utc(),
        key_storage_security: None,
        last_modified: OffsetDateTime::now_utc(),
        name: "credential schema".to_string(),
        format: "JWT".into(),
        revocation_method: "NONE".to_string(),
        claim_schemas: Some(claim_schemas.clone()),
        organisation: Some(organisation.clone()),
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: "CredentialSchemaId".to_owned(),
        allow_suspension: true,
        requires_app_attestation: false,
    };

    let credential = Credential {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        issuance_date: None,
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        protocol: "".into(),
        redirect_uri: None,
        role: CredentialRole::Holder,
        state: CredentialStateEnum::Accepted,
        suspend_end_date: None,
        claims: Some(vec![
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: None,
                path: "key".into(),
                selectively_disclosable: false,
                schema: Some(claim_schemas[0].schema.clone()),
            },
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: None,
                path: "key/address".into(),
                selectively_disclosable: false,
                schema: Some(claim_schemas[1].schema.clone()),
            },
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: Some("foo1".into()),
                path: "key/address/0".into(),
                selectively_disclosable: false,
                schema: Some(claim_schemas[1].schema.clone()),
            },
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: Some("foo2".into()),
                path: "key/address/1".into(),
                selectively_disclosable: false,
                schema: Some(claim_schemas[1].schema.clone()),
            },
        ]),
        issuer_identifier: None,
        issuer_certificate: None,
        holder_identifier: None,
        schema: Some(credential_schema.clone()),
        interaction: None,
        key: None,
        profile: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_app_attestation_blob_id: None,
    };

    let proof = Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        protocol: "OPENID4VP_DRAFT20".to_string(),
        transport: "HTTP".to_string(),
        state: ProofStateEnum::Created,
        redirect_uri: None,
        requested_date: None,
        completed_date: None,
        schema: None,
        claims: Some(
            credential
                .claims
                .iter()
                .flatten()
                .map(|claim| ProofClaim {
                    claim: claim.clone(),
                    credential: Some(credential.clone()),
                })
                .collect(),
        ),
        verifier_identifier: Some(Identifier {
            did: Some(Did {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "did".to_string(),
                did: "did:example:123".parse().unwrap(),
                did_type: DidType::Local,
                did_method: "KEY".to_string(),
                organisation: None,
                keys: None,
                deactivated: false,
                log: None,
            }),
            organisation: Some(organisation.clone()),
            ..dummy_identifier()
        }),
        verifier_key: None,
        verifier_certificate: None,
        interaction: Some(Interaction {
            id: Uuid::new_v4(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            data: None,
            organisation: Some(organisation),
            nonce_id: None,
            interaction_type: InteractionType::Verification,
            expires_at: None,
        }),
        role: ProofRole::Holder,
        profile: None,
        proof_blob_id: None,
        engagement: None,
    };
    {
        let res_clone = proof.clone();
        proof_repository
            .expect_get_proof()
            .with(
                eq(proof.id.to_owned()),
                eq(ProofRelations {
                    schema: Some(ProofSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        proof_inputs: Some(ProofInputSchemaRelations {
                            claim_schemas: Some(ProofSchemaClaimRelations::default()),
                            credential_schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(ClaimSchemaRelations::default()),
                                organisation: None,
                            }),
                        }),
                    }),
                    claims: Some(ProofClaimRelations {
                        claim: ClaimRelations {
                            schema: Some(Default::default()),
                        },
                        credential: Some(CredentialRelations {
                            claims: Some(ClaimRelations {
                                schema: Some(Default::default()),
                            }),
                            schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(Default::default()),
                                organisation: Some(Default::default()),
                            }),
                            issuer_identifier: Some(IdentifierRelations {
                                did: Some(Default::default()),
                                ..Default::default()
                            }),
                            issuer_certificate: Some(CertificateRelations::default()),
                            holder_identifier: Some(IdentifierRelations {
                                did: Some(Default::default()),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                    }),
                    verifier_identifier: Some(IdentifierRelations {
                        organisation: Some(Default::default()),
                        ..Default::default()
                    }),
                    verifier_certificate: Some(CertificateRelations::default()),
                    interaction: Some(InteractionRelations {
                        organisation: Some(Default::default()),
                    }),
                    ..Default::default()
                }),
                eq(None),
            )
            .returning(move |_, _, _| Ok(Some(res_clone.clone())));
    }

    history_repository.expect_get_history_list().returning(|_| {
        Ok(GetHistoryList {
            values: vec![],
            total_pages: 1,
            total_items: 1,
        })
    });

    let service = setup_service(Repositories {
        proof_repository,
        history_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_proof(&proof.id).await.unwrap();
    assert_eq!(result.id, proof.id);

    assert_eq!(result.proof_inputs[0].claims[0].path, "key");
    let claims = match &result.proof_inputs[0].claims[0].value {
        Some(ProofClaimValueDTO::Claims(values)) => values,
        _ => panic!("not nested field"),
    };

    assert_eq!(claims[0].path, "key/address");
    let claims = match &claims[0].value {
        Some(ProofClaimValueDTO::Claims(values)) => values,
        _ => panic!("not nested field"),
    };

    assert_eq!(claims[0].path, "key/address/0");
    assert!(matches!(
        &claims[0].value,
        Some(ProofClaimValueDTO::Value(val)) if val == "foo1"
    ));
    assert_eq!(claims[1].path, "key/address/1");
    assert!(matches!(
        &claims[1].value,
        Some(ProofClaimValueDTO::Value(val)) if val == "foo2"
    ));
}

#[tokio::test]
async fn test_get_proof_with_object_array_holder() {
    let mut proof_repository = MockProofRepository::default();
    let mut history_repository = MockHistoryRepository::default();

    let organisation = dummy_organisation(None);
    let claim_schemas = vec![
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "key".to_string(),
                data_type: "OBJECT".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: true,
                metadata: false,
            },
            required: true,
        },
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "key/address".to_string(),
                data_type: "STRING".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: false,
                metadata: false,
            },
            required: true,
        },
    ];

    let credential_schema = CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        created_date: OffsetDateTime::now_utc(),
        key_storage_security: None,
        imported_source_url: "CORE_URL".to_string(),
        last_modified: OffsetDateTime::now_utc(),
        name: "credential schema".to_string(),
        format: "JWT".into(),
        revocation_method: "NONE".to_string(),
        claim_schemas: Some(claim_schemas.clone()),
        organisation: Some(organisation.clone()),
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: "CredentialSchemaId".to_owned(),
        allow_suspension: true,
        requires_app_attestation: false,
    };

    let credential = Credential {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        issuance_date: None,
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        protocol: "".into(),
        redirect_uri: None,
        role: CredentialRole::Holder,
        state: CredentialStateEnum::Accepted,
        suspend_end_date: None,
        claims: Some(vec![
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: None,
                path: "key".into(),
                selectively_disclosable: false,
                schema: Some(claim_schemas[0].schema.clone()),
            },
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: None,
                path: "key/0".into(),
                selectively_disclosable: false,
                schema: Some(claim_schemas[0].schema.clone()),
            },
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: None,
                path: "key/1".into(),
                selectively_disclosable: false,
                schema: Some(claim_schemas[0].schema.clone()),
            },
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: Some("foo1".into()),
                path: "key/0/address".into(),
                selectively_disclosable: false,
                schema: Some(claim_schemas[1].schema.clone()),
            },
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: Some("foo2".into()),
                path: "key/1/address".into(),
                selectively_disclosable: false,
                schema: Some(claim_schemas[1].schema.clone()),
            },
        ]),
        issuer_identifier: None,
        issuer_certificate: None,
        holder_identifier: None,
        schema: Some(credential_schema.clone()),
        interaction: None,
        key: None,
        profile: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_app_attestation_blob_id: None,
    };

    let proof = Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        protocol: "OPENID4VP_DRAFT20".to_string(),
        transport: "HTTP".to_string(),
        state: ProofStateEnum::Created,
        redirect_uri: None,
        requested_date: None,
        completed_date: None,
        schema: None,
        claims: Some(
            credential
                .claims
                .iter()
                .flatten()
                .map(|claim| ProofClaim {
                    claim: claim.clone(),
                    credential: Some(credential.clone()),
                })
                .collect(),
        ),
        verifier_identifier: Some(Identifier {
            did: Some(Did {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "did".to_string(),
                did: "did:example:123".parse().unwrap(),
                did_type: DidType::Local,
                did_method: "KEY".to_string(),
                organisation: None,
                keys: None,
                deactivated: false,
                log: None,
            }),
            organisation: Some(organisation),
            ..dummy_identifier()
        }),
        verifier_key: None,
        verifier_certificate: None,
        interaction: Some(Interaction {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            data: None,
            organisation: Some(dummy_organisation(None)),
            nonce_id: None,
            interaction_type: InteractionType::Verification,
            expires_at: None,
        }),
        role: ProofRole::Holder,
        profile: None,
        proof_blob_id: None,
        engagement: None,
    };
    {
        let res_clone = proof.clone();
        proof_repository
            .expect_get_proof()
            .with(
                eq(proof.id.to_owned()),
                eq(ProofRelations {
                    schema: Some(ProofSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        proof_inputs: Some(ProofInputSchemaRelations {
                            claim_schemas: Some(ProofSchemaClaimRelations::default()),
                            credential_schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(ClaimSchemaRelations::default()),
                                organisation: None,
                            }),
                        }),
                    }),
                    claims: Some(ProofClaimRelations {
                        claim: ClaimRelations {
                            schema: Some(Default::default()),
                        },
                        credential: Some(CredentialRelations {
                            claims: Some(ClaimRelations {
                                schema: Some(Default::default()),
                            }),
                            schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(Default::default()),
                                organisation: Some(Default::default()),
                            }),
                            issuer_identifier: Some(IdentifierRelations {
                                did: Some(Default::default()),
                                ..Default::default()
                            }),
                            issuer_certificate: Some(CertificateRelations::default()),
                            holder_identifier: Some(IdentifierRelations {
                                did: Some(Default::default()),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                    }),
                    verifier_identifier: Some(IdentifierRelations {
                        organisation: Some(Default::default()),
                        ..Default::default()
                    }),
                    verifier_certificate: Some(CertificateRelations::default()),
                    interaction: Some(InteractionRelations {
                        organisation: Some(Default::default()),
                    }),
                    ..Default::default()
                }),
                eq(None),
            )
            .returning(move |_, _, _| Ok(Some(res_clone.clone())));
    }

    history_repository.expect_get_history_list().returning(|_| {
        Ok(GetHistoryList {
            values: vec![],
            total_pages: 1,
            total_items: 1,
        })
    });

    let service = setup_service(Repositories {
        proof_repository,
        history_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_proof(&proof.id).await.unwrap();
    assert_eq!(result.id, proof.id);

    assert_eq!(result.proof_inputs[0].claims[0].path, "key");

    let claims = match &result.proof_inputs[0].claims[0].value {
        Some(ProofClaimValueDTO::Claims(values)) => values,
        _ => panic!("not array field"),
    };

    assert_eq!(claims[0].path, "key/0");
    let claim_0 = match &claims[0].value {
        Some(ProofClaimValueDTO::Claims(values)) => values,
        _ => panic!("not array field"),
    };

    assert_eq!(claim_0[0].path, "key/0/address");
    assert!(matches!(
        &claim_0[0].value,
        Some(ProofClaimValueDTO::Value(val)) if val == "foo1"
    ));

    assert_eq!(claims[1].path, "key/1");
    let claim_1 = match &claims[1].value {
        Some(ProofClaimValueDTO::Claims(values)) => values,
        _ => panic!("not array field"),
    };
    assert_eq!(claim_1[0].path, "key/1/address");
    assert!(matches!(
        &claim_1[0].value,
        Some(ProofClaimValueDTO::Value(val)) if val == "foo2"
    ));
}

#[tokio::test]
async fn test_get_proof_with_array() {
    let mut proof_repository = MockProofRepository::default();
    let mut history_repository = MockHistoryRepository::default();

    let organisation = dummy_organisation(None);

    let claim_schema = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "key".to_string(),
        data_type: "STRING".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: true,
        metadata: false,
    };

    let credential_schema = CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        created_date: OffsetDateTime::now_utc(),
        key_storage_security: None,
        imported_source_url: "CORE_URL".to_string(),
        last_modified: OffsetDateTime::now_utc(),
        name: "credential schema".to_string(),
        format: "JWT".into(),
        revocation_method: "NONE".to_string(),
        claim_schemas: Some(vec![CredentialSchemaClaim {
            schema: claim_schema.clone(),
            required: true,
        }]),
        organisation: Some(organisation.clone()),
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: "CredentialSchemaId".to_owned(),
        allow_suspension: true,
        requires_app_attestation: false,
    };

    let credential = Credential {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        issuance_date: None,
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        protocol: "".into(),
        redirect_uri: None,
        role: CredentialRole::Holder,
        state: CredentialStateEnum::Accepted,
        suspend_end_date: None,
        claims: Some(vec![
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: None,
                path: "key".into(),
                selectively_disclosable: false,
                schema: Some(claim_schema.clone()),
            },
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: Some("foo1".into()),
                path: "key/0".into(),
                selectively_disclosable: false,
                schema: Some(claim_schema.clone()),
            },
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: Some("foo2".into()),
                path: "key/1".into(),
                selectively_disclosable: false,
                schema: Some(claim_schema.clone()),
            },
        ]),
        issuer_identifier: None,
        issuer_certificate: None,
        holder_identifier: None,
        schema: Some(credential_schema.clone()),
        interaction: None,
        key: None,
        profile: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_app_attestation_blob_id: None,
    };

    let proof = Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        protocol: "OPENID4VP_DRAFT20".to_string(),
        transport: "HTTP".to_string(),
        state: ProofStateEnum::Created,
        redirect_uri: None,
        requested_date: None,
        completed_date: None,
        schema: Some(ProofSchema {
            id: Uuid::new_v4().into(),
            imported_source_url: Some("CORE_URL".to_string()),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            deleted_at: None,
            name: "proof schema".to_string(),
            expire_duration: 0,
            organisation: Some(organisation.clone()),
            input_schemas: Some(vec![ProofInputSchema {
                validity_constraint: None,
                claim_schemas: Some(vec![ProofInputClaimSchema {
                    schema: claim_schema.clone(),
                    required: true,
                    order: 0,
                }]),
                credential_schema: Some(credential_schema.clone()),
            }]),
        }),
        claims: Some(
            credential
                .claims
                .iter()
                .flatten()
                .map(|claim| ProofClaim {
                    claim: claim.clone(),
                    credential: Some(credential.clone()),
                })
                .collect(),
        ),
        verifier_identifier: Some(Identifier {
            did: Some(Did {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "did".to_string(),
                did: "did:example:123".parse().unwrap(),
                did_type: DidType::Local,
                did_method: "KEY".to_string(),
                organisation: None,
                keys: None,
                deactivated: false,
                log: None,
            }),
            ..dummy_identifier()
        }),
        verifier_key: None,
        verifier_certificate: None,
        interaction: None,
        role: ProofRole::Verifier,
        profile: None,
        proof_blob_id: None,
        engagement: None,
    };
    {
        let res_clone = proof.clone();
        proof_repository
            .expect_get_proof()
            .with(
                eq(proof.id.to_owned()),
                eq(ProofRelations {
                    schema: Some(ProofSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        proof_inputs: Some(ProofInputSchemaRelations {
                            claim_schemas: Some(ProofSchemaClaimRelations::default()),
                            credential_schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(ClaimSchemaRelations::default()),
                                organisation: None,
                            }),
                        }),
                    }),
                    claims: Some(ProofClaimRelations {
                        claim: ClaimRelations {
                            schema: Some(Default::default()),
                        },
                        credential: Some(CredentialRelations {
                            claims: Some(ClaimRelations {
                                schema: Some(Default::default()),
                            }),
                            schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(Default::default()),
                                organisation: Some(Default::default()),
                            }),
                            issuer_identifier: Some(IdentifierRelations {
                                did: Some(Default::default()),
                                ..Default::default()
                            }),
                            issuer_certificate: Some(CertificateRelations::default()),
                            holder_identifier: Some(IdentifierRelations {
                                did: Some(Default::default()),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                    }),
                    verifier_identifier: Some(IdentifierRelations {
                        organisation: Some(Default::default()),
                        ..Default::default()
                    }),
                    verifier_certificate: Some(CertificateRelations::default()),
                    interaction: Some(InteractionRelations {
                        organisation: Some(Default::default()),
                    }),
                    ..Default::default()
                }),
                eq(None),
            )
            .returning(move |_, _, _| Ok(Some(res_clone.clone())));
    }

    history_repository.expect_get_history_list().returning(|_| {
        Ok(GetHistoryList {
            values: vec![],
            total_pages: 1,
            total_items: 1,
        })
    });

    let service = setup_service(Repositories {
        proof_repository,
        history_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_proof(&proof.id).await.unwrap();
    assert_eq!(result.id, proof.id);

    assert_eq!(result.proof_inputs[0].claims[0].path, "key");

    let claims = match &result.proof_inputs[0].claims[0].value {
        Some(ProofClaimValueDTO::Claims(values)) => values,
        _ => panic!("not array field"),
    };

    assert_eq!(claims[0].path, "key/0");
    assert!(matches!(
        &claims[0].value,
        Some(ProofClaimValueDTO::Value(val)) if val == "foo1"
    ));
    assert_eq!(claims[1].path, "key/1");
    assert!(matches!(
        &claims[1].value,
        Some(ProofClaimValueDTO::Value(val)) if val == "foo2"
    ));
}

#[tokio::test]
async fn test_get_proof_with_array_in_object() {
    let mut proof_repository = MockProofRepository::default();
    let mut history_repository = MockHistoryRepository::default();

    let organisation = dummy_organisation(None);
    let claim_schemas = vec![
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "key".to_string(),
                data_type: "OBJECT".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: false,
                metadata: false,
            },
            required: true,
        },
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "key/address".to_string(),
                data_type: "STRING".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: true,
                metadata: false,
            },
            required: true,
        },
    ];

    let credential_schema = CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        imported_source_url: "CORE_URL".to_string(),
        created_date: OffsetDateTime::now_utc(),
        key_storage_security: None,
        last_modified: OffsetDateTime::now_utc(),
        name: "credential schema".to_string(),
        format: "JWT".into(),
        revocation_method: "NONE".to_string(),
        claim_schemas: Some(claim_schemas.clone()),
        organisation: Some(organisation.clone()),
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: "CredentialSchemaId".to_owned(),
        allow_suspension: true,
        requires_app_attestation: false,
    };

    let credential = Credential {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        issuance_date: None,
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        protocol: "".into(),
        redirect_uri: None,
        role: CredentialRole::Holder,
        state: CredentialStateEnum::Accepted,
        suspend_end_date: None,
        claims: Some(vec![
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: None,
                path: "key".into(),
                selectively_disclosable: false,
                schema: Some(claim_schemas[0].schema.clone()),
            },
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: None,
                path: "key/address".into(),
                selectively_disclosable: false,
                schema: Some(claim_schemas[1].schema.clone()),
            },
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: Some("foo1".into()),
                path: "key/address/0".into(),
                selectively_disclosable: false,
                schema: Some(claim_schemas[1].schema.clone()),
            },
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: Some("foo2".into()),
                path: "key/address/1".into(),
                selectively_disclosable: false,
                schema: Some(claim_schemas[1].schema.clone()),
            },
        ]),
        issuer_identifier: None,
        issuer_certificate: None,
        holder_identifier: None,
        schema: Some(credential_schema.clone()),
        interaction: None,
        key: None,
        profile: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_app_attestation_blob_id: None,
    };

    let proof = Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        protocol: "OPENID4VP_DRAFT20".to_string(),
        transport: "HTTP".to_string(),
        state: ProofStateEnum::Created,
        redirect_uri: None,
        requested_date: None,
        completed_date: None,
        schema: Some(ProofSchema {
            id: Uuid::new_v4().into(),
            imported_source_url: Some("CORE_URL".to_string()),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            deleted_at: None,
            name: "proof schema".to_string(),
            expire_duration: 0,
            organisation: Some(organisation.clone()),
            input_schemas: Some(vec![ProofInputSchema {
                validity_constraint: None,
                claim_schemas: Some(vec![ProofInputClaimSchema {
                    schema: claim_schemas[0].schema.clone(),
                    required: true,
                    order: 0,
                }]),
                credential_schema: Some(credential_schema.clone()),
            }]),
        }),
        claims: Some(
            credential
                .claims
                .iter()
                .flatten()
                .map(|claim| ProofClaim {
                    claim: claim.clone(),
                    credential: Some(credential.clone()),
                })
                .collect(),
        ),
        verifier_identifier: Some(Identifier {
            did: Some(Did {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "did".to_string(),
                did: "did:example:123".parse().unwrap(),
                did_type: DidType::Local,
                did_method: "KEY".to_string(),
                organisation: None,
                keys: None,
                deactivated: false,
                log: None,
            }),
            ..dummy_identifier()
        }),
        verifier_key: None,
        verifier_certificate: None,
        interaction: None,
        role: ProofRole::Verifier,
        profile: None,
        proof_blob_id: None,
        engagement: None,
    };
    {
        let res_clone = proof.clone();
        proof_repository
            .expect_get_proof()
            .with(
                eq(proof.id.to_owned()),
                eq(ProofRelations {
                    schema: Some(ProofSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        proof_inputs: Some(ProofInputSchemaRelations {
                            claim_schemas: Some(ProofSchemaClaimRelations::default()),
                            credential_schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(ClaimSchemaRelations::default()),
                                organisation: None,
                            }),
                        }),
                    }),
                    claims: Some(ProofClaimRelations {
                        claim: ClaimRelations {
                            schema: Some(Default::default()),
                        },
                        credential: Some(CredentialRelations {
                            claims: Some(ClaimRelations {
                                schema: Some(Default::default()),
                            }),
                            schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(Default::default()),
                                organisation: Some(Default::default()),
                            }),
                            issuer_identifier: Some(IdentifierRelations {
                                did: Some(Default::default()),
                                ..Default::default()
                            }),
                            issuer_certificate: Some(CertificateRelations::default()),
                            holder_identifier: Some(IdentifierRelations {
                                did: Some(Default::default()),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                    }),
                    verifier_identifier: Some(IdentifierRelations {
                        organisation: Some(Default::default()),
                        ..Default::default()
                    }),
                    verifier_certificate: Some(CertificateRelations::default()),
                    interaction: Some(InteractionRelations {
                        organisation: Some(Default::default()),
                    }),
                    ..Default::default()
                }),
                eq(None),
            )
            .returning(move |_, _, _| Ok(Some(res_clone.clone())));
    }

    history_repository.expect_get_history_list().returning(|_| {
        Ok(GetHistoryList {
            values: vec![],
            total_pages: 1,
            total_items: 1,
        })
    });

    let service = setup_service(Repositories {
        proof_repository,
        history_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_proof(&proof.id).await.unwrap();
    assert_eq!(result.id, proof.id);

    assert_eq!(result.proof_inputs[0].claims[0].path, "key");

    let claims = match &result.proof_inputs[0].claims[0].value {
        Some(ProofClaimValueDTO::Claims(values)) => values,
        _ => panic!("not array field"),
    };

    assert_eq!(claims[0].path, "key/address");
    let claims = match &claims[0].value {
        Some(ProofClaimValueDTO::Claims(values)) => values,
        _ => panic!("not array field"),
    };

    assert_eq!(claims[0].path, "key/address/0");
    assert!(matches!(
        &claims[0].value,
        Some(ProofClaimValueDTO::Value(val)) if val == "foo1"
    ));
    assert_eq!(claims[1].path, "key/address/1");
    assert!(matches!(
        &claims[1].value,
        Some(ProofClaimValueDTO::Value(val)) if val == "foo2"
    ));
}

#[tokio::test]
async fn test_get_proof_with_object_array() {
    let mut proof_repository = MockProofRepository::default();
    let mut history_repository = MockHistoryRepository::default();

    let organisation = dummy_organisation(None);
    let claim_schemas = vec![
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "key".to_string(),
                data_type: "OBJECT".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: true,
                metadata: false,
            },
            required: true,
        },
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "key/address".to_string(),
                data_type: "STRING".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: false,
                metadata: false,
            },
            required: true,
        },
    ];

    let credential_schema = CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        created_date: OffsetDateTime::now_utc(),
        key_storage_security: None,
        imported_source_url: "CORE_URL".to_string(),
        last_modified: OffsetDateTime::now_utc(),
        name: "credential schema".to_string(),
        format: "JWT".into(),
        revocation_method: "NONE".to_string(),
        claim_schemas: Some(claim_schemas.clone()),
        organisation: Some(organisation.clone()),
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: "CredentialSchemaId".to_owned(),
        allow_suspension: true,
        requires_app_attestation: false,
    };

    let credential = Credential {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        issuance_date: None,
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        protocol: "".into(),
        redirect_uri: None,
        role: CredentialRole::Holder,
        state: CredentialStateEnum::Accepted,
        suspend_end_date: None,
        claims: Some(vec![
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: None,
                path: "key".into(),
                selectively_disclosable: false,
                schema: Some(claim_schemas[0].schema.clone()),
            },
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: None,
                path: "key/0".into(),
                selectively_disclosable: false,
                schema: Some(claim_schemas[0].schema.clone()),
            },
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: None,
                path: "key/1".into(),
                selectively_disclosable: false,
                schema: Some(claim_schemas[0].schema.clone()),
            },
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: Some("foo1".into()),
                path: "key/0/address".into(),
                selectively_disclosable: false,
                schema: Some(claim_schemas[1].schema.clone()),
            },
            Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: Some("foo2".into()),
                path: "key/1/address".into(),
                selectively_disclosable: false,
                schema: Some(claim_schemas[1].schema.clone()),
            },
        ]),
        issuer_identifier: None,
        issuer_certificate: None,
        holder_identifier: None,
        schema: Some(credential_schema.clone()),
        interaction: None,
        key: None,
        profile: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_app_attestation_blob_id: None,
    };

    let proof = Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        protocol: "OPENID4VP_DRAFT20".to_string(),
        transport: "HTTP".to_string(),
        state: ProofStateEnum::Created,
        redirect_uri: None,
        requested_date: None,
        completed_date: None,
        schema: Some(ProofSchema {
            id: Uuid::new_v4().into(),
            imported_source_url: Some("CORE_URL".to_string()),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            deleted_at: None,
            name: "proof schema".to_string(),
            expire_duration: 0,
            organisation: Some(organisation.clone()),
            input_schemas: Some(vec![ProofInputSchema {
                validity_constraint: None,
                claim_schemas: Some(vec![ProofInputClaimSchema {
                    schema: claim_schemas[0].schema.clone(),
                    required: true,
                    order: 0,
                }]),
                credential_schema: Some(credential_schema.clone()),
            }]),
        }),
        claims: Some(
            credential
                .claims
                .iter()
                .flatten()
                .map(|claim| ProofClaim {
                    claim: claim.clone(),
                    credential: Some(credential.clone()),
                })
                .collect(),
        ),
        verifier_identifier: Some(Identifier {
            did: Some(Did {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "did".to_string(),
                did: "did:example:123".parse().unwrap(),
                did_type: DidType::Local,
                did_method: "KEY".to_string(),
                organisation: None,
                keys: None,
                deactivated: false,
                log: None,
            }),
            ..dummy_identifier()
        }),
        verifier_key: None,
        verifier_certificate: None,
        interaction: None,
        role: ProofRole::Verifier,
        profile: None,
        proof_blob_id: None,
        engagement: None,
    };
    {
        let res_clone = proof.clone();
        proof_repository
            .expect_get_proof()
            .with(
                eq(proof.id.to_owned()),
                eq(ProofRelations {
                    schema: Some(ProofSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        proof_inputs: Some(ProofInputSchemaRelations {
                            claim_schemas: Some(ProofSchemaClaimRelations::default()),
                            credential_schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(ClaimSchemaRelations::default()),
                                organisation: None,
                            }),
                        }),
                    }),
                    claims: Some(ProofClaimRelations {
                        claim: ClaimRelations {
                            schema: Some(Default::default()),
                        },
                        credential: Some(CredentialRelations {
                            claims: Some(ClaimRelations {
                                schema: Some(Default::default()),
                            }),
                            schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(Default::default()),
                                organisation: Some(Default::default()),
                            }),
                            issuer_identifier: Some(IdentifierRelations {
                                did: Some(Default::default()),
                                ..Default::default()
                            }),
                            issuer_certificate: Some(CertificateRelations::default()),
                            holder_identifier: Some(IdentifierRelations {
                                did: Some(Default::default()),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                    }),
                    verifier_identifier: Some(IdentifierRelations {
                        organisation: Some(Default::default()),
                        ..Default::default()
                    }),
                    verifier_certificate: Some(CertificateRelations::default()),
                    interaction: Some(InteractionRelations {
                        organisation: Some(Default::default()),
                    }),
                    ..Default::default()
                }),
                eq(None),
            )
            .returning(move |_, _, _| Ok(Some(res_clone.clone())));
    }

    history_repository.expect_get_history_list().returning(|_| {
        Ok(GetHistoryList {
            values: vec![],
            total_pages: 1,
            total_items: 1,
        })
    });

    let service = setup_service(Repositories {
        proof_repository,
        history_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_proof(&proof.id).await.unwrap();

    assert_eq!(result.id, proof.id);

    assert_eq!(result.proof_inputs[0].claims[0].path, "key");

    let claims = match &result.proof_inputs[0].claims[0].value {
        Some(ProofClaimValueDTO::Claims(values)) => values,
        _ => panic!("not array field"),
    };

    assert_eq!(claims[0].path, "key/0");
    let claim_0 = match &claims[0].value {
        Some(ProofClaimValueDTO::Claims(values)) => values,
        _ => panic!("not array field"),
    };

    assert_eq!(claim_0[0].path, "key/0/address");
    assert!(matches!(
        &claim_0[0].value,
        Some(ProofClaimValueDTO::Value(val)) if val == "foo1"
    ));

    assert_eq!(claims[1].path, "key/1");
    let claim_1 = match &claims[1].value {
        Some(ProofClaimValueDTO::Claims(values)) => values,
        _ => panic!("not array field"),
    };
    assert_eq!(claim_1[0].path, "key/1/address");
    assert!(matches!(
        &claim_1[0].value,
        Some(ProofClaimValueDTO::Value(val)) if val == "foo2"
    ));
}

#[tokio::test]
async fn test_get_proof_missing() {
    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_get_proof()
        .once()
        .returning(|_, _, _| Ok(None));

    let service = setup_service(Repositories {
        proof_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_proof(&Uuid::new_v4().into()).await;
    assert!(matches!(
        result,
        Err(ServiceError::EntityNotFound(EntityNotFoundError::Proof(_)))
    ));
}

#[tokio::test]
async fn test_get_proof_list_success() {
    let mut proof_repository = MockProofRepository::default();
    let mut history_repository = MockHistoryRepository::default();

    let proof = Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        protocol: "OPENID4VP_DRAFT20".to_string(),
        transport: "HTTP".to_string(),
        redirect_uri: None,
        state: ProofStateEnum::Created,
        role: ProofRole::Verifier,
        requested_date: None,
        completed_date: None,
        schema: Some(ProofSchema {
            imported_source_url: Some("CORE_URL".to_string()),
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            deleted_at: None,
            name: "proof schema".to_string(),
            expire_duration: 0,
            organisation: None,
            input_schemas: None,
        }),
        claims: None,
        verifier_identifier: Some(Identifier {
            did: Some(Did {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "did".to_string(),
                did: "did:example:123".parse().unwrap(),
                did_type: DidType::Local,
                did_method: "KEY".to_string(),
                organisation: None,
                keys: None,
                deactivated: false,
                log: None,
            }),
            ..dummy_identifier()
        }),
        verifier_key: None,
        verifier_certificate: None,
        interaction: None,
        profile: None,
        proof_blob_id: None,
        engagement: None,
    };
    {
        let res_clone = proof.clone();
        proof_repository
            .expect_get_proof_list()
            .once()
            .returning(move |_| {
                Ok(GetProofList {
                    values: vec![res_clone.to_owned()],
                    total_pages: 1,
                    total_items: 1,
                })
            });
        history_repository
            .expect_get_history_list()
            .return_once(move |_| {
                Ok(GetHistoryList {
                    values: vec![],
                    total_pages: 0,
                    total_items: 0,
                })
            });
    }

    let service = setup_service(Repositories {
        history_repository,
        proof_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let organisation_id = Uuid::new_v4().into();
    let result = service
        .get_proof_list(
            &organisation_id,
            GetProofQueryDTO {
                filtering: ProofFilterValue::OrganisationId(organisation_id)
                    .condition()
                    .into(),
                pagination: Some(ListPagination {
                    page: 0,
                    page_size: 1,
                }),
                sorting: None,
                include: None,
            },
        )
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.total_items, 1);
    assert_eq!(result.total_pages, 1);
    assert_eq!(result.values.len(), 1);
    let result = &result.values[0];
    assert_eq!(result.id, proof.id);
}

#[tokio::test]
async fn test_create_proof_using_formatter_doesnt_support_did_identifiers() {
    let exchange_type = VerificationProtocolType::OpenId4VpDraft20;
    let request = CreateProofRequestDTO {
        proof_schema_id: Uuid::new_v4().into(),
        verifier_did_id: Some(Uuid::new_v4().into()),
        verifier_identifier_id: None,
        protocol: exchange_type.to_string(),
        redirect_uri: None,
        verifier_key: None,
        verifier_certificate: None,
        scan_to_verify: None,
        iso_mdl_engagement: None,
        transport: None,
        profile: None,
        engagement: None,
    };

    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .once()
        .withf(move |id, _| &request.proof_schema_id == id)
        .returning(|id, _| {
            Ok(Some(ProofSchema {
                id: id.to_owned(),
                imported_source_url: Some("CORE_URL".to_string()),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "proof schema".to_string(),
                expire_duration: 0,
                organisation: Some(dummy_organisation(None)),
                input_schemas: Some(vec![generic_proof_input_schema()]),
            }))
        });

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_, _| Ok(Some(dummy_identifier())));

    let mut formatter = MockCredentialFormatter::default();
    let mut credential_formatter_provider = MockCredentialFormatterProvider::default();
    formatter
        .expect_get_capabilities()
        .times(1)
        .returning(move || FormatterCapabilities {
            proof_exchange_protocols: vec![exchange_type],
            verification_key_storages: vec![KeyStorageType::Internal],
            verification_identifier_types: vec![],
            ..Default::default()
        });

    let formatter: Arc<dyn CredentialFormatter> = Arc::new(formatter);
    credential_formatter_provider
        .expect_get_credential_formatter()
        .times(1)
        .returning(move |_| Some(formatter.clone()));

    let mut protocol_provider = MockVerificationProtocolProvider::default();
    protocol_provider.expect_get_protocol().return_once(|_| {
        let mut protocol = MockVerificationProtocol::default();

        protocol.expect_get_capabilities().times(1).returning(|| {
            VerificationProtocolCapabilities {
                supported_transports: vec![TransportType::Http],
                did_methods: vec![crate::config::core_config::DidType::Key],
                verifier_identifier_types: vec![IdentifierType::Did],
                supported_presentation_definition: vec![],
            }
        });

        Some(Arc::new(protocol))
    });

    let service = setup_service(Repositories {
        identifier_repository,
        proof_schema_repository,
        credential_formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.create_proof(request).await;
    assert!(matches!(
        result,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::IncompatibleProofVerificationIdentifier
        ))
    ));
}

#[tokio::test]
async fn test_create_proof_using_invalid_did_method() {
    let exchange_type = VerificationProtocolType::OpenId4VpDraft20;
    let request = CreateProofRequestDTO {
        proof_schema_id: Uuid::new_v4().into(),
        verifier_did_id: Some(Uuid::new_v4().into()),
        verifier_identifier_id: None,
        protocol: exchange_type.to_string(),
        redirect_uri: None,
        verifier_key: None,
        verifier_certificate: None,
        scan_to_verify: None,
        iso_mdl_engagement: None,
        transport: None,
        profile: None,
        engagement: None,
    };

    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .once()
        .withf(move |id, _| &request.proof_schema_id == id)
        .returning(|id, _| {
            Ok(Some(ProofSchema {
                id: id.to_owned(),
                imported_source_url: Some("CORE_URL".to_string()),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "proof schema".to_string(),
                expire_duration: 0,
                organisation: Some(dummy_organisation(None)),
                input_schemas: Some(vec![generic_proof_input_schema()]),
            }))
        });

    let verifier_key_id = Uuid::new_v4();

    let request_clone = request.clone();
    let verifier_did = Did {
        id: request_clone.verifier_did_id.unwrap(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "did".to_string(),
        did: "did:example:123".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "INVALID".to_string(),
        organisation: None,
        keys: Some(vec![RelatedKey {
            role: KeyRole::Authentication,
            key: Key {
                id: verifier_key_id.into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                public_key: vec![],
                name: "key".to_string(),
                key_reference: None,
                storage_type: "INTERNAL".to_string(),
                key_type: "EDDSA".to_string(),
                organisation: None,
            },
            reference: "1".to_string(),
        }]),
        deactivated: false,
        log: None,
    };

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_, _| {
            Ok(Some(Identifier {
                did: Some(verifier_did),
                ..dummy_identifier()
            }))
        });

    let mut formatter = MockCredentialFormatter::default();
    let mut credential_formatter_provider = MockCredentialFormatterProvider::default();
    formatter
        .expect_get_capabilities()
        .returning(move || FormatterCapabilities {
            proof_exchange_protocols: vec![exchange_type],
            verification_key_storages: vec![KeyStorageType::Internal],
            verification_identifier_types: vec![IdentifierType::Did],
            ..Default::default()
        });

    let formatter: Arc<dyn CredentialFormatter> = Arc::new(formatter);
    credential_formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Some(formatter.clone()));

    let mut protocol_provider = MockVerificationProtocolProvider::default();
    protocol_provider.expect_get_protocol().return_once(|_| {
        let mut protocol = MockVerificationProtocol::default();

        protocol.expect_get_capabilities().times(1).returning(|| {
            VerificationProtocolCapabilities {
                supported_transports: vec![TransportType::Http],
                did_methods: vec![crate::config::core_config::DidType::Key],
                verifier_identifier_types: vec![IdentifierType::Did],
                supported_presentation_definition: vec![],
            }
        });

        Some(Arc::new(protocol))
    });

    let service = setup_service(Repositories {
        identifier_repository,
        proof_schema_repository,
        credential_formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.create_proof(request).await;
    assert!(matches!(
        result,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::InvalidDidMethod { .. }
        ))
    ));
}

#[tokio::test]
async fn test_create_proof_using_identifier() {
    let exchange_type = VerificationProtocolType::OpenId4VpDraft20;
    let request = CreateProofRequestDTO {
        proof_schema_id: Uuid::new_v4().into(),
        verifier_did_id: None,
        verifier_identifier_id: Some(Uuid::new_v4().into()),
        protocol: exchange_type.to_string(),
        redirect_uri: None,
        verifier_key: None,
        verifier_certificate: None,
        scan_to_verify: None,
        iso_mdl_engagement: None,
        transport: None,
        profile: None,
        engagement: None,
    };

    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .once()
        .withf(move |id, _| &request.proof_schema_id == id)
        .returning(|id, _| {
            Ok(Some(ProofSchema {
                id: id.to_owned(),
                imported_source_url: Some("CORE_URL".to_string()),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "proof schema".to_string(),
                expire_duration: 0,
                organisation: Some(dummy_organisation(None)),
                input_schemas: Some(vec![generic_proof_input_schema()]),
            }))
        });

    let verifier_did = Did {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "did".to_string(),
        did: "did:example:123".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        organisation: None,
        keys: Some(vec![RelatedKey {
            role: KeyRole::Authentication,
            key: Key {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                public_key: vec![],
                name: "key".to_string(),
                key_reference: None,
                storage_type: "INTERNAL".to_string(),
                key_type: "EDDSA".to_string(),
                organisation: None,
            },
            reference: "1".to_string(),
        }]),
        deactivated: false,
        log: None,
    };

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository.expect_get().return_once(|_, _| {
        Ok(Some(Identifier {
            did: Some(verifier_did),
            ..dummy_identifier()
        }))
    });

    let mut formatter = MockCredentialFormatter::default();
    let mut credential_formatter_provider = MockCredentialFormatterProvider::default();
    formatter
        .expect_get_capabilities()
        .times(3)
        .returning(move || FormatterCapabilities {
            proof_exchange_protocols: vec![exchange_type],
            verification_key_storages: vec![KeyStorageType::Internal],
            verification_identifier_types: vec![IdentifierType::Did],
            ..Default::default()
        });

    let formatter: Arc<dyn CredentialFormatter> = Arc::new(formatter);
    credential_formatter_provider
        .expect_get_credential_formatter()
        .times(3)
        .returning(move |_| Some(formatter.clone()));

    let proof_id = Uuid::new_v4().into();
    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_create_proof()
        .once()
        .withf(move |proof| {
            proof.protocol == exchange_type.to_string() && proof.engagement.is_none()
        })
        .returning(move |_| Ok(proof_id));

    let mut protocol_provider = MockVerificationProtocolProvider::default();
    protocol_provider.expect_get_protocol().return_once(|_| {
        let mut protocol = MockVerificationProtocol::default();

        protocol.expect_get_capabilities().times(1).returning(|| {
            VerificationProtocolCapabilities {
                supported_transports: vec![TransportType::Http],
                did_methods: vec![crate::config::core_config::DidType::Key],
                verifier_identifier_types: vec![IdentifierType::Did],
                supported_presentation_definition: vec![],
            }
        });

        Some(Arc::new(protocol))
    });

    let service = setup_service(Repositories {
        proof_repository,
        identifier_repository,
        proof_schema_repository,
        credential_formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.create_proof(request).await;
    assert_eq!(result.unwrap(), proof_id);
}

#[tokio::test]
async fn test_create_proof_without_related_key() {
    let exchange_type = VerificationProtocolType::OpenId4VpDraft20;
    let request = CreateProofRequestDTO {
        proof_schema_id: Uuid::new_v4().into(),
        verifier_did_id: Some(Uuid::new_v4().into()),
        verifier_identifier_id: None,
        protocol: exchange_type.to_string(),
        redirect_uri: None,
        verifier_key: None,
        verifier_certificate: None,
        scan_to_verify: None,
        iso_mdl_engagement: None,
        transport: None,
        profile: None,
        engagement: None,
    };

    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .once()
        .withf(move |id, _| &request.proof_schema_id == id)
        .returning(|id, _| {
            Ok(Some(ProofSchema {
                id: id.to_owned(),
                imported_source_url: Some("CORE_URL".to_string()),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "proof schema".to_string(),
                expire_duration: 0,
                organisation: Some(dummy_organisation(None)),
                input_schemas: Some(vec![generic_proof_input_schema()]),
            }))
        });

    let verifier_key_id = Uuid::new_v4();

    let request_clone = request.clone();

    let verifier_did = Did {
        id: request_clone.verifier_did_id.unwrap(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "did".to_string(),
        did: "did:example:123".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        organisation: None,
        keys: Some(vec![RelatedKey {
            role: KeyRole::Authentication,
            key: Key {
                id: verifier_key_id.into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                public_key: vec![],
                name: "key".to_string(),
                key_reference: None,
                storage_type: "INTERNAL".to_string(),
                key_type: "EDDSA".to_string(),
                organisation: None,
            },
            reference: "1".to_string(),
        }]),
        deactivated: false,
        log: None,
    };

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_, _| {
            Ok(Some(Identifier {
                did: Some(verifier_did),
                ..dummy_identifier()
            }))
        });

    let mut formatter = MockCredentialFormatter::default();
    let mut credential_formatter_provider = MockCredentialFormatterProvider::default();
    formatter
        .expect_get_capabilities()
        .times(3)
        .returning(move || FormatterCapabilities {
            proof_exchange_protocols: vec![exchange_type],
            verification_key_storages: vec![KeyStorageType::Internal],
            verification_identifier_types: vec![IdentifierType::Did],
            ..Default::default()
        });

    let formatter: Arc<dyn CredentialFormatter> = Arc::new(formatter);
    credential_formatter_provider
        .expect_get_credential_formatter()
        .times(3)
        .returning(move |_| Some(formatter.clone()));

    let proof_id = Uuid::new_v4().into();
    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_create_proof()
        .once()
        .withf(move |proof| proof.protocol == exchange_type.to_string())
        .returning(move |_| Ok(proof_id));

    let mut protocol_provider = MockVerificationProtocolProvider::default();
    protocol_provider.expect_get_protocol().return_once(|_| {
        let mut protocol = MockVerificationProtocol::default();

        protocol.expect_get_capabilities().times(1).returning(|| {
            VerificationProtocolCapabilities {
                supported_transports: vec![TransportType::Http],
                did_methods: vec![crate::config::core_config::DidType::Key],
                verifier_identifier_types: vec![IdentifierType::Did],
                supported_presentation_definition: vec![],
            }
        });

        Some(Arc::new(protocol))
    });

    let service = setup_service(Repositories {
        proof_repository,
        identifier_repository,
        proof_schema_repository,
        credential_formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.create_proof(request).await;
    assert_eq!(result.unwrap(), proof_id);
}

#[tokio::test]
async fn test_create_proof_with_related_key() {
    let exchange_type = VerificationProtocolType::OpenId4VpDraft20;
    let verifier_key_id = Uuid::new_v4().into();
    let request = CreateProofRequestDTO {
        proof_schema_id: Uuid::new_v4().into(),
        verifier_did_id: Some(Uuid::new_v4().into()),
        verifier_identifier_id: None,
        protocol: exchange_type.to_string(),
        redirect_uri: None,
        verifier_key: Some(verifier_key_id),
        verifier_certificate: None,
        scan_to_verify: None,
        iso_mdl_engagement: None,
        transport: None,
        profile: None,
        engagement: None,
    };

    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .once()
        .withf(move |id, _| &request.proof_schema_id == id)
        .returning(|id, _| {
            Ok(Some(ProofSchema {
                id: id.to_owned(),
                imported_source_url: Some("CORE_URL".to_string()),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "proof schema".to_string(),
                expire_duration: 0,
                organisation: Some(dummy_organisation(None)),
                input_schemas: Some(vec![generic_proof_input_schema()]),
            }))
        });

    let request_clone = request.clone();
    let verifier_did = Did {
        id: request_clone.verifier_did_id.unwrap(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "did".to_string(),
        did: "did:example:123".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        organisation: None,
        keys: Some(vec![RelatedKey {
            role: KeyRole::Authentication,
            key: Key {
                id: verifier_key_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                public_key: vec![],
                name: "key".to_string(),
                key_reference: None,
                storage_type: "INTERNAL".to_string(),
                key_type: "EDDSA".to_string(),
                organisation: None,
            },
            reference: "1".to_string(),
        }]),
        deactivated: false,
        log: None,
    };

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_, _| {
            Ok(Some(Identifier {
                did: Some(verifier_did),
                ..dummy_identifier()
            }))
        });

    let mut formatter = MockCredentialFormatter::default();
    let mut credential_formatter_provider = MockCredentialFormatterProvider::default();
    formatter
        .expect_get_capabilities()
        .times(3)
        .returning(move || FormatterCapabilities {
            proof_exchange_protocols: vec![exchange_type],
            verification_key_storages: vec![KeyStorageType::Internal],
            verification_identifier_types: vec![IdentifierType::Did],
            ..Default::default()
        });

    let formatter: Arc<dyn CredentialFormatter> = Arc::new(formatter);
    credential_formatter_provider
        .expect_get_credential_formatter()
        .times(3)
        .returning(move |_| Some(formatter.clone()));

    let proof_id = Uuid::new_v4().into();
    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_create_proof()
        .once()
        .withf(move |proof| proof.protocol == exchange_type.to_string())
        .returning(move |_| Ok(proof_id));

    let mut protocol_provider = MockVerificationProtocolProvider::default();
    protocol_provider.expect_get_protocol().return_once(|_| {
        let mut protocol = MockVerificationProtocol::default();

        protocol.expect_get_capabilities().times(1).returning(|| {
            VerificationProtocolCapabilities {
                supported_transports: vec![TransportType::Http],
                did_methods: vec![crate::config::core_config::DidType::Key],
                verifier_identifier_types: vec![IdentifierType::Did],
                supported_presentation_definition: vec![],
            }
        });

        Some(Arc::new(protocol))
    });

    let service = setup_service(Repositories {
        proof_repository,
        identifier_repository,
        proof_schema_repository,
        credential_formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.create_proof(request).await;
    assert_eq!(result.unwrap(), proof_id);
}

#[tokio::test]
async fn test_create_proof_fail_unsupported_wallet_storage_type() {
    let exchange_type = VerificationProtocolType::OpenId4VpDraft20;
    let request = CreateProofRequestDTO {
        proof_schema_id: Uuid::new_v4().into(),
        verifier_did_id: Some(Uuid::new_v4().into()),
        verifier_identifier_id: None,
        protocol: exchange_type.to_string(),
        redirect_uri: None,
        verifier_key: None,
        verifier_certificate: None,
        scan_to_verify: None,
        iso_mdl_engagement: None,
        transport: None,
        profile: None,
        engagement: None,
    };

    let mut proof_input_schema = generic_proof_input_schema();
    proof_input_schema
        .credential_schema
        .as_mut()
        .unwrap()
        .key_storage_security = Some(KeyStorageSecurity::EnhancedBasic);

    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .once()
        .withf(move |id, _| &request.proof_schema_id == id)
        .return_once(|id, _| {
            Ok(Some(ProofSchema {
                id: id.to_owned(),
                imported_source_url: Some("CORE_URL".to_string()),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "proof schema".to_string(),
                expire_duration: 0,
                organisation: Some(dummy_organisation(None)),
                input_schemas: Some(vec![proof_input_schema]),
            }))
        });

    let verifier_did = Did {
        id: request.verifier_did_id.to_owned().unwrap(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "did".to_string(),
        did: "did:example:123".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        organisation: None,
        keys: Some(vec![RelatedKey {
            role: KeyRole::Authentication,
            key: Key {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                public_key: vec![],
                name: "key".to_string(),
                key_reference: None,
                storage_type: "INTERNAL".to_string(),
                key_type: "EDDSA".to_string(),
                organisation: None,
            },
            reference: "1".to_string(),
        }]),
        deactivated: false,
        log: None,
    };

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_, _| {
            Ok(Some(Identifier {
                did: Some(verifier_did),
                ..dummy_identifier()
            }))
        });

    let mut formatter = MockCredentialFormatter::default();
    let mut credential_formatter_provider = MockCredentialFormatterProvider::default();
    formatter
        .expect_get_capabilities()
        .times(1)
        .returning(move || FormatterCapabilities {
            proof_exchange_protocols: vec![exchange_type],
            verification_key_storages: vec![KeyStorageType::Internal],
            verification_identifier_types: vec![IdentifierType::Did],
            ..Default::default()
        });

    let formatter: Arc<dyn CredentialFormatter> = Arc::new(formatter);
    credential_formatter_provider
        .expect_get_credential_formatter()
        .times(1)
        .returning(move |_| Some(formatter.clone()));

    let mut protocol_provider = MockVerificationProtocolProvider::default();
    protocol_provider.expect_get_protocol().return_once(|_| {
        let mut protocol = MockVerificationProtocol::default();

        protocol.expect_get_capabilities().times(1).returning(|| {
            VerificationProtocolCapabilities {
                supported_transports: vec![TransportType::Http],
                did_methods: vec![crate::config::core_config::DidType::Key],
                verifier_identifier_types: vec![IdentifierType::Did],
                supported_presentation_definition: vec![],
            }
        });

        Some(Arc::new(protocol))
    });

    let service = setup_service(Repositories {
        identifier_repository,
        proof_schema_repository,
        credential_formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.create_proof(request).await;
    assert!(result.is_err_and(|e| matches!(
        e,
        ServiceError::Validation(ValidationError::KeyStorageSecurityDisabled(_))
    )));
}

#[tokio::test]
async fn test_create_proof_failed_no_key_with_authentication_method_role() {
    let exchange_type = VerificationProtocolType::OpenId4VpDraft20;
    let request = CreateProofRequestDTO {
        proof_schema_id: Uuid::new_v4().into(),
        verifier_did_id: Some(Uuid::new_v4().into()),
        verifier_identifier_id: None,
        protocol: exchange_type.to_string(),
        redirect_uri: None,
        verifier_key: None,
        verifier_certificate: None,
        scan_to_verify: None,
        iso_mdl_engagement: None,
        transport: None,
        profile: None,
        engagement: None,
    };

    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .once()
        .withf(move |id, _| &request.proof_schema_id == id)
        .returning(|id, _| {
            Ok(Some(ProofSchema {
                id: id.to_owned(),
                imported_source_url: Some("CORE_URL".to_string()),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "proof schema".to_string(),
                expire_duration: 0,
                organisation: Some(dummy_organisation(None)),
                input_schemas: Some(vec![generic_proof_input_schema()]),
            }))
        });

    let request_clone = request.clone();
    let verifier_did = Did {
        id: request_clone.verifier_did_id.unwrap(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "did".to_string(),
        did: "did:example:123".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        organisation: None,
        keys: Some(vec![]),
        deactivated: false,
        log: None,
    };

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_, _| {
            Ok(Some(Identifier {
                did: Some(verifier_did),
                ..dummy_identifier()
            }))
        });

    let mut formatter = MockCredentialFormatter::default();
    let mut credential_formatter_provider = MockCredentialFormatterProvider::default();
    formatter
        .expect_get_capabilities()
        .returning(move || FormatterCapabilities {
            proof_exchange_protocols: vec![exchange_type],
            verification_identifier_types: vec![IdentifierType::Did],
            ..Default::default()
        });
    let formatter = Arc::new(formatter);
    credential_formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Some(formatter.clone()));

    let mut protocol_provider = MockVerificationProtocolProvider::default();
    protocol_provider.expect_get_protocol().return_once(|_| {
        let mut protocol = MockVerificationProtocol::default();

        protocol.expect_get_capabilities().times(1).returning(|| {
            VerificationProtocolCapabilities {
                supported_transports: vec![TransportType::Http],
                did_methods: vec![crate::config::core_config::DidType::Key],
                verifier_identifier_types: vec![IdentifierType::Did],
                supported_presentation_definition: vec![],
            }
        });

        Some(Arc::new(protocol))
    });

    let service = setup_service(Repositories {
        identifier_repository,
        proof_schema_repository,
        credential_formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.create_proof(request).await;
    assert!(matches!(
        result.unwrap_err(),
        ServiceError::Validation(ValidationError::InvalidKey(_))
    ));
}

#[tokio::test]
async fn test_create_proof_failed_incompatible_exchange() {
    let exchange = "OPENID4VP_DRAFT20".to_string();
    let request = CreateProofRequestDTO {
        proof_schema_id: Uuid::new_v4().into(),
        verifier_did_id: Some(Uuid::new_v4().into()),
        verifier_identifier_id: None,
        protocol: exchange.to_owned(),
        redirect_uri: None,
        verifier_key: None,
        verifier_certificate: None,
        scan_to_verify: None,
        iso_mdl_engagement: None,
        transport: None,
        profile: None,
        engagement: None,
    };

    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .once()
        .withf(move |id, _| &request.proof_schema_id == id)
        .returning(|id, _| {
            Ok(Some(ProofSchema {
                id: id.to_owned(),
                imported_source_url: Some("CORE_URL".to_string()),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "proof schema".to_string(),
                expire_duration: 0,
                organisation: Some(dummy_organisation(None)),
                input_schemas: Some(vec![generic_proof_input_schema()]),
            }))
        });

    let mut formatter = MockCredentialFormatter::default();
    let mut credential_formatter_provider = MockCredentialFormatterProvider::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(FormatterCapabilities::default);
    credential_formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let service = setup_service(Repositories {
        proof_schema_repository,
        credential_formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.create_proof(request).await;
    assert!(matches!(
        result.unwrap_err(),
        ServiceError::BusinessLogic(BusinessLogicError::IncompatibleProofExchangeProtocol)
    ));
}

#[tokio::test]
async fn test_create_proof_did_deactivated_error() {
    let exchange_type = VerificationProtocolType::OpenId4VpDraft20;
    let request = CreateProofRequestDTO {
        proof_schema_id: Uuid::new_v4().into(),
        verifier_did_id: Some(Uuid::new_v4().into()),
        verifier_identifier_id: None,
        protocol: exchange_type.to_string(),
        redirect_uri: None,
        verifier_key: None,
        verifier_certificate: None,
        scan_to_verify: None,
        iso_mdl_engagement: None,
        transport: None,
        profile: None,
        engagement: None,
    };

    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .once()
        .withf(move |id, _| &request.proof_schema_id == id)
        .returning(|id, _| {
            Ok(Some(ProofSchema {
                id: id.to_owned(),
                imported_source_url: Some("CORE_URL".to_string()),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "proof schema".to_string(),
                expire_duration: 0,
                organisation: Some(dummy_organisation(None)),
                input_schemas: Some(vec![generic_proof_input_schema()]),
            }))
        });

    let request_clone = request.clone();
    let verifier_did = Did {
        id: request_clone.verifier_did_id.unwrap(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "did".to_string(),
        did: "did:example:123".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        organisation: None,
        keys: None,
        deactivated: true,
        log: None,
    };
    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_, _| {
            Ok(Some(Identifier {
                did: Some(verifier_did),
                ..dummy_identifier()
            }))
        });

    let mut formatter = MockCredentialFormatter::default();
    let mut credential_formatter_provider = MockCredentialFormatterProvider::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(move || FormatterCapabilities {
            proof_exchange_protocols: vec![exchange_type],
            verification_identifier_types: vec![IdentifierType::Did],
            ..Default::default()
        });
    credential_formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let mut protocol_provider = MockVerificationProtocolProvider::default();
    protocol_provider.expect_get_protocol().return_once(|_| {
        let mut protocol = MockVerificationProtocol::default();

        protocol.expect_get_capabilities().times(1).returning(|| {
            VerificationProtocolCapabilities {
                supported_transports: vec![TransportType::Http],
                did_methods: vec![crate::config::core_config::DidType::Key],
                verifier_identifier_types: vec![IdentifierType::Did],
                supported_presentation_definition: vec![],
            }
        });

        Some(Arc::new(protocol))
    });

    let service = setup_service(Repositories {
        identifier_repository,
        proof_schema_repository,
        credential_formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.create_proof(request).await;
    assert2::assert!(
        let Err(
            ServiceError::BusinessLogic(
                BusinessLogicError::DidIsDeactivated(_)
            )
        ) = result
    );
}

#[tokio::test]
async fn test_create_proof_schema_deleted() {
    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .once()
        .returning(|id, _| {
            Ok(Some(ProofSchema {
                id: id.to_owned(),
                imported_source_url: Some("CORE_URL".to_string()),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: Some(OffsetDateTime::now_utc()),
                name: "proof schema".to_string(),
                expire_duration: 0,
                organisation: Some(dummy_organisation(None)),
                input_schemas: None,
            }))
        });

    let service = setup_service(Repositories {
        proof_schema_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_proof(CreateProofRequestDTO {
            proof_schema_id: Uuid::new_v4().into(),
            verifier_did_id: Some(Uuid::new_v4().into()),
            verifier_identifier_id: None,
            protocol: "OPENID4VP_DRAFT20".to_string(),
            redirect_uri: None,
            verifier_key: None,
            verifier_certificate: None,
            scan_to_verify: None,
            iso_mdl_engagement: None,
            transport: None,
            profile: None,
            engagement: None,
        })
        .await;
    assert2::assert!(
        let Err(ServiceError::BusinessLogic(BusinessLogicError::ProofSchemaDeleted {..})) = result
    );
}

#[tokio::test]
async fn test_create_proof_failed_scan_to_verify_in_unsupported_exchange() {
    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .once()
        .returning(|id, _| {
            Ok(Some(ProofSchema {
                id: id.to_owned(),
                imported_source_url: Some("CORE_URL".to_string()),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "proof schema".to_string(),
                expire_duration: 0,
                organisation: Some(dummy_organisation(None)),
                input_schemas: Some(vec![generic_proof_input_schema()]),
            }))
        });

    let mut formatter = MockCredentialFormatter::default();
    let mut credential_formatter_provider = MockCredentialFormatterProvider::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(move || FormatterCapabilities {
            proof_exchange_protocols: vec![VerificationProtocolType::OpenId4VpDraft20],
            verification_identifier_types: vec![IdentifierType::Did],
            ..Default::default()
        });
    credential_formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let service = setup_service(Repositories {
        proof_schema_repository,
        credential_formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_proof(CreateProofRequestDTO {
            proof_schema_id: Uuid::new_v4().into(),
            verifier_did_id: Some(Uuid::new_v4().into()),
            verifier_identifier_id: None,
            protocol: "OPENID4VP_DRAFT20".to_string(),
            redirect_uri: None,
            verifier_key: None,
            verifier_certificate: None,
            scan_to_verify: Some(ScanToVerifyRequestDTO {
                credential: "credential".to_string(),
                barcode: "barcode".to_string(),
                barcode_type: ScanToVerifyBarcodeTypeEnum::MRZ,
            }),
            iso_mdl_engagement: None,
            transport: None,
            profile: None,
            engagement: None,
        })
        .await;
    assert2::assert!(
        let Err(ServiceError::Validation(ValidationError::InvalidScanToVerifyParameters)) = result
    );
}

#[tokio::test]
async fn test_create_proof_failed_incompatible_verification_key_storage() {
    let exchange_type = VerificationProtocolType::OpenId4VpDraft20;
    let request = CreateProofRequestDTO {
        proof_schema_id: Uuid::new_v4().into(),
        verifier_did_id: Some(Uuid::new_v4().into()),
        verifier_identifier_id: None,
        protocol: exchange_type.to_string(),
        redirect_uri: None,
        verifier_key: None,
        verifier_certificate: None,
        scan_to_verify: None,
        iso_mdl_engagement: None,
        transport: None,
        profile: None,
        engagement: None,
    };

    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .once()
        .withf(move |id, _| &request.proof_schema_id == id)
        .returning(|id, _| {
            Ok(Some(ProofSchema {
                id: id.to_owned(),
                imported_source_url: Some("CORE_URL".to_string()),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "proof schema".to_string(),
                expire_duration: 0,
                organisation: Some(dummy_organisation(None)),
                input_schemas: Some(vec![generic_proof_input_schema()]),
            }))
        });

    let verifier_key_id = Uuid::new_v4();

    let request_clone = request.clone();
    let verifier_did = Did {
        id: request_clone.verifier_did_id.unwrap(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "did".to_string(),
        did: "did:example:123".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        organisation: None,
        keys: Some(vec![RelatedKey {
            role: KeyRole::Authentication,
            key: Key {
                id: verifier_key_id.into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                public_key: vec![],
                name: "key".to_string(),
                key_reference: None,
                storage_type: "INTERNAL".to_string(),
                key_type: "EDDSA".to_string(),
                organisation: None,
            },
            reference: "1".to_string(),
        }]),
        deactivated: false,
        log: None,
    };

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_, _| {
            Ok(Some(Identifier {
                did: Some(verifier_did),
                ..dummy_identifier()
            }))
        });

    let mut formatter = MockCredentialFormatter::default();
    let mut credential_formatter_provider = MockCredentialFormatterProvider::default();
    formatter
        .expect_get_capabilities()
        .returning(move || FormatterCapabilities {
            proof_exchange_protocols: vec![exchange_type],
            verification_key_storages: vec![],
            verification_identifier_types: vec![IdentifierType::Did],
            ..Default::default()
        });

    let formatter: Arc<dyn CredentialFormatter> = Arc::new(formatter);
    credential_formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Some(formatter.clone()));

    let mut protocol_provider = MockVerificationProtocolProvider::default();
    protocol_provider.expect_get_protocol().return_once(|_| {
        let mut protocol = MockVerificationProtocol::default();

        protocol.expect_get_capabilities().times(1).returning(|| {
            VerificationProtocolCapabilities {
                supported_transports: vec![TransportType::Http],
                did_methods: vec![crate::config::core_config::DidType::Key],
                verifier_identifier_types: vec![IdentifierType::Did],
                supported_presentation_definition: vec![],
            }
        });

        Some(Arc::new(protocol))
    });

    let service = setup_service(Repositories {
        identifier_repository,
        proof_schema_repository,
        credential_formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.create_proof(request).await;
    assert!(matches!(
        result,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::IncompatibleProofVerificationKeyStorage
        ))
    ));
}

#[tokio::test]
async fn test_create_proof_failed_invalid_redirect_uri() {
    let service = setup_service(Repositories {
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_proof(CreateProofRequestDTO {
            proof_schema_id: Uuid::new_v4().into(),
            verifier_did_id: Some(Uuid::new_v4().into()),
            verifier_identifier_id: None,
            protocol: "OPENID4VP_DRAFT20".to_string(),
            redirect_uri: Some("invalid://domain.com".to_string()),
            verifier_key: None,
            verifier_certificate: None,
            scan_to_verify: None,
            iso_mdl_engagement: None,
            transport: None,
            profile: None,
            engagement: None,
        })
        .await;
    assert!(matches!(
        result.unwrap_err(),
        ServiceError::Validation(ValidationError::InvalidRedirectUri)
    ));
}

#[tokio::test]
async fn test_share_proof_created_success() {
    let proof_id = Uuid::new_v4().into();
    let proof = construct_proof_with_state(&proof_id, ProofStateEnum::Created);
    let mut protocol = MockVerificationProtocol::default();
    let mut protocol_provider = MockVerificationProtocolProvider::default();

    let mut key_algorithm = MockKeyAlgorithm::new();
    key_algorithm
        .expect_reconstruct_key()
        .return_once(|_, _, _| {
            let mut key_handle = MockSignaturePublicKeyHandle::default();
            key_handle.expect_as_jwk().return_once(|| {
                Ok(PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
                    alg: None,
                    r#use: Some(JwkUse::Encryption),
                    kid: None,
                    crv: "123".to_string(),
                    x: "456".to_string(),
                    y: None,
                }))
            });
            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(key_handle),
            )))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .return_once(|_| Some(Arc::new(key_algorithm)));

    let mut key_provider = MockKeyProvider::new();
    key_provider.expect_get_key_storage().return_once(|_| {
        let mut key_storage = MockKeyStorage::default();
        key_storage
            .expect_get_capabilities()
            .return_once(|| KeyStorageCapabilities {
                features: vec![],
                algorithms: vec![],
            });

        Some(Arc::new(key_storage))
    });

    let expected_url = "test_url";
    let interaction_id = Uuid::new_v4();
    let expires_at = OffsetDateTime::now_utc();
    protocol
        .expect_verifier_share_proof()
        .once()
        .returning(move |_, _, _, _, _| {
            Ok(ShareResponse {
                url: expected_url.to_owned(),
                interaction_id,
                interaction_data: None,
                expires_at: Some(expires_at),
            })
        });

    let protocol = Arc::new(protocol);

    protocol_provider
        .expect_get_protocol()
        .once()
        .returning(move |_| Some(protocol.clone()));

    let mut seq = Sequence::new();
    let mut proof_repository = MockProofRepository::default();
    {
        let res_clone = proof.clone();
        proof_repository
            .expect_get_proof()
            .once()
            .in_sequence(&mut seq)
            .withf(move |id, _, _| id == &proof_id)
            .returning(move |_, _, _| Ok(Some(res_clone.to_owned())));
    }

    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_create_interaction()
        .withf(move |interaction| {
            interaction.id == interaction_id && interaction.expires_at.unwrap() == expires_at
        })
        .once()
        .in_sequence(&mut seq)
        .returning(move |_| Ok(interaction_id));

    proof_repository
        .expect_update_proof()
        .once()
        .in_sequence(&mut seq)
        .withf(move |id, update, _| {
            id == &proof_id
                && update.state == Some(ProofStateEnum::Pending)
                && update.interaction == Some(Some(interaction_id))
                && update.engagement == Some(Some("QR_CODE".to_string()))
        })
        .returning(|_, _, _| Ok(()));

    let service = setup_service(Repositories {
        proof_repository,
        protocol_provider,
        interaction_repository,
        key_algorithm_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .share_proof(&proof_id, ShareProofRequestDTO::default())
        .await
        .unwrap();

    assert_eq!(result.url, expected_url);
    assert_eq!(result.expires_at.unwrap(), expires_at);
}

#[tokio::test]
async fn test_share_proof_pending_success() {
    let proof_id = Uuid::new_v4().into();
    let proof = construct_proof_with_state(&proof_id, ProofStateEnum::Pending);
    let mut protocol = MockVerificationProtocol::default();
    let mut protocol_provider = MockVerificationProtocolProvider::default();

    let mut key_algorithm = MockKeyAlgorithm::new();
    key_algorithm
        .expect_reconstruct_key()
        .return_once(|_, _, _| {
            let mut key_handle = MockSignaturePublicKeyHandle::default();
            key_handle.expect_as_jwk().return_once(|| {
                Ok(PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
                    alg: None,
                    r#use: Some(JwkUse::Encryption),
                    kid: None,
                    crv: "123".to_string(),
                    x: "456".to_string(),
                    y: None,
                }))
            });
            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(key_handle),
            )))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .return_once(|_| Some(Arc::new(key_algorithm)));

    let expected_url = "test_url";
    let interaction_id = Uuid::new_v4();
    let expires_at = OffsetDateTime::now_utc();
    protocol
        .expect_verifier_share_proof()
        .once()
        .returning(move |_, _, _, _, _| {
            Ok(ShareResponse {
                url: expected_url.to_owned(),
                interaction_id,
                interaction_data: None,
                expires_at: Some(expires_at),
            })
        });

    let protocol = Arc::new(protocol);

    protocol_provider
        .expect_get_protocol()
        .once()
        .returning(move |_| Some(protocol.clone()));

    let mut proof_repository = MockProofRepository::default();
    {
        let res_clone = proof.clone();
        proof_repository
            .expect_get_proof()
            .once()
            .withf(move |id, _, _| id == &proof_id)
            .returning(move |_, _, _| Ok(Some(res_clone.to_owned())));
    }

    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_create_interaction()
        .once()
        .returning(move |_| Ok(interaction_id));

    proof_repository
        .expect_update_proof()
        .once()
        .withf(move |id, update, _| {
            id == &proof_id && update.interaction == Some(Some(interaction_id))
        })
        .returning(|_, _, _| Ok(()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut key_provider = MockKeyProvider::new();
    key_provider.expect_get_key_storage().return_once(|_| {
        let mut key_storage = MockKeyStorage::default();
        key_storage
            .expect_get_capabilities()
            .return_once(|| KeyStorageCapabilities {
                features: vec![],
                algorithms: vec![],
            });
        Some(Arc::new(key_storage))
    });

    let service = setup_service(Repositories {
        proof_repository,
        protocol_provider,
        history_repository,
        interaction_repository,
        key_algorithm_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .share_proof(&proof_id, ShareProofRequestDTO::default())
        .await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().expires_at.unwrap(), expires_at);
}

#[tokio::test]
async fn test_share_proof_interaction_expired_success() {
    let proof_id = Uuid::new_v4().into();
    let proof = construct_proof_with_state(&proof_id, ProofStateEnum::InteractionExpired);
    let mut protocol = MockVerificationProtocol::default();
    let mut protocol_provider = MockVerificationProtocolProvider::default();

    let mut key_algorithm = MockKeyAlgorithm::new();
    key_algorithm
        .expect_reconstruct_key()
        .return_once(|_, _, _| {
            let mut key_handle = MockSignaturePublicKeyHandle::default();
            key_handle.expect_as_jwk().return_once(|| {
                Ok(PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
                    alg: None,
                    r#use: Some(JwkUse::Encryption),
                    kid: None,
                    crv: "123".to_string(),
                    x: "456".to_string(),
                    y: None,
                }))
            });
            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(key_handle),
            )))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .return_once(|_| Some(Arc::new(key_algorithm)));

    let expected_url = "test_url";
    let interaction_id = Uuid::new_v4();
    let expires_at = OffsetDateTime::now_utc();
    protocol
        .expect_verifier_share_proof()
        .once()
        .returning(move |_, _, _, _, _| {
            Ok(ShareResponse {
                url: expected_url.to_owned(),
                interaction_id,
                interaction_data: None,
                expires_at: Some(expires_at),
            })
        });

    let protocol = Arc::new(protocol);

    protocol_provider
        .expect_get_protocol()
        .once()
        .returning(move |_| Some(protocol.clone()));

    let mut proof_repository = MockProofRepository::default();
    {
        let res_clone = proof.clone();
        proof_repository
            .expect_get_proof()
            .once()
            .withf(move |id, _, _| id == &proof_id)
            .returning(move |_, _, _| Ok(Some(res_clone.to_owned())));
    }

    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_create_interaction()
        .once()
        .returning(move |_| Ok(interaction_id));

    proof_repository
        .expect_update_proof()
        .once()
        .withf(move |id, update, _| {
            id == &proof_id
                && update.interaction == Some(Some(interaction_id))
                && update.state == Some(ProofStateEnum::Pending)
        })
        .returning(|_, _, _| Ok(()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut key_provider = MockKeyProvider::new();
    key_provider.expect_get_key_storage().return_once(|_| {
        let mut key_storage = MockKeyStorage::default();
        key_storage
            .expect_get_capabilities()
            .return_once(|| KeyStorageCapabilities {
                features: vec![],
                algorithms: vec![],
            });
        Some(Arc::new(key_storage))
    });

    let service = setup_service(Repositories {
        proof_repository,
        protocol_provider,
        history_repository,
        interaction_repository,
        key_algorithm_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .share_proof(&proof_id, ShareProofRequestDTO::default())
        .await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().expires_at.unwrap(), expires_at);
}

#[tokio::test]
async fn test_share_proof_invalid_state() {
    let proof_id = Uuid::new_v4().into();
    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_get_proof()
        .once()
        .returning(move |_, _, _| {
            Ok(Some(construct_proof_with_state(
                &proof_id,
                ProofStateEnum::Rejected,
            )))
        });

    let service = setup_service(Repositories {
        proof_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .share_proof(&proof_id, ShareProofRequestDTO::default())
        .await;
    assert!(matches!(
        result,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::InvalidProofState { .. }
        ))
    ));
}

#[tokio::test]
async fn test_share_proof_fails_when_engagement_is_present() {
    // given
    let proof_id = Uuid::new_v4().into();
    let mut proof = construct_proof_with_state(&proof_id, ProofStateEnum::Pending);
    proof.engagement = Some("SOME_ENGAGEMENT".to_string());

    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_get_proof()
        .once()
        .withf(move |id, _, _| id == &proof_id)
        .returning(move |_, _, _| Ok(Some(proof.to_owned())));

    let service = setup_service(Repositories {
        proof_repository,
        config: generic_config().core,
        ..Default::default()
    });

    // when
    let result = service
        .share_proof(&proof_id, ShareProofRequestDTO::default())
        .await;

    // then
    let_assert!(
        Err(ServiceError::Validation(
            ValidationError::InvalidProofEngagement
        )) = result
    );
}

#[rstest]
#[tokio::test]
async fn test_delete_proof_ok_for_allowed_state(
    #[values(ProofStateEnum::Created, ProofStateEnum::Pending)] state: ProofStateEnum,
) {
    let proof_id = ProofId::from(Uuid::new_v4());
    let interaction_id = InteractionId::from(Uuid::new_v4());

    let mut proof = construct_proof_with_state(&proof_id, state);
    proof.protocol = "OPENID4VP_DRAFT20".to_string();
    proof.transport = "HTTP".to_string();
    proof.interaction = Some(Interaction {
        id: interaction_id,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        data: Some(vec![]),
        organisation: None,
        nonce_id: None,
        interaction_type: InteractionType::Verification,
        expires_at: None,
    });

    let mut protocol_provider = MockVerificationProtocolProvider::default();
    protocol_provider.expect_get_protocol().return_once(|_| {
        let mut protocol = MockVerificationProtocol::default();
        protocol
            .expect_retract_proof()
            .times(1)
            .returning(|_| Ok(()));

        Some(Arc::new(protocol))
    });

    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_get_proof()
        .once()
        .withf(move |id, relations, _| {
            id == &proof_id
                && relations
                    == &ProofRelations {
                        interaction: Some(InteractionRelations {
                            organisation: Some(OrganisationRelations::default()),
                        }),
                        schema: Some(ProofSchemaRelations {
                            organisation: Some(OrganisationRelations::default()),
                            proof_inputs: None,
                        }),
                        ..Default::default()
                    }
        })
        .returning({
            let proof = proof.clone();
            move |_, _, _| Ok(Some(proof.clone()))
        });

    proof_repository
        .expect_delete_proof()
        .once()
        .with(eq(proof_id))
        .returning(|_| Ok(()));

    let mut interaction_repository = MockInteractionRepository::new();

    interaction_repository
        .expect_delete_interaction()
        .once()
        .with(eq(interaction_id))
        .returning(|_| Ok(()));

    let service = setup_service(Repositories {
        proof_repository,
        interaction_repository,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.delete_proof(proof_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_delete_proof_ok_for_requested_state() {
    let proof_id = ProofId::from(Uuid::new_v4());
    let interaction_id = InteractionId::from(Uuid::new_v4());

    let mut proof = construct_proof_with_state(&proof_id, ProofStateEnum::Requested);
    proof.protocol = "OPENID4VP_DRAFT20".to_string();
    proof.transport = "HTTP".to_string();
    proof.interaction = Some(Interaction {
        id: interaction_id,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        data: Some(vec![]),
        organisation: None,
        nonce_id: None,
        interaction_type: InteractionType::Verification,
        expires_at: None,
    });

    let mut protocol_provider = MockVerificationProtocolProvider::default();
    protocol_provider.expect_get_protocol().return_once(|_| {
        let mut protocol = MockVerificationProtocol::default();
        protocol
            .expect_retract_proof()
            .times(1)
            .returning(|_| Ok(()));

        Some(Arc::new(protocol))
    });

    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_get_proof()
        .once()
        .withf(move |id, relations, _| {
            id == &proof_id
                && relations
                    == &ProofRelations {
                        interaction: Some(InteractionRelations {
                            organisation: Some(OrganisationRelations::default()),
                        }),
                        schema: Some(ProofSchemaRelations {
                            organisation: Some(OrganisationRelations::default()),
                            proof_inputs: None,
                        }),
                        ..Default::default()
                    }
        })
        .returning({
            let proof = proof.clone();
            move |_, _, _| Ok(Some(proof.clone()))
        });

    proof_repository
        .expect_update_proof()
        .once()
        .withf(move |id, update, _| {
            id == &proof_id && update.state == Some(ProofStateEnum::Retracted)
        })
        .returning(|_, _, _| Ok(()));

    let service = setup_service(Repositories {
        proof_repository,
        interaction_repository: MockInteractionRepository::new(),
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.delete_proof(proof_id).await;
    assert!(result.is_ok());
}

#[rstest]
#[tokio::test]
async fn test_delete_proof_fails_for_invalid_state(
    #[values(
        ProofStateEnum::Retracted,
        ProofStateEnum::Accepted,
        ProofStateEnum::Rejected,
        ProofStateEnum::Error
    )]
    state: ProofStateEnum,
) {
    let proof_id = ProofId::from(Uuid::new_v4());
    let interaction_id = InteractionId::from(Uuid::new_v4());

    let mut proof = construct_proof_with_state(&proof_id, state);
    proof.protocol = "OPENID4VP_DRAFT20".to_string();
    proof.transport = "HTTP".to_string();
    proof.interaction = Some(Interaction {
        id: interaction_id,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        data: None,
        organisation: None,
        nonce_id: None,
        interaction_type: InteractionType::Verification,
        expires_at: None,
    });

    let mut proof_repository = MockProofRepository::default();

    proof_repository
        .expect_get_proof()
        .once()
        .withf(move |id, relations, _| {
            id == &proof_id
                && relations
                    == &ProofRelations {
                        interaction: Some(InteractionRelations {
                            organisation: Some(OrganisationRelations::default()),
                        }),
                        schema: Some(ProofSchemaRelations {
                            organisation: Some(OrganisationRelations::default()),
                            proof_inputs: None,
                        }),
                        ..Default::default()
                    }
        })
        .returning({
            let proof = proof.clone();
            move |_, _, _| Ok(Some(proof.clone()))
        });

    let service = setup_service(Repositories {
        proof_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let error = service.delete_proof(proof_id).await.unwrap_err();

    assert!(matches!(
        error,
        ServiceError::BusinessLogic(BusinessLogicError::InvalidProofState { state: got_state }) if got_state == state
    ))
}

#[tokio::test]
async fn test_retract_proof_with_bluetooth_ok() {
    let proof_id = ProofId::from(Uuid::new_v4());
    let interaction_id = InteractionId::from(Uuid::new_v4());

    let device_address = "00000001-5026-444A-9E0E-F6F2450F3A77";

    let mut proof = construct_proof_with_state(&proof_id, ProofStateEnum::Pending);
    proof.protocol = "OPENID4VP_DRAFT20".to_string();
    proof.transport = "BLE".to_string();
    proof.interaction = Some(Interaction {
        id: interaction_id,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        organisation: Some(dummy_organisation(None)),
        data: Some({
            let data = BLEOpenID4VPInteractionDataVerifier {
                client_id: "did:example:123".to_string(),
                nonce: "nonce".to_string(),
                task_id: Uuid::new_v4(),

                peer: BLEPeer::new(
                    DeviceInfo::new(device_address.to_owned(), 123),
                    SecretSlice::from(vec![0; 32]),
                    SecretSlice::from(vec![1; 32]),
                    [2; 12],
                ),
                mdoc_generated_nonce: None,
                protocol_data: BLEVerifierProtocolData::V2 {
                    request: AuthorizationRequest {
                        client_id: "did:example:123".to_string(),
                        response_uri: None,
                        response_mode: None,
                        response_type: None,
                        client_metadata: None,
                        state: None,
                        nonce: Some("nonce".to_string()),
                        redirect_uri: None,
                        dcql_query: Some(DcqlQuery {
                            credentials: vec![],
                            credential_sets: None,
                        }),
                    },
                    submission: None,
                    dcql_query: DcqlQuery {
                        credentials: vec![],
                        credential_sets: None,
                    },
                },
            };

            serde_json::to_vec(&data).unwrap()
        }),
        nonce_id: None,
        interaction_type: InteractionType::Verification,
        expires_at: None,
    });

    let mut protocol_provider = MockVerificationProtocolProvider::default();
    protocol_provider.expect_get_protocol().return_once(|_| {
        let mut protocol = MockVerificationProtocol::default();
        protocol
            .expect_retract_proof()
            .times(1)
            .returning(|_| Ok(()));

        Some(Arc::new(protocol))
    });

    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_get_proof()
        .once()
        .withf(move |id, relations, _| {
            id == &proof_id
                && relations
                    == &ProofRelations {
                        interaction: Some(InteractionRelations {
                            organisation: Some(OrganisationRelations::default()),
                        }),
                        schema: Some(ProofSchemaRelations {
                            organisation: Some(OrganisationRelations::default()),
                            proof_inputs: None,
                        }),
                        ..Default::default()
                    }
        })
        .returning({
            let proof = proof.clone();
            move |_, _, _| Ok(Some(proof.clone()))
        });
    proof_repository
        .expect_delete_proof()
        .once()
        .with(eq(proof_id))
        .returning(|_| Ok(()));

    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_delete_interaction()
        .once()
        .with(eq(interaction_id))
        .returning(|_| Ok(()));

    let mut config = generic_config().core;
    config.transport.insert(
        "BLE".to_string(),
        Fields {
            r#type: TransportType::Ble,
            display: "".into(),
            order: None,
            priority: None,
            enabled: true,
            capabilities: None,
            params: None,
        },
    );

    let service = setup_service(Repositories {
        proof_repository,
        interaction_repository,
        protocol_provider,
        ble_peripheral: Some(Default::default()),
        config,
        ..Default::default()
    });

    let result = service.delete_proof(proof_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_retract_proof_success_holder_iso_mdl() {
    let proof_id = ProofId::from(Uuid::new_v4());
    let interaction_id = InteractionId::from(Uuid::new_v4());
    let mut proof = construct_proof_with_state(&proof_id, ProofStateEnum::Pending);
    proof.protocol = "ISO_MDL".to_string();
    proof.schema = None;
    proof.role = ProofRole::Holder;
    proof.interaction = Some(Interaction {
        id: interaction_id,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        data: None,
        organisation: Some(dummy_organisation(None)),
        nonce_id: None,
        interaction_type: InteractionType::Verification,
        expires_at: None,
    });

    let mut protocol_provider = MockVerificationProtocolProvider::default();
    protocol_provider.expect_get_protocol().return_once(|_| {
        let mut protocol = MockVerificationProtocol::default();
        protocol
            .expect_retract_proof()
            .times(1)
            .returning(|_| Ok(()));

        Some(Arc::new(protocol))
    });

    let mut proof_repository = MockProofRepository::default();

    proof_repository
        .expect_get_proof()
        .once()
        .withf(move |id, relations, _| {
            id == &proof_id
                && relations
                    == &ProofRelations {
                        interaction: Some(InteractionRelations {
                            organisation: Some(OrganisationRelations::default()),
                        }),
                        schema: Some(ProofSchemaRelations {
                            organisation: Some(OrganisationRelations::default()),
                            proof_inputs: None,
                        }),
                        ..Default::default()
                    }
        })
        .returning({
            let proof = proof.clone();
            move |_, _, _| Ok(Some(proof.clone()))
        });
    proof_repository
        .expect_delete_proof()
        .once()
        .with(eq(proof_id))
        .returning(|_| Ok(()));
    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_delete_interaction()
        .once()
        .with(eq(interaction_id))
        .returning(|_| Ok(()));

    let service = setup_service(Repositories {
        proof_repository,
        protocol_provider,
        interaction_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.delete_proof(proof_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_proof_session_org_mismatch() {
    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .once()
        .returning(|id, _| {
            Ok(Some(ProofSchema {
                id: id.to_owned(),
                imported_source_url: Some("CORE_URL".to_string()),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: Some(OffsetDateTime::now_utc()),
                name: "proof schema".to_string(),
                expire_duration: 0,
                organisation: Some(dummy_organisation(None)),
                input_schemas: None,
            }))
        });
    let service = setup_service(Repositories {
        session_provider: Some(Arc::new(StaticSessionProvider::new_random())),
        proof_schema_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_proof(CreateProofRequestDTO {
            proof_schema_id: Uuid::new_v4().into(),
            verifier_did_id: Some(Uuid::new_v4().into()),
            verifier_identifier_id: None,
            protocol: "OPENID4VP_DRAFT20".to_string(),
            redirect_uri: None,
            verifier_key: None,
            verifier_certificate: None,
            scan_to_verify: Some(ScanToVerifyRequestDTO {
                credential: "credential".to_string(),
                barcode: "barcode".to_string(),
                barcode_type: ScanToVerifyBarcodeTypeEnum::MRZ,
            }),
            iso_mdl_engagement: None,
            transport: None,
            profile: None,
            engagement: None,
        })
        .await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));
}

#[tokio::test]
async fn test_list_proof_session_org_mismatch() {
    let service = setup_service(Repositories {
        session_provider: Some(Arc::new(StaticSessionProvider::new_random())),
        ..Default::default()
    });

    let result = service
        .get_proof_list(
            &Uuid::new_v4().into(),
            GetProofQueryDTO {
                pagination: None,
                sorting: None,
                filtering: None,
                include: None,
            },
        )
        .await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));
}

#[tokio::test]
async fn test_proof_ops_session_org_mismatch() {
    let proof_id = Uuid::new_v4().into();
    let proof = construct_proof_with_state(&proof_id, ProofStateEnum::Created);
    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_get_proof()
        .returning(move |_, _, _| Ok(Some(proof.clone())));
    let mut protocol_provider = MockVerificationProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .returning(|_| Some(Arc::new(MockVerificationProtocol::default())));
    let service = setup_service(Repositories {
        session_provider: Some(Arc::new(StaticSessionProvider::new_random())),
        protocol_provider,
        proof_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_proof(&proof_id).await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));

    let result = service
        .share_proof(&proof_id, ShareProofRequestDTO { params: None })
        .await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));

    let result = service.delete_proof(proof_id).await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));

    let result = service.delete_proof_claims(proof_id).await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));

    let result = service.get_proof_presentation_definition(&proof_id).await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));

    let result = service
        .propose_proof(ProposeProofRequestDTO {
            protocol: "exchange".to_string(),
            organisation_id: Uuid::new_v4().into(),
            engagement: vec![],
            ui_message: None,
        })
        .await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));
}
