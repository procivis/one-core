use std::sync::Arc;

use mockall::predicate::*;
use mockall::Sequence;
use shared_types::ProofId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::ProofService;
use crate::config::core_config::CoreConfig;
use crate::model::claim::{Claim, ClaimRelations};
use crate::model::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use crate::model::credential::{
    Credential, CredentialRelations, CredentialRole, CredentialState, CredentialStateEnum,
};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaRelations, CredentialSchemaType,
    LayoutType, WalletStorageTypeEnum,
};
use crate::model::did::{Did, DidRelations, DidType, KeyRole, RelatedKey};
use crate::model::interaction::InteractionRelations;
use crate::model::key::Key;
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListPagination;
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::model::proof::{
    GetProofList, Proof, ProofClaim, ProofClaimRelations, ProofRelations, ProofState,
    ProofStateEnum, ProofStateRelations,
};
use crate::model::proof_schema::{
    ProofInputClaimSchema, ProofInputSchema, ProofInputSchemaRelations, ProofSchema,
    ProofSchemaClaimRelations, ProofSchemaRelations,
};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::credential_formatter::test_utilities::get_dummy_date;
use crate::provider::credential_formatter::{FormatterCapabilities, MockCredentialFormatter};
use crate::provider::exchange_protocol::provider::MockExchangeProtocolProvider;
use crate::provider::exchange_protocol::MockExchangeProtocol;
use crate::repository::did_repository::MockDidRepository;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::proof_repository::MockProofRepository;
use crate::repository::proof_schema_repository::MockProofSchemaRepository;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, ServiceError, ValidationError,
};
use crate::service::proof::dto::{
    CreateProofRequestDTO, GetProofQueryDTO, ProofClaimValueDTO, ProofFilterValue,
};
use crate::service::test_utilities::generic_config;

#[derive(Default)]
struct Repositories {
    pub proof_repository: MockProofRepository,
    pub proof_schema_repository: MockProofSchemaRepository,
    pub did_repository: MockDidRepository,
    pub history_repository: MockHistoryRepository,
    pub credential_formatter_provider: MockCredentialFormatterProvider,
    pub protocol_provider: MockExchangeProtocolProvider,
    pub config: CoreConfig,
}

fn setup_service(repositories: Repositories) -> ProofService {
    ProofService::new(
        Arc::new(repositories.proof_repository),
        Arc::new(repositories.proof_schema_repository),
        Arc::new(repositories.did_repository),
        Arc::new(repositories.history_repository),
        Arc::new(repositories.credential_formatter_provider),
        Arc::new(repositories.protocol_provider),
        Arc::new(repositories.config),
    )
}

fn construct_proof_with_state(proof_id: &ProofId, state: ProofStateEnum) -> Proof {
    Proof {
        id: proof_id.to_owned(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        exchange: "PROCIVIS_TEMPORARY".to_string(),
        redirect_uri: None,
        state: Some(vec![ProofState {
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            state,
        }]),
        schema: None,
        claims: None,
        verifier_did: Some(Did {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "did".to_string(),
            organisation: Some(Organisation {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            }),
            did: "did".parse().unwrap(),
            did_type: DidType::Local,
            did_method: "KEY".to_string(),
            keys: None,
            deactivated: false,
        }),
        holder_did: None,
        verifier_key: None,
        interaction: None,
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
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            wallet_storage_type: None,
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: "".to_string(),
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            claim_schemas: None,
            organisation: None,
        }),
    }
}

#[tokio::test]
async fn test_get_presentation_definition_holder_did_not_local() {
    let mut proof_repository = MockProofRepository::default();

    let proof = Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        exchange: "PROCIVIS_TEMPORARY".to_string(),
        state: Some(vec![ProofState {
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            state: ProofStateEnum::Pending,
        }]),
        redirect_uri: None,
        schema: Some(ProofSchema {
            id: Uuid::new_v4().into(),
            deleted_at: None,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "proof schema".to_string(),
            expire_duration: 0,
            organisation: Some(Organisation {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            }),
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
                    },
                    required: true,
                    order: 0,
                }]),
                credential_schema: Some(CredentialSchema {
                    id: Uuid::new_v4().into(),
                    deleted_at: None,
                    created_date: OffsetDateTime::now_utc(),
                    wallet_storage_type: Some(WalletStorageTypeEnum::Software),
                    last_modified: OffsetDateTime::now_utc(),
                    name: "credential schema".to_string(),
                    format: "JWT".to_string(),
                    revocation_method: "NONE".to_string(),
                    claim_schemas: None,
                    organisation: None,
                    layout_type: LayoutType::Card,
                    layout_properties: None,
                    schema_type: CredentialSchemaType::ProcivisOneSchema2024,
                    schema_id: "CredentialSchemaId".to_owned(),
                }),
            }]),
        }),
        claims: Some(vec![]),
        verifier_did: Some(Did {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "did".to_string(),
            did: "did".parse().unwrap(),
            did_type: DidType::Local,
            did_method: "KEY".to_string(),
            organisation: None,
            keys: None,
            deactivated: false,
        }),
        holder_did: Some(Did {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "did".to_string(),
            did: "did".parse().unwrap(),
            did_type: DidType::Remote,
            did_method: "KEY".to_string(),
            organisation: None,
            keys: None,
            deactivated: false,
        }),
        verifier_key: None,
        interaction: None,
    };

    {
        let res_clone = proof.clone();
        proof_repository
            .expect_get_proof()
            .times(1)
            .with(
                eq(proof.id.to_owned()),
                eq(ProofRelations {
                    state: Some(ProofStateRelations::default()),
                    holder_did: Some(DidRelations::default()),
                    interaction: Some(InteractionRelations::default()),
                    ..Default::default()
                }),
            )
            .returning(move |_, _| Ok(Some(res_clone.clone())));
    }

    let service = setup_service(Repositories {
        proof_repository,
        ..Default::default()
    });

    let result = service.get_proof_presentation_definition(&proof.id).await;

    assert!(result.is_err_and(|e| matches!(
        e,
        ServiceError::BusinessLogic(BusinessLogicError::IncompatibleDidType { .. })
    )));
}

#[tokio::test]
async fn test_get_proof_exists() {
    let mut proof_repository = MockProofRepository::default();

    let proof = Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        exchange: "PROCIVIS_TEMPORARY".to_string(),
        state: Some(vec![ProofState {
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            state: ProofStateEnum::Created,
        }]),
        redirect_uri: None,
        schema: Some(ProofSchema {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            deleted_at: None,
            name: "proof schema".to_string(),
            expire_duration: 0,
            organisation: Some(Organisation {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            }),
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
                    },
                    required: true,
                    order: 0,
                }]),
                credential_schema: Some(CredentialSchema {
                    id: Uuid::new_v4().into(),
                    deleted_at: None,
                    created_date: OffsetDateTime::now_utc(),
                    wallet_storage_type: Some(WalletStorageTypeEnum::Software),
                    last_modified: OffsetDateTime::now_utc(),
                    name: "credential schema".to_string(),
                    format: "JWT".to_string(),
                    revocation_method: "NONE".to_string(),
                    claim_schemas: Some(vec![CredentialSchemaClaim {
                        schema: ClaimSchema {
                            id: Uuid::new_v4().into(),
                            key: "ClaimKey".to_owned(),
                            data_type: "STRING".to_owned(),
                            created_date: OffsetDateTime::now_utc(),
                            last_modified: OffsetDateTime::now_utc(),
                            array: false,
                        },
                        required: true,
                    }]),
                    organisation: None,
                    layout_type: LayoutType::Card,
                    layout_properties: None,
                    schema_type: CredentialSchemaType::ProcivisOneSchema2024,
                    schema_id: "CredentialSchemaId".to_owned(),
                }),
            }]),
        }),
        claims: Some(vec![]),
        verifier_did: Some(Did {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "did".to_string(),
            did: "did".parse().unwrap(),
            did_type: DidType::Local,
            did_method: "KEY".to_string(),
            organisation: None,
            keys: None,
            deactivated: false,
        }),
        holder_did: None,
        verifier_key: None,
        interaction: None,
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
                    state: Some(ProofStateRelations::default()),
                    claims: Some(ProofClaimRelations {
                        claim: ClaimRelations {
                            schema: Some(Default::default()),
                        },
                        credential: Some(CredentialRelations {
                            state: Some(Default::default()),
                            claims: Some(ClaimRelations {
                                schema: Some(Default::default()),
                            }),
                            schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(Default::default()),
                                organisation: Some(Default::default()),
                            }),
                            issuer_did: Some(Default::default()),
                            holder_did: Some(Default::default()),
                            ..Default::default()
                        }),
                    }),
                    verifier_did: Some(DidRelations::default()),
                    holder_did: Some(DidRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    verifier_key: None,
                    interaction: Some(InteractionRelations::default()),
                }),
            )
            .returning(move |_, _| Ok(Some(res_clone.clone())));
    }

    let service = setup_service(Repositories {
        proof_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_proof(&proof.id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.id, proof.id);
    assert_eq!(result.exchange, proof.exchange);
}

#[tokio::test]
async fn test_get_proof_with_array_holder() {
    let mut proof_repository = MockProofRepository::default();

    let organisation = Organisation {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
    };

    let claim_schema = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "key".to_string(),
        data_type: "STRING".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: true,
    };

    let credential_schema = CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        created_date: OffsetDateTime::now_utc(),
        wallet_storage_type: Some(WalletStorageTypeEnum::Software),
        last_modified: OffsetDateTime::now_utc(),
        name: "credential schema".to_string(),
        format: "JWT".to_string(),
        revocation_method: "NONE".to_string(),
        claim_schemas: Some(vec![CredentialSchemaClaim {
            schema: claim_schema.clone(),
            required: true,
        }]),
        organisation: Some(organisation.clone()),
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_type: CredentialSchemaType::ProcivisOneSchema2024,
        schema_id: "CredentialSchemaId".to_owned(),
    };

    let credential = Credential {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        credential: vec![],
        exchange: "".into(),
        redirect_uri: None,
        role: CredentialRole::Holder,
        state: Some(vec![CredentialState {
            created_date: OffsetDateTime::now_utc(),
            state: CredentialStateEnum::Accepted,
            suspend_end_date: None,
        }]),
        claims: Some(vec![
            Claim {
                id: Uuid::new_v4(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: "foo1".into(),
                path: "key/0".into(),
                schema: Some(claim_schema.clone()),
            },
            Claim {
                id: Uuid::new_v4(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: "foo2".into(),
                path: "key/1".into(),
                schema: Some(claim_schema.clone()),
            },
        ]),
        issuer_did: None,
        holder_did: None,
        schema: Some(credential_schema.clone()),
        interaction: None,
        revocation_list: None,
        key: None,
    };

    let proof = Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        exchange: "PROCIVIS_TEMPORARY".to_string(),
        state: Some(vec![ProofState {
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            state: ProofStateEnum::Created,
        }]),
        redirect_uri: None,
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
        verifier_did: Some(Did {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "did".to_string(),
            did: "did".parse().unwrap(),
            did_type: DidType::Local,
            did_method: "KEY".to_string(),
            organisation: None,
            keys: None,
            deactivated: false,
        }),
        holder_did: None,
        verifier_key: None,
        interaction: None,
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
                    state: Some(ProofStateRelations::default()),
                    claims: Some(ProofClaimRelations {
                        claim: ClaimRelations {
                            schema: Some(Default::default()),
                        },
                        credential: Some(CredentialRelations {
                            state: Some(Default::default()),
                            claims: Some(ClaimRelations {
                                schema: Some(Default::default()),
                            }),
                            schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(Default::default()),
                                organisation: Some(Default::default()),
                            }),
                            issuer_did: Some(Default::default()),
                            holder_did: Some(Default::default()),
                            ..Default::default()
                        }),
                    }),
                    verifier_did: Some(DidRelations::default()),
                    holder_did: Some(DidRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    verifier_key: None,
                    interaction: Some(InteractionRelations::default()),
                }),
            )
            .returning(move |_, _| Ok(Some(res_clone.clone())));
    }

    let service = setup_service(Repositories {
        proof_repository,
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

    let organisation = Organisation {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
    };

    let claim_schemas = vec![
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "key".to_string(),
                data_type: "OBJECT".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: false,
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
            },
            required: true,
        },
    ];

    let credential_schema = CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        created_date: OffsetDateTime::now_utc(),
        wallet_storage_type: Some(WalletStorageTypeEnum::Software),
        last_modified: OffsetDateTime::now_utc(),
        name: "credential schema".to_string(),
        format: "JWT".to_string(),
        revocation_method: "NONE".to_string(),
        claim_schemas: Some(claim_schemas.clone()),
        organisation: Some(organisation.clone()),
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_type: CredentialSchemaType::ProcivisOneSchema2024,
        schema_id: "CredentialSchemaId".to_owned(),
    };

    let credential = Credential {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        credential: vec![],
        exchange: "".into(),
        redirect_uri: None,
        role: CredentialRole::Holder,
        state: Some(vec![CredentialState {
            created_date: OffsetDateTime::now_utc(),
            state: CredentialStateEnum::Accepted,
            suspend_end_date: None,
        }]),
        claims: Some(vec![
            Claim {
                id: Uuid::new_v4(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: "foo1".into(),
                path: "key/address/0".into(),
                schema: Some(claim_schemas[1].schema.clone()),
            },
            Claim {
                id: Uuid::new_v4(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: "foo2".into(),
                path: "key/address/1".into(),
                schema: Some(claim_schemas[1].schema.clone()),
            },
        ]),
        issuer_did: None,
        holder_did: None,
        schema: Some(credential_schema.clone()),
        interaction: None,
        revocation_list: None,
        key: None,
    };

    let proof = Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        exchange: "PROCIVIS_TEMPORARY".to_string(),
        state: Some(vec![ProofState {
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            state: ProofStateEnum::Created,
        }]),
        redirect_uri: None,
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
        verifier_did: Some(Did {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "did".to_string(),
            did: "did".parse().unwrap(),
            did_type: DidType::Local,
            did_method: "KEY".to_string(),
            organisation: None,
            keys: None,
            deactivated: false,
        }),
        holder_did: None,
        verifier_key: None,
        interaction: None,
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
                    state: Some(ProofStateRelations::default()),
                    claims: Some(ProofClaimRelations {
                        claim: ClaimRelations {
                            schema: Some(Default::default()),
                        },
                        credential: Some(CredentialRelations {
                            state: Some(Default::default()),
                            claims: Some(ClaimRelations {
                                schema: Some(Default::default()),
                            }),
                            schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(Default::default()),
                                organisation: Some(Default::default()),
                            }),
                            issuer_did: Some(Default::default()),
                            holder_did: Some(Default::default()),
                            ..Default::default()
                        }),
                    }),
                    verifier_did: Some(DidRelations::default()),
                    holder_did: Some(DidRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    verifier_key: None,
                    interaction: Some(InteractionRelations::default()),
                }),
            )
            .returning(move |_, _| Ok(Some(res_clone.clone())));
    }

    let service = setup_service(Repositories {
        proof_repository,
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
async fn test_get_proof_with_object_array_holder() {
    let mut proof_repository = MockProofRepository::default();

    let organisation = Organisation {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
    };

    let claim_schemas = vec![
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "key".to_string(),
                data_type: "OBJECT".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: true,
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
            },
            required: true,
        },
    ];

    let credential_schema = CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        created_date: OffsetDateTime::now_utc(),
        wallet_storage_type: Some(WalletStorageTypeEnum::Software),
        last_modified: OffsetDateTime::now_utc(),
        name: "credential schema".to_string(),
        format: "JWT".to_string(),
        revocation_method: "NONE".to_string(),
        claim_schemas: Some(claim_schemas.clone()),
        organisation: Some(organisation.clone()),
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_type: CredentialSchemaType::ProcivisOneSchema2024,
        schema_id: "CredentialSchemaId".to_owned(),
    };

    let credential = Credential {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        credential: vec![],
        exchange: "".into(),
        redirect_uri: None,
        role: CredentialRole::Holder,
        state: Some(vec![CredentialState {
            created_date: OffsetDateTime::now_utc(),
            state: CredentialStateEnum::Accepted,
            suspend_end_date: None,
        }]),
        claims: Some(vec![
            Claim {
                id: Uuid::new_v4(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: "foo1".into(),
                path: "key/0/address".into(),
                schema: Some(claim_schemas[1].schema.clone()),
            },
            Claim {
                id: Uuid::new_v4(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: "foo2".into(),
                path: "key/1/address".into(),
                schema: Some(claim_schemas[1].schema.clone()),
            },
        ]),
        issuer_did: None,
        holder_did: None,
        schema: Some(credential_schema.clone()),
        interaction: None,
        revocation_list: None,
        key: None,
    };

    let proof = Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        exchange: "PROCIVIS_TEMPORARY".to_string(),
        state: Some(vec![ProofState {
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            state: ProofStateEnum::Created,
        }]),
        redirect_uri: None,
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
        verifier_did: Some(Did {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "did".to_string(),
            did: "did".parse().unwrap(),
            did_type: DidType::Local,
            did_method: "KEY".to_string(),
            organisation: None,
            keys: None,
            deactivated: false,
        }),
        holder_did: None,
        verifier_key: None,
        interaction: None,
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
                    state: Some(ProofStateRelations::default()),
                    claims: Some(ProofClaimRelations {
                        claim: ClaimRelations {
                            schema: Some(Default::default()),
                        },
                        credential: Some(CredentialRelations {
                            state: Some(Default::default()),
                            claims: Some(ClaimRelations {
                                schema: Some(Default::default()),
                            }),
                            schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(Default::default()),
                                organisation: Some(Default::default()),
                            }),
                            issuer_did: Some(Default::default()),
                            holder_did: Some(Default::default()),
                            ..Default::default()
                        }),
                    }),
                    verifier_did: Some(DidRelations::default()),
                    holder_did: Some(DidRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    verifier_key: None,
                    interaction: Some(InteractionRelations::default()),
                }),
            )
            .returning(move |_, _| Ok(Some(res_clone.clone())));
    }

    let service = setup_service(Repositories {
        proof_repository,
        ..Default::default()
    });

    let result = service.get_proof(&proof.id).await.unwrap();
    assert_eq!(result.id, proof.id);

    assert_eq!(result.proof_inputs[0].claims[0].path, "key");

    let claims = match &result.proof_inputs[0].claims[0].value {
        Some(ProofClaimValueDTO::Claims(values)) => values,
        _ => panic!("not array field"),
    };

    assert_eq!(claims[0].path, "key/0/address");
    assert!(matches!(
        &claims[0].value,
        Some(ProofClaimValueDTO::Value(val)) if val == "foo1"
    ));
    assert_eq!(claims[1].path, "key/1/address");
    assert!(matches!(
        &claims[1].value,
        Some(ProofClaimValueDTO::Value(val)) if val == "foo2"
    ));
}

#[tokio::test]
async fn test_get_proof_with_array() {
    let mut proof_repository = MockProofRepository::default();

    let organisation = Organisation {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
    };

    let claim_schema = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "key".to_string(),
        data_type: "STRING".to_string(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        array: true,
    };

    let credential_schema = CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        created_date: OffsetDateTime::now_utc(),
        wallet_storage_type: Some(WalletStorageTypeEnum::Software),
        last_modified: OffsetDateTime::now_utc(),
        name: "credential schema".to_string(),
        format: "JWT".to_string(),
        revocation_method: "NONE".to_string(),
        claim_schemas: Some(vec![CredentialSchemaClaim {
            schema: claim_schema.clone(),
            required: true,
        }]),
        organisation: Some(organisation.clone()),
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_type: CredentialSchemaType::ProcivisOneSchema2024,
        schema_id: "CredentialSchemaId".to_owned(),
    };

    let credential = Credential {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        credential: vec![],
        exchange: "".into(),
        redirect_uri: None,
        role: CredentialRole::Holder,
        state: Some(vec![CredentialState {
            created_date: OffsetDateTime::now_utc(),
            state: CredentialStateEnum::Accepted,
            suspend_end_date: None,
        }]),
        claims: Some(vec![
            Claim {
                id: Uuid::new_v4(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: "foo1".into(),
                path: "key/0".into(),
                schema: Some(claim_schema.clone()),
            },
            Claim {
                id: Uuid::new_v4(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: "foo2".into(),
                path: "key/1".into(),
                schema: Some(claim_schema.clone()),
            },
        ]),
        issuer_did: None,
        holder_did: None,
        schema: Some(credential_schema.clone()),
        interaction: None,
        revocation_list: None,
        key: None,
    };

    let proof = Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        exchange: "PROCIVIS_TEMPORARY".to_string(),
        state: Some(vec![ProofState {
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            state: ProofStateEnum::Created,
        }]),
        redirect_uri: None,
        schema: Some(ProofSchema {
            id: Uuid::new_v4().into(),
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
        verifier_did: Some(Did {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "did".to_string(),
            did: "did".parse().unwrap(),
            did_type: DidType::Local,
            did_method: "KEY".to_string(),
            organisation: None,
            keys: None,
            deactivated: false,
        }),
        holder_did: None,
        verifier_key: None,
        interaction: None,
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
                    state: Some(ProofStateRelations::default()),
                    claims: Some(ProofClaimRelations {
                        claim: ClaimRelations {
                            schema: Some(Default::default()),
                        },
                        credential: Some(CredentialRelations {
                            state: Some(Default::default()),
                            claims: Some(ClaimRelations {
                                schema: Some(Default::default()),
                            }),
                            schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(Default::default()),
                                organisation: Some(Default::default()),
                            }),
                            issuer_did: Some(Default::default()),
                            holder_did: Some(Default::default()),
                            ..Default::default()
                        }),
                    }),
                    verifier_did: Some(DidRelations::default()),
                    holder_did: Some(DidRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    verifier_key: None,
                    interaction: Some(InteractionRelations::default()),
                }),
            )
            .returning(move |_, _| Ok(Some(res_clone.clone())));
    }

    let service = setup_service(Repositories {
        proof_repository,
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

    let organisation = Organisation {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
    };

    let claim_schemas = vec![
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "key".to_string(),
                data_type: "OBJECT".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: false,
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
            },
            required: true,
        },
    ];

    let credential_schema = CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        created_date: OffsetDateTime::now_utc(),
        wallet_storage_type: Some(WalletStorageTypeEnum::Software),
        last_modified: OffsetDateTime::now_utc(),
        name: "credential schema".to_string(),
        format: "JWT".to_string(),
        revocation_method: "NONE".to_string(),
        claim_schemas: Some(claim_schemas.clone()),
        organisation: Some(organisation.clone()),
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_type: CredentialSchemaType::ProcivisOneSchema2024,
        schema_id: "CredentialSchemaId".to_owned(),
    };

    let credential = Credential {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        credential: vec![],
        exchange: "".into(),
        redirect_uri: None,
        role: CredentialRole::Holder,
        state: Some(vec![CredentialState {
            created_date: OffsetDateTime::now_utc(),
            state: CredentialStateEnum::Accepted,
            suspend_end_date: None,
        }]),
        claims: Some(vec![
            Claim {
                id: Uuid::new_v4(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: "foo1".into(),
                path: "key/address/0".into(),
                schema: Some(claim_schemas[1].schema.clone()),
            },
            Claim {
                id: Uuid::new_v4(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: "foo2".into(),
                path: "key/address/1".into(),
                schema: Some(claim_schemas[1].schema.clone()),
            },
        ]),
        issuer_did: None,
        holder_did: None,
        schema: Some(credential_schema.clone()),
        interaction: None,
        revocation_list: None,
        key: None,
    };

    let proof = Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        exchange: "PROCIVIS_TEMPORARY".to_string(),
        state: Some(vec![ProofState {
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            state: ProofStateEnum::Created,
        }]),
        redirect_uri: None,
        schema: Some(ProofSchema {
            id: Uuid::new_v4().into(),
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
        verifier_did: Some(Did {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "did".to_string(),
            did: "did".parse().unwrap(),
            did_type: DidType::Local,
            did_method: "KEY".to_string(),
            organisation: None,
            keys: None,
            deactivated: false,
        }),
        holder_did: None,
        verifier_key: None,
        interaction: None,
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
                    state: Some(ProofStateRelations::default()),
                    claims: Some(ProofClaimRelations {
                        claim: ClaimRelations {
                            schema: Some(Default::default()),
                        },
                        credential: Some(CredentialRelations {
                            state: Some(Default::default()),
                            claims: Some(ClaimRelations {
                                schema: Some(Default::default()),
                            }),
                            schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(Default::default()),
                                organisation: Some(Default::default()),
                            }),
                            issuer_did: Some(Default::default()),
                            holder_did: Some(Default::default()),
                            ..Default::default()
                        }),
                    }),
                    verifier_did: Some(DidRelations::default()),
                    holder_did: Some(DidRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    verifier_key: None,
                    interaction: Some(InteractionRelations::default()),
                }),
            )
            .returning(move |_, _| Ok(Some(res_clone.clone())));
    }

    let service = setup_service(Repositories {
        proof_repository,
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

    let organisation = Organisation {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
    };

    let claim_schemas = vec![
        CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: "key".to_string(),
                data_type: "OBJECT".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: true,
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
            },
            required: true,
        },
    ];

    let credential_schema = CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        created_date: OffsetDateTime::now_utc(),
        wallet_storage_type: Some(WalletStorageTypeEnum::Software),
        last_modified: OffsetDateTime::now_utc(),
        name: "credential schema".to_string(),
        format: "JWT".to_string(),
        revocation_method: "NONE".to_string(),
        claim_schemas: Some(claim_schemas.clone()),
        organisation: Some(organisation.clone()),
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_type: CredentialSchemaType::ProcivisOneSchema2024,
        schema_id: "CredentialSchemaId".to_owned(),
    };

    let credential = Credential {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        credential: vec![],
        exchange: "".into(),
        redirect_uri: None,
        role: CredentialRole::Holder,
        state: Some(vec![CredentialState {
            created_date: OffsetDateTime::now_utc(),
            state: CredentialStateEnum::Accepted,
            suspend_end_date: None,
        }]),
        claims: Some(vec![
            Claim {
                id: Uuid::new_v4(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: "foo1".into(),
                path: "key/0/address".into(),
                schema: Some(claim_schemas[1].schema.clone()),
            },
            Claim {
                id: Uuid::new_v4(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: "foo2".into(),
                path: "key/1/address".into(),
                schema: Some(claim_schemas[1].schema.clone()),
            },
        ]),
        issuer_did: None,
        holder_did: None,
        schema: Some(credential_schema.clone()),
        interaction: None,
        revocation_list: None,
        key: None,
    };

    let proof = Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        exchange: "PROCIVIS_TEMPORARY".to_string(),
        state: Some(vec![ProofState {
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            state: ProofStateEnum::Created,
        }]),
        redirect_uri: None,
        schema: Some(ProofSchema {
            id: Uuid::new_v4().into(),
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
        verifier_did: Some(Did {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "did".to_string(),
            did: "did".parse().unwrap(),
            did_type: DidType::Local,
            did_method: "KEY".to_string(),
            organisation: None,
            keys: None,
            deactivated: false,
        }),
        holder_did: None,
        verifier_key: None,
        interaction: None,
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
                    state: Some(ProofStateRelations::default()),
                    claims: Some(ProofClaimRelations {
                        claim: ClaimRelations {
                            schema: Some(Default::default()),
                        },
                        credential: Some(CredentialRelations {
                            state: Some(Default::default()),
                            claims: Some(ClaimRelations {
                                schema: Some(Default::default()),
                            }),
                            schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(Default::default()),
                                organisation: Some(Default::default()),
                            }),
                            issuer_did: Some(Default::default()),
                            holder_did: Some(Default::default()),
                            ..Default::default()
                        }),
                    }),
                    verifier_did: Some(DidRelations::default()),
                    holder_did: Some(DidRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    verifier_key: None,
                    interaction: Some(InteractionRelations::default()),
                }),
            )
            .returning(move |_, _| Ok(Some(res_clone.clone())));
    }

    let service = setup_service(Repositories {
        proof_repository,
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

    assert_eq!(claims[0].path, "key/0/address");
    assert!(matches!(
        &claims[0].value,
        Some(ProofClaimValueDTO::Value(val)) if val == "foo1"
    ));
    assert_eq!(claims[1].path, "key/1/address");
    assert!(matches!(
        &claims[1].value,
        Some(ProofClaimValueDTO::Value(val)) if val == "foo2"
    ));
}

#[tokio::test]
async fn test_get_proof_missing() {
    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_get_proof()
        .times(1)
        .returning(|_, _| Ok(None));

    let service = setup_service(Repositories {
        proof_repository,
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

    let proof = Proof {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        exchange: "PROCIVIS_TEMPORARY".to_string(),
        redirect_uri: None,
        state: Some(vec![ProofState {
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            state: ProofStateEnum::Created,
        }]),
        schema: Some(ProofSchema {
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
        verifier_did: Some(Did {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "did".to_string(),
            did: "did".parse().unwrap(),
            did_type: DidType::Local,
            did_method: "KEY".to_string(),
            organisation: None,
            keys: None,
            deactivated: false,
        }),
        holder_did: None,
        verifier_key: None,
        interaction: None,
    };
    {
        let res_clone = proof.clone();
        proof_repository
            .expect_get_proof_list()
            .times(1)
            .returning(move |_| {
                Ok(GetProofList {
                    values: vec![res_clone.to_owned()],
                    total_pages: 1,
                    total_items: 1,
                })
            });
    }

    let service = setup_service(Repositories {
        proof_repository,
        ..Default::default()
    });

    let result = service
        .get_proof_list(GetProofQueryDTO {
            filtering: ProofFilterValue::OrganisationId(Uuid::new_v4().into())
                .condition()
                .into(),
            pagination: Some(ListPagination {
                page: 0,
                page_size: 1,
            }),
            sorting: None,
            include: None,
        })
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
async fn test_create_proof_without_related_key() {
    let exchange = "PROCIVIS_TEMPORARY".to_string();
    let request = CreateProofRequestDTO {
        proof_schema_id: Uuid::new_v4().into(),
        verifier_did_id: Uuid::new_v4().into(),
        exchange: exchange.to_owned(),
        redirect_uri: None,
        verifier_key: None,
    };

    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .times(1)
        .withf(move |id, _| &request.proof_schema_id == id)
        .returning(|id, _| {
            Ok(Some(ProofSchema {
                id: id.to_owned(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "proof schema".to_string(),
                expire_duration: 0,
                organisation: None,
                input_schemas: Some(vec![generic_proof_input_schema()]),
            }))
        });

    let verifier_key_id = Uuid::new_v4();

    let request_clone = request.clone();
    let mut did_repository = MockDidRepository::default();
    did_repository
        .expect_get_did()
        .times(1)
        .withf(move |id, _| &request_clone.verifier_did_id == id)
        .returning(move |id, _| {
            Ok(Some(Did {
                id: id.to_owned(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "did".to_string(),
                did: "did".parse().unwrap(),
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
                        key_reference: vec![],
                        storage_type: "INTERNAL".to_string(),
                        key_type: "EDDSA".to_string(),
                        organisation: None,
                    },
                }]),
                deactivated: false,
            }))
        });

    let mut formatter = MockCredentialFormatter::default();
    let mut credential_formatter_provider = MockCredentialFormatterProvider::default();
    let exchange_copy = exchange.to_owned();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(|| FormatterCapabilities {
            proof_exchange_protocols: vec![exchange_copy],
            ..Default::default()
        });
    credential_formatter_provider
        .expect_get_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let proof_id = Uuid::new_v4().into();
    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_create_proof()
        .times(1)
        .withf(move |proof| proof.exchange == exchange)
        .returning(move |_| Ok(proof_id));

    let service = setup_service(Repositories {
        proof_repository,
        did_repository,
        proof_schema_repository,
        credential_formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.create_proof(request.to_owned()).await;
    assert_eq!(result.unwrap(), proof_id);
}

#[tokio::test]
async fn test_create_proof_with_related_key() {
    let exchange = "PROCIVIS_TEMPORARY".to_string();
    let verifier_key_id = Uuid::new_v4().into();
    let request = CreateProofRequestDTO {
        proof_schema_id: Uuid::new_v4().into(),
        verifier_did_id: Uuid::new_v4().into(),
        exchange: exchange.to_owned(),
        redirect_uri: None,
        verifier_key: Some(verifier_key_id),
    };

    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .times(1)
        .withf(move |id, _| &request.proof_schema_id == id)
        .returning(|id, _| {
            Ok(Some(ProofSchema {
                id: id.to_owned(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "proof schema".to_string(),
                expire_duration: 0,
                organisation: None,
                input_schemas: Some(vec![generic_proof_input_schema()]),
            }))
        });

    let request_clone = request.clone();
    let mut did_repository = MockDidRepository::default();
    did_repository
        .expect_get_did()
        .times(1)
        .withf(move |id, _| &request_clone.verifier_did_id == id)
        .returning(move |id, _| {
            Ok(Some(Did {
                id: id.to_owned(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "did".to_string(),
                did: "did".parse().unwrap(),
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
                        key_reference: vec![],
                        storage_type: "INTERNAL".to_string(),
                        key_type: "EDDSA".to_string(),
                        organisation: None,
                    },
                }]),
                deactivated: false,
            }))
        });

    let mut formatter = MockCredentialFormatter::default();
    let mut credential_formatter_provider = MockCredentialFormatterProvider::default();
    let exchange_copy = exchange.to_owned();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(move || FormatterCapabilities {
            proof_exchange_protocols: vec![exchange_copy],
            ..Default::default()
        });
    credential_formatter_provider
        .expect_get_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let proof_id = Uuid::new_v4().into();
    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_create_proof()
        .times(1)
        .withf(move |proof| proof.exchange == exchange)
        .returning(move |_| Ok(proof_id));

    let service = setup_service(Repositories {
        proof_repository,
        did_repository,
        proof_schema_repository,
        credential_formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.create_proof(request).await;
    assert_eq!(result.unwrap(), proof_id);
}

#[tokio::test]
async fn test_create_proof_failed_no_key_with_assertion_method_role() {
    let exchange = "PROCIVIS_TEMPORARY".to_string();
    let request = CreateProofRequestDTO {
        proof_schema_id: Uuid::new_v4().into(),
        verifier_did_id: Uuid::new_v4().into(),
        exchange: exchange.to_owned(),
        redirect_uri: None,
        verifier_key: None,
    };

    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .times(1)
        .withf(move |id, _| &request.proof_schema_id == id)
        .returning(|id, _| {
            Ok(Some(ProofSchema {
                id: id.to_owned(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "proof schema".to_string(),
                expire_duration: 0,
                organisation: None,
                input_schemas: Some(vec![generic_proof_input_schema()]),
            }))
        });

    let request_clone = request.clone();
    let mut did_repository = MockDidRepository::default();
    did_repository
        .expect_get_did()
        .times(1)
        .withf(move |id, _| &request_clone.verifier_did_id == id)
        .returning(move |id, _| {
            Ok(Some(Did {
                id: id.to_owned(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "did".to_string(),
                did: "did".parse().unwrap(),
                did_type: DidType::Local,
                did_method: "KEY".to_string(),
                organisation: None,
                keys: Some(vec![]),
                deactivated: false,
            }))
        });

    let mut formatter = MockCredentialFormatter::default();
    let mut credential_formatter_provider = MockCredentialFormatterProvider::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(|| FormatterCapabilities {
            proof_exchange_protocols: vec![exchange],
            ..Default::default()
        });
    credential_formatter_provider
        .expect_get_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let service = setup_service(Repositories {
        did_repository,
        proof_schema_repository,
        credential_formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.create_proof(request.to_owned()).await;
    assert!(matches!(
        result.unwrap_err(),
        ServiceError::Validation(ValidationError::InvalidKey(_))
    ));
}

#[tokio::test]
async fn test_create_proof_failed_incompatible_exchange() {
    let exchange = "PROCIVIS_TEMPORARY".to_string();
    let request = CreateProofRequestDTO {
        proof_schema_id: Uuid::new_v4().into(),
        verifier_did_id: Uuid::new_v4().into(),
        exchange: exchange.to_owned(),
        redirect_uri: None,
        verifier_key: None,
    };

    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .times(1)
        .withf(move |id, _| &request.proof_schema_id == id)
        .returning(|id, _| {
            Ok(Some(ProofSchema {
                id: id.to_owned(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "proof schema".to_string(),
                expire_duration: 0,
                organisation: None,
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
        .expect_get_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let service = setup_service(Repositories {
        proof_schema_repository,
        credential_formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.create_proof(request.to_owned()).await;
    assert!(matches!(
        result.unwrap_err(),
        ServiceError::BusinessLogic(BusinessLogicError::IncompatibleProofExchangeProtocol)
    ));
}

#[tokio::test]
async fn test_create_proof_did_deactivated_error() {
    let exchange = "PROCIVIS_TEMPORARY".to_string();
    let request = CreateProofRequestDTO {
        proof_schema_id: Uuid::new_v4().into(),
        verifier_did_id: Uuid::new_v4().into(),
        exchange: exchange.to_owned(),
        redirect_uri: None,
        verifier_key: None,
    };

    let mut proof_schema_repository = MockProofSchemaRepository::default();
    proof_schema_repository
        .expect_get_proof_schema()
        .once()
        .withf(move |id, _| &request.proof_schema_id == id)
        .returning(|id, _| {
            Ok(Some(ProofSchema {
                id: id.to_owned(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: None,
                name: "proof schema".to_string(),
                expire_duration: 0,
                organisation: None,
                input_schemas: Some(vec![generic_proof_input_schema()]),
            }))
        });

    let request_clone = request.clone();
    let mut did_repository = MockDidRepository::default();
    did_repository
        .expect_get_did()
        .once()
        .withf(move |id, _| &request_clone.verifier_did_id == id)
        .returning(|id, _| {
            Ok(Some(Did {
                id: id.to_owned(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: "did".to_string(),
                did: "did".parse().unwrap(),
                did_type: DidType::Local,
                did_method: "KEY".to_string(),
                organisation: None,
                keys: None,
                deactivated: true,
            }))
        });

    let mut formatter = MockCredentialFormatter::default();
    let mut credential_formatter_provider = MockCredentialFormatterProvider::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(|| FormatterCapabilities {
            proof_exchange_protocols: vec![exchange],
            ..Default::default()
        });
    credential_formatter_provider
        .expect_get_formatter()
        .once()
        .return_once(|_| Some(Arc::new(formatter)));

    let service = setup_service(Repositories {
        did_repository,
        proof_schema_repository,
        credential_formatter_provider,
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
        .times(1)
        .returning(|id, _| {
            Ok(Some(ProofSchema {
                id: id.to_owned(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deleted_at: Some(OffsetDateTime::now_utc()),
                name: "proof schema".to_string(),
                expire_duration: 0,
                organisation: None,
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
            verifier_did_id: Uuid::new_v4().into(),
            exchange: "PROCIVIS_TEMPORARY".to_string(),
            redirect_uri: None,
            verifier_key: None,
        })
        .await;
    assert2::assert!(
        let Err(ServiceError::BusinessLogic(BusinessLogicError::ProofSchemaDeleted {..})) = result
    );
}

#[tokio::test]
async fn test_share_proof_created_success() {
    let proof_id = Uuid::new_v4().into();
    let proof = construct_proof_with_state(&proof_id, ProofStateEnum::Created);
    let mut protocol = MockExchangeProtocol::default();
    let mut protocol_provider = MockExchangeProtocolProvider::default();

    let expected_url = "test_url";
    protocol
        .expect_share_proof()
        .times(1)
        .returning(|_| Ok(expected_url.to_owned()));

    let protocol = Arc::new(protocol);

    protocol_provider
        .expect_get_protocol()
        .times(1)
        .returning(move |_| Some(protocol.clone()));

    let mut seq = Sequence::new();
    let mut proof_repository = MockProofRepository::default();
    {
        let res_clone = proof.clone();
        proof_repository
            .expect_get_proof()
            .times(1)
            .in_sequence(&mut seq)
            .withf(move |id, relations| {
                id == &proof_id
                    && relations
                        == &ProofRelations {
                            state: Some(ProofStateRelations::default()),
                            schema: Some(ProofSchemaRelations {
                                organisation: Some(Default::default()),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }
            })
            .returning(move |_, _| Ok(Some(res_clone.to_owned())));
    }

    proof_repository
        .expect_set_proof_state()
        .times(1)
        .in_sequence(&mut seq)
        .withf(move |id, state| id == &proof_id && state.state == ProofStateEnum::Pending)
        .returning(|_, _| Ok(()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let service = setup_service(Repositories {
        proof_repository,
        protocol_provider,
        history_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.share_proof(&proof_id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.url, expected_url);
}

#[tokio::test]
async fn test_share_proof_pending_success() {
    let proof_id = Uuid::new_v4().into();
    let proof = construct_proof_with_state(&proof_id, ProofStateEnum::Pending);
    let mut protocol = MockExchangeProtocol::default();
    let mut protocol_provider = MockExchangeProtocolProvider::default();

    let expected_url = "test_url";
    protocol
        .expect_share_proof()
        .times(1)
        .returning(|_| Ok(expected_url.to_owned()));

    let protocol = Arc::new(protocol);

    protocol_provider
        .expect_get_protocol()
        .times(1)
        .returning(move |_| Some(protocol.clone()));

    let mut proof_repository = MockProofRepository::default();
    {
        let res_clone = proof.clone();
        proof_repository
            .expect_get_proof()
            .times(1)
            .withf(move |id, relations| {
                id == &proof_id
                    && relations
                        == &ProofRelations {
                            state: Some(ProofStateRelations::default()),
                            schema: Some(ProofSchemaRelations {
                                organisation: Some(Default::default()),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }
            })
            .returning(move |_, _| Ok(Some(res_clone.to_owned())));
    }

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let service = setup_service(Repositories {
        proof_repository,
        protocol_provider,
        history_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.share_proof(&proof_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_share_proof_invalid_state() {
    let proof_id = Uuid::new_v4().into();
    let mut proof_repository = MockProofRepository::default();
    proof_repository
        .expect_get_proof()
        .times(1)
        .returning(move |_, _| {
            Ok(Some(construct_proof_with_state(
                &proof_id,
                ProofStateEnum::Rejected,
            )))
        });

    let service = setup_service(Repositories {
        proof_repository,
        ..Default::default()
    });

    let result = service.share_proof(&proof_id).await;
    assert!(matches!(
        result,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::InvalidProofState { .. }
        ))
    ));
}
