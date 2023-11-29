use std::str::FromStr;

use core_server::Config;
use one_core::model::claim::{Claim, ClaimRelations};
use one_core::model::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use one_core::model::credential::{Credential, CredentialState, CredentialStateEnum};
use one_core::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaId, CredentialSchemaRelations,
};
use one_core::model::did::{Did, DidRelations, DidType, KeyRole};
use one_core::model::interaction::{Interaction, InteractionRelations};
use one_core::model::organisation::{Organisation, OrganisationRelations};
use one_core::model::proof::{Proof, ProofState, ProofStateEnum};
use one_core::model::proof::{ProofId, ProofRelations, ProofStateRelations};
use one_core::model::proof_schema::{
    ProofSchema, ProofSchemaClaim, ProofSchemaClaimRelations, ProofSchemaId, ProofSchemaRelations,
};
use one_core::repository::DataRepository;
use shared_types::{DidId, DidValue};
use sql_data_provider::{self, test_utilities::*, DataLayer, DbConn};
use url::Url;
use uuid::Uuid;

pub fn create_config(core_base_url: impl Into<String>) -> Config {
    Config {
        config_file: "../../config.yml".to_string(),
        database_url: "sqlite::memory:".to_string(),
        auth_token: "test".to_string(),
        core_base_url: core_base_url.into(),
        server_ip: None,
        server_port: None,
        trace_json: None,
        sentry_dsn: None,
        sentry_environment: None,
    }
}

pub async fn create_db(config: &Config) -> DbConn {
    sql_data_provider::db_conn(&config.database_url).await
}

pub async fn create_organisation(db_conn: &DbConn) -> Organisation {
    let data_layer = DataLayer::build(db_conn.to_owned());

    let organisation = Organisation {
        id: Uuid::new_v4(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
    };

    data_layer
        .get_organisation_repository()
        .create_organisation(organisation.to_owned())
        .await
        .unwrap();
    organisation
}

pub async fn create_key_did(db_conn: &DbConn, did_id: &str, key_id: &str, key_role: KeyRole) {
    insert_key_did(db_conn, did_id, key_id, key_role.into())
        .await
        .unwrap()
}
pub async fn create_es256_key(
    db_conn: &DbConn,
    algorithm: String,
    organisation_id: &str,
    did_id: &DidId,
) -> String {
    insert_key_to_database(
        db_conn,
        algorithm,
        vec![
            2, 212, 74, 108, 171, 101, 55, 25, 228, 113, 137, 107, 244, 59, 53, 18, 151, 14, 117,
            14, 156, 106, 178, 135, 104, 150, 113, 122, 229, 191, 40, 5, 96,
        ],
        Some(did_id.to_owned()),
        organisation_id,
    )
    .await
    .unwrap()
}

pub async fn create_eddsa_key(
    db_conn: &DbConn,
    algorithm: String,
    organisation_id: &str,
    did_id: &DidId,
) -> String {
    insert_key_to_database(
        db_conn,
        algorithm,
        vec![
            155, 176, 4, 229, 68, 29, 140, 187, 130, 58, 118, 71, 7, 88, 2, 21, 250, 54, 186, 248,
            76, 233, 111, 248, 196, 89, 169, 36, 173, 54, 175, 187,
        ],
        Some(did_id.to_owned()),
        organisation_id,
    )
    .await
    .unwrap()
}

pub async fn create_did_key(db_conn: &DbConn, organisation: &Organisation) -> Did {
    let data_layer = DataLayer::build(db_conn.to_owned());

    let did = Did {
        id: DidId::from(Uuid::new_v4()),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test-did-key".to_string(),
        did: DidValue::from_str("did:key:123").unwrap(),
        organisation: Some(organisation.to_owned()),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        deactivated: false,
        keys: None,
    };

    data_layer
        .get_did_repository()
        .create_did(did.to_owned())
        .await
        .unwrap();

    did
}

pub async fn create_did_web(
    db_conn: &DbConn,
    organisation: &Organisation,
    deactivated: bool,
    did_type: DidType,
) -> Did {
    let data_layer = DataLayer::build(db_conn.to_owned());

    let did_id = DidId::from(Uuid::new_v4());
    let did = Did {
        id: did_id.to_owned(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test-did-web".to_string(),
        did: DidValue::from_str(&format!("did:web:{did_id}")).unwrap(),
        organisation: Some(organisation.to_owned()),
        did_type,
        did_method: "WEB".to_string(),
        deactivated,
        keys: None,
    };

    data_layer
        .get_did_repository()
        .create_did(did.to_owned())
        .await
        .unwrap();

    did
}

pub async fn create_credential_schema(
    db_conn: &DbConn,
    name: &str,
    organisation: &Organisation,
    revocation_method: &str,
) -> CredentialSchema {
    let data_layer = DataLayer::build(db_conn.to_owned());

    let claim_schema = ClaimSchema {
        id: Uuid::new_v4(),
        key: "firstName".to_string(),
        data_type: "STRING".to_string(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
    };
    let claim_schemas = vec![CredentialSchemaClaim {
        schema: claim_schema.to_owned(),
        required: true,
    }];

    let credential_schema = CredentialSchema {
        id: Uuid::new_v4(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: name.to_owned(),
        organisation: Some(organisation.to_owned()),
        deleted_at: None,
        format: "JWT".to_string(),
        revocation_method: revocation_method.to_owned(),
        claim_schemas: Some(claim_schemas),
    };

    data_layer
        .get_credential_schema_repository()
        .create_credential_schema(credential_schema.to_owned())
        .await
        .unwrap();

    credential_schema
}

pub async fn create_credential_schema_with_claims(
    db_conn: &DbConn,
    name: &str,
    organisation: &Organisation,
    revocation_method: &str,
    claims: &[(Uuid, &str, bool, &str)],
) -> CredentialSchema {
    let data_layer = DataLayer::build(db_conn.to_owned());

    let claim_schemas = claims
        .iter()
        .map(|(id, key, required, data_type)| CredentialSchemaClaim {
            schema: ClaimSchema {
                id: id.to_owned(),
                key: key.to_string(),
                data_type: data_type.to_string(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
            },
            required: required.to_owned(),
        })
        .collect();

    let credential_schema = CredentialSchema {
        id: Uuid::new_v4(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: name.to_owned(),
        organisation: Some(organisation.to_owned()),
        deleted_at: None,
        format: "JWT".to_string(),
        revocation_method: revocation_method.to_owned(),
        claim_schemas: Some(claim_schemas),
    };

    data_layer
        .get_credential_schema_repository()
        .create_credential_schema(credential_schema.to_owned())
        .await
        .unwrap();

    credential_schema
}

pub async fn create_proof_schema(
    db_conn: &DbConn,
    name: &str,
    organisation: &Organisation,
    claims: &[(Uuid, &str, bool, &str)],
) -> ProofSchema {
    let data_layer = DataLayer::build(db_conn.to_owned());

    let claim_schemas = claims
        .iter()
        .map(|(id, key, required, data_type)| ProofSchemaClaim {
            schema: ClaimSchema {
                id: id.to_owned(),
                key: key.to_string(),
                data_type: data_type.to_string(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
            },
            required: required.to_owned(),
            credential_schema: None,
        })
        .collect();

    let proof_schema = ProofSchema {
        id: Uuid::new_v4(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: name.to_owned(),
        organisation: Some(organisation.to_owned()),
        deleted_at: None,
        claim_schemas: Some(claim_schemas),
        expire_duration: 0,
    };

    data_layer
        .get_proof_schema_repository()
        .create_proof_schema(proof_schema.to_owned())
        .await
        .unwrap();

    proof_schema
}

pub async fn create_interaction(db_conn: &DbConn, host: &str, data: &[u8]) -> Interaction {
    let data_layer = DataLayer::build(db_conn.to_owned());

    let interaction = Interaction {
        id: Uuid::new_v4(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        host: Some(Url::parse(host).unwrap()),
        data: Some(data.into()),
    };

    data_layer
        .get_interaction_repository()
        .create_interaction(interaction.to_owned())
        .await
        .unwrap();

    interaction
}

pub async fn create_credential(
    db_conn: &DbConn,
    credential_schema: &CredentialSchema,
    state: CredentialStateEnum,
    issuer_did: &Did,
    transport: &str,
) -> Credential {
    let data_layer = DataLayer::build(db_conn.to_owned());

    let claims: Vec<Claim> = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .iter()
        .map(|claim_schema| Claim {
            id: Uuid::new_v4(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            value: "test".to_string(),
            schema: Some(claim_schema.schema.to_owned()),
        })
        .collect();

    let credential = Credential {
        id: Uuid::new_v4(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        issuance_date: get_dummy_date(),
        credential: vec![],
        transport: transport.to_owned(),
        state: Some(vec![CredentialState {
            created_date: get_dummy_date(),
            state,
        }]),
        claims: Some(claims),
        issuer_did: Some(issuer_did.to_owned()),
        holder_did: None,
        schema: Some(credential_schema.to_owned()),
        interaction: None,
        revocation_list: None,
        key: None,
    };

    data_layer
        .get_credential_repository()
        .create_credential(credential.to_owned())
        .await
        .unwrap();

    credential
}

#[allow(clippy::too_many_arguments)]
pub async fn create_proof(
    db_conn: &DbConn,
    verifier_did: &Did,
    holder_did: Option<&Did>,
    proof_schema: Option<&ProofSchema>,
    state: ProofStateEnum,
    transport: &str,
    interaction: Option<&Interaction>,
) -> Proof {
    let data_layer = DataLayer::build(db_conn.to_owned());

    let proof = Proof {
        id: Uuid::new_v4(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        issuance_date: get_dummy_date(),
        transport: transport.to_owned(),
        state: Some(vec![ProofState {
            state,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        }]),
        claims: None,
        schema: proof_schema.cloned(),
        verifier_did: Some(verifier_did.to_owned()),
        holder_did: holder_did.cloned(),
        interaction: interaction.cloned(),
    };

    data_layer
        .get_proof_repository()
        .create_proof(proof.to_owned())
        .await
        .unwrap();

    proof
}

pub async fn get_proof_schema(db_conn: &DbConn, proof_schema_id: &ProofSchemaId) -> ProofSchema {
    let data_layer = DataLayer::build(db_conn.to_owned());
    data_layer
        .get_proof_schema_repository()
        .get_proof_schema(
            proof_schema_id,
            &ProofSchemaRelations {
                claim_schemas: Some(ProofSchemaClaimRelations {
                    credential_schema: Some(CredentialSchemaRelations {
                        claim_schemas: Some(ClaimSchemaRelations {}),
                        ..Default::default()
                    }),
                }),
                organisation: Some(OrganisationRelations {}),
            },
        )
        .await
        .unwrap()
}

pub async fn get_credential_schema(
    db_conn: &DbConn,
    credential_schema_id: &CredentialSchemaId,
) -> CredentialSchema {
    let data_layer = DataLayer::build(db_conn.to_owned());
    data_layer
        .get_credential_schema_repository()
        .get_credential_schema(
            credential_schema_id,
            &CredentialSchemaRelations {
                claim_schemas: Some(ClaimSchemaRelations::default()),
                organisation: Some(OrganisationRelations::default()),
            },
        )
        .await
        .unwrap()
}

pub async fn get_proof(db_conn: &DbConn, proof_id: &ProofId) -> Proof {
    let data_layer = DataLayer::build(db_conn.to_owned());
    data_layer
        .get_proof_repository()
        .get_proof(
            proof_id,
            &ProofRelations {
                state: Some(ProofStateRelations {}),
                claims: Some(ClaimRelations {
                    schema: Some(ClaimSchemaRelations {}),
                }),
                schema: Some(ProofSchemaRelations {
                    claim_schemas: Some(ProofSchemaClaimRelations {
                        credential_schema: Some(CredentialSchemaRelations {
                            claim_schemas: Some(ClaimSchemaRelations {}),
                            ..Default::default()
                        }),
                    }),
                    organisation: Some(OrganisationRelations {}),
                }),
                verifier_did: Some(DidRelations::default()),
                holder_did: Some(DidRelations::default()),
                interaction: Some(InteractionRelations {}),
            },
        )
        .await
        .unwrap()
}
