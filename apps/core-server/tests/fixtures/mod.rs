use std::str::FromStr;

use core_server::Config;
use one_core::model::claim::{Claim, ClaimRelations};
use one_core::model::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use one_core::model::credential::{
    Credential, CredentialId, CredentialRelations, CredentialState, CredentialStateEnum,
    CredentialStateRelations,
};
use one_core::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaId, CredentialSchemaRelations,
};
use one_core::model::did::{Did, DidRelations, DidType, KeyRole};
use one_core::model::interaction::{Interaction, InteractionRelations};
use one_core::model::key::{Key, KeyId, KeyRelations};
use one_core::model::organisation::{Organisation, OrganisationId, OrganisationRelations};
use one_core::model::proof::{Proof, ProofState, ProofStateEnum};
use one_core::model::proof::{ProofId, ProofRelations, ProofStateRelations};
use one_core::model::proof_schema::{
    ProofSchema, ProofSchemaClaim, ProofSchemaClaimRelations, ProofSchemaId, ProofSchemaRelations,
};
use one_core::model::revocation_list::RevocationList;
use one_core::repository::DataRepository;
use shared_types::{DidId, DidValue};
use sql_data_provider::{self, test_utilities::*, DataLayer, DbConn};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

pub fn create_config(core_base_url: impl Into<String>) -> Config {
    let root = std::env!("CARGO_MANIFEST_DIR");

    Config {
        config_file: format!("{}/../../config.yml", root),
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

pub async fn get_organisation(db_conn: &DbConn, organisation_id: &OrganisationId) -> Organisation {
    let data_layer = DataLayer::build(db_conn.to_owned());
    data_layer
        .get_organisation_repository()
        .get_organisation(organisation_id, &OrganisationRelations {})
        .await
        .unwrap()
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
    did_id: Option<DidId>,
) -> String {
    insert_key_to_database(
        db_conn,
        algorithm,
        vec![
            2, 212, 74, 108, 171, 101, 55, 25, 228, 113, 137, 107, 244, 59, 53, 18, 151, 14, 117,
            14, 156, 106, 178, 135, 104, 150, 113, 122, 229, 191, 40, 5, 96,
        ],
        vec![],
        did_id,
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
            59, 147, 149, 138, 47, 163, 27, 121, 194, 202, 219, 189, 55, 120, 146, 135, 204, 49,
            120, 110, 206, 132, 78, 224, 94, 221, 61, 161, 171, 61, 238, 124,
        ],
        vec![
            62, 32, 184, 150, 100, 131, 44, 102, 69, 60, 205, 5, 0, 0, 0, 0, 0, 0, 0, 32, 165, 39,
            201, 216, 231, 240, 137, 12, 128, 49, 56, 255, 170, 204, 126, 54, 82, 73, 7, 68, 21,
            252, 40, 65, 56, 169, 144, 236, 15, 50, 143, 27, 221, 239, 195, 169, 242, 159, 95, 87,
            87, 124, 188, 24, 103, 205, 137, 162,
        ],
        Some(did_id.to_owned()),
        organisation_id,
    )
    .await
    .unwrap()
}

pub async fn create_did_key_with_value(
    value: DidValue,
    db_conn: &DbConn,
    organisation: &Organisation,
) -> Did {
    let data_layer = DataLayer::build(db_conn.to_owned());

    let did = Did {
        id: DidId::from(Uuid::new_v4()),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test-did-key".to_string(),
        did: value,
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

pub async fn get_did_by_id(db_conn: &DbConn, did_id: &DidId) -> Did {
    let data_layer = DataLayer::build(db_conn.to_owned());
    data_layer
        .get_did_repository()
        .get_did(
            did_id,
            &DidRelations {
                keys: Some(KeyRelations::default()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
}

pub async fn create_did_key(db_conn: &DbConn, organisation: &Organisation) -> Did {
    create_did_key_with_value("did:key:123".parse().unwrap(), db_conn, organisation).await
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

pub async fn create_interaction_with_id(
    id: Uuid,
    db_conn: &DbConn,
    host: &str,
    data: &[u8],
) -> Interaction {
    let data_layer = DataLayer::build(db_conn.to_owned());

    let interaction = Interaction {
        id,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
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

pub async fn create_interaction(db_conn: &DbConn, host: &str, data: &[u8]) -> Interaction {
    create_interaction_with_id(Uuid::new_v4(), db_conn, host, data).await
}

pub async fn create_revocation_list(
    db_conn: &DbConn,
    issuer_did: &Did,
    credentials: Option<&[u8]>,
) -> RevocationList {
    let data_layer = DataLayer::build(db_conn.to_owned());

    let revocation_list = RevocationList {
        id: Default::default(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        credentials: credentials.unwrap_or_default().to_owned(),
        issuer_did: Some(issuer_did.to_owned()),
    };

    data_layer
        .get_revocation_list_repository()
        .create_revocation_list(revocation_list.to_owned())
        .await
        .unwrap();

    revocation_list
}

#[allow(clippy::too_many_arguments)]
pub async fn create_credential(
    db_conn: &DbConn,
    credential_schema: &CredentialSchema,
    state: CredentialStateEnum,
    issuer_did: &Did,
    holder_did: Option<Did>,
    credential: Option<&str>,
    interaction: Option<Interaction>,
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
        credential: credential.unwrap_or("").as_bytes().to_owned(),
        transport: transport.to_owned(),
        state: Some(vec![CredentialState {
            created_date: get_dummy_date(),
            state,
        }]),
        claims: Some(claims),
        issuer_did: Some(issuer_did.to_owned()),
        holder_did,
        schema: Some(credential_schema.to_owned()),
        interaction,
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

pub async fn get_credential(db_conn: &DbConn, credential_id: &CredentialId) -> Credential {
    let data_layer = DataLayer::build(db_conn.to_owned());
    data_layer
        .get_credential_repository()
        .get_credential(
            credential_id,
            &CredentialRelations {
                state: Some(CredentialStateRelations {}),
                claims: Some(ClaimRelations {
                    schema: Some(ClaimSchemaRelations {}),
                }),
                schema: Some(CredentialSchemaRelations {
                    claim_schemas: Some(ClaimSchemaRelations::default()),
                    organisation: Some(OrganisationRelations::default()),
                }),
                holder_did: Some(DidRelations::default()),
                interaction: Some(InteractionRelations {}),
                revocation_list: None,
                issuer_did: None,
                key: None,
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

pub async fn create_key(
    db_conn: &DbConn,
    name: &str,
    public_key: &[u8],
    organisation: &Organisation,
) -> Key {
    let data_layer = DataLayer::build(db_conn.to_owned());
    let now = OffsetDateTime::now_utc();

    let key = Key {
        id: Uuid::new_v4(),
        created_date: now,
        last_modified: now,
        public_key: public_key.to_owned(),
        name: name.to_owned(),
        key_reference: vec![],
        storage_type: "INTERNAL".to_owned(),
        key_type: "ES256".to_owned(),
        organisation: Some(organisation.to_owned()),
    };

    data_layer
        .get_key_repository()
        .create_key(key.clone())
        .await
        .unwrap();

    key
}

pub async fn get_key(db_conn: &DbConn, id: &KeyId) -> Key {
    let data_layer = DataLayer::build(db_conn.to_owned());
    data_layer
        .get_key_repository()
        .get_key(
            id,
            &KeyRelations {
                organisation: Some(OrganisationRelations::default()),
            },
        )
        .await
        .unwrap()
}
