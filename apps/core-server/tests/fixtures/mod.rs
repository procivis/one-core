use std::str::FromStr;

use core_server::ServerConfig;
use one_core::config::core_config::{self, AppConfig};
use one_core::model::claim::{Claim, ClaimRelations};
use one_core::model::claim_schema::{ClaimSchema, ClaimSchemaRelations};
use one_core::model::credential::{
    Credential, CredentialRole, CredentialState, CredentialStateEnum,
};
use one_core::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaRelations, CredentialSchemaType,
    LayoutProperties, LayoutType, WalletStorageTypeEnum,
};
use one_core::model::did::{Did, DidRelations, DidType, RelatedKey};
use one_core::model::interaction::{Interaction, InteractionRelations};
use one_core::model::key::{Key, KeyRelations};
use one_core::model::organisation::{Organisation, OrganisationRelations};
use one_core::model::proof::{
    Proof, ProofClaimRelations, ProofRelations, ProofState, ProofStateEnum, ProofStateRelations,
};
use one_core::model::proof_schema::{
    ProofInputClaimSchema, ProofInputSchema, ProofInputSchemaRelations, ProofSchema,
    ProofSchemaClaimRelations, ProofSchemaRelations,
};
use one_core::model::revocation_list::{RevocationList, RevocationListPurpose};
use one_core::repository::DataRepository;
use rand::distributions::Alphanumeric;
use rand::Rng;
use sea_orm::ConnectionTrait;
use shared_types::{CredentialSchemaId, DidId, DidValue, KeyId, ProofId};
use sql_data_provider::test_utilities::*;
use sql_data_provider::{DataLayer, DbConn};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::utils::db_clients::proof_schemas::CreateProofInputSchema;

pub fn unwrap_or_random(op: Option<String>) -> String {
    op.unwrap_or_else(|| {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect()
    })
}

#[derive(Debug, Default)]
pub struct TestingConfigParams {
    pub mock_url: Option<String>,
    pub additional_config: Option<String>,
}

pub fn create_config(
    core_base_url: impl Into<String>,
    params: Option<TestingConfigParams>,
) -> AppConfig<ServerConfig> {
    let params = params.unwrap_or_default();
    let ion_config = params.mock_url.map(|mock_url| {
        indoc::formatdoc! {"
            did:
                ION:
                    display: \"did.ion\"
                    order: 9
                    disabled: true
                    type: \"UNIVERSAL_RESOLVER\"
                    params:
                        public:
                            resolverUrl: {mock_url}
        "}
    });
    let allow_insecure_http = Some(
        indoc::indoc! {"
        exchange:
            OPENID4VC:
                params:
                    public:
                        allowInsecureHttpTransport: true
    "}
        .to_string(),
    );

    let root = std::env!("CARGO_MANIFEST_DIR");

    let configs = [
        format!("{}/../../config/config.yml", root),
        format!("{}/../../config/config-procivis-base.yml", root),
        format!("{}/../../config/config-local.yml", root),
    ]
    .into_iter()
    .map(|path| std::fs::read_to_string(path).unwrap())
    .chain(ion_config)
    .chain(params.additional_config)
    .chain(allow_insecure_http);

    let mut app_config: AppConfig<ServerConfig> =
        core_config::AppConfig::from_yaml_str_configs(configs.collect()).unwrap();

    app_config.app = ServerConfig {
        database_url: std::env::var("ONE_app__databaseUrl").unwrap_or("sqlite::memory:".into()),
        auth_token: "test".to_string(),
        core_base_url: core_base_url.into(),
        server_ip: None,
        server_port: None,
        trace_json: None,
        sentry_dsn: None,
        sentry_environment: None,
        trace_level: Some("debug,hyper=error,sea_orm=info,sqlx::query=error".into()),
        hide_error_response_cause: true,
        allow_insecure_http_transport: true,
        insecure_vc_api_endpoints_enabled: true,
    };

    app_config
}

pub async fn create_db(config: &AppConfig<ServerConfig>) -> DbConn {
    let db = sql_data_provider::db_conn(&config.app.database_url, true)
        .await
        .unwrap();

    let url = std::env::var("ONE_app__databaseUrl").ok();
    let prefix = url.as_ref().and_then(|val| val.rsplit_once('/'));

    if let Some((prefix, _)) = prefix {
        let this_test_db: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();

        db.execute_unprepared(&format!("CREATE DATABASE {this_test_db};"))
            .await
            .unwrap();

        db.execute_unprepared(&format!("USE {this_test_db};"))
            .await
            .unwrap();

        sql_data_provider::db_conn(&format!("{prefix}/{this_test_db}"), true)
            .await
            .unwrap()
    } else {
        db
    }
}

pub async fn create_organisation(db_conn: &DbConn) -> Organisation {
    let data_layer = DataLayer::build(db_conn.to_owned(), vec![]);

    let organisation = Organisation {
        id: Uuid::new_v4().into(),
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

#[derive(Debug, Default, Clone)]
pub struct TestingKeyParams {
    pub id: Option<KeyId>,
    pub created_date: Option<OffsetDateTime>,
    pub last_modified: Option<OffsetDateTime>,
    pub name: Option<String>,
    pub key_type: Option<String>,
    pub storage_type: Option<String>,
    pub public_key: Option<Vec<u8>>,
    pub key_reference: Option<Vec<u8>>,
}

pub async fn create_key(
    db_conn: &DbConn,
    organisation: &Organisation,
    params: Option<TestingKeyParams>,
) -> Key {
    let data_layer = DataLayer::build(db_conn.to_owned(), vec![]);
    let now = OffsetDateTime::now_utc();
    let params = params.unwrap_or_default();

    let key = Key {
        id: params.id.unwrap_or(Uuid::new_v4().into()),
        created_date: params.created_date.unwrap_or(now),
        last_modified: params.last_modified.unwrap_or(now),
        public_key: params.public_key.unwrap_or_default(),
        name: unwrap_or_random(params.name),
        key_reference: params.key_reference.unwrap_or_default(),
        storage_type: params.storage_type.unwrap_or_default(),
        key_type: params.key_type.unwrap_or_default(),
        organisation: Some(organisation.to_owned()),
    };

    data_layer
        .get_key_repository()
        .create_key(key.clone())
        .await
        .unwrap();

    key
}

pub async fn create_es256_key(db_conn: &DbConn, organisation: &Organisation) -> Key {
    create_key(
        db_conn,
        organisation,
        Some(TestingKeyParams {
            key_type: Some("ES256".to_string()),
            storage_type: Some("INTERNAL".to_string()),

            // multibase: zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ
            public_key: Some(vec![
                2, 113, 223, 203, 78, 208, 144, 157, 171, 118, 94, 112, 196, 150, 233, 175, 129, 0,
                12, 229, 151, 39, 80, 197, 83, 144, 248, 160, 227, 159, 2, 215, 39,
            ]),
            key_reference: Some(vec![
                191, 117, 227, 19, 61, 61, 70, 152, 133, 158, 83, 244, 0, 0, 0, 0, 0, 0, 0, 32, 1,
                0, 223, 243, 57, 200, 101, 206, 133, 43, 169, 194, 153, 38, 105, 35, 100, 79, 106,
                61, 68, 62, 9, 96, 48, 202, 28, 74, 43, 89, 96, 100, 154, 148, 140, 180, 17, 135,
                78, 216, 169, 229, 27, 196, 181, 163, 95, 116,
            ]),
            ..Default::default()
        }),
    )
    .await
}

pub async fn create_eddsa_key(db_conn: &DbConn, organisation: &Organisation) -> Key {
    create_key(
        db_conn,
        organisation,
        Some(TestingKeyParams {
            key_type: Some("EDDSA".to_string()),
            storage_type: Some("INTERNAL".to_string()),

            // multibase: z6MkuJnXWiLNmV3SooQ72iDYmUE1sz5HTCXWhKNhDZuqk4Rj
            public_key: Some(vec![
                220, 179, 138, 196, 30, 98, 147, 213, 162, 146, 4, 38, 168, 209, 109, 154, 235,
                205, 11, 65, 76, 20, 85, 87, 175, 160, 19, 86, 130, 254, 145, 62,
            ]),
            key_reference: Some(vec![
                137, 117, 80, 218, 12, 180, 214, 27, 139, 193, 39, 109, 0, 0, 0, 0, 0, 0, 0, 64,
                27, 191, 169, 38, 174, 140, 216, 204, 199, 58, 207, 176, 104, 109, 111, 51, 113,
                53, 229, 160, 125, 208, 198, 14, 199, 255, 116, 28, 11, 74, 4, 69, 215, 159, 141,
                82, 169, 237, 124, 127, 162, 116, 118, 69, 243, 155, 160, 38, 198, 175, 156, 153,
                77, 15, 10, 73, 103, 31, 60, 21, 33, 76, 209, 173, 243, 252, 126, 244, 144, 37, 80,
                7, 74, 235, 155, 135, 54, 94, 173, 118,
            ]),
            ..Default::default()
        }),
    )
    .await
}

pub async fn get_key(db_conn: &DbConn, id: &KeyId) -> Key {
    let data_layer = DataLayer::build(db_conn.to_owned(), vec![]);
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
        .unwrap()
}

#[derive(Debug, Default)]
pub struct TestingDidParams {
    pub id: Option<DidId>,
    pub created_date: Option<OffsetDateTime>,
    pub last_modified: Option<OffsetDateTime>,
    pub name: Option<String>,
    pub did: Option<DidValue>,
    pub did_type: Option<DidType>,
    pub did_method: Option<String>,
    pub deactivated: Option<bool>,
    pub keys: Option<Vec<RelatedKey>>,
}

pub async fn create_did(
    db_conn: &DbConn,
    organisation: &Organisation,
    params: Option<TestingDidParams>,
) -> Did {
    let data_layer = DataLayer::build(db_conn.to_owned(), vec![]);
    let now = OffsetDateTime::now_utc();
    let params = params.unwrap_or_default();

    let did_id = params.id.unwrap_or(DidId::from(Uuid::new_v4()));
    let did = Did {
        id: did_id.to_owned(),
        created_date: params.created_date.unwrap_or(now),
        last_modified: params.last_modified.unwrap_or(now),
        name: unwrap_or_random(params.name),
        organisation: Some(organisation.to_owned()),
        did: params
            .did
            .unwrap_or(DidValue::from_str(&format!("did:test:{did_id}")).unwrap()),
        did_type: params.did_type.unwrap_or(DidType::Local),
        did_method: params.did_method.unwrap_or("KEY".to_string()),
        deactivated: params.deactivated.unwrap_or(false),
        keys: params.keys,
    };

    data_layer
        .get_did_repository()
        .create_did(did.to_owned())
        .await
        .unwrap();

    did
}

#[derive(Debug, Default)]
pub struct TestingCredentialSchemaParams {
    pub id: Option<CredentialSchemaId>,
    pub created_date: Option<OffsetDateTime>,
    pub last_modified: Option<OffsetDateTime>,
    pub deleted_at: Option<OffsetDateTime>,
    pub name: Option<String>,
    pub format: Option<String>,
    pub wallet_storage_type: Option<Option<WalletStorageTypeEnum>>,
    pub revocation_method: Option<String>,
    pub layout_type: Option<LayoutType>,
    pub layout_properties: Option<LayoutProperties>,
    pub schema_type: Option<CredentialSchemaType>,
    pub schema_id: Option<String>,
}

pub async fn create_credential_schema(
    db_conn: &DbConn,
    organisation: &Organisation,
    params: Option<TestingCredentialSchemaParams>,
) -> CredentialSchema {
    let data_layer = DataLayer::build(db_conn.to_owned(), vec![]);

    let claim_schema = ClaimSchema {
        id: Uuid::new_v4().into(),
        key: "firstName".to_string(),
        data_type: "STRING".to_string(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        array: false,
    };
    let claim_schemas = vec![CredentialSchemaClaim {
        schema: claim_schema.to_owned(),
        required: true,
    }];

    let params = params.unwrap_or_default();
    let now = OffsetDateTime::now_utc();
    let id = params
        .id
        .unwrap_or(CredentialSchemaId::from(Uuid::new_v4()));
    let credential_schema = CredentialSchema {
        id,
        created_date: params.created_date.unwrap_or(now),
        imported_source_url: "CORE_URL".to_string(),
        last_modified: params.last_modified.unwrap_or(now),
        name: unwrap_or_random(params.name),
        wallet_storage_type: params
            .wallet_storage_type
            .unwrap_or(Some(WalletStorageTypeEnum::Software)),
        organisation: Some(organisation.to_owned()),
        deleted_at: params.deleted_at,
        format: params.format.unwrap_or("JWT".to_string()),
        revocation_method: params.revocation_method.unwrap_or("NONE".to_string()),
        claim_schemas: Some(claim_schemas),
        layout_type: params.layout_type.unwrap_or(LayoutType::Card),
        layout_properties: params.layout_properties,
        schema_type: params
            .schema_type
            .unwrap_or(CredentialSchemaType::ProcivisOneSchema2024),
        schema_id: params.schema_id.unwrap_or(id.to_string()),
        allow_suspension: true,
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
    claims: &[(Uuid, &str, bool, &str, bool)],
) -> CredentialSchema {
    let data_layer = DataLayer::build(db_conn.to_owned(), vec![]);

    let claim_schemas = claims
        .iter()
        .map(
            |(id, key, required, data_type, array)| CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: (*id).into(),
                    key: key.to_string(),
                    data_type: data_type.to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: *array,
                },
                required: required.to_owned(),
            },
        )
        .collect();
    let id = Uuid::new_v4();
    let credential_schema = CredentialSchema {
        id: id.into(),
        imported_source_url: "CORE_URL".to_string(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        wallet_storage_type: None,
        name: name.to_owned(),
        organisation: Some(organisation.to_owned()),
        deleted_at: None,
        format: "JWT".to_string(),
        revocation_method: revocation_method.to_owned(),
        claim_schemas: Some(claim_schemas),
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_type: CredentialSchemaType::ProcivisOneSchema2024,
        schema_id: id.to_string(),
        allow_suspension: true,
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
    proof_input_schemas: &[CreateProofInputSchema<'_>],
) -> ProofSchema {
    let data_layer = DataLayer::build(db_conn.to_owned(), vec![]);

    let input_schemas = proof_input_schemas
        .iter()
        .map(|proof_input_schema| {
            let claim_schemas = proof_input_schema
                .claims
                .iter()
                .enumerate()
                .map(|(order, claim)| ProofInputClaimSchema {
                    schema: ClaimSchema {
                        id: claim.id.to_owned(),
                        key: claim.key.to_string(),
                        data_type: claim.data_type.to_string(),
                        created_date: get_dummy_date(),
                        last_modified: get_dummy_date(),
                        array: false,
                    },
                    required: claim.required.to_owned(),
                    order: order as _,
                })
                .collect();

            ProofInputSchema {
                validity_constraint: proof_input_schema.validity_constraint,
                claim_schemas: Some(claim_schemas),
                credential_schema: Some(proof_input_schema.credential_schema.to_owned()),
            }
        })
        .collect();

    let proof_schema = ProofSchema {
        id: Uuid::new_v4().into(),
        imported_source_url: Some("CORE_URL".to_string()),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: name.to_owned(),
        organisation: Some(organisation.to_owned()),
        deleted_at: None,
        expire_duration: 0,
        input_schemas: Some(input_schemas),
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
    organisation: &Organisation,
) -> Interaction {
    let data_layer = DataLayer::build(db_conn.to_owned(), vec![]);

    let interaction = Interaction {
        id,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        host: Some(Url::parse(host).unwrap()),
        data: Some(data.into()),
        organisation: Some(organisation.to_owned()),
    };

    data_layer
        .get_interaction_repository()
        .create_interaction(interaction.to_owned())
        .await
        .unwrap();

    interaction
}

pub async fn create_interaction(
    db_conn: &DbConn,
    host: &str,
    data: &[u8],
    organisation: &Organisation,
) -> Interaction {
    create_interaction_with_id(Uuid::new_v4(), db_conn, host, data, organisation).await
}

pub async fn create_revocation_list(
    db_conn: &DbConn,
    issuer_did: &Did,
    credentials: Option<&[u8]>,
) -> RevocationList {
    let data_layer = DataLayer::build(db_conn.to_owned(), vec![]);

    let revocation_list = RevocationList {
        id: Default::default(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        credentials: credentials.unwrap_or_default().to_owned(),
        purpose: RevocationListPurpose::Revocation,
        issuer_did: Some(issuer_did.to_owned()),
    };

    data_layer
        .get_revocation_list_repository()
        .create_revocation_list(revocation_list.to_owned())
        .await
        .unwrap();

    revocation_list
}

type ClaimPath<'a> = &'a str;
type ClaimValue<'a> = &'a str;
type TestClaimSchema = Uuid;

#[derive(Debug, Default)]
pub struct TestingCredentialParams<'a> {
    pub holder_did: Option<Did>,
    pub credential: Option<&'a str>,
    pub interaction: Option<Interaction>,
    pub deleted_at: Option<OffsetDateTime>,
    pub role: Option<CredentialRole>,
    pub key: Option<Key>,
    pub suspend_end_date: Option<OffsetDateTime>,
    pub random_claims: bool,
    pub claims_data: Option<Vec<(TestClaimSchema, ClaimPath<'a>, ClaimValue<'a>)>>,
}

#[allow(clippy::too_many_arguments)]
pub async fn create_credential(
    db_conn: &DbConn,
    credential_schema: &CredentialSchema,
    state: CredentialStateEnum,
    issuer_did: &Did,
    exchange: &str,
    params: TestingCredentialParams<'_>,
) -> Credential {
    let data_layer = DataLayer::build(db_conn.to_owned(), vec![]);

    let credential_id = Uuid::new_v4().into();
    let claims: Vec<Claim> = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .iter()
        .map(move |claim_schema| Claim {
            id: Uuid::new_v4(),
            credential_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            value: "test".to_string(),
            schema: Some(claim_schema.schema.to_owned()),
            path: claim_schema.schema.key.clone(),
        })
        .collect();

    let credential = Credential {
        id: credential_id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        issuance_date: get_dummy_date(),
        deleted_at: params.deleted_at,
        credential: params.credential.unwrap_or("").as_bytes().to_owned(),
        exchange: exchange.to_owned(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        state: Some(vec![CredentialState {
            created_date: get_dummy_date(),
            state,
            suspend_end_date: params.suspend_end_date,
        }]),
        claims: Some(claims),
        issuer_did: Some(issuer_did.to_owned()),
        holder_did: params.holder_did,
        schema: Some(credential_schema.to_owned()),
        interaction: params.interaction,
        revocation_list: None,
        key: params.key,
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
    exchange: &str,
    interaction: Option<&Interaction>,
) -> Proof {
    let data_layer = DataLayer::build(db_conn.to_owned(), vec![]);

    let proof = Proof {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        issuance_date: get_dummy_date(),
        exchange: exchange.to_owned(),
        transport: "HTTP".to_string(),
        redirect_uri: None,
        state: Some(vec![ProofState {
            state,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        }]),
        claims: None,
        schema: proof_schema.cloned(),
        verifier_did: Some(verifier_did.to_owned()),
        holder_did: holder_did.cloned(),
        verifier_key: None,
        interaction: interaction.cloned(),
    };

    data_layer
        .get_proof_repository()
        .create_proof(proof.to_owned())
        .await
        .unwrap();

    proof
}

pub async fn get_proof(db_conn: &DbConn, proof_id: &ProofId) -> Proof {
    let data_layer = DataLayer::build(db_conn.to_owned(), vec![]);
    data_layer
        .get_proof_repository()
        .get_proof(
            proof_id,
            &ProofRelations {
                state: Some(ProofStateRelations {}),
                claims: Some(ProofClaimRelations {
                    claim: ClaimRelations {
                        schema: Some(ClaimSchemaRelations {}),
                    },
                    ..Default::default()
                }),
                schema: Some(ProofSchemaRelations {
                    organisation: Some(OrganisationRelations {}),
                    proof_inputs: Some(ProofInputSchemaRelations {
                        claim_schemas: Some(ProofSchemaClaimRelations::default()),
                        credential_schema: Some(CredentialSchemaRelations::default()),
                    }),
                }),
                verifier_did: Some(DidRelations::default()),
                holder_did: Some(DidRelations::default()),
                verifier_key: Some(KeyRelations::default()),
                interaction: Some(InteractionRelations { organisation: None }),
            },
        )
        .await
        .unwrap()
        .unwrap()
}
