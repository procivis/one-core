use one_core::{
    model::{
        claim::{Claim, ClaimRelations},
        claim_schema::{ClaimSchema, ClaimSchemaRelations},
        credential::{
            Credential, CredentialId, CredentialRelations, CredentialState, CredentialStateEnum,
            CredentialStateRelations,
        },
        credential_schema::{CredentialSchema, CredentialSchemaClaim, CredentialSchemaRelations},
        did::{Did, DidRelations, DidType},
        interaction::InteractionRelations,
        organisation::{Organisation, OrganisationRelations},
    },
    repository::DataRepository,
};
use sql_data_provider::{test_utilities::get_dummy_date, DataLayer, DbConn};
use std::str::FromStr;
use time::OffsetDateTime;
use uuid::Uuid;

use shared_types::{DidId, DidValue};

use crate::fixtures::{TestingCredentialParams, TestingDidParams};

pub struct DbClient {
    data_layer: DataLayer,
}

impl DbClient {
    pub fn new(db: DbConn) -> Self {
        Self {
            data_layer: DataLayer::build(db),
        }
    }

    pub async fn get_organisation(&self, id: Uuid) -> Organisation {
        self.data_layer
            .get_organisation_repository()
            .get_organisation(&id, &OrganisationRelations {})
            .await
            .unwrap()
    }

    pub async fn create_organisation(&self) -> Organisation {
        let id = Uuid::new_v4();

        let organisation = Organisation {
            id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        };

        self.data_layer
            .get_organisation_repository()
            .create_organisation(organisation)
            .await
            .unwrap();

        self.get_organisation(id).await
    }

    pub async fn create_credential(
        &self,
        credential_schema: &CredentialSchema,
        state: CredentialStateEnum,
        issuer_did: &Did,
        transport: &str,
        params: TestingCredentialParams<'_>,
    ) -> Credential {
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
            deleted_at: params.deleted_at,
            credential: params.credential.unwrap_or("").as_bytes().to_owned(),
            transport: transport.to_owned(),
            redirect_uri: None,
            state: Some(vec![CredentialState {
                created_date: get_dummy_date(),
                state,
            }]),
            claims: Some(claims),
            issuer_did: Some(issuer_did.to_owned()),
            holder_did: params.holder_did,
            schema: Some(credential_schema.to_owned()),
            interaction: params.interaction,
            revocation_list: None,
            key: None,
        };

        self.data_layer
            .get_credential_repository()
            .create_credential(credential.to_owned())
            .await
            .unwrap();

        credential
    }

    pub async fn get_credential(&self, credential_id: &CredentialId) -> Credential {
        self.data_layer
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

    pub async fn create_credential_schema(
        &self,
        name: &str,
        organisation: &Organisation,
        revocation_method: &str,
    ) -> CredentialSchema {
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

        self.data_layer
            .get_credential_schema_repository()
            .create_credential_schema(credential_schema.to_owned())
            .await
            .unwrap();

        credential_schema
    }

    pub async fn create_did(
        &self,
        organisation: &Organisation,
        params: Option<TestingDidParams>,
    ) -> Did {
        let now = OffsetDateTime::now_utc();
        let params = params.unwrap_or_default();

        let did_id = params.id.unwrap_or(DidId::from(Uuid::new_v4()));
        let did = Did {
            id: did_id.to_owned(),
            created_date: params.created_date.unwrap_or(now),
            last_modified: params.last_modified.unwrap_or(now),
            name: params.name.unwrap_or_default(),
            organisation: Some(organisation.to_owned()),
            did: params
                .did
                .unwrap_or(DidValue::from_str(&format!("did:test:{did_id}")).unwrap()),
            did_type: params.did_type.unwrap_or(DidType::Local),
            did_method: params.did_method.unwrap_or("TEST".to_string()),
            deactivated: params.deactivated.unwrap_or(false),
            keys: params.keys,
        };

        self.data_layer
            .get_did_repository()
            .create_did(did.to_owned())
            .await
            .unwrap();

        did
    }
}
