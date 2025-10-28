use std::sync::Arc;

use one_core::model::claim::{Claim, ClaimRelations};
use one_core::model::credential::{
    Credential, CredentialRelations, CredentialRole, CredentialStateEnum,
};
use one_core::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaRelations,
};
use one_core::model::identifier::{Identifier, IdentifierRelations};
use one_core::repository::credential_repository::CredentialRepository;
use rand::{RngCore, thread_rng};
use shared_types::CredentialId;
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

use crate::fixtures::TestingCredentialParams;

pub struct CredentialsDB {
    repository: Arc<dyn CredentialRepository>,
}

impl CredentialsDB {
    pub fn new(repository: Arc<dyn CredentialRepository>) -> Self {
        Self { repository }
    }

    pub async fn get(&self, credential_id: &CredentialId) -> Credential {
        self.repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    claims: Some(ClaimRelations {
                        schema: Some(Default::default()),
                    }),
                    schema: Some(CredentialSchemaRelations {
                        claim_schemas: Some(Default::default()),
                        organisation: Some(Default::default()),
                    }),
                    interaction: Some(Default::default()),
                    holder_identifier: Some(IdentifierRelations {
                        did: Some(Default::default()),
                        ..Default::default()
                    }),
                    key: Some(Default::default()),
                    issuer_identifier: Some(Default::default()),
                    issuer_certificate: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .unwrap()
    }

    pub async fn create(
        &self,
        credential_schema: &CredentialSchema,
        state: CredentialStateEnum,
        issuer_identifier: &Identifier,
        protocol: &str,
        params: TestingCredentialParams,
    ) -> Credential {
        let credential_id = Uuid::new_v4().into();
        let claim_schemas = credential_schema.claim_schemas.as_ref().unwrap();

        let claims = if let Some(claims_data) = params.claims_data {
            claims_data
                .into_iter()
                .map(|new_claim| {
                    let claim_schema = claim_schemas
                        .iter()
                        .find(|schema| schema.schema.id == new_claim.schema_id)
                        .expect("Missing claim schema id");

                    Claim {
                        id: Uuid::new_v4(),
                        credential_id,
                        created_date: get_dummy_date(),
                        last_modified: get_dummy_date(),
                        value: new_claim.value,
                        path: new_claim.path,
                        selectively_disclosable: new_claim.selectively_disclosable,
                        schema: Some(claim_schema.schema.to_owned()),
                    }
                })
                .collect()
        } else {
            claim_schemas
                .iter()
                .filter(|claim_schema| {
                    claim_schema.schema.data_type != "OBJECT" && !claim_schema.schema.array
                })
                .flat_map(|claim_schema| {
                    let path = add_intermediary_indices_to_claim_schema_key(
                        &claim_schema.schema.key,
                        claim_schemas,
                    );
                    if claim_schema.schema.array {
                        vec![
                            Claim {
                                id: Uuid::new_v4(),
                                credential_id,
                                created_date: get_dummy_date(),
                                last_modified: get_dummy_date(),
                                value: schema_to_dummy_value(claim_schema, params.random_claims),
                                path: format!("{path}/0"),
                                selectively_disclosable: false,
                                schema: Some(claim_schema.schema.to_owned()),
                            },
                            Claim {
                                id: Uuid::new_v4(),
                                credential_id,
                                created_date: get_dummy_date(),
                                last_modified: get_dummy_date(),
                                value: None,
                                path,
                                selectively_disclosable: false,
                                schema: Some(claim_schema.schema.to_owned()),
                            },
                        ]
                    } else {
                        vec![Claim {
                            id: Uuid::new_v4(),
                            credential_id,
                            created_date: get_dummy_date(),
                            last_modified: get_dummy_date(),
                            value: schema_to_dummy_value(claim_schema, params.random_claims),
                            path,
                            selectively_disclosable: false,
                            schema: Some(claim_schema.schema.to_owned()),
                        }]
                    }
                })
                .collect()
        };

        let issuance_date = if state == CredentialStateEnum::Accepted {
            Some(get_dummy_date())
        } else {
            None
        };

        let credential = Credential {
            id: credential_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            issuance_date,
            deleted_at: params.deleted_at,
            protocol: protocol.to_owned(),
            redirect_uri: None,
            role: params.role.unwrap_or(CredentialRole::Issuer),
            state,
            suspend_end_date: params.suspend_end_date,
            claims: Some(claims),
            issuer_identifier: Some(issuer_identifier.to_owned()),
            issuer_certificate: params.issuer_certificate.or(issuer_identifier
                .certificates
                .as_ref()
                .and_then(|certs| certs.first().cloned())),
            holder_identifier: params.holder_identifier,
            schema: Some(credential_schema.to_owned()),
            interaction: params.interaction,
            revocation_list: None,
            key: params.key,
            profile: params.profile,
            credential_blob_id: params.credential_blob_id,
            wallet_unit_attestation_blob_id: params.wallet_unit_attestation_blob_id,
        };

        let id = self
            .repository
            .create_credential(credential.to_owned())
            .await
            .unwrap();

        self.get(&id).await
    }
}

fn add_intermediary_indices_to_claim_schema_key(
    schema_key: &str,
    schemas: &[CredentialSchemaClaim],
) -> String {
    let mut current_schema_key = "".to_string();
    let mut claim_path = vec![];
    for segment in schema_key.split('/') {
        claim_path.push(segment.to_owned());
        current_schema_key += segment;
        if current_schema_key != schema_key // otherwise we're at the end
            && schemas
                .iter()
                .find(|schema| schema.schema.key == current_schema_key)
                .expect("schema not found")
                .schema
                .array
        {
            claim_path.push("0".to_string())
        }
        current_schema_key += "/";
    }
    claim_path.join("/")
}

fn schema_to_dummy_value(
    claim_schema: &CredentialSchemaClaim,
    random_claims: bool,
) -> Option<String> {
    let data_type = &claim_schema.schema.data_type;
    if data_type == "OBJECT" {
        return None;
    }
    let value = match data_type.as_str() {
        "NUMBER" => {
            if random_claims {
                thread_rng().next_u32().to_string()
            } else {
                "42".to_string()
            }
        }
        "BOOLEAN" => {
            if random_claims {
                thread_rng().next_u32().is_multiple_of(2).to_string()
            } else {
                "true".to_string()
            }
        }
        _ => {
            if random_claims {
                format!("test:{}", Uuid::new_v4())
            } else {
                "test".to_string()
            }
        }
    };
    Some(value)
}
