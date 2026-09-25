use std::sync::Arc;

use one_core::model::claim::Claim;
use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential::{
    Credential, CredentialFilterValue, CredentialListQuery, CredentialRole, CredentialStateEnum,
    CredentialType, UpdateCredentialRequest,
};
use one_core::model::credential_schema::CredentialSchema;
use one_core::model::identifier::{Identifier, IdentifierData};
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::relation::Related;
use one_core::repository::credential_repository::CredentialRepository;
use one_dto_mapper::convert_inner;
use shared_types::CredentialId;
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

use crate::fixtures::TestingCredentialParams;
use crate::utils::db_clients::blobs::{BlobsDB, TestingBlobParams};

pub struct CredentialsDB {
    repository: Arc<dyn CredentialRepository>,
}

impl CredentialsDB {
    pub fn new(repository: Arc<dyn CredentialRepository>) -> Self {
        Self { repository }
    }

    pub async fn get(&self, credential_id: &CredentialId) -> Credential {
        self.repository.get_credential(credential_id).await.unwrap()
    }

    pub async fn list(
        &self,
        filter: ListFilterCondition<CredentialFilterValue>,
    ) -> Vec<Credential> {
        let creds = self
            .repository
            .get_credential_list(CredentialListQuery {
                filtering: Some(filter),
                ..Default::default()
            })
            .await
            .unwrap()
            .values;
        let mut result = vec![];
        for cred in creds {
            result.push(self.get(&cred.id).await);
        }
        result
    }

    pub async fn update(&self, id: CredentialId, update: UpdateCredentialRequest) {
        self.repository.update_credential(id, update).await.unwrap();
    }

    pub async fn create(
        &self,
        credential_schema: &CredentialSchema,
        state: CredentialStateEnum,
        issuer_identifier: &Identifier,
        protocol: &str,
        params: TestingCredentialParams,
    ) -> Credential {
        let credential = self
            .prepare_credential(
                credential_schema,
                state,
                issuer_identifier,
                protocol,
                params,
            )
            .await;

        let id = self
            .repository
            .create_credential(credential.to_owned())
            .await
            .unwrap();

        self.get(&id).await
    }

    async fn prepare_credential(
        &self,
        credential_schema: &CredentialSchema,
        state: CredentialStateEnum,
        issuer_identifier: &Identifier,
        protocol: &str,
        params: TestingCredentialParams,
    ) -> Credential {
        let credential_id = params.id.unwrap_or(Uuid::new_v4().into());
        let claim_schemas = credential_schema.claim_schemas.as_ref().await.unwrap();

        let claims: Vec<Claim> = if let Some(claims_data) = params.claims_data {
            claims_data
                .into_iter()
                .map(|new_claim| {
                    let claim_schema = claim_schemas
                        .iter()
                        .find(|schema| schema.id == new_claim.schema_id)
                        .expect("Missing claim schema id");

                    Claim {
                        id: Uuid::new_v4().into(),
                        created_date: get_dummy_date(),
                        last_modified: get_dummy_date(),
                        value: new_claim.value,
                        path: new_claim.path,
                        selectively_disclosable: new_claim.selectively_disclosable,
                        schema: claim_schema.to_owned().into(),
                    }
                })
                .collect()
        } else {
            claim_schemas
                .iter()
                .filter(|claim_schema| claim_schema.data_type != "OBJECT" && !claim_schema.array)
                .flat_map(|claim_schema| {
                    let path = add_intermediary_indices_to_claim_schema_key(
                        &claim_schema.key,
                        &claim_schemas,
                    );
                    if claim_schema.array {
                        vec![
                            Claim {
                                id: Uuid::new_v4().into(),
                                created_date: get_dummy_date(),
                                last_modified: get_dummy_date(),
                                value: schema_to_dummy_value(claim_schema, params.random_claims),
                                path: format!("{path}/0"),
                                selectively_disclosable: false,
                                schema: claim_schema.to_owned().into(),
                            },
                            Claim {
                                id: Uuid::new_v4().into(),
                                created_date: get_dummy_date(),
                                last_modified: get_dummy_date(),
                                value: None,
                                path,
                                selectively_disclosable: false,
                                schema: claim_schema.to_owned().into(),
                            },
                        ]
                    } else {
                        vec![Claim {
                            id: Uuid::new_v4().into(),
                            created_date: get_dummy_date(),
                            last_modified: get_dummy_date(),
                            value: schema_to_dummy_value(claim_schema, params.random_claims),
                            path,
                            selectively_disclosable: false,
                            schema: claim_schema.to_owned().into(),
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

        let format = credential_schema
            .formats
            .as_ref()
            .await
            .unwrap()
            .first()
            .cloned();

        Credential {
            expires_at: params.expires_at,
            ecosystem: params.ecosystem,
            id: credential_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            issuance_date,
            deleted_at: params.deleted_at,
            consumed_at: params.consumed_at,
            protocol: protocol.to_owned(),
            redirect_uri: None,
            role: params.role.unwrap_or(CredentialRole::Issuer),
            r#type: params.r#type.unwrap_or(CredentialType::Single),
            state,
            suspend_end_date: params.suspend_end_date,
            claims: claims.into(),
            issuer_identifier: Some(issuer_identifier.to_owned().into()),
            issuer_certificate: params
                .issuer_certificate
                .or(match &issuer_identifier.data {
                    IdentifierData::Certificate(certs)
                    | IdentifierData::CertificateAuthority(certs) => {
                        certs.as_ref().await.unwrap().first().cloned()
                    }
                    _ => None,
                })
                .map(Into::into),
            holder_identifier: params.holder_identifier.map(Into::into),
            schema: credential_schema.to_owned().into(),
            interaction: convert_inner(params.interaction),
            key: params.key.map(Into::into),
            profile: params.profile,
            credential_blob_id: params.credential_blob_id,
            wallet_key_attestation_blob_id: params.wallet_key_attestation_blob_id,
            wallet_instance_attestation_blob_id: params.wallet_instance_attestation_blob_id,
            webhook_url: params.webhook_url,
            embedded_disclosure_policy: params.embedded_disclosure_policy,
            subscriber_information: None,
            parent: params
                .parent_id
                .map(|id| Related::new(id, self.repository.clone())),
            format: convert_inner(params.format.or(format)),
        }
    }

    #[expect(clippy::too_many_arguments)]
    pub async fn create_batch(
        &self,
        credential_schema: &CredentialSchema,
        state: CredentialStateEnum,
        issuer_identifier: &Identifier,
        protocol: &str,
        mut params: TestingCredentialParams,
        num_items: usize,
        blob_storage: Option<&BlobsDB>,
    ) -> Credential {
        credential_schema
            .batch_size
            .expect("schema batch size is required to create credential batch");
        let key = params.key.take().map(Into::into);
        let holder_identifier = params.holder_identifier.take().map(Into::into);
        let mut credential = self
            .prepare_credential(
                credential_schema,
                state,
                issuer_identifier,
                protocol,
                params,
            )
            .await;
        credential.r#type = CredentialType::BatchParent;
        let holder_claims = if credential.role == CredentialRole::Holder {
            let claims = credential.claims.as_ref().await.unwrap().to_owned();
            credential.claims = Default::default();
            Some(claims)
        } else {
            None
        };
        let embedded_disclosure_policy = if credential.role == CredentialRole::Holder {
            credential.embedded_disclosure_policy.take()
        } else {
            credential.embedded_disclosure_policy.clone()
        };

        let id = self
            .repository
            .create_credential(credential.to_owned())
            .await
            .unwrap();
        let batch_item_template = Credential {
            claims: Default::default(),
            r#type: CredentialType::BatchItem,
            embedded_disclosure_policy,
            webhook_url: None,
            parent: Some(Related::new(id, self.repository.clone())),
            interaction: None,
            key,
            holder_identifier,
            ..credential.clone()
        };
        for _ in 0..num_items {
            let credential_blob_id = if let Some(blob_storage) = blob_storage {
                Some(
                    blob_storage
                        .create(TestingBlobParams {
                            value: Some("TOKEN".as_bytes().to_vec()),
                            ..Default::default()
                        })
                        .await
                        .id,
                )
            } else {
                None
            };
            let item_id = Uuid::new_v4().into();
            let claims = holder_claims
                .as_ref()
                .map(|claims| {
                    claims
                        .iter()
                        .map(|claim| Claim {
                            id: Uuid::new_v4().into(),
                            ..claim.clone()
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let batch_item_credential = Credential {
                id: item_id,
                claims: claims.into(),
                credential_blob_id,
                ..batch_item_template.clone()
            };
            self.repository
                .create_credential(batch_item_credential.to_owned())
                .await
                .unwrap();
        }

        self.get(&id).await
    }
}

fn add_intermediary_indices_to_claim_schema_key(
    schema_key: &str,
    schemas: &[ClaimSchema],
) -> String {
    let mut current_schema_key = "".to_string();
    let mut claim_path = vec![];
    for segment in schema_key.split('/') {
        claim_path.push(segment.to_owned());
        current_schema_key += segment;
        if current_schema_key != schema_key // otherwise we're at the end
            && schemas
                .iter()
                .find(|schema| schema.key == current_schema_key)
                .expect("schema not found")
                .array
        {
            claim_path.push("0".to_string())
        }
        current_schema_key += "/";
    }
    claim_path.join("/")
}

fn schema_to_dummy_value(claim_schema: &ClaimSchema, random_claims: bool) -> Option<String> {
    let data_type = &claim_schema.data_type;
    if data_type == "OBJECT" {
        return None;
    }
    let value = match data_type.as_str() {
        "NUMBER" => {
            if random_claims {
                rand::random::<u32>().to_string()
            } else {
                "42".to_string()
            }
        }
        "BOOLEAN" => {
            if random_claims {
                rand::random::<u32>().is_multiple_of(2).to_string()
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
