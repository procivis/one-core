use std::sync::Arc;

use one_core::model::claim::Claim;
use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential::{
    Credential, CredentialCommon, CredentialFilterValue, CredentialListQuery, CredentialRole,
    CredentialStateEnum, CredentialType, UpdateCredentialRequest,
};
use one_core::model::credential_schema::CredentialSchema;
use one_core::model::identifier::{Identifier, IdentifierData};
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::relation::Related;
use one_core::repository::credential_repository::CredentialRepository;
use one_core::service::test_utilities::CredentialBuilder;
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
            result.push(self.get(&cred.common().id).await);
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

        let credential = CredentialBuilder {
            common: CredentialCommon {
                expires_at: params.expires_at,
                ecosystem: params.ecosystem,
                id: credential_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                issuance_date,
                deleted_at: params.deleted_at,
                protocol: protocol.to_owned(),
                redirect_uri: None,
                state,
                schema: credential_schema.to_owned().into(),
                interaction: convert_inner(params.interaction),
                profile: params.profile,
            },
            consumed_at: params.consumed_at,
            role: params.role.unwrap_or(CredentialRole::Issuer),
            r#type: params.r#type.unwrap_or(CredentialType::Single),
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
            key: params.key.map(Into::into),
            credential_blob_id: params.credential_blob_id,
            wallet_key_attestation_blob_id: params.wallet_key_attestation_blob_id,
            wallet_instance_attestation_blob_id: params.wallet_instance_attestation_blob_id,
            webhook_url: params.webhook_url,
            embedded_disclosure_policy: params.embedded_disclosure_policy,
            subscriber_information: params.subscriber_information,
            parent: params
                .parent_id
                .map(|id| Related::new(id, self.repository.clone())),
            format: convert_inner(params.format.or(format)),
        };
        credential_fixture(credential).await
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
        params.r#type = Some(if params.role == Some(CredentialRole::Holder) {
            CredentialType::Single
        } else {
            CredentialType::BatchParent
        });
        let key = if params.role == Some(CredentialRole::Holder) {
            params.key.take()
        } else {
            params.key.clone()
        }
        .map(Into::into);
        let item_format = params.format.clone();
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
        let (holder_claims, embedded_disclosure_policy) =
            if let Ok(holder) = credential.holder_mut() {
                let claims = holder.data.claims.as_ref().await.unwrap().to_owned();
                holder.data.claims = Default::default();
                (Some(claims), holder.data.embedded_disclosure_policy.take())
            } else {
                (None, None)
            };

        let holder_data = if let Credential::HolderSingle {
            credential: data, ..
        } = &credential
        {
            Some(data.clone())
        } else {
            None
        };
        if holder_data.is_some() {
            credential = Credential::HolderBatchParent {
                common: credential.common().clone(),
            };
        }
        let id = self
            .repository
            .create_credential(credential.to_owned())
            .await
            .unwrap();
        let batch_item_template =
            if let Credential::IssuerBatchParent { common, issuer, .. } = &credential {
                let mut common = common.clone();
                common.interaction = None;
                let item_format = match item_format {
                    Some(format) => format,
                    None => credential_schema.formats.as_ref().await.unwrap()[0].clone(),
                };
                Credential::IssuerBatchItem {
                    common,
                    issuer: issuer.clone(),
                    parent: Related::new(id, self.repository.clone()),
                    credential: one_core::model::credential::IssuerCredentialData {
                        format: item_format.into(),
                        holder_identifier,
                        credential_blob_id: None,
                        wallet_key_attestation_blob_id: None,
                    },
                }
            } else {
                let mut common = credential.common().clone();
                common.interaction = None;
                let mut data = holder_data.unwrap();
                data.embedded_disclosure_policy = embedded_disclosure_policy;
                data.binding = match (holder_identifier, key) {
                    (Some(identifier), Some(key)) => {
                        Some(one_core::model::credential::HolderBinding { identifier, key })
                    }
                    (None, None) => None,
                    _ => panic!("holder identifier and key must be supplied together"),
                };
                Credential::HolderBatchItem {
                    common,
                    parent: Related::new(id, self.repository.clone()),
                    credential: data,
                    consumed_at: None,
                }
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
            let batch_item_credential = {
                let mut updated_credential = batch_item_template.clone();
                updated_credential.common_mut().id = item_id;
                if let Ok(holder) = updated_credential.holder_mut() {
                    holder.data.claims = claims.into();
                    holder.data.credential_blob_id = credential_blob_id;
                } else {
                    updated_credential
                        .issuer_credential_mut()
                        .unwrap()
                        .data
                        .credential_blob_id = credential_blob_id;
                }
                updated_credential
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

pub async fn credential_fixture(mut credential: CredentialBuilder) -> Credential {
    if credential.role == CredentialRole::Issuer && credential.key.is_none() {
        let key = match &credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .data
        {
            IdentifierData::Key(key) => key.clone(),
            IdentifierData::Did(did) => did
                .as_ref()
                .await
                .unwrap()
                .keys
                .as_ref()
                .await
                .unwrap()
                .first()
                .expect("issuer requires a signing key")
                .key
                .clone()
                .into(),
            IdentifierData::Certificate(_) | IdentifierData::CertificateAuthority(_) => credential
                .issuer_certificate
                .as_ref()
                .unwrap()
                .as_ref()
                .await
                .unwrap()
                .key
                .as_ref()
                .expect("issuer certificate requires a signing key")
                .clone(),
        };
        credential.key = Some(key);
    }
    credential.build()
}
