use super::{dto::IssuerResponseDTO, SSIIssuerService};
use crate::{
    common_mapper::get_algorithm_from_key_algorithm,
    model::{
        claim::ClaimRelations,
        claim_schema::ClaimSchemaRelations,
        credential::{
            CredentialId, CredentialRelations, CredentialState, CredentialStateEnum,
            CredentialStateRelations, UpdateCredentialRequest,
        },
        credential_schema::CredentialSchemaRelations,
        did::{Did, DidId, DidRelations, DidType, KeyRole},
        key::KeyRelations,
        organisation::OrganisationRelations,
    },
    repository::error::DataLayerError,
    service::{
        credential::dto::CredentialDetailResponseDTO, error::ServiceError,
        ssi_issuer::mapper::from_credential_id_and_token,
    },
};
use time::OffsetDateTime;

impl SSIIssuerService {
    pub async fn issuer_connect(
        &self,
        credential_id: &CredentialId,
        holder_did_value: &String,
    ) -> Result<CredentialDetailResponseDTO, ServiceError> {
        let mut credential = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations::default()),
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        claim_schemas: Some(ClaimSchemaRelations::default()),
                    }),
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    issuer_did: Some(DidRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let latest_state = credential
            .state
            .as_ref()
            .ok_or(ServiceError::MappingError("state is None".to_string()))?
            .get(0)
            .ok_or(ServiceError::MappingError("state is missing".to_string()))?;
        if latest_state.state != CredentialStateEnum::Pending {
            return Err(ServiceError::AlreadyExists);
        }

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError("schema is None".to_string()))?;

        let holder_did =
            match self
                .did_repository
                .get_did_by_value(holder_did_value, &DidRelations::default())
                .await
            {
                Ok(did) => did,
                Err(DataLayerError::RecordNotFound) => {
                    let organisation = credential_schema.organisation.as_ref().ok_or(
                        ServiceError::MappingError("organisation is None".to_string()),
                    )?;

                    let did = Did {
                        id: DidId::new_v4(),
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                        name: "holder".to_string(),
                        organisation: Some(organisation.to_owned()),
                        did: holder_did_value.clone(),
                        did_method: "KEY".to_string(),
                        did_type: DidType::Remote,
                        keys: None,
                    };
                    self.did_repository.create_did(did.clone()).await?;
                    did
                }
                Err(e) => {
                    return Err(ServiceError::from(e));
                }
            };

        let now: OffsetDateTime = OffsetDateTime::now_utc();
        let new_state = CredentialStateEnum::Offered;

        self.credential_repository
            .update_credential(UpdateCredentialRequest {
                id: credential_id.to_owned(),
                credential: None,
                holder_did_id: Some(holder_did.id),
                state: Some(CredentialState {
                    created_date: now,
                    state: new_state.clone(),
                }),
            })
            .await?;

        // Update local copy for conversion.
        credential.holder_did = Some(holder_did);
        if let Some(states) = &mut credential.state {
            states.push(CredentialState {
                created_date: now,
                state: new_state,
            });
        }

        credential.try_into()
    }

    pub async fn issuer_submit(
        &self,
        credential_id: &CredentialId,
    ) -> Result<IssuerResponseDTO, ServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations::default()),
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        claim_schemas: Some(ClaimSchemaRelations::default()),
                    }),
                    issuer_did: Some(DidRelations {
                        keys: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                    holder_did: Some(DidRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let latest_state = credential
            .state
            .as_ref()
            .ok_or(ServiceError::MappingError("state is None".to_string()))?
            .get(0)
            .ok_or(ServiceError::MappingError("state is missing".to_string()))?;
        if latest_state.state != CredentialStateEnum::Offered {
            return Err(ServiceError::AlreadyExists);
        }

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError("schema is None".to_string()))?;

        let holder_did = credential
            .holder_did
            .as_ref()
            .ok_or(ServiceError::MappingError("holder did is None".to_string()))?
            .clone();

        let issuer_did = credential
            .issuer_did
            .as_ref()
            .ok_or(ServiceError::MappingError("issuer did is None".to_string()))?
            .clone();

        let format = credential_schema.format.to_owned();

        let revocation_method = self
            .revocation_method_provider
            .get_revocation_method(&credential_schema.revocation_method)?;
        let (credential_status, additional_context) =
            match revocation_method.add_issued_credential(&credential).await? {
                None => (None, vec![]),
                Some(revocation_info) => (
                    Some(revocation_info.credential_status),
                    revocation_info.additional_vc_contexts,
                ),
            };

        let keys = issuer_did
            .keys
            .as_ref()
            .ok_or(ServiceError::MappingError("Issuer has no keys".to_string()))?;

        let key = keys
            .iter()
            .find(|k| k.role == KeyRole::AssertionMethod)
            .ok_or(ServiceError::Other("Missing Key".to_owned()))?;

        let algorithm = get_algorithm_from_key_algorithm(&key.key.key_type, &self.config)?;

        let signer = self
            .crypto
            .signers
            .get(&algorithm)
            .ok_or(ServiceError::MissingSigner(algorithm))?
            .clone();

        let key_provider = self.key_provider.get_key_storage(&key.key.storage_type)?;

        let private_key_moved = key_provider.decrypt_private_key(&key.key.private_key)?;
        let public_key_moved = key.key.public_key.clone();

        let auth_fn = Box::new(move |data: &str| {
            let signer = signer;
            let private_key = private_key_moved;
            let public_key = public_key_moved;
            signer.sign(data, &public_key, &private_key)
        });

        let token: String = self
            .formatter_provider
            .get_formatter(&format)?
            .format_credentials(
                &credential.try_into()?,
                credential_status,
                &holder_did.did,
                &key.key.key_type,
                additional_context,
                vec![],
                auth_fn,
            )?;

        self.credential_repository
            .update_credential(from_credential_id_and_token(credential_id, &token))
            .await?;

        Ok(IssuerResponseDTO {
            credential: token,
            format,
        })
    }

    pub async fn issuer_reject(&self, credential_id: &CredentialId) -> Result<(), ServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations::default()),
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    ..Default::default()
                },
            )
            .await?;

        let latest_state = credential
            .state
            .as_ref()
            .ok_or(ServiceError::MappingError("state is None".to_string()))?
            .get(0)
            .ok_or(ServiceError::MappingError("state is missing".to_string()))?;
        if latest_state.state != CredentialStateEnum::Offered {
            return Err(ServiceError::AlreadyExists);
        }

        self.credential_repository
            .update_credential(UpdateCredentialRequest {
                id: credential_id.to_owned(),
                credential: None,
                holder_did_id: None,
                state: Some(CredentialState {
                    created_date: OffsetDateTime::now_utc(),
                    state: CredentialStateEnum::Rejected,
                }),
            })
            .await?;

        Ok(())
    }
}
