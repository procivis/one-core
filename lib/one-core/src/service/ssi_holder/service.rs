use super::{
    dto::InvitationResponseDTO,
    mapper::{credential_schema_from_jwt, parse_query, remote_did_from_value, string_to_uuid},
    SSIHolderService,
};
use crate::{
    model::{
        claim::{Claim, ClaimId},
        credential::{
            Credential, CredentialId, CredentialRelations, CredentialState, CredentialStateEnum,
        },
        did::{Did, DidRelations},
        organisation::OrganisationRelations,
    },
    repository::error::DataLayerError,
    service::{did::dto::DidId, error::ServiceError, proof::dto::ProofId},
    transport_protocol::dto::{ConnectIssuerResponse, ConnectVerifierResponse, InvitationResponse},
};
use time::OffsetDateTime;

impl SSIHolderService {
    pub async fn handle_invitation(
        &self,
        url: &str,
        holder_did_id: &DidId,
    ) -> Result<InvitationResponseDTO, ServiceError> {
        let url_query_params = parse_query(url)?;

        let holder_did = self
            .did_repository
            .get_did(holder_did_id, &DidRelations::default())
            .await?;

        let connect_response = self
            .protocol_provider
            .get_protocol(&url_query_params.protocol)?
            .handle_invitation(url, &holder_did.did)
            .await?;

        match connect_response {
            InvitationResponse::Proof {
                proof_id,
                proof_request,
            } => self.handle_proof_invitation(url, proof_id, proof_request),
            InvitationResponse::Credential(issuer_response) => {
                let credential_id = url_query_params
                    .credential
                    .ok_or(ServiceError::IncorrectParameters)?;

                self.handle_credential_invitation(credential_id, holder_did, issuer_response)
                    .await
            }
        }
    }

    pub async fn reject_proof_request(
        &self,
        transport_protocol: &str,
        base_url: &str,
        proof_id: &ProofId,
    ) -> Result<(), ServiceError> {
        self.protocol_provider
            .get_protocol(transport_protocol)?
            .reject_proof(base_url, &proof_id.to_string())
            .await
            .map_err(ServiceError::from)
    }

    pub async fn submit_proof(
        &self,
        transport_protocol: &str,
        base_url: &str,
        proof_id: &ProofId,
        credential_ids: &[CredentialId],
        holder_did_id: &DidId,
    ) -> Result<(), ServiceError> {
        let holder_did = self
            .did_repository
            .get_did(holder_did_id, &DidRelations::default())
            .await?;

        let mut credentials: Vec<String> = vec![];
        for credential_id in credential_ids {
            let credential_data = self
                .credential_repository
                .get_credential(credential_id, &CredentialRelations::default())
                .await?
                .credential;

            if credential_data.is_empty() {
                return Err(ServiceError::NotFound);
            }
            let credential_content = std::str::from_utf8(&credential_data)
                .map_err(|e| ServiceError::MappingError(e.to_string()))?;

            credentials.push(credential_content.to_owned());
        }

        // FIXME - pick correct formatter
        let formatter = self.formatter_provider.get_formatter("JWT")?;
        let presentation = formatter.format_presentation(&credentials, &holder_did.did)?;

        self.protocol_provider
            .get_protocol(transport_protocol)?
            .submit_proof(base_url, &proof_id.to_string(), &presentation)
            .await
            .map_err(ServiceError::from)
    }

    // ====== private methods
    fn handle_proof_invitation(
        &self,
        url: &str,
        proof_id: String,
        proof_request: ConnectVerifierResponse,
    ) -> Result<InvitationResponseDTO, ServiceError> {
        let url_parsed = reqwest::Url::parse(url).map_err(|_| ServiceError::IncorrectParameters)?;
        let base_url = format!(
            "{}://{}",
            url_parsed.scheme(),
            url_parsed
                .host_str()
                .ok_or(ServiceError::IncorrectParameters)?
        );

        Ok(InvitationResponseDTO::ProofRequest {
            proof_id: string_to_uuid(&proof_id)?,
            proof_request: proof_request.try_into()?,
            base_url,
        })
    }

    async fn handle_credential_invitation(
        &self,
        credential_id: CredentialId,
        holder_did: Did,
        issuer_response: ConnectIssuerResponse,
    ) -> Result<InvitationResponseDTO, ServiceError> {
        let organisation_id = holder_did.organisation_id;
        let organisation = self
            .organisation_repository
            .get_organisation(&organisation_id, &OrganisationRelations::default())
            .await?;

        let raw_credential = issuer_response.credential;
        let format = issuer_response.format;

        let formatter = self.formatter_provider.get_formatter(&format)?;

        let credential = formatter.extract_credentials(&raw_credential)?;

        // check headers
        let issuer_did_value = credential.issuer_did.ok_or(ServiceError::ValidationError(
            "IssuerDid missing".to_owned(),
        ))?;

        if let Some(parsed_credential_id) = credential.id {
            if parsed_credential_id != credential_id.to_string() {
                return Err(ServiceError::ValidationError(
                    "Credential ID mismatch".to_owned(),
                ));
            }
        } else {
            return Err(ServiceError::ValidationError(
                "Credential ID missing".to_owned(),
            ));
        }

        if let Some(holder_did_value) = credential.subject {
            if holder_did_value != holder_did.did {
                return Err(ServiceError::ValidationError(
                    "Holder DID mismatch".to_owned(),
                ));
            }
        } else {
            return Err(ServiceError::ValidationError(
                "Holder ID missing".to_owned(),
            ));
        }

        // insert credential schema if not yet known
        let schema = credential.claims.one_credential_schema;
        let credential_schema = credential_schema_from_jwt(schema, organisation)?;

        let result = self
            .credential_schema_repository
            .create_credential_schema(credential_schema.clone())
            .await;
        if let Err(error) = result {
            if error != DataLayerError::AlreadyExists {
                return Err(ServiceError::from(error));
            }
        }

        // insert issuer did if not yet known
        let issuer_did = remote_did_from_value(issuer_did_value.to_owned(), organisation_id);
        let did_insert_result = self.did_repository.create_did(issuer_did.clone()).await;
        let issuer_did = match did_insert_result {
            Ok(_) => issuer_did,
            Err(DataLayerError::AlreadyExists) => {
                self.did_repository
                    .get_did_by_value(&issuer_did_value, &DidRelations::default())
                    .await?
            }
            Err(e) => return Err(ServiceError::from(e)),
        };

        // create credential
        let now = OffsetDateTime::now_utc();
        let incoming_claims = credential.claims.values;
        let claims = credential_schema
            .claim_schemas
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "claim_schemas is None".to_string(),
            ))?
            .iter()
            .map(|claim_schema| -> Result<Option<Claim>, ServiceError> {
                if let Some(value) = incoming_claims.get(&claim_schema.schema.key) {
                    Ok(Some(Claim {
                        schema: Some(claim_schema.schema.to_owned()),
                        value: value.to_owned(),
                        id: ClaimId::new_v4(),
                        created_date: now,
                        last_modified: now,
                    }))
                } else if claim_schema.required {
                    Err(ServiceError::ValidationError(format!(
                        "Claim key {} missing",
                        &claim_schema.schema.key
                    )))
                } else {
                    Ok(None) // missing optional claim
                }
            })
            .collect::<Result<Vec<Option<Claim>>, ServiceError>>()?
            .into_iter()
            .flatten()
            .collect();

        self.credential_repository
            .create_credential(Credential {
                id: credential_id.to_owned(),
                created_date: now,
                issuance_date: now,
                last_modified: now,
                credential: raw_credential.bytes().collect(),
                transport: "PROCIVIS_TEMPORARY".to_string(),
                state: Some(vec![CredentialState {
                    created_date: now,
                    state: CredentialStateEnum::Accepted,
                }]),
                claims: Some(claims),
                issuer_did: Some(issuer_did),
                holder_did: Some(holder_did),
                schema: Some(credential_schema),
            })
            .await?;

        Ok(InvitationResponseDTO::Credential {
            issued_credential_id: credential_id,
        })
    }
}
