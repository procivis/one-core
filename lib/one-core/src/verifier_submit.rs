use time::OffsetDateTime;
use uuid::Uuid;

use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::Arc,
};

use crate::{
    credential_formatter::{CredentialFormatter, ParseError},
    data_model::VerifierSubmitRequest,
    error::{OneCoreError, SSIError},
    model::{
        did::{Did, DidRelations},
        proof::ProofStateEnum,
    },
    repository::error::DataLayerError,
    service::{
        credential_schema::dto::{ClaimSchemaId, CredentialSchemaId},
        error::ServiceError,
        proof::dto::CreateProofClaimRequestDTO,
        proof_schema::dto::GetProofSchemaResponseDTO,
    },
    OneCore,
};

fn validate_issuance_time(issued_at: Option<OffsetDateTime>) -> Result<(), OneCoreError> {
    let now = OffsetDateTime::now_utc();
    let issued = issued_at.ok_or(SSIError::ParseError(ParseError::Failed(
        "Missing issuance date".to_owned(),
    )))?;

    if issued > now {
        return Err(SSIError::IncorrectParameters("Issued in future".to_owned()).into());
    }

    Ok(())
}

fn validate_expiration_time(expires_at: Option<OffsetDateTime>) -> Result<(), OneCoreError> {
    let now = OffsetDateTime::now_utc();
    let expires = expires_at.ok_or(SSIError::ParseError(ParseError::Failed(
        "Missing expiration date".to_owned(),
    )))?;

    if expires < now {
        return Err(SSIError::IncorrectParameters("Expired".to_owned()).into());
    }

    Ok(())
}

fn validate_proof(
    proof_schema: GetProofSchemaResponseDTO,
    holder_did: &Did,
    presentation: &str,
    formatter: &Arc<dyn CredentialFormatter + Send + Sync>,
) -> Result<Vec<CreateProofClaimRequestDTO>, OneCoreError> {
    // TODO Check if the signature of the ProofSubmitRequestDTO(JWT) is signed with did of the issuer property (holder did)
    // Add when key management introduced. For now we use the same pair of keys for everything.
    // If it's extracted - it's properly signed
    // This will change when we started using external signature providers
    let presentation = formatter.extract_presentation(presentation)?;

    // Check if presentation is expired
    validate_issuance_time(presentation.issued_at)?;
    validate_expiration_time(presentation.expires_at)?;

    let requested_cred_schema_ids: HashSet<CredentialSchemaId> = proof_schema
        .claim_schemas
        .iter()
        .map(|claim| claim.credential_schema.id)
        .collect();

    let mut remaining_requested_claims: HashMap<CredentialSchemaId, Vec<ClaimSchemaId>> =
        HashMap::new();
    requested_cred_schema_ids
        .into_iter()
        .for_each(|cred_schema_id| {
            remaining_requested_claims.insert(
                cred_schema_id,
                proof_schema
                    .claim_schemas
                    .iter()
                    .filter(|claim_schema| claim_schema.credential_schema.id == cred_schema_id)
                    .map(|claim_schema| claim_schema.id)
                    .collect(),
            );
        });

    let mut proved_credentials: HashMap<CredentialSchemaId, Vec<CreateProofClaimRequestDTO>> =
        HashMap::new();

    for credential in presentation.credentials {
        let claim = formatter
            .extract_credentials(&credential)
            .map_err(|_| OneCoreError::SSIError(SSIError::IncorrectProof))?;

        // Check if “nbf” attribute of VCs and VP are valid. || Check if VCs are expired.
        validate_issuance_time(claim.invalid_before)?;
        validate_expiration_time(claim.expires_at)?;

        // Check if all subjects of the submitted VCs is matching the holder did.
        let claim_subject = match claim.subject {
            None => {
                return Err(
                    SSIError::IncorrectParameters("Claim Holder DID missing".to_owned()).into(),
                );
            }
            Some(did) => did,
        };
        if claim_subject != holder_did.did {
            return Err(
                SSIError::IncorrectParameters("Holder DID doesn't match.".to_owned()).into(),
            );
        }

        // check if this credential was requested
        let credential_schema_id = Uuid::from_str(&claim.claims.one_credential_schema.id)
            .map_err(|_| OneCoreError::DataLayerError(DataLayerError::MappingError))?;
        let requested_claims: Result<Vec<ClaimSchemaId>, SSIError> =
            match remaining_requested_claims.remove_entry(&credential_schema_id) {
                None => {
                    if proved_credentials.contains_key(&credential_schema_id) {
                        Err(SSIError::IncorrectParameters(format!(
                            "Duplicit credential for schema '{credential_schema_id}' received"
                        )))
                    } else {
                        Err(SSIError::IncorrectParameters(format!(
                            "Credential for schema '{credential_schema_id}' not requested"
                        )))
                    }
                }
                Some((.., value)) => Ok(value),
            };

        let mut collected_proved_claims: Vec<CreateProofClaimRequestDTO> = vec![];
        for requested_claim_schema_id in requested_claims.map_err(OneCoreError::SSIError)? {
            let claim_schema = proof_schema
                .claim_schemas
                .iter()
                .find(|schema| schema.id == requested_claim_schema_id)
                .ok_or(OneCoreError::DataLayerError(
                    DataLayerError::GeneralRuntimeError("Missing claim schema".to_owned()),
                ))?;

            let value =
                claim
                    .claims
                    .values
                    .get(&claim_schema.key)
                    .ok_or(SSIError::IncorrectParameters(format!(
                        "Credential key '{}' missing",
                        &claim_schema.key
                    )))?;

            collected_proved_claims.push(CreateProofClaimRequestDTO {
                claim_schema_id: requested_claim_schema_id,
                value: value.to_owned(),
            });
        }

        // TODO Validate collected_proved_claims when validators are ready

        proved_credentials.insert(credential_schema_id, collected_proved_claims);
    }

    if !remaining_requested_claims.is_empty() {
        return Err(
            SSIError::IncorrectParameters("Not all requested claims fulfilled".to_owned()).into(),
        );
    }

    Ok(proved_credentials
        .into_iter()
        .flat_map(|(.., claims)| claims)
        .collect())
}

impl OneCore {
    pub async fn verifier_submit(
        &self,
        //transport_protocol: &str,
        request: &VerifierSubmitRequest,
    ) -> Result<(), OneCoreError> {
        // Not used for now
        //let _transport = self.get_transport_protocol(transport_protocol)?;

        let proof_id = &request.proof;
        let proof = self
            .proof_service
            .get_proof(proof_id)
            .await
            .map_err(|e| match e {
                ServiceError::NotFound => OneCoreError::SSIError(SSIError::MissingProof),
                e => OneCoreError::ServiceError(e),
            })?;

        // Check if proof request is in “OFFERED” state
        if proof.state != ProofStateEnum::Offered {
            tracing::error!(
                "Incorrect proof state. Was: {:?}; Expected: Offered",
                proof.state
            );
            return Err(OneCoreError::SSIError(SSIError::IncorrectProofState));
        }

        let holder_did = match &proof.holder_did_id {
            None => {
                return Err(SSIError::IncorrectParameters("Holder DID missing".to_owned()).into());
            }
            Some(holder_did_id) => self
                .did_repository
                .get_did(holder_did_id, &DidRelations::default())
                .await
                .map_err(OneCoreError::DataLayerError)?,
        };

        let proof_schema = self
            .proof_schema_service
            .get_proof_schema(&proof.schema.id)
            .await
            .map_err(OneCoreError::ServiceError)?;

        // FIXME What's the format?
        let format = "JWT";
        let formatter = self.get_formatter(format)?;

        let proved_claims = match validate_proof(
            proof_schema,
            &holder_did,
            &request.proof_submit_request,
            &formatter,
        ) {
            Ok(claims) => claims,
            Err(e) => {
                self.proof_service.fail_proof(proof_id).await?;
                return Err(e);
            }
        };

        self.proof_service
            .accept_proof(proof_id, proved_claims)
            .await?;

        Ok(())
    }
}

// #[cfg(test)]
// mod tests {
//     use std::str::FromStr;

//     use crate::{
//         config::data_structure::{ConfigKind, UnparsedConfig},
//         data_model::VerifierSubmitRequest,
//         repository::data_provider::{
//             ClaimProofSchemaRequest, CreateCredentialRequest, CreateCredentialRequestClaim,
//             CreateCredentialSchemaRequest, CreateDidRequest, CreateOrganisationRequest,
//             CreateProofRequest, CreateProofResponse, CreateProofSchemaRequest,
//             CredentialClaimSchemaRequest, Format, ProofRequestState, RevocationMethod, Transport,
//         },
//         OneCore,
//     };
//     use uuid::Uuid;

//     struct TestData {
//         pub one_core: OneCore,
//         pub jwt_correct: String,
//         pub jwt_incorrect: String,
//         pub proof_response: CreateProofResponse,
//         pub holder_did: String,
//     }

//     async fn setup_test_data() -> TestData {
//         let minimal_config = r#"{
//           "format": {},
//           "exchange": {},
//           "transport": {},
//           "revocation": {},
//           "did": {},
//           "datatype": {}
//         }
//         "#
//         .to_string();

//         let unparsed_config = UnparsedConfig {
//             content: minimal_config,
//             kind: ConfigKind::Json,
//         };
//         let mut one_core = OneCore::new("sqlite::memory:", unparsed_config)
//             .await
//             .unwrap();
//         one_core.config.datatype = get_datatypes();

//         let organisation_id = one_core
//             .data_layer
//             .create_organisation(CreateOrganisationRequest { id: None })
//             .await
//             .unwrap()
//             .id;

//         let holder_did_value = "HOLDER:DID".to_string();
//         let holder_did_id = one_core
//             .data_layer
//             .create_did(CreateDidRequest {
//                 name: "holder".to_string(),
//                 organisation_id: organisation_id.to_owned(),
//                 did: holder_did_value.to_owned(),
//                 did_type: Default::default(),
//                 method: Default::default(),
//             })
//             .await
//             .unwrap()
//             .id;

//         let issuer_did_value = "ISSUER:DID".to_string();
//         let issuer_did_id = one_core
//             .data_layer
//             .create_did(CreateDidRequest {
//                 name: "issuer".to_string(),
//                 organisation_id: organisation_id.to_owned(),
//                 did: issuer_did_value.to_owned(),
//                 did_type: Default::default(),
//                 method: Default::default(),
//             })
//             .await
//             .unwrap()
//             .id;

//         let verifier_did_value = "VERIFIER:DID".to_string();
//         let verifier_did_id = one_core
//             .data_layer
//             .create_did(CreateDidRequest {
//                 name: "verifier".to_string(),
//                 organisation_id: organisation_id.to_owned(),
//                 did: verifier_did_value.to_owned(),
//                 did_type: Default::default(),
//                 method: Default::default(),
//             })
//             .await
//             .unwrap()
//             .id;

//         let credential_schema_id = one_core
//             .data_layer
//             .create_credential_schema(
//                 CreateCredentialSchemaRequest {
//                     name: "CREDENTIAL_SCHEMA".to_string(),
//                     format: Format::Jwt,
//                     revocation_method: RevocationMethod::None,
//                     organisation_id: Uuid::from_str(&organisation_id).unwrap(),
//                     claims: vec![CredentialClaimSchemaRequest {
//                         key: "Something".to_string(),
//                         datatype: "STRING".to_string(),
//                     }],
//                 },
//                 &one_core.config.datatype,
//             )
//             .await
//             .unwrap()
//             .id;

//         let credential_schema = one_core
//             .data_layer
//             .get_credential_schema_details(&credential_schema_id)
//             .await
//             .unwrap();

//         let credential_response = one_core
//             .data_layer
//             .create_credential(
//                 CreateCredentialRequest {
//                     credential_id: None,
//                     credential_schema_id: Uuid::from_str(&credential_schema.id).unwrap(),
//                     issuer_did: Uuid::from_str(&issuer_did_id).unwrap(),
//                     transport: Transport::ProcivisTemporary,
//                     claim_values: credential_schema
//                         .claims
//                         .iter()
//                         .map(|claim| CreateCredentialRequestClaim {
//                             claim_id: Uuid::from_str(&claim.id).unwrap(),
//                             value: "test".to_owned(),
//                         })
//                         .collect(),
//                     receiver_did_id: Some(Uuid::from_str(&holder_did_id).unwrap()),
//                     credential: None,
//                 },
//                 &one_core.config.datatype,
//             )
//             .await
//             .unwrap();

//         let credential_details = one_core
//             .data_layer
//             .get_credential_details(&credential_response.id)
//             .await
//             .unwrap();

//         let jwt_correct = one_core
//             .get_formatter("JWT")
//             .unwrap()
//             .format_credentials(&credential_details, &holder_did_value.to_string())
//             .unwrap();

//         let mut incorrect_credential = credential_details.clone();
//         incorrect_credential.schema.id = "invalid".to_string();
//         let jwt_incorrect = one_core
//             .get_formatter("JWT")
//             .unwrap()
//             .format_credentials(&incorrect_credential, &holder_did_value.to_string())
//             .unwrap();

//         let proof_schema_response = one_core
//             .data_layer
//             .create_proof_schema(CreateProofSchemaRequest {
//                 name: "PROOF_SCHEMA".to_owned(),
//                 organisation_id: Uuid::from_str(&organisation_id).unwrap(),
//                 expire_duration: 0,
//                 claim_schemas: credential_schema
//                     .claims
//                     .iter()
//                     .map(|claim| ClaimProofSchemaRequest {
//                         id: Uuid::from_str(&claim.id).unwrap(),
//                     })
//                     .collect(),
//             })
//             .await
//             .unwrap();

//         let proof_response = one_core
//             .data_layer
//             .create_proof(CreateProofRequest {
//                 proof_schema_id: Uuid::from_str(&proof_schema_response.id).unwrap(),
//                 verifier_did_id: Uuid::from_str(&verifier_did_id).unwrap(),
//                 transport: Transport::ProcivisTemporary,
//             })
//             .await
//             .unwrap();
//         let proof_uuid = Uuid::from_str(&proof_response.id).unwrap();

//         one_core
//             .data_layer
//             .share_proof(&proof_response.id)
//             .await
//             .unwrap();

//         one_core
//             .verifier_connect(
//                 "PROCIVIS_TEMPORARY",
//                 &crate::data_model::ConnectVerifierRequest {
//                     proof: proof_uuid,
//                     did: holder_did_value.clone(),
//                 },
//             )
//             .await
//             .unwrap();

//         TestData {
//             one_core,
//             jwt_correct,
//             jwt_incorrect,
//             proof_response,
//             holder_did: holder_did_value,
//         }
//     }

//     #[tokio::test]
//     #[tracing_test::traced_test]
//     async fn test_verify_correct_proof() {
//         let test_data = setup_test_data().await;

//         let core = test_data.one_core;

//         let formatter = core.get_formatter("JWT").unwrap();

//         let presentation = formatter
//             .format_presentation(&[test_data.jwt_correct], &test_data.holder_did)
//             .unwrap();

//         let result = core
//             .verifier_submit(&VerifierSubmitRequest {
//                 proof: Uuid::from_str(&test_data.proof_response.id).unwrap(),
//                 proof_submit_request: presentation,
//             })
//             .await;

//         assert!(result.is_ok());

//         let details = core
//             .data_layer
//             .get_proof_details(&test_data.proof_response.id)
//             .await
//             .unwrap();

//         assert_eq!(details.state, ProofRequestState::Accepted);
//         assert_eq!(details.claims.len(), 1);
//     }

//     #[tokio::test]
//     #[tracing_test::traced_test]
//     async fn test_verify_incorrect_proof_state() {
//         let test_data = setup_test_data().await;

//         let core = test_data.one_core;

//         let formatter = core.get_formatter("JWT").unwrap();

//         // Set proof state to incorrect
//         core.data_layer
//             .set_proof_state(&test_data.proof_response.id, ProofRequestState::Rejected)
//             .await
//             .unwrap();

//         let presentation = formatter
//             .format_presentation(&[test_data.jwt_correct], &test_data.holder_did)
//             .unwrap();

//         let result = core
//             .verifier_submit(&VerifierSubmitRequest {
//                 proof: Uuid::from_str(&test_data.proof_response.id).unwrap(),
//                 proof_submit_request: presentation,
//             })
//             .await;

//         assert!(matches!(
//             result,
//             Err(crate::error::OneCoreError::SSIError(
//                 crate::error::SSIError::IncorrectProofState
//             ))
//         ))
//     }

//     #[tokio::test]
//     #[tracing_test::traced_test]
//     async fn test_verify_incorrect_schema() {
//         let test_data = setup_test_data().await;

//         let formatter = test_data.one_core.get_formatter("JWT").unwrap();

//         let presentation = formatter
//             .format_presentation(&[test_data.jwt_incorrect], &test_data.holder_did)
//             .unwrap();

//         let result = test_data
//             .one_core
//             .verifier_submit(&VerifierSubmitRequest {
//                 proof: Uuid::from_str(&test_data.proof_response.id).unwrap(),
//                 proof_submit_request: presentation,
//             })
//             .await;

//         assert!(matches!(
//             result,
//             Err(crate::error::OneCoreError::SSIError(
//                 crate::error::SSIError::IncorrectParameters(_)
//             ))
//         ))
//     }

//     // Additional testcases:
//     // Claims signed with incorrect key - when key repository introduced
//     // Presentation signed with incorrect key - when key repository introduced
//     // Incorrect claims format - when data format verifiers ready
//     //
// }
