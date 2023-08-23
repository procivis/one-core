use std::collections::HashMap;
use std::str::FromStr;
use uuid::Uuid;

use crate::credential_formatter::{
    ParseError, VCCredentialClaimSchemaResponse, VCCredentialSchemaResponse,
};
use crate::data_model::ConnectVerifierResponse;
use crate::error::SSIError;
use crate::local_did_helpers::{get_first_local_did, get_first_organisation_id};
use crate::repository::data_provider::{
    CreateCredentialRequest, CreateCredentialRequestClaim, CredentialState,
};
use crate::repository::error::DataLayerError;
use crate::transport_protocol::TransportProtocolError;
use crate::{
    data_model::HandleInvitationQueryRequest,
    error::OneCoreError,
    repository::data_provider::{
        CreateCredentialSchemaFromJwtRequest, CreateDidRequest,
        CredentialClaimSchemaFromJwtRequest, DidType,
    },
    OneCore,
};

fn parse_query(url: &str) -> Result<HandleInvitationQueryRequest, OneCoreError> {
    let query: HashMap<String, String> = reqwest::Url::parse(url)
        .map_err(|e| OneCoreError::SSIError(SSIError::IncorrectParameters(e.to_string())))?
        .query_pairs()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();

    fn option_parse_uuid(input: Option<&String>) -> Result<Option<Uuid>, OneCoreError> {
        Ok(match input {
            None => None,
            Some(str) => Some(string_to_uuid(str)?),
        })
    }

    Ok(HandleInvitationQueryRequest {
        protocol: query
            .get("protocol")
            .ok_or(OneCoreError::SSIError(SSIError::IncorrectParameters(
                "Incorrect protocol".to_owned(),
            )))?
            .to_owned(),
        credential: option_parse_uuid(query.get("credential"))?,
        proof: option_parse_uuid(query.get("proof"))?,
    })
}

fn string_to_uuid(value: &str) -> Result<Uuid, OneCoreError> {
    Uuid::from_str(value).map_err(|e| {
        OneCoreError::SSIError(SSIError::ParseError(ParseError::Failed(e.to_string())))
    })
}

fn credential_claim_schema_request_from_jwt(
    claim: &VCCredentialClaimSchemaResponse,
) -> Result<CredentialClaimSchemaFromJwtRequest, OneCoreError> {
    Ok(CredentialClaimSchemaFromJwtRequest {
        id: string_to_uuid(&claim.id)?,
        key: claim.key.to_owned(),
        datatype: claim.datatype.to_owned(),
    })
}

fn create_credential_schema_request_from_jwt(
    schema: VCCredentialSchemaResponse,
    organisation_id: &str,
) -> Result<CreateCredentialSchemaFromJwtRequest, OneCoreError> {
    let claims: Result<Vec<CredentialClaimSchemaFromJwtRequest>, OneCoreError> = schema
        .claims
        .iter()
        .map(credential_claim_schema_request_from_jwt)
        .collect();

    Ok(CreateCredentialSchemaFromJwtRequest {
        id: string_to_uuid(&schema.id)?,
        name: schema.name,
        format: "JWT".to_string(),
        revocation_method: "NONE".to_string(),
        organisation_id: string_to_uuid(organisation_id)?,
        claims: claims?,
    })
}

#[derive(Clone)]
pub enum InvitationResponse {
    Credential {
        issued_credential_id: String,
    },
    ProofRequest {
        proof_request: ConnectVerifierResponse,
        proof_id: String,
        base_url: String,
    },
}

impl OneCore {
    pub async fn handle_invitation(&self, url: &str) -> Result<InvitationResponse, OneCoreError> {
        let url_query_params = parse_query(url)?;

        // FIXME - these two should be fetched correctly
        let organisation_id = get_first_organisation_id(&self.organisation_repository).await?;
        let expected_holder_did = get_first_local_did(&self.data_layer, &organisation_id).await?;

        let connect_response = self
            .get_transport_protocol(&url_query_params.protocol)?
            .handle_invitation(url, &expected_holder_did.did)
            .await
            .map_err(|e| OneCoreError::SSIError(SSIError::TransportProtocolError(e)))?;

        let issuer_response = match connect_response {
            crate::transport_protocol::InvitationResponse::Proof {
                proof_id,
                proof_request,
            } => {
                let url_parsed = reqwest::Url::parse(url).map_err(|e| {
                    OneCoreError::SSIError(SSIError::IncorrectParameters(e.to_string()))
                })?;
                let base_url = format!(
                    "{}://{}",
                    url_parsed.scheme(),
                    url_parsed.host_str().ok_or(OneCoreError::SSIError(
                        SSIError::IncorrectParameters("Missing host".to_string())
                    ))?
                );

                return Ok(InvitationResponse::ProofRequest {
                    proof_id,
                    proof_request,
                    base_url,
                });
            }
            crate::transport_protocol::InvitationResponse::Credential(issuer_response) => {
                issuer_response
            }
        };

        let raw_credential = issuer_response.credential;
        let format = issuer_response.format;

        let formatter = self.get_formatter(&format)?;

        let credential = formatter
            .extract_credentials(&raw_credential)
            .map_err(OneCoreError::FormatterError)?;

        // check headers
        let issuer_did_value =
            credential
                .issuer_did
                .ok_or(OneCoreError::SSIError(SSIError::ParseError(
                    ParseError::Failed("IssuerDid missing".to_owned()),
                )))?;

        let expected_credential_id = match url_query_params.credential {
            None => {
                return Err(OneCoreError::SSIError(SSIError::ParseError(
                    ParseError::Failed("Credential ID missing".to_owned()),
                )));
            }
            Some(uuid) => uuid.to_string(),
        };

        if let Some(credential_id) = credential.id {
            if credential_id != expected_credential_id {
                return Err(OneCoreError::SSIError(SSIError::TransportProtocolError(
                    TransportProtocolError::Failed("Credential ID mismatch".to_owned()),
                )));
            }
        } else {
            return Err(OneCoreError::SSIError(SSIError::ParseError(
                ParseError::Failed("Credential ID missing".to_owned()),
            )));
        }

        if let Some(holder_did) = credential.subject {
            if holder_did != expected_holder_did.did {
                return Err(OneCoreError::SSIError(SSIError::TransportProtocolError(
                    TransportProtocolError::Failed("Holder DID mismatch".to_owned()),
                )));
            }
        } else {
            return Err(OneCoreError::SSIError(SSIError::ParseError(
                ParseError::Failed("Holder ID missing".to_owned()),
            )));
        }

        // insert credential schema if not yet known
        let schema = credential.claims.one_credential_schema;

        let credential_schema_id = schema.id.to_owned();

        let credential_schema_request =
            create_credential_schema_request_from_jwt(schema, &organisation_id.to_string())?;
        let result = self
            .data_layer
            .create_credential_schema_from_jwt(
                credential_schema_request.clone(),
                &self.config.format,
                &self.config.revocation,
                &self.config.datatype,
            )
            .await;
        if let Err(error) = result {
            if error != DataLayerError::AlreadyExists {
                return Err(OneCoreError::DataLayerError(error));
            }
        }

        // insert issuer did if not yet known
        let did_insert_result = self
            .data_layer
            .create_did(
                CreateDidRequest {
                    name: "NEW_DID_FIXME".to_string(),
                    organisation_id: organisation_id.to_string(),
                    did: issuer_did_value.to_owned(),
                    did_type: DidType::Remote,
                    method: "KEY".to_string(),
                },
                &self.config.did,
            )
            .await;
        let issuer_did_id = match did_insert_result {
            Ok(did) => did.id,
            Err(DataLayerError::AlreadyExists) => {
                self.data_layer
                    .get_did_details_by_value(&issuer_did_value)
                    .await
                    .map_err(OneCoreError::DataLayerError)?
                    .id
            }
            Err(e) => return Err(OneCoreError::DataLayerError(e)),
        };

        // create credential
        let incoming_claims = credential.claims.values;
        let claim_values: Result<Vec<CreateCredentialRequestClaim>, _> = credential_schema_request
            .claims
            .iter()
            .map(
                |claim_schema| -> Result<CreateCredentialRequestClaim, OneCoreError> {
                    if let Some(value) = incoming_claims.get(&claim_schema.key) {
                        Ok(CreateCredentialRequestClaim {
                            claim_id: claim_schema.id,
                            value: value.to_owned(),
                        })
                    } else {
                        Err(OneCoreError::SSIError(SSIError::ParseError(
                            ParseError::Failed(format!("Claim key {} missing", &claim_schema.key)),
                        )))
                    }
                },
            )
            .collect();

        self.data_layer
            .create_credential(
                CreateCredentialRequest {
                    credential_id: Some(expected_credential_id.to_owned()),
                    credential_schema_id: string_to_uuid(&credential_schema_id)?,
                    issuer_did: string_to_uuid(&issuer_did_id)?,
                    transport: "PROCIVIS_TEMPORARY".to_string(),
                    claim_values: claim_values?,
                    receiver_did_id: Some(string_to_uuid(&expected_holder_did.id)?),
                    credential: Some(raw_credential.bytes().collect()),
                },
                &self.config.datatype,
                &self.config.exchange,
            )
            .await
            .map_err(OneCoreError::DataLayerError)?;

        self.data_layer
            .set_credential_state(&expected_credential_id, CredentialState::Accepted)
            .await
            .map_err(OneCoreError::DataLayerError)?;

        Ok(InvitationResponse::Credential {
            issued_credential_id: expected_credential_id,
        })
    }
}

// #[cfg(test)]
// mod tests {
//     use crate::{
//         config::data_structure::{ConfigKind, UnparsedConfig},
//         data_layer::{
//             self,
//             data_model::{
//                 CreateCredentialSchemaRequest, CreateDidRequest, CreateOrganisationRequest,
//                 CredentialClaimSchemaRequest, CredentialClaimSchemaResponse, CredentialState,
//                 DetailCredentialClaimResponse, DetailCredentialResponse, Format,
//                 ListCredentialSchemaResponse, RevocationMethod,
//             },
//             test_utilities::get_datatypes,
//         },
//         data_model::{ConnectIssuerResponse, ConnectVerifierResponse, ProofClaimSchema},
//         error::{OneCoreError, SSIError},
//         transport_protocol::{TransportProtocol, TransportProtocolError},
//         OneCore,
//     };

//     use async_trait::async_trait;
//     use std::str::FromStr;
//     use std::sync::Arc;
//     use time::OffsetDateTime;
//     use tokio::sync::RwLock;
//     use uuid::Uuid;

//     pub struct StubTransportProtocol {
//         handle_invitation_result:
//             Arc<RwLock<Result<crate::transport_protocol::InvitationResponse, String>>>,
//     }

//     impl Default for StubTransportProtocol {
//         fn default() -> Self {
//             Self {
//                 handle_invitation_result: Arc::new(RwLock::new(Err("Uninitialized".to_string()))),
//             }
//         }
//     }

//     impl StubTransportProtocol {
//         async fn set_handle_invitation_result(
//             &self,
//             value: Result<crate::transport_protocol::InvitationResponse, String>,
//         ) {
//             let mut handle_invitation_result = self.handle_invitation_result.write().await;
//             *handle_invitation_result = value;
//         }
//     }

//     #[async_trait]
//     impl TransportProtocol for StubTransportProtocol {
//         async fn handle_invitation(
//             &self,
//             _url: &str,
//             _own_did: &str,
//         ) -> Result<crate::transport_protocol::InvitationResponse, TransportProtocolError> {
//             let handle_invitation_result = self.handle_invitation_result.read().await;
//             match &*handle_invitation_result {
//                 Ok(value) => Ok(value.to_owned()),
//                 Err(error) => Err(TransportProtocolError::Failed(error.to_owned())),
//             }
//         }

//         async fn reject_proof(
//             &self,
//             _base_url: &str,
//             _proof_id: &str,
//         ) -> Result<(), TransportProtocolError> {
//             Err(TransportProtocolError::Failed("Error".to_owned()))
//         }

//         async fn submit_proof(
//             &self,
//             _base_url: &str,
//             _proof_id: &str,
//             _presentation: &str,
//         ) -> Result<(), TransportProtocolError> {
//             Err(TransportProtocolError::Failed("Error".to_owned()))
//         }
//     }

//     struct TestData {
//         pub one_core: OneCore,
//         pub tp: Arc<StubTransportProtocol>,

//         pub credential_id: String,

//         pub correct_url: String,
//         pub credential_response: ConnectIssuerResponse,
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
//         let stub_transport_protocol = Arc::new(StubTransportProtocol::default());
//         one_core.transport_protocols.push((
//             "StubTransportProtocol".to_string(),
//             stub_transport_protocol.clone(),
//         ));

//         let organisation_id = one_core
//             .data_layer
//             .create_organisation(CreateOrganisationRequest { id: None })
//             .await
//             .unwrap()
//             .id;

//         let holder_did_value = "HOLDER:DID".to_string();
//         let _holder_did_id = one_core
//             .data_layer
//             .create_did(CreateDidRequest {
//                 name: "holder".to_string(),
//                 organisation_id: organisation_id.to_owned(),
//                 did: holder_did_value.to_owned(),
//                 did_type: data_layer::data_model::DidType::Local,
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

//         let credential_id = Uuid::new_v4().to_string();
//         let credential = DetailCredentialResponse {
//             id: credential_id.to_owned(),
//             created_date: OffsetDateTime::now_utc(),
//             issuance_date: OffsetDateTime::now_utc(),
//             state: CredentialState::Pending,
//             last_modified: OffsetDateTime::now_utc(),
//             issuer_did: Some("ISSUER:DID".to_string()),
//             schema: ListCredentialSchemaResponse {
//                 id: credential_schema.id,
//                 created_date: OffsetDateTime::now_utc(),
//                 last_modified: OffsetDateTime::now_utc(),
//                 name: credential_schema.name,
//                 format: credential_schema.format,
//                 revocation_method: credential_schema.revocation_method,
//                 organisation_id,
//             },
//             claims: credential_schema
//                 .claims
//                 .into_iter()
//                 .map(|claim| DetailCredentialClaimResponse {
//                     schema: CredentialClaimSchemaResponse {
//                         id: claim.id,
//                         created_date: claim.created_date,
//                         last_modified: claim.last_modified,
//                         key: claim.key,
//                         datatype: claim.datatype,
//                     },
//                     value: "Test".to_string(),
//                 })
//                 .collect(),
//             credential: vec![],
//         };

//         let correct_url = format!("http://127.0.0.1/ssi/temporary-issuer/v1/connect?protocol=StubTransportProtocol&credential={credential_id}");

//         let jwt = one_core
//             .get_formatter("JWT")
//             .unwrap()
//             .format_credentials(&credential, &holder_did_value.to_string())
//             .unwrap();
//         let credential_response = ConnectIssuerResponse {
//             credential: jwt,
//             format: "JWT".to_string(),
//         };

//         TestData {
//             one_core,
//             tp: stub_transport_protocol,
//             credential_id,
//             correct_url,
//             credential_response,
//         }
//     }

//     #[tokio::test]
//     async fn test_fail_incorrect_query_params() {
//         let test_data = setup_test_data().await;

//         const THIS_IS_NOT_AN_URL: &str = "I love pizza";
//         assert!(test_data
//             .one_core
//             .handle_invitation(THIS_IS_NOT_AN_URL)
//             .await
//             .is_err());

//         const NO_QUERY_PARAMS: &str = "http://127.0.0.1/404_query_params_not_found";
//         assert!(test_data
//             .one_core
//             .handle_invitation(NO_QUERY_PARAMS)
//             .await
//             .is_err());

//         const CREDENTIAL_IS_NOT_UUID: &str = "http://127.0.0.1/ssi/temporary-issuer/v1/connect?protocol=ProcivisTemporary&credential=CREDENTIAL_NOT_UUID";
//         assert!(test_data
//             .one_core
//             .handle_invitation(CREDENTIAL_IS_NOT_UUID)
//             .await
//             .is_err());
//     }

//     #[tokio::test]
//     async fn test_fail_transport_protocol_failures() {
//         let test_data = setup_test_data().await;

//         test_data
//             .tp
//             .set_handle_invitation_result(Err("This test should fail".to_string()))
//             .await;
//         let response_is_error = test_data
//             .one_core
//             .handle_invitation(&test_data.correct_url)
//             .await;
//         assert!(response_is_error.is_err_and(|e| matches!(
//             e,
//             OneCoreError::SSIError(SSIError::TransportProtocolError(_))
//         )));

//         test_data
//             .tp
//             .set_handle_invitation_result(Ok(
//                 crate::transport_protocol::InvitationResponse::Credential(ConnectIssuerResponse {
//                     credential: "".to_string(),
//                     format: "".to_string(),
//                 }),
//             ))
//             .await;
//         let transport_success_but_format_is_wrong = test_data
//             .one_core
//             .handle_invitation(&test_data.correct_url)
//             .await;
//         assert!(
//             transport_success_but_format_is_wrong.is_err_and(|e| matches!(
//                 e,
//                 OneCoreError::SSIError(SSIError::UnsupportedCredentialFormat)
//             ))
//         );

//         test_data
//             .tp
//             .set_handle_invitation_result(Ok(
//                 crate::transport_protocol::InvitationResponse::Credential(ConnectIssuerResponse {
//                     credential: "".to_string(),
//                     format: "JWT".to_string(),
//                 }),
//             ))
//             .await;
//         let transport_success_but_credential_is_wrong = test_data
//             .one_core
//             .handle_invitation(&test_data.correct_url)
//             .await;
//         assert!(transport_success_but_credential_is_wrong
//             .is_err_and(|e| matches!(e, OneCoreError::FormatterError(_))));
//     }

//     #[tokio::test]
//     async fn test_success_credential_issuance() {
//         let test_data = setup_test_data().await;

//         test_data
//             .tp
//             .set_handle_invitation_result(Ok(
//                 crate::transport_protocol::InvitationResponse::Credential(
//                     test_data.credential_response,
//                 ),
//             ))
//             .await;

//         let result = test_data
//             .one_core
//             .handle_invitation(&test_data.correct_url)
//             .await;
//         assert!(result.is_ok());
//         match result.unwrap() {
//             super::InvitationResponse::Credential {
//                 issued_credential_id,
//             } => {
//                 assert_eq!(&test_data.credential_id, &issued_credential_id);
//             }
//             super::InvitationResponse::ProofRequest { .. } => {
//                 unreachable!();
//             }
//         };

//         let credential_after = test_data
//             .one_core
//             .data_layer
//             .get_credential_details(&test_data.credential_id)
//             .await
//             .unwrap();
//         assert_eq!(CredentialState::Accepted, credential_after.state);
//     }

//     #[tokio::test]
//     async fn test_success_proof_request() {
//         let test_data = setup_test_data().await;

//         test_data
//             .tp
//             .set_handle_invitation_result(Ok(
//                 crate::transport_protocol::InvitationResponse::Proof {
//                     proof_id: "id".to_string(),
//                     proof_request: ConnectVerifierResponse {
//                         claims: vec![ProofClaimSchema {
//                             id: "id".to_string(),
//                             created_date: OffsetDateTime::now_utc(),
//                             last_modified: OffsetDateTime::now_utc(),
//                             key: "key".to_string(),
//                             datatype: "STRING".to_string(),
//                             required: true,
//                             credential_schema: ListCredentialSchemaResponse {
//                                 id: "schema-id".to_string(),
//                                 created_date: OffsetDateTime::now_utc(),
//                                 last_modified: OffsetDateTime::now_utc(),
//                                 name: "name".to_string(),
//                                 format: Format::Jwt,
//                                 revocation_method: RevocationMethod::None,
//                                 organisation_id: "organisation-id".to_string(),
//                             },
//                         }],
//                     },
//                 },
//             ))
//             .await;

//         let result = test_data
//             .one_core
//             .handle_invitation(&test_data.correct_url)
//             .await;
//         assert!(result.is_ok());
//         match result.unwrap() {
//             super::InvitationResponse::Credential { .. } => {
//                 unreachable!();
//             }
//             super::InvitationResponse::ProofRequest { proof_request, .. } => {
//                 assert_eq!(1, proof_request.claims.len());
//                 assert_eq!("id", proof_request.claims[0].id);
//                 assert_eq!("key", proof_request.claims[0].key);
//             }
//         };
//     }
// }
