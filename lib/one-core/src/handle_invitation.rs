use axum::extract::Query;
use axum::http::Uri;
use std::str::FromStr;
use uuid::Uuid;

use crate::credential_formatter::ParseError;
use crate::data_layer::data_model::{
    CreateCredentialRequest, CreateCredentialRequestClaim, Transport,
};
use crate::error::SSIError;
use crate::transport_protocol::TransportProtocolError;
use crate::{
    credential_formatter,
    credential_formatter::jwt_formatter::{
        VCCredentialClaimSchemaResponse, VCCredentialSchemaResponse,
    },
    data_layer::{
        data_model::{
            CreateCredentialSchemaFromJwtRequest, CreateDidRequest,
            CredentialClaimSchemaFromJwtRequest, Datatype, DidMethod, DidType, Format,
            GetDidDetailsResponse, RevocationMethod,
        },
        entities::credential_state::CredentialState,
        get_dids::GetDidQuery,
        DataLayer, DataLayerError,
    },
    data_model::HandleInvitationQueryRequest,
    error::OneCoreError,
    OneCore,
};

fn parse_query(url: &str) -> Result<HandleInvitationQueryRequest, OneCoreError> {
    let uri =
        Uri::from_str(url).map_err(|_| OneCoreError::SSIError(SSIError::IncorrectParameters))?;
    let result: Query<HandleInvitationQueryRequest> = Query::try_from_uri(&uri)
        .map_err(|e| OneCoreError::SSIError(SSIError::QueryRejection(e)))?;
    Ok(result.0)
}

async fn get_first_organisation_id(data_layer: &DataLayer) -> Result<String, OneCoreError> {
    let organisations = data_layer
        .get_organisations()
        .await
        .map_err(OneCoreError::DataLayerError)?;
    Ok(organisations
        .first()
        .ok_or(OneCoreError::DataLayerError(DataLayerError::RecordNotFound))?
        .id
        .to_owned())
}

async fn get_first_did(
    data_layer: &DataLayer,
    organisation_id: &str,
) -> Result<GetDidDetailsResponse, OneCoreError> {
    let dids = data_layer
        .get_dids(GetDidQuery {
            page: 0,
            page_size: 1,
            sort: None,
            sort_direction: None,
            name: None,
            organisation_id: organisation_id.to_string(),
        })
        .await
        .map_err(OneCoreError::DataLayerError)?;
    Ok(dids
        .values
        .first()
        .ok_or(OneCoreError::DataLayerError(DataLayerError::RecordNotFound))?
        .to_owned())
}

fn string_to_uuid(value: &str) -> Result<Uuid, OneCoreError> {
    Uuid::from_str(value).map_err(|e| {
        OneCoreError::SSIError(SSIError::ParseError(ParseError::Failed(e.to_string())))
    })
}

impl FromStr for Datatype {
    type Err = OneCoreError;

    fn from_str(s: &str) -> Result<Self, OneCoreError> {
        match s {
            "STRING" => Ok(Datatype::String),
            "DATE" => Ok(Datatype::Date),
            "NUMBER" => Ok(Datatype::Number),
            _ => Err(OneCoreError::SSIError(SSIError::IncorrectParameters)),
        }
    }
}

fn credential_claim_schema_request_from_jwt(
    claim: &VCCredentialClaimSchemaResponse,
) -> Result<CredentialClaimSchemaFromJwtRequest, OneCoreError> {
    Ok(CredentialClaimSchemaFromJwtRequest {
        id: string_to_uuid(&claim.id)?,
        key: claim.key.to_owned(),
        datatype: Datatype::from_str(&claim.datatype)?,
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
        format: Format::Jwt,
        revocation_method: RevocationMethod::None,
        organisation_id: string_to_uuid(organisation_id)?,
        claims: claims?,
    })
}

impl OneCore {
    pub async fn handle_invitation(&self, url: &str) -> Result<String, OneCoreError> {
        let url_query_params = parse_query(url)?;
        let credential_id = url_query_params.credential.to_string();

        // FIXME - these two should be fetched correctly
        let organisation_id = get_first_organisation_id(&self.data_layer).await?;
        let holder_did = get_first_did(&self.data_layer, &organisation_id).await?;

        let connect_response = self
            .get_transport_protocol(&url_query_params.protocol)?
            .handle_invitation(url, &holder_did.did)
            .await
            .map_err(|e| OneCoreError::SSIError(SSIError::TransportProtocolError(e)))?;

        if connect_response.format != "JWT" {
            return Err(OneCoreError::SSIError(
                SSIError::UnsupportedCredentialFormat,
            ));
        }

        let jwt = connect_response.credential;
        let jwt_claims = credential_formatter::jwt_formatter::from_jwt(&jwt)
            .map_err(|e| OneCoreError::SSIError(SSIError::ParseError(e)))?;

        // check headers
        let issuer_did_value =
            jwt_claims
                .issuer
                .ok_or(OneCoreError::SSIError(SSIError::ParseError(
                    ParseError::Failed("IssuerDid missing".to_owned()),
                )))?;

        if let Some(jwt_credential_id) = jwt_claims.jwt_id {
            if jwt_credential_id != credential_id {
                return Err(OneCoreError::SSIError(SSIError::TransportProtocolError(
                    TransportProtocolError::Failed("Credential ID mismatch".to_owned()),
                )));
            }
        } else {
            return Err(OneCoreError::SSIError(SSIError::ParseError(
                ParseError::Failed("Credential ID missing".to_owned()),
            )));
        }

        if let Some(jwt_holder_did) = jwt_claims.subject {
            if jwt_holder_did != holder_did.did {
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
        let schema = jwt_claims
            .custom
            .vc
            .credential_subject
            .one_credential_schema;

        let credential_schema_id = schema.id.to_owned();

        let credential_schema_request =
            create_credential_schema_request_from_jwt(schema, &organisation_id)?;
        let result = self
            .data_layer
            .create_credential_schema_from_jwt(credential_schema_request.clone())
            .await;
        if let Err(error) = result {
            if error != DataLayerError::AlreadyExists {
                return Err(OneCoreError::DataLayerError(error));
            }
        }

        // insert issuer did if not yet known
        let did_insert_result = self
            .data_layer
            .create_did(CreateDidRequest {
                name: "NEW_DID_FIXME".to_string(),
                organisation_id: organisation_id.to_owned(),
                did: issuer_did_value.to_owned(),
                did_type: DidType::Remote,
                method: DidMethod::Key,
            })
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
        let incoming_claims = jwt_claims.custom.vc.credential_subject.values;
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
            .create_credential(CreateCredentialRequest {
                credential_id: Some(credential_id.to_owned()),
                credential_schema_id: string_to_uuid(&credential_schema_id)?,
                issuer_did: string_to_uuid(&issuer_did_id)?,
                transport: Transport::ProcivisTemporary,
                claim_values: claim_values?,
                receiver_did_id: Some(string_to_uuid(&holder_did.id)?),
                credential: Some(jwt.bytes().collect()),
            })
            .await
            .map_err(OneCoreError::DataLayerError)?;

        self.data_layer
            .set_credential_state(&credential_id, CredentialState::Accepted)
            .await
            .map_err(OneCoreError::DataLayerError)?;

        Ok(credential_id)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        config::data_structure::{ConfigKind, UnparsedConfig},
        data_layer::data_model::{
            CreateCredentialSchemaRequest, CreateDidRequest, CreateOrganisationRequest,
            CredentialClaimSchemaRequest, CredentialClaimSchemaResponse, CredentialState,
            DetailCredentialClaimResponse, Format, ListCredentialSchemaResponse, RevocationMethod,
        },
        data_layer::{self, data_model::DetailCredentialResponse},
        data_model::ConnectIssuerResponse,
        error::{OneCoreError, SSIError},
        transport_protocol::{TransportProtocol, TransportProtocolError},
        OneCore,
    };

    use async_trait::async_trait;
    use std::str::FromStr;
    use std::sync::Arc;
    use time::OffsetDateTime;
    use tokio::sync::RwLock;
    use uuid::Uuid;

    pub struct StubTransportProtocol {
        handle_invitation_result: Arc<RwLock<Result<ConnectIssuerResponse, String>>>,
    }

    impl Default for StubTransportProtocol {
        fn default() -> Self {
            Self {
                handle_invitation_result: Arc::new(RwLock::new(Err("Uninitialized".to_string()))),
            }
        }
    }

    impl StubTransportProtocol {
        async fn set_handle_invitation_result(&self, value: Result<ConnectIssuerResponse, String>) {
            let mut handle_invitation_result = self.handle_invitation_result.write().await;
            *handle_invitation_result = value;
        }
    }

    #[async_trait]
    impl TransportProtocol for StubTransportProtocol {
        async fn handle_invitation(
            &self,
            _url: &str,
            _own_did: &str,
        ) -> Result<ConnectIssuerResponse, TransportProtocolError> {
            let handle_invitation_result = self.handle_invitation_result.read().await;
            match &*handle_invitation_result {
                Ok(value) => Ok(value.to_owned()),
                Err(error) => Err(TransportProtocolError::Failed(error.to_owned())),
            }
        }

        fn send(&self, _input: &str) -> Result<(), TransportProtocolError> {
            Ok(())
        }
        fn handle_message(&self, _message: &str) -> Result<(), TransportProtocolError> {
            Ok(())
        }
    }

    struct TestData {
        pub one_core: OneCore,
        pub tp: Arc<StubTransportProtocol>,

        pub credential_id: String,

        pub correct_url: String,
        pub correct_response: ConnectIssuerResponse,
    }

    async fn setup_test_data() -> TestData {
        let minimal_config = r#"{
          "format": {},
          "exchange": {},
          "did": {},
          "datatype": {}
        }
        "#
        .to_string();

        let unparsed_config = UnparsedConfig {
            content: minimal_config,
            kind: ConfigKind::Json,
        };
        let mut one_core = OneCore::new("sqlite::memory:", unparsed_config)
            .await
            .unwrap();
        let stub_transport_protocol = Arc::new(StubTransportProtocol::default());
        one_core.transport_protocols.push((
            "StubTransportProtocol".to_string(),
            stub_transport_protocol.clone(),
        ));

        let organisation_id = one_core
            .data_layer
            .create_organisation(CreateOrganisationRequest { id: None })
            .await
            .unwrap()
            .id;

        let holder_did_value = "HOLDER:DID".to_string();
        let _holder_did_id = one_core
            .data_layer
            .create_did(CreateDidRequest {
                name: "holder".to_string(),
                organisation_id: organisation_id.to_owned(),
                did: holder_did_value.to_owned(),
                did_type: Default::default(),
                method: Default::default(),
            })
            .await
            .unwrap()
            .id;

        let credential_schema_id = one_core
            .data_layer
            .create_credential_schema(CreateCredentialSchemaRequest {
                name: "CREDENTIAL_SCHEMA".to_string(),
                format: Format::Jwt,
                revocation_method: RevocationMethod::None,
                organisation_id: Uuid::from_str(&organisation_id).unwrap(),
                claims: vec![CredentialClaimSchemaRequest {
                    key: "Something".to_string(),
                    datatype: data_layer::data_model::Datatype::String,
                }],
            })
            .await
            .unwrap()
            .id;

        let credential_schema = one_core
            .data_layer
            .get_credential_schema_details(&credential_schema_id)
            .await
            .unwrap();

        let credential_id = Uuid::new_v4().to_string();
        let credential = DetailCredentialResponse {
            id: credential_id.to_owned(),
            created_date: OffsetDateTime::now_utc(),
            issuance_date: OffsetDateTime::now_utc(),
            state: CredentialState::Pending,
            last_modified: OffsetDateTime::now_utc(),
            issuer_did: Some("ISSUER:DID".to_string()),
            schema: ListCredentialSchemaResponse {
                id: credential_schema.id,
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                name: credential_schema.name,
                format: credential_schema.format,
                revocation_method: credential_schema.revocation_method,
                organisation_id,
            },
            claims: credential_schema
                .claims
                .into_iter()
                .map(|claim| DetailCredentialClaimResponse {
                    schema: CredentialClaimSchemaResponse {
                        id: claim.id,
                        created_date: claim.created_date,
                        last_modified: claim.last_modified,
                        key: claim.key,
                        datatype: claim.datatype,
                    },
                    value: "Test".to_string(),
                })
                .collect(),
        };

        let correct_url = format!("http://127.0.0.1/ssi/temporary-issuer/v1/connect?protocol=StubTransportProtocol&credential={credential_id}");

        let jwt = one_core
            .get_formatter("JWT")
            .unwrap()
            .format(&credential, &holder_did_value.to_string())
            .unwrap();
        let correct_response = ConnectIssuerResponse {
            credential: jwt,
            format: "JWT".to_string(),
        };

        TestData {
            one_core,
            tp: stub_transport_protocol,
            credential_id,
            correct_url,
            correct_response,
        }
    }

    #[tokio::test]
    async fn test_fail_incorrect_query_params() {
        let test_data = setup_test_data().await;

        const THIS_IS_NOT_AN_URL: &str = "I love pizza";
        assert!(test_data
            .one_core
            .handle_invitation(THIS_IS_NOT_AN_URL)
            .await
            .is_err());

        const NO_QUERY_PARAMS: &str = "http://127.0.0.1/404_query_params_not_found";
        assert!(test_data
            .one_core
            .handle_invitation(NO_QUERY_PARAMS)
            .await
            .is_err());

        const CREDENTIAL_IS_NOT_UUID: &str = "http://127.0.0.1/ssi/temporary-issuer/v1/connect?protocol=ProcivisTemporary&credential=CREDENTIAL_NOT_UUID";
        assert!(test_data
            .one_core
            .handle_invitation(CREDENTIAL_IS_NOT_UUID)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_fail_transport_protocol_failures() {
        let test_data = setup_test_data().await;

        test_data
            .tp
            .set_handle_invitation_result(Err("This test should fail".to_string()))
            .await;
        let response_is_error = test_data
            .one_core
            .handle_invitation(&test_data.correct_url)
            .await;
        assert!(response_is_error.is_err_and(|e| matches!(
            e,
            OneCoreError::SSIError(SSIError::TransportProtocolError(_))
        )));

        test_data
            .tp
            .set_handle_invitation_result(Ok(ConnectIssuerResponse {
                credential: "".to_string(),
                format: "".to_string(),
            }))
            .await;
        let transport_success_but_format_is_wrong = test_data
            .one_core
            .handle_invitation(&test_data.correct_url)
            .await;
        assert!(
            transport_success_but_format_is_wrong.is_err_and(|e| matches!(
                e,
                OneCoreError::SSIError(SSIError::UnsupportedCredentialFormat)
            ))
        );

        test_data
            .tp
            .set_handle_invitation_result(Ok(ConnectIssuerResponse {
                credential: "".to_string(),
                format: "JWT".to_string(),
            }))
            .await;
        let transport_success_but_credential_is_wrong = test_data
            .one_core
            .handle_invitation(&test_data.correct_url)
            .await;
        assert!(transport_success_but_credential_is_wrong
            .is_err_and(|e| matches!(e, OneCoreError::SSIError(SSIError::ParseError(_)))));
    }

    #[tokio::test]
    async fn test_success() {
        let test_data = setup_test_data().await;

        test_data
            .tp
            .set_handle_invitation_result(Ok(test_data.correct_response))
            .await;

        let result = test_data
            .one_core
            .handle_invitation(&test_data.correct_url)
            .await;
        assert!(result.is_ok());

        assert_eq!(&test_data.credential_id, &result.unwrap());
        let credential_after = test_data
            .one_core
            .data_layer
            .get_credential_details(&test_data.credential_id)
            .await
            .unwrap();
        assert_eq!(CredentialState::Accepted, credential_after.state);
    }
}
