use axum::extract::Query;
use axum::http::Uri;
use std::str::FromStr;
use uuid::Uuid;

use crate::error::SSIError;
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
    Uuid::from_str(value).map_err(|_| OneCoreError::DataLayerError(DataLayerError::Other))
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
    pub async fn handle_invitation(&self, url: &str) -> Result<(), OneCoreError> {
        let url_query_params = parse_query(url)?;
        let credential_id = url_query_params.credential.to_string();

        // FIXME - these two should be fetched correctly
        let organisation_id = get_first_organisation_id(&self.data_layer).await?;
        let did = get_first_did(&self.data_layer, &organisation_id).await?;

        let connect_response = self
            .get_transport_protocol(&url_query_params.protocol)?
            .handle_invitation(url, &did.did)
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

        let schema = jwt_claims
            .custom
            .vc
            .credential_subject
            .one_credential_schema;

        const ISSUER_DID_VALUE: &str = "ISSUER:DID";
        let did_insert_result = self
            .data_layer
            .create_did(CreateDidRequest {
                name: "NEW_DID_FIXME".to_string(),
                organisation_id: organisation_id.to_owned(),
                did: ISSUER_DID_VALUE.to_string(),
                did_type: DidType::Remote,
                did_method: DidMethod::Web,
            })
            .await;

        match did_insert_result {
            Ok(did) => self
                .data_layer
                .update_credential_issuer_did(&credential_id.to_string(), &did.id)
                .await
                .map_err(OneCoreError::DataLayerError)?,
            Err(DataLayerError::AlreadyExists) => {
                let did = self
                    .data_layer
                    .get_did_details_by_value(ISSUER_DID_VALUE)
                    .await
                    .map_err(OneCoreError::DataLayerError)?;
                self.data_layer
                    .update_credential_issuer_did(&credential_id.to_string(), &did.id)
                    .await
                    .map_err(OneCoreError::DataLayerError)?
            }
            Err(e) => return Err(OneCoreError::DataLayerError(e)),
        }

        let credential_schema_id = schema.id.to_owned();

        let request = create_credential_schema_request_from_jwt(schema, &organisation_id)?;
        let result = self
            .data_layer
            .create_credential_schema_from_jwt(request)
            .await;
        if let Err(error) = result {
            if error != DataLayerError::AlreadyExists {
                return Err(OneCoreError::DataLayerError(error));
            }
        }

        self.data_layer
            .update_credential_schema_id(&credential_id, &credential_schema_id)
            .await
            .map_err(OneCoreError::DataLayerError)?;

        self.data_layer
            .set_credential_state(&credential_id, CredentialState::Accepted)
            .await
            .map_err(OneCoreError::DataLayerError)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        data_layer,
        data_layer::data_model::{
            CreateCredentialRequest, CreateCredentialRequestClaim, CreateCredentialSchemaRequest,
            CreateDidRequest, CreateOrganisationRequest, CredentialClaimSchemaRequest,
            CredentialState, Format, RevocationMethod, Transport,
        },
        data_model::ConnectIssuerResponse,
        error::{OneCoreError, SSIError},
        transport_protocol::{TransportProtocol, TransportProtocolError},
        OneCore,
    };

    use async_trait::async_trait;
    use std::str::FromStr;
    use std::sync::Arc;
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
        let mut one_core = OneCore::new("sqlite::memory:").await;
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
        let did_id = one_core
            .data_layer
            .create_did(CreateDidRequest {
                name: "bla".to_string(),
                organisation_id: organisation_id.to_owned(),
                did: "RECEIVER:DID".to_string(),
                did_type: Default::default(),
                did_method: Default::default(),
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

        let credential_id = one_core
            .data_layer
            .create_credential(CreateCredentialRequest {
                credential_schema_id: Uuid::from_str(&credential_schema_id).unwrap(),
                issuer_did: Uuid::from_str(&did_id).unwrap(),
                transport: Transport::ProcivisTemporary,
                claim_values: vec![CreateCredentialRequestClaim {
                    claim_id: Uuid::from_str(&credential_schema.claims[0].id).unwrap(),
                    value: "Test".to_string(),
                }],
            })
            .await
            .unwrap()
            .id;
        let credential = one_core
            .data_layer
            .get_credential_details(&credential_id)
            .await
            .unwrap();

        let _ = one_core
            .data_layer
            .share_credential(&credential_id)
            .await
            .unwrap();

        let correct_url = format!("http://127.0.0.1/ssi/temporary-issuer/v1/connect?protocol=StubTransportProtocol&credential={credential_id}");

        let holder_did = Uuid::new_v4();
        let jwt = one_core
            .get_formatter("JWT")
            .unwrap()
            .format(&credential, &holder_did.to_string())
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

        let credential_before = test_data
            .one_core
            .data_layer
            .get_credential_details(&test_data.credential_id)
            .await
            .unwrap();
        assert_eq!(CredentialState::Offered, credential_before.state);

        let success = test_data
            .one_core
            .handle_invitation(&test_data.correct_url)
            .await;
        assert!(success.is_ok());

        let credential_after = test_data
            .one_core
            .data_layer
            .get_credential_details(&test_data.credential_id)
            .await
            .unwrap();
        assert_eq!(CredentialState::Accepted, credential_after.state);
    }
}
