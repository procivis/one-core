use std::fmt::Display;

use serde_json::json;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

pub struct MockServer {
    mock: wiremock::MockServer,
}

impl MockServer {
    pub async fn new() -> Self {
        let mock = wiremock::MockServer::start().await;
        Self { mock }
    }

    pub fn uri(&self) -> String {
        self.mock.uri()
    }

    pub async fn ssi_reject(&self) {
        Mock::given(method(Method::POST))
            .and(path("/ssi/temporary-issuer/v1/reject"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&self.mock)
            .await;
    }

    pub async fn ssi_issuance(&self, protocol: &str, credential_id: impl Display) {
        Mock::given(method(Method::POST))
            .and(path("/ssi/temporary-issuer/v1/connect"))
            .and(query_param("protocol", protocol))
            .and(query_param("credential", credential_id.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!(
                {
                    "claims": [
                        {
                            "schema": {
                                "createdDate": "2023-11-08T15:46:14.997Z",
                                "datatype": "STRING",
                                "id": "48db4654-01c4-4a43-9df4-300f1f425c40",
                                "key": "field",
                                "lastModified": "2023-11-08T15:46:14.997Z",
                                "required": true
                            },
                            "value": "aae"
                        }
                    ],
                    "createdDate": "2023-11-09T08:39:16.459Z",
                    "id": credential_id.to_string(),
                    "issuanceDate": "2023-11-09T08:39:16.459Z",
                    "issuerDid": {
                        "id": "48db4654-01c4-4a43-9df4-300f1f425c40",
                        "createdDate": "2023-11-09T08:39:16.460Z",
                        "lastModified": "2023-11-09T08:39:16.459Z",
                        "name": "foo",
                        "did": "did:key:z6Mkm1qx9JYefnqDVyyUBovf4Jo97jDxVzPejTeStyrNzyqU",
                        "type": "REMOTE",
                        "method": "KEY",
                        "deactivated": false,
                    },
                    "lastModified": "2023-11-09T08:39:16.548Z",
                    "revocationDate": null,
                    "schema": {
                        "createdDate": "2023-11-08T15:46:14.997Z",
                        "format": "SDJWT",
                        "id": "293d1376-62ea-4b0e-8c16-2dfe4f7ac0bd",
                        "lastModified": "2023-11-08T15:46:14.997Z",
                        "name": "detox-e2e-revocable-12a4212d-9b28-4bb0-9640-23c938f8a8b1",
                        "organisationId": "2476ebaa-0108-413d-aa72-c2a6babd423f",
                        "revocationMethod": "BITSTRINGSTATUSLIST"
                    },
                    "state": "PENDING",
                    "role": "ISSUER",
                }
            )))
            .mount(&self.mock)
            .await;
    }

    pub async fn universal_resolving(&self, did: &str, document: serde_json::Value) {
        Mock::given(method(Method::GET))
            .and(path(format!("/1.0/identifiers/{did}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "didDocument": document,
            })))
            .expect(1)
            .mount(&self.mock)
            .await;
    }

    pub async fn fail_universal_resolving(&self, did: &str) {
        Mock::given(method(Method::GET))
            .and(path(format!("/1.0/identifiers/{did}")))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&self.mock)
            .await;
    }

    pub async fn json_ld_context(&self, schema_id: &Uuid, schema_name_pascal: &str) {
        Mock::given(method(Method::GET))
            .and(path(format!("/ssi/context/v1/{schema_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!(
                {
                    "@context": {
                        "@version": 1.1,
                        "@protected": true,
                        "id": "@id",
                        "type": "@type",
                        format!("{schema_name_pascal}Credential"): {
                            "@id": format!("{}/ssi/context/v1/{schema_id}#{schema_name_pascal}Credential", self.mock.uri()),
                            "@context": {
                                "@version": 1.1,
                                "@protected": true,
                                "id": "@id",
                                "type": "@type"
                            }
                        },
                        format!("{schema_name_pascal}Subject"): {
                            "@id": format!("{}/ssi/context/v1/{schema_id}#{schema_name_pascal}Subject", self.mock.uri()),
                            "@context": {
                                "@version": 1.1,
                                "@protected": true,
                                "id": "@id",
                                "type": "@type",
                                "Key": format!("{}/ssi/context/v1/{schema_id}#Key", self.mock.uri()),
                                "Name": format!("{}/ssi/context/v1/{schema_id}#Name", self.mock.uri()),
                                "Address": format!("{}/ssi/context/v1/{schema_id}#Address", self.mock.uri())
                            }
                        }
                    }
                }
            )))
            .mount(&self.mock)
            .await;
    }
}
