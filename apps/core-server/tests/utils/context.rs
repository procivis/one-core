use std::ops::Add;
use std::str::FromStr;

use core_server::ServerConfig;
use one_core::config::core_config::AppConfig;
use one_core::model::certificate::{Certificate, CertificateState};
use one_core::model::did::{Did, DidType, KeyRole, RelatedKey};
use one_core::model::identifier::{Identifier, IdentifierType};
use one_core::model::key::Key;
use one_core::model::organisation::Organisation;
use rcgen::CertificateParams;
use shared_types::DidValue;
use time::{Duration, OffsetDateTime};
use tokio::task::JoinHandle;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use uuid::Uuid;

use super::api_clients::Client;
use super::db_clients::DbClient;
use super::db_clients::keys::ecdsa_testing_params;
use super::mock_server::MockServer;
use super::server::run_server;
use crate::fixtures::certificate::{create_ca_cert, create_cert, ecdsa, eddsa};
use crate::fixtures::{self, TestingConfigParams, TestingDidParams, TestingIdentifierParams};
use crate::utils::db_clients::certificates::TestingCertificateParams;

pub struct TestContext {
    pub db: DbClient,
    pub api: Client,
    pub server_mock: MockServer,
    pub config: AppConfig<ServerConfig>,
    handle: JoinHandle<()>,
}

impl Drop for TestContext {
    fn drop(&mut self) {
        self.handle.abort()
    }
}

impl TestContext {
    pub async fn new(additional_config: Option<String>) -> Self {
        Self::new_with_token("test", additional_config).await
    }

    pub async fn new_with_token(token: &str, additional_config: Option<String>) -> Self {
        let server_mock = MockServer::new().await;
        let stdout_log = tracing_subscriber::fmt::layer().with_test_writer();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());

        let config = fixtures::create_config(
            &base_url,
            Some(TestingConfigParams {
                mock_url: Some(server_mock.uri()),
                additional_config,
            }),
        );
        let db = fixtures::create_db(&config).await;
        let handle = run_server(listener, config.to_owned(), &db).await;

        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .or_else(|_| {
                tracing_subscriber::EnvFilter::try_new(
                    config
                        .app
                        .trace_level
                        .as_ref()
                        .unwrap_or(&"debug".to_string()),
                )
            })
            .expect("Failed to create env filter");
        // no point logging failure of initializing the tracing subscriber
        #[allow(unused_must_use)]
        tracing_subscriber::registry()
            .with(stdout_log)
            .with(filter)
            .try_init();

        Self {
            db: DbClient::new(db),
            api: Client::new(base_url.clone(), token.into()),
            server_mock,
            config,
            handle,
        }
    }

    pub async fn new_with_organisation(additional_config: Option<String>) -> (Self, Organisation) {
        let context = Self::new(additional_config).await;
        let organisation = context.db.organisations.create().await;
        (context, organisation)
    }

    pub async fn new_with_did(
        additional_config: Option<String>,
    ) -> (Self, Organisation, Did, Identifier, Key) {
        let (context, organisation) = Self::new_with_organisation(additional_config).await;
        let key = context
            .db
            .keys
            .create(&organisation, ecdsa_testing_params())
            .await;
        let did = context
            .db
            .dids
            .create(
                Some(organisation.clone()),
                TestingDidParams {
                    keys: Some(vec![
                        RelatedKey {
                            role: KeyRole::AssertionMethod,
                            key: key.to_owned(),
                            reference: "1".to_string(),
                        },
                        RelatedKey {
                            role: KeyRole::Authentication,
                            key: key.to_owned(),
                            reference: "1".to_string(),
                        },
                        RelatedKey {
                            role: KeyRole::KeyAgreement,
                            key: key.to_owned(),
                            reference: "1".to_string(),
                        },
                    ]),
                    did: Some(
                        DidValue::from_str(
                            "did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ",
                        )
                        .unwrap(),
                    ),
                    ..Default::default()
                },
            )
            .await;

        let identifier = context
            .db
            .identifiers
            .create(
                &organisation,
                TestingIdentifierParams {
                    did: Some(did.clone()),
                    r#type: Some(IdentifierType::Did),
                    is_remote: Some(did.did_type == DidType::Remote),
                    ..Default::default()
                },
            )
            .await;

        (context, organisation, did, identifier, key)
    }

    pub async fn new_with_certificate_identifier(
        additional_config: Option<String>,
    ) -> (Self, Organisation, Identifier, Certificate, Key) {
        let (context, organisation) = Self::new_with_organisation(additional_config).await;
        let key = context
            .db
            .keys
            .create(&organisation, ecdsa_testing_params())
            .await;
        let ca_cert = create_ca_cert(CertificateParams::default(), eddsa::key());
        let cert = create_cert(
            CertificateParams::default(),
            ecdsa::key(),
            &ca_cert,
            eddsa::key(),
        );

        let identifier_id = Uuid::new_v4().into();
        let now = OffsetDateTime::now_utc();
        let certificate = Certificate {
            id: Uuid::new_v4().into(),
            identifier_id,
            organisation_id: Some(organisation.id),
            created_date: now,
            last_modified: now,
            expiry_date: now.add(Duration::minutes(10)),
            name: "test cert".to_string(),
            chain: format!("{}{}", cert.pem(), ca_cert.pem()),
            fingerprint: "fingerprint".to_string(),
            state: CertificateState::Active,
            key: Some(key.clone()),
        };

        let identifier = context
            .db
            .identifiers
            .create(
                &organisation,
                TestingIdentifierParams {
                    r#type: Some(IdentifierType::Certificate),
                    certificates: Some(vec![certificate.clone()]),
                    ..Default::default()
                },
            )
            .await;

        let certificate = context
            .db
            .certificates
            .create(identifier.id, TestingCertificateParams::from(certificate))
            .await;
        (context, organisation, identifier, certificate, key)
    }
}
