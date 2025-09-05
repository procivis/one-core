use std::collections::HashMap;
use std::sync::Arc;

use core_server::ServerConfig;
use indexmap::IndexMap;
use indoc::indoc;
use one_core::config::core_config::{AppConfig, DatatypeConfig, InputFormat, KeyAlgorithmType};
use one_core::model::certificate::{Certificate, CertificateState};
use one_core::provider::caching_loader::android_attestation_crl::{
    AndroidAttestationCrlCache, AndroidAttestationCrlResolver,
};
use one_core::provider::caching_loader::x509_crl::{X509CrlCache, X509CrlResolver};
use one_core::provider::credential_formatter::CredentialFormatter;
use one_core::provider::credential_formatter::mdoc_formatter::{MdocFormatter, Params};
use one_core::provider::credential_formatter::model::CredentialData;
use one_core::provider::did_method::DidMethod;
use one_core::provider::did_method::jwk::JWKDidMethod;
use one_core::provider::did_method::key::KeyDidMethod;
use one_core::provider::did_method::provider::DidMethodProviderImpl;
use one_core::provider::did_method::resolver::DidCachingLoader;
use one_core::provider::http_client::reqwest_client::ReqwestClient;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use one_core::provider::key_algorithm::eddsa::Eddsa;
use one_core::provider::key_algorithm::provider::KeyAlgorithmProviderImpl;
use one_core::provider::remote_entity_storage::RemoteEntityType;
use one_core::provider::remote_entity_storage::in_memory::InMemoryStorage;
use one_core::service::certificate::validator::CertificateValidatorImpl;
use one_core::util::clock::DefaultClock;
use rcgen::CertificateParams;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::fixtures::certificate::{create_ca_cert, create_cert, ecdsa, eddsa};

pub(crate) async fn format_mdoc_credential(
    mut credential_data: CredentialData,
    params: Params,
) -> String {
    let did_cache = DidCachingLoader::new(
        RemoteEntityType::DidDocument,
        Arc::new(InMemoryStorage::new(HashMap::new())),
        100,
        Duration::minutes(1),
        Duration::minutes(1),
    );
    let crl_cache = Arc::new(X509CrlCache::new(
        Arc::new(X509CrlResolver::new(Arc::new(ReqwestClient::default()))),
        Arc::new(InMemoryStorage::new(HashMap::new())),
        100,
        Duration::minutes(1),
        Duration::minutes(1),
    ));
    let android_key_attestation_crl_cache = Arc::new(AndroidAttestationCrlCache::new(
        Arc::new(AndroidAttestationCrlResolver::new(Arc::new(
            ReqwestClient::default(),
        ))),
        Arc::new(InMemoryStorage::new(HashMap::new())),
        1,
        Duration::days(1),
        Duration::days(1),
    ));

    let key_alg_eddsa = Eddsa;
    let key_alg_ecdsa = Ecdsa;
    let key_algorithm_provider = Arc::new(KeyAlgorithmProviderImpl::new(HashMap::from_iter(vec![
        (
            KeyAlgorithmType::Eddsa,
            Arc::new(key_alg_eddsa) as Arc<dyn KeyAlgorithm>,
        ),
        (
            KeyAlgorithmType::Ecdsa,
            Arc::new(key_alg_ecdsa) as Arc<dyn KeyAlgorithm>,
        ),
    ])));

    let did_method_provider = Arc::new(DidMethodProviderImpl::new(
        did_cache,
        IndexMap::from_iter(vec![
            (
                "JWK".to_owned(),
                Arc::new(JWKDidMethod::new(key_algorithm_provider.clone())) as Arc<dyn DidMethod>,
            ),
            (
                "KEY".to_owned(),
                Arc::new(KeyDidMethod::new(key_algorithm_provider.clone())) as Arc<dyn DidMethod>,
            ),
        ]),
    ));

    let ca_cert = create_ca_cert(CertificateParams::default(), eddsa::key());

    let cert = create_cert(
        CertificateParams::default(),
        ecdsa::key(),
        &ca_cert,
        eddsa::key(),
    );

    let chain = format!("{}{}", cert.pem(), ca_cert.pem());

    // the formatter will only use the chain
    credential_data.issuer_certificate = Some(Certificate {
        id: Uuid::new_v4().into(),
        identifier_id: Uuid::new_v4().into(),
        organisation_id: None,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        expiry_date: OffsetDateTime::now_utc(),
        name: "".to_string(),
        chain,
        fingerprint: "".to_string(),
        state: CertificateState::Active,
        key: None,
    });

    let formatter = MdocFormatter::new(
        params,
        Arc::new(CertificateValidatorImpl::new(
            key_algorithm_provider.clone(),
            crl_cache,
            Arc::new(DefaultClock),
            android_key_attestation_crl_cache,
        )) as _,
        did_method_provider.clone(),
        datatype_config(),
    );
    formatter
        .format_credential(credential_data, ecdsa::signature_provider())
        .await
        .unwrap()
}

pub fn datatype_config() -> DatatypeConfig {
    let config = indoc! {"
        datatype:
            STRING:
                display: 'display'
                type: 'STRING'
                order: 100
                params: null
            NUMBER:
                display: 'display'
                type: 'NUMBER'
                order: 200
                params: null
            OBJECT:
                display: 'display'
                type: 'OBJECT'
                order: 300
                params: null
        format: {}
        identifier: {}
        issuanceProtocol: {}
        verificationProtocol: {}
        revocation: {}
        did: {}
        keyAlgorithm: {}
        keyStorage: {}
        task: {}
        trustManagement: {}
        transport: {}
        cacheEntities: {}
        holderKeyStorage: {}
        blobStorage: {}
        walletProvider: {}
        credentialIssuer: {}
        verificationEngagement: {}
    "};

    AppConfig::<ServerConfig>::parse(vec![InputFormat::yaml_str(config)])
        .unwrap()
        .core
        .datatype
}
