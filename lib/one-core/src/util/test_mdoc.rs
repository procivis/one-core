#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::Arc;

use coset::{CoseKeyBuilder, iana};
use shared_types::SerializedCredential;
use time::Duration;

use crate::config::core_config::KeyAlgorithmType;
use crate::proto::certificate_validator::CertificateValidatorImpl;
use crate::proto::http_client::reqwest_client::ReqwestClient;
use crate::provider::caching_loader::android_attestation_crl::{
    AndroidAttestationCrlCache, AndroidAttestationCrlResolver,
};
use crate::provider::caching_loader::x509_crl::{X509CrlCache, X509CrlResolver};
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::mdoc_formatter::MdocFormatter;
use crate::provider::credential_formatter::model::{AuthenticationFn, CredentialData};
use crate::provider::data_type::provider::data_type_provider_from_config;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::key_algorithm::provider::{MockKeyAlgorithmProvider, ParsedKey};
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::service::test_utilities::{dummy_did_document, generic_config};

pub async fn format_mdoc_credential(
    credential_data: CredentialData,
    params: serde_json::Value,
    auth_fn: AuthenticationFn,
) -> SerializedCredential {
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

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .returning(|_| Ok(Arc::new(Ecdsa)));
    key_algorithm_provider.expect_parse_jwk().returning(|_| {
        let mut public_key = MockSignaturePublicKeyHandle::new();
        public_key.expect_as_cose().returning(|| {
            Ok(
                CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, vec![0x00], vec![0x01])
                    .build(),
            )
        });
        Ok(ParsedKey {
            algorithm_type: KeyAlgorithmType::Ecdsa,
            key: KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(Arc::new(public_key))),
        })
    });
    let key_algorithm_provider = Arc::new(key_algorithm_provider);

    let mut did_method_provider = MockDidMethodProvider::new();
    did_method_provider
        .expect_resolve()
        .returning(move |did| Ok(dummy_did_document(did)));

    let mut config = generic_config().core;
    let datatype_provider = data_type_provider_from_config(&mut config).unwrap();
    let formatter = MdocFormatter::new(
        Some("test".into()),
        "MDOC".into(),
        params,
        Arc::new(CertificateValidatorImpl::new(
            key_algorithm_provider.clone(),
            crl_cache,
            Duration::minutes(1),
            android_key_attestation_crl_cache,
        )) as _,
        Arc::new(did_method_provider),
        datatype_provider,
        key_algorithm_provider,
        Arc::new(ReqwestClient::default()),
    )
    .unwrap();
    formatter
        .format_credential(credential_data, auth_fn)
        .await
        .unwrap()
}
