use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use rcgen::{
    CertificateParams, CertifiedKey, SignatureAlgorithm, PKCS_ECDSA_P256_SHA256, PKCS_ED25519,
};
use serde_json::json;
use shared_types::DidId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{DidMdl, Params};
use crate::model::key::Key;
use crate::provider::did_method::keys::Keys;
use crate::provider::did_method::DidMethod;
use crate::provider::key_algorithm::eddsa::Eddsa;
use crate::provider::key_algorithm::es256::Es256;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_algorithm::KeyAlgorithm;

#[test]
fn test_new_did_mdl_instance() {
    let certificate = rcgen::generate_simple_self_signed(["procivis.test".to_string()])
        .unwrap()
        .cert
        .der()
        .to_vec();

    let key_algorithm_provider = Arc::new(MockKeyAlgorithmProvider::new());
    let params = Params {
        keys: Keys::default(),
        iaca_certificate: certificate,
    };

    assert!(DidMdl::new(params, key_algorithm_provider).is_ok())
}

#[tokio::test]
async fn test_create_mdl_did_for_e256_key() {
    let key_algorithm: Arc<dyn KeyAlgorithm> = Arc::new(Es256) as _;

    test_create_mdl_did_for("ES256", key_algorithm, &PKCS_ECDSA_P256_SHA256).await
}

#[tokio::test]
async fn test_create_mdl_did_for_ed25519_key() {
    let key_algorithm: Arc<dyn KeyAlgorithm> = Arc::new(Eddsa) as _;

    test_create_mdl_did_for("EDDSA", key_algorithm, &PKCS_ED25519).await
}

async fn test_create_mdl_did_for(
    key_type: &str,
    key_algorithm: Arc<dyn KeyAlgorithm>,
    signature_algorithm: &'static SignatureAlgorithm,
) {
    // arrange
    let CertifiedKey {
        cert: root_cert,
        key_pair: issuer_key,
    } = rcgen::generate_simple_self_signed(["procivis.test".to_string()]).unwrap();

    let key = rcgen::KeyPair::generate_for(signature_algorithm).unwrap();
    let public_key = key.public_key_der();
    let public_key = key_algorithm.parse_raw(&public_key).unwrap();

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();

    key_algorithm_provider
        .expect_key_algorithm_from_name()
        .returning(move |_| Some(key_algorithm.clone()));

    let service = DidMdl::new(
        Params {
            keys: Keys::default(),
            iaca_certificate: root_cert.der().to_vec(),
        },
        Arc::new(key_algorithm_provider),
    )
    .unwrap();

    let did_id = DidId::from(Uuid::new_v4());

    let certificate = CertificateParams::new(["procivis2.test".to_string()])
        .unwrap()
        .signed_by(&key, &root_cert, &issuer_key)
        .unwrap();

    let params = json!({
        "certificate": certificate.pem()
    });

    let keys = [Key {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        public_key: public_key.public_key_as_raw(),
        name: "test-did-mld".to_string(),
        key_reference: vec![],
        storage_type: "INTERNAL".to_string(),
        key_type: key_type.to_string(),
        organisation: None,
    }];

    let certificate_der_base64 =
        Base64UrlSafeNoPadding::encode_to_string(certificate.der()).unwrap();

    // act
    let did = service
        .create(Some(did_id), &Some(params), Some(keys.to_vec()))
        .await
        .unwrap();

    // assert
    assert_eq!(
        &format!("did:mdl:certificate:{certificate_der_base64}"),
        did.as_str()
    )
}
