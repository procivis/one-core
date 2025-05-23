use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateRevocationList,
    CertificateRevocationListParams, CrlDistributionPoint, DistinguishedName, DnType, IsCa,
    KeyPair, RemoteKeyPair, RevokedCertParams,
};
use time::{Duration, OffsetDateTime};
use validator::ValidateLength;

use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::ecdsa_testing_params;
use crate::utils::field_match::FieldHelpers;

type InputKey = Box<dyn RemoteKeyPair + Send + Sync>;

// hardcoded key pair - equivalent of `ecdsa_testing_params()`
mod ecdsa {
    use std::sync::LazyLock;

    use asn1_rs::{Integer, SequenceOf, ToDer};
    use one_crypto::Signer;
    use one_crypto::signer::ecdsa::ECDSASigner;
    use rcgen::{PKCS_ECDSA_P256_SHA256, RemoteKeyPair, SignatureAlgorithm};
    use secrecy::SecretSlice;

    static PRIV_KEY: LazyLock<Vec<u8>> = LazyLock::new(|| {
        vec![
            56, 151, 105, 61, 235, 90, 246, 249, 183, 236, 90, 157, 106, 176, 145, 114, 36, 199,
            115, 51, 234, 102, 21, 254, 34, 219, 38, 210, 7, 172, 169, 157,
        ]
    });
    static PUB_KEY_COMPRESSED: LazyLock<Vec<u8>> = LazyLock::new(|| {
        vec![
            2, 113, 223, 203, 78, 208, 144, 157, 171, 118, 94, 112, 196, 150, 233, 175, 129, 0, 12,
            229, 151, 39, 80, 197, 83, 144, 248, 160, 227, 159, 2, 215, 39,
        ]
    });
    static PUB_KEY_UNCOMPRESSED: LazyLock<Vec<u8>> =
        LazyLock::new(|| ECDSASigner::parse_public_key(&PUB_KEY_COMPRESSED, false).unwrap());

    struct Key;

    pub fn key() -> super::InputKey {
        Box::new(Key)
    }

    impl RemoteKeyPair for Key {
        fn public_key(&self) -> &[u8] {
            &PUB_KEY_UNCOMPRESSED
        }

        fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
            let mut signature = ECDSASigner {}
                .sign(
                    msg,
                    &PUB_KEY_COMPRESSED,
                    &SecretSlice::from(PRIV_KEY.to_owned()),
                )
                .unwrap();

            // P256 signature must be ASN.1 encoded
            let s: [u8; 32] = signature.split_off(32).try_into().unwrap();
            let r: [u8; 32] = signature.try_into().unwrap();

            let r = Integer::from_const_array(r);
            let s = Integer::from_const_array(s);
            let seq = SequenceOf::from_iter([r, s]);
            Ok(seq.to_der_vec().unwrap())
        }

        fn algorithm(&self) -> &'static SignatureAlgorithm {
            &PKCS_ECDSA_P256_SHA256
        }
    }
}

// hardcoded key pair - equivalent of `eddsa_testing_params()`
mod eddsa {
    use std::sync::LazyLock;

    use one_crypto::Signer;
    use one_crypto::signer::eddsa::EDDSASigner;
    use rcgen::{PKCS_ED25519, RemoteKeyPair, SignatureAlgorithm};
    use secrecy::SecretSlice;

    static PRIV_KEY: LazyLock<Vec<u8>> = LazyLock::new(|| {
        vec![
            198, 42, 58, 194, 72, 37, 250, 120, 202, 196, 254, 252, 111, 170, 50, 115, 237, 210,
            60, 246, 89, 235, 38, 17, 208, 42, 2, 2, 229, 233, 217, 178, 74, 4, 73, 201, 147, 238,
            139, 201, 79, 45, 112, 196, 152, 35, 15, 38, 190, 141, 58, 19, 101, 184, 37, 84, 210,
            101, 19, 245, 37, 171, 239, 95,
        ]
    });
    static PUB_KEY: LazyLock<Vec<u8>> = LazyLock::new(|| {
        vec![
            74, 4, 73, 201, 147, 238, 139, 201, 79, 45, 112, 196, 152, 35, 15, 38, 190, 141, 58,
            19, 101, 184, 37, 84, 210, 101, 19, 245, 37, 171, 239, 95,
        ]
    });

    struct Key;

    pub fn key() -> super::InputKey {
        Box::new(Key)
    }

    impl RemoteKeyPair for Key {
        fn public_key(&self) -> &[u8] {
            &PUB_KEY
        }

        fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
            Ok(EDDSASigner {}
                .sign(msg, &PUB_KEY, &SecretSlice::from(PRIV_KEY.to_owned()))
                .unwrap())
        }

        fn algorithm(&self) -> &'static SignatureAlgorithm {
            &PKCS_ED25519
        }
    }
}

fn create_ca_cert(mut params: CertificateParams, key: InputKey) -> Certificate {
    let key = KeyPair::from_remote(key).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.use_authority_key_identifier_extension = true;
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "CA cert");
    params.distinguished_name = distinguished_name;

    let min_not_before = OffsetDateTime::now_utc()
        .checked_sub(Duration::weeks(100))
        .unwrap(); // ~2year before now
    let max_not_after = OffsetDateTime::now_utc()
        .checked_add(Duration::weeks(500))
        .unwrap(); // ~10years from now

    if params.not_before < min_not_before {
        params.not_before = min_not_before;
    }
    if params.not_after > max_not_after {
        params.not_after = max_not_after;
    }

    params.self_signed(&key).unwrap()
}

fn create_cert(
    mut params: CertificateParams,
    key: InputKey,
    issuer: &Certificate,
    issuer_key: InputKey,
) -> Certificate {
    let key = KeyPair::from_remote(key).unwrap();
    let issuer_key = KeyPair::from_remote(issuer_key).unwrap();

    params.use_authority_key_identifier_extension = true;
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "test cert");
    params.distinguished_name = distinguished_name;

    let parent_not_before = issuer.params().not_before;
    let parent_not_after = issuer.params().not_after;
    if params.not_before < parent_not_before {
        params.not_before = parent_not_before;
    }
    if params.not_after > parent_not_after {
        params.not_after = parent_not_after;
    }
    params.signed_by(&key, issuer, &issuer_key).unwrap()
}

fn create_crl(
    params: CertificateRevocationListParams,
    issuer: &Certificate,
    issuer_key: InputKey,
) -> CertificateRevocationList {
    let issuer_key = KeyPair::from_remote(issuer_key).unwrap();
    params.signed_by(issuer, &issuer_key).unwrap()
}

#[tokio::test]
async fn test_create_certificate_identifier_no_crl() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

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

    let chain = format!("{}{}", cert.pem(), ca_cert.pem());

    let result = context
        .api
        .identifiers
        .create_certificate_identifier("test-identifier", key.id, organisation.id, &chain)
        .await;

    assert_eq!(result.status(), 201);
}

#[tokio::test]
async fn test_create_certificate_identifier_crl_not_available() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let ca_cert = create_ca_cert(CertificateParams::default(), eddsa::key());

    let crl_uri = format!("{}/crl/1", context.server_mock.uri());
    context.server_mock.fail_crl_download("1").await;

    let mut params = CertificateParams::new(["test.com".to_string()]).unwrap();
    params.crl_distribution_points = vec![CrlDistributionPoint {
        uris: vec![crl_uri],
    }];
    let cert = create_cert(params, ecdsa::key(), &ca_cert, eddsa::key());

    let chain = format!("{}{}", cert.pem(), ca_cert.pem());

    let result = context
        .api
        .identifiers
        .create_certificate_identifier("test-identifier", key.id, organisation.id, &chain)
        .await;

    // revocation error
    assert_eq!(result.status(), 500);
    assert_eq!(result.error_code().await, "BR_0101");
}

#[tokio::test]
async fn test_create_certificate_identifier_with_crl() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let ca_params = CertificateParams::default();
    let crl_params = CertificateRevocationListParams {
        this_update: OffsetDateTime::now_utc()
            .checked_sub(Duration::hours(1))
            .unwrap(),
        next_update: OffsetDateTime::now_utc()
            .checked_add(Duration::hours(24))
            .unwrap(),
        crl_number: vec![0].into(),
        issuing_distribution_point: None,
        revoked_certs: vec![],
        key_identifier_method: ca_params.key_identifier_method.to_owned(),
    };
    let ca_cert = create_ca_cert(ca_params, eddsa::key());
    let crl = create_crl(crl_params, &ca_cert, eddsa::key());

    let crl_uri = format!("{}/crl/1", context.server_mock.uri());
    context.server_mock.crl_download("1", crl.der()).await;

    let mut params = CertificateParams::default();
    params.crl_distribution_points = vec![CrlDistributionPoint {
        uris: vec![crl_uri],
    }];
    let cert = create_cert(params, ecdsa::key(), &ca_cert, eddsa::key());

    let chain = format!("{}{}", cert.pem(), ca_cert.pem());

    let result = context
        .api
        .identifiers
        .create_certificate_identifier("test-identifier", key.id, organisation.id, &chain)
        .await;

    assert_eq!(result.status(), 201);
    let resp = result.json_value().await;
    let identifier_id = resp["id"].as_str().unwrap().parse().unwrap();

    let result = context.api.identifiers.get(&identifier_id).await;
    assert_eq!(result.status(), 200);
    let resp = result.json_value().await;

    assert_eq!(resp["name"].as_str().unwrap(), "test-identifier");
    assert_eq!(resp["type"].as_str().unwrap(), "CERTIFICATE");
    assert_eq!(resp["state"].as_str().unwrap(), "ACTIVE");
    assert!(!resp["isRemote"].as_bool().unwrap());
    assert_eq!(
        resp["organisationId"].as_str().unwrap(),
        organisation.id.to_string()
    );
    assert_eq!(resp["certificates"].as_array().length().unwrap(), 1);

    let certificate = &resp["certificates"][0];
    assert_eq!(certificate["name"].as_str().unwrap(), "test cert");
    assert_eq!(certificate["state"].as_str().unwrap(), "ACTIVE");
    assert_eq!(
        certificate["x509Attributes"]["issuer"].as_str().unwrap(),
        "CN=CA cert"
    );
    assert_eq!(
        certificate["x509Attributes"]["subject"].as_str().unwrap(),
        "CN=test cert"
    );

    let certificate_id = certificate["id"].as_str().unwrap().parse().unwrap();
    let result = context.api.certificates.get(&certificate_id).await;
    assert_eq!(result.status(), 200);
    let resp = result.json_value().await;
    resp["id"].assert_eq(&certificate_id);
    resp["organisationId"].assert_eq(&organisation.id);
}

#[tokio::test]
async fn test_create_certificate_identifier_with_crl_revoked() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let ca_params = CertificateParams::default();
    let ca_cert = create_ca_cert(ca_params.to_owned(), eddsa::key());

    let crl_uri = format!("{}/crl/1", context.server_mock.uri());
    let mut params = CertificateParams::default();
    params.crl_distribution_points = vec![CrlDistributionPoint {
        uris: vec![crl_uri],
    }];
    params.serial_number = Some(vec![1].into());
    let cert = create_cert(params, ecdsa::key(), &ca_cert, eddsa::key());

    let one_hour_before = OffsetDateTime::now_utc()
        .checked_sub(Duration::hours(1))
        .unwrap();
    let crl_params = CertificateRevocationListParams {
        this_update: one_hour_before,
        next_update: OffsetDateTime::now_utc()
            .checked_add(Duration::hours(24))
            .unwrap(),
        crl_number: vec![0].into(),
        issuing_distribution_point: None,
        revoked_certs: vec![RevokedCertParams {
            serial_number: cert.params().serial_number.to_owned().unwrap(),
            revocation_time: one_hour_before,
            reason_code: None,
            invalidity_date: None,
        }],
        key_identifier_method: ca_params.key_identifier_method.to_owned(),
    };

    let crl = create_crl(crl_params, &ca_cert, eddsa::key());

    context.server_mock.crl_download("1", crl.der()).await;

    let chain = format!("{}{}", cert.pem(), ca_cert.pem());

    let result = context
        .api
        .identifiers
        .create_certificate_identifier("test-identifier", key.id, organisation.id, &chain)
        .await;

    assert_eq!(result.status(), 400);
    assert_eq!(result.error_code().await, "BR_0212");
}
