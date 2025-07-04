use asn1_rs::nom::AsBytes;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateRevocationList,
    CertificateRevocationListParams, DistinguishedName, DnType, IsCa, KeyPair, RemoteKeyPair,
};
use time::{Duration, OffsetDateTime};

type InputKey = Box<dyn RemoteKeyPair + Send + Sync>;

// hardcoded key pair - equivalent of `ecdsa_testing_params()`
pub mod ecdsa {
    use std::sync::LazyLock;

    use asn1_rs::{Integer, SequenceOf, ToDer};
    use async_trait::async_trait;
    use one_core::config::core_config::KeyAlgorithmType;
    use one_core::provider::credential_formatter::model::SignatureProvider;
    use one_crypto::signer::ecdsa::ECDSASigner;
    use one_crypto::{Signer, SignerError};
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

    pub fn signature_provider() -> Box<dyn SignatureProvider> {
        Box::new(Key)
    }

    impl RemoteKeyPair for Key {
        fn public_key(&self) -> &[u8] {
            &PUB_KEY_UNCOMPRESSED
        }

        fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
            Ok(Self::sign(msg))
        }

        fn algorithm(&self) -> &'static SignatureAlgorithm {
            &PKCS_ECDSA_P256_SHA256
        }
    }

    impl Key {
        fn sign(msg: &[u8]) -> Vec<u8> {
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
            seq.to_der_vec().unwrap()
        }
    }

    #[async_trait]
    impl SignatureProvider for Key {
        async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
            Ok(Self::sign(message))
        }

        fn get_key_id(&self) -> Option<String> {
            unimplemented!()
        }

        fn get_key_algorithm(&self) -> Result<KeyAlgorithmType, String> {
            Ok(KeyAlgorithmType::Ecdsa)
        }

        fn jose_alg(&self) -> Option<String> {
            Some(String::from("ES256"))
        }

        fn get_public_key(&self) -> Vec<u8> {
            PUB_KEY_UNCOMPRESSED.to_vec()
        }
    }
}

// hardcoded key pair - equivalent of `eddsa_testing_params()`
pub mod eddsa {
    use std::sync::LazyLock;

    use async_trait::async_trait;
    use one_core::config::core_config::KeyAlgorithmType;
    use one_core::provider::credential_formatter::model::SignatureProvider;
    use one_crypto::signer::eddsa::EDDSASigner;
    use one_crypto::{Signer, SignerError};
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

    pub const KEY_IDENTIFIER: &str = "61:20:eb:7e:ae:c1:f4:b5:bc:26:a1:5f:f0:6a:32:a6:2c:75:f5:fb";

    struct Key;

    pub fn key() -> super::InputKey {
        Box::new(Key)
    }

    #[allow(unused)]
    pub fn signature_provider() -> Box<dyn SignatureProvider> {
        Box::new(Key)
    }

    impl RemoteKeyPair for Key {
        fn public_key(&self) -> &[u8] {
            &PUB_KEY
        }

        fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
            Ok(Self::sign(msg))
        }

        fn algorithm(&self) -> &'static SignatureAlgorithm {
            &PKCS_ED25519
        }
    }

    impl Key {
        fn sign(msg: &[u8]) -> Vec<u8> {
            EDDSASigner {}
                .sign(msg, &PUB_KEY, &SecretSlice::from(PRIV_KEY.to_owned()))
                .unwrap()
        }
    }

    #[async_trait]
    impl SignatureProvider for Key {
        async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
            Ok(Self::sign(message))
        }

        fn get_key_id(&self) -> Option<String> {
            unimplemented!()
        }

        fn get_key_algorithm(&self) -> Result<KeyAlgorithmType, String> {
            Ok(KeyAlgorithmType::Eddsa)
        }

        fn jose_alg(&self) -> Option<String> {
            Some("EdDSA".to_string())
        }

        fn get_public_key(&self) -> Vec<u8> {
            PUB_KEY.to_vec()
        }
    }
}

pub(crate) fn create_ca_cert(mut params: CertificateParams, key: InputKey) -> Certificate {
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

pub(crate) fn create_cert(
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

pub(crate) fn create_crl(
    params: CertificateRevocationListParams,
    issuer: &Certificate,
    issuer_key: InputKey,
) -> CertificateRevocationList {
    let issuer_key = KeyPair::from_remote(issuer_key).unwrap();
    params.signed_by(issuer, &issuer_key).unwrap()
}

pub(crate) fn fingerprint(cert: &Certificate) -> String {
    hex::encode(SHA256.hash(cert.der().as_bytes()).unwrap())
}
