use std::sync::Arc;

use mockall::predicate;
use one_crypto::{MockCryptoProvider, MockHasher};
use serde_json::json;
use time::OffsetDateTime;

use super::PhysicalCardFormatter;
use crate::provider::credential_formatter::json_ld::context::caching_loader::JsonLdCachingLoader;
use crate::provider::credential_formatter::model::MockTokenVerifier;
use crate::provider::credential_formatter::physical_card::mappers::terse_bitstring_status_list_to_bitstring_status;
use crate::provider::credential_formatter::physical_card::model::{
    OptiocalBarcodeCredential, TerseBitstringStatusListEntry,
};
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::exchange_protocol::scan_to_verify::dto::ScanToVerifyCredentialDTO;
use crate::provider::http_client::reqwest_client::ReqwestClient;
use crate::provider::remote_entity_storage::{
    MockRemoteEntityStorage, RemoteEntity, RemoteEntityType,
};

// https://w3c-ccg.github.io/vc-barcodes/#example-a-json-ld-vc-for-a-utopia-ead-vcb-0
// https://w3c-ccg.github.io/vc-barcodes/#verifying-0
// The example in the specification has incorrect checksums,
// they are corrected here.
const MRZ: &str = "IAUTO0000007010SRC0000000701<<\
    8804190M2601054NOT<<<<<<<<<<<7\
    SMITH<<JOHN<<<<<<<<<<<<<<<<<<<";

fn prepare_caching_loader() -> JsonLdCachingLoader {
    let mut storage = MockRemoteEntityStorage::default();
    storage
        .expect_get_by_key()
        .with(predicate::eq("https://www.w3.org/ns/credentials/v2"))
        .returning(|url| {
            let now = OffsetDateTime::now_utc();
            Ok(Some(RemoteEntity {
                last_modified: now,
                entity_type: RemoteEntityType::JsonLdContext,
                value: W3_ORG_NS_CREDENTIALS_V2.to_string().into_bytes(),
                key: url.to_string(),
                hit_counter: 0,
                media_type: None,
                persistent: false,
            }))
        });

    storage
        .expect_get_by_key()
        .with(predicate::eq("https://w3id.org/vc-barcodes/v1"))
        .returning(|url| {
            let now = OffsetDateTime::now_utc();
            Ok(Some(RemoteEntity {
                last_modified: now,
                entity_type: RemoteEntityType::JsonLdContext,
                value: BARCODE_CONTEXT.to_string().into_bytes(),
                key: url.to_string(),
                hit_counter: 0,
                media_type: None,
                persistent: false,
            }))
        });

    storage
        .expect_get_by_key()
        .with(predicate::eq("https://w3id.org/utopia/v2"))
        .returning(|url| {
            let now = OffsetDateTime::now_utc();
            Ok(Some(RemoteEntity {
                last_modified: now,
                entity_type: RemoteEntityType::JsonLdContext,
                value: UTOPIA_CONTEXT.to_string().into_bytes(),
                key: url.to_string(),
                hit_counter: 0,
                media_type: None,
                persistent: false,
            }))
        });

    storage.expect_insert().times(..).returning(|_| Ok(()));

    storage
        .expect_get_storage_size()
        .times(..)
        .returning(|_| Ok(2));

    JsonLdCachingLoader::new(
        RemoteEntityType::JsonLdContext,
        Arc::new(storage),
        10000,
        time::Duration::seconds(1000),
        time::Duration::seconds(999),
    )
}

fn employment_document_credential() -> serde_json::Value {
    json!(
      {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://w3id.org/vc-barcodes/v1",
          "https://w3id.org/utopia/v2"
        ],
        "type": [
          "VerifiableCredential",
          "OpticalBarcodeCredential"
        ],
        "credentialSubject": {
          "type": "MachineReadableZone"
        },
        "issuer": "did:key:zDnaeZSD9XcuULaS8qmgDUa6TMg2QjF9xABnZK42awDH3BEzj",
        "proof": {
          "type": "DataIntegrityProof",
          "verificationMethod": "did:key:zDnaeZSD9XcuULaS8qmgDUa6TMg2QjF9xABnZK42awDH3BEzj#zDnaeZSD9XcuULaS8qmgDUa6TMg2QjF9xABnZK42awDH3BEzj",
          "cryptosuite": "ecdsa-xi-2023",
          "proofPurpose": "assertionMethod",
          "proofValue": "z4B8AQgjwgsEdcPEZkrkK2mTVKn7qufoDgDkv9Qitf9tjxQPMoJaGdXwDrThjp7LUdvzsDJ7UwYu6Xpm9fjbo6QnJ"
        }
      }
    )
}

#[tokio::test]
async fn test_mrz_proof_process() {
    let schema: &str = "UtopiaEmploymentDocument";
    let credential = employment_document_credential();

    let token = serde_json::to_string(&ScanToVerifyCredentialDTO {
        schema_id: schema.to_string(),
        credential: credential.to_string(),
        barcode: MRZ.to_string(),
    })
    .unwrap();

    let credential_with_optical_data = OptiocalBarcodeCredential::from_token(&token).unwrap();

    let mut token_verifier = MockTokenVerifier::new();
    let caching_loader = prepare_caching_loader();
    let mut hasher = MockHasher::default();
    let mut crypto = MockCryptoProvider::default();

    let extra_information = credential_with_optical_data
        .extra_information_bytes()
        .unwrap();

    hasher.expect_hash().times(2).returning(|_| Ok(vec![1]));
    hasher
        .expect_hash()
        .once()
        .with(predicate::eq(extra_information.clone()))
        .returning(|_| Ok(vec![2]));

    let hasher = Arc::new(hasher);
    crypto
        .expect_get_hasher()
        .once()
        .with(predicate::eq("sha-256"))
        .returning(move |_| Ok(hasher.clone()));

    let credential = &credential_with_optical_data.credential;

    let expected_issuer = credential.issuer.clone();
    token_verifier.expect_verify().once().returning(
        move |issuer, verification_method, alg, digest, signature| {
            let expected_issuer = expected_issuer.to_did_value().unwrap();
            assert_eq!(issuer, Some(expected_issuer));
            assert_eq!(verification_method, verification_method);
            assert_eq!(alg, "ECDSA");
            assert_eq!(digest.len(), 3);
            assert_eq!(signature.len(), 64);
            Ok(())
        },
    );

    let formatter = PhysicalCardFormatter::new(
        Arc::new(crypto),
        caching_loader,
        Arc::new(ReqwestClient::default()),
    );

    formatter
        .extract_credentials(&token, Box::new(token_verifier), None)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_employment_document_mrz_claim_extraction() {
    let schema = "UtopiaEmploymentDocument";
    let credential = employment_document_credential();

    let formatter = PhysicalCardFormatter::new(
        Arc::new(MockCryptoProvider::default()),
        prepare_caching_loader(),
        Arc::new(ReqwestClient::default()),
    );

    let token = serde_json::to_string(&ScanToVerifyCredentialDTO {
        schema_id: schema.to_string(),
        credential: credential.to_string(),
        barcode: MRZ.to_string(),
    })
    .unwrap();

    let credential = formatter
        .extract_credentials_unverified(&token)
        .await
        .unwrap();

    let given_names = credential.claims.claims.get("Given Name(s)").unwrap();
    assert!(given_names.is_array());
    assert_eq!(given_names.as_array().unwrap().len(), 1);
    assert_eq!(given_names.as_array().unwrap()[0].as_str().unwrap(), "JOHN");

    let birth_date = credential.claims.claims.get("Date of Birth").unwrap();
    assert_eq!(birth_date.as_str().unwrap(), "1988-04-19T00:00:00Z");

    let expiration_date = credential.claims.claims.get("Date of Expiry").unwrap();
    assert_eq!(expiration_date.as_str().unwrap(), "2026-01-05T00:00:00Z");
}

#[tokio::test]
async fn test_terse_list_to_bitstring_conversion() {
    // Example terse list from the specification
    // https://w3c-ccg.github.io/vc-barcodes/#example-a-json-ld-vc-for-a-utopia-driver-s-license-vcb-0
    let terse_status_list = TerseBitstringStatusListEntry {
        terse_status_list_index: 3851559041,
        terse_status_list_base_url:
            "https://sandbox.platform.veres.dev/statuses/z19rJ4oGrbFCqf3cNTVDHSbNd/status-lists"
                .to_string(),
    };

    // Expected result
    // https://w3c-ccg.github.io/vc-barcodes/#status-checking
    let bistring_status_list =
        terse_bitstring_status_list_to_bitstring_status(terse_status_list, None).unwrap();

    assert_eq!(bistring_status_list.len(), 2);

    let revocation_status = &bistring_status_list[0];
    let suspension_status = &bistring_status_list[1];

    assert_eq!(
        bistring_status_list[0].status_purpose,
        Some("revocation".to_string())
    );
    assert_eq!(
        bistring_status_list[1].status_purpose,
        Some("suspension".to_string())
    );

    assert_eq!(
        "https://sandbox.platform.veres.dev/statuses/z19rJ4oGrbFCqf3cNTVDHSbNd/status-lists/revocation/29385",
        revocation_status
            .additional_fields
            .get("statusListCredential")
            .unwrap()
            .as_str()
            .unwrap()
    );

    assert_eq!(
        "https://sandbox.platform.veres.dev/statuses/z19rJ4oGrbFCqf3cNTVDHSbNd/status-lists/suspension/29385",
        suspension_status
            .additional_fields
            .get("statusListCredential")
            .unwrap()
            .as_str()
            .unwrap()
    );

    assert_eq!(
        "8321",
        revocation_status
            .additional_fields
            .get("statusListIndex")
            .unwrap()
            .as_str()
            .unwrap()
    );

    assert_eq!(
        "8321",
        revocation_status
            .additional_fields
            .get("statusListIndex")
            .unwrap()
            .as_str()
            .unwrap()
    );
}

#[tokio::test]
async fn test_mrz_normalization() {
    let schema = "UtopiaEmploymentDocument";
    let credential = employment_document_credential();
    let expected_mrz: &str = "IAUTO0000007010SRC0000000701<<\n8804190M2601054NOT<<<<<<<<<<<7\nSMITH<<JOHN<<<<<<<<<<<<<<<<<<<\n";

    // https://w3c-ccg.github.io/vc-barcodes/#machinereadablezone-credentials
    let mrz_format_1 = "IAUTO0000007010SRC0000000701<< 8804190M2601054NOT<<<<<<<<<<<7\nSMITH<<JOHN<<<<<<<<<<<<<<<<<<<  ";
    let mrz_format_2 = "IAUTO0000007010SRC0000000701<<8804190M2601054NOT<<<<<<<<<<<7  \n SMITH<<JOHN<<<<<<<<<<<<<<<<<<<";
    let mrz_format_3 = "IAUTO0000007010SRC0000000701<<8804190M2601054NOT<<<<<<<<<<<7SMITH<<JOHN<<<<<<<<<<<<<<<<<<<";

    let mrz_representations = vec![mrz_format_1, mrz_format_2, mrz_format_3];

    for mrz in mrz_representations {
        let token = serde_json::to_string(&ScanToVerifyCredentialDTO {
            schema_id: schema.to_string(),
            credential: credential.to_string(),
            barcode: mrz.to_string(),
        })
        .unwrap();

        let credential_with_optical_data = OptiocalBarcodeCredential::from_token(&token).unwrap();
        let extra_information = credential_with_optical_data
            .extra_information_bytes()
            .unwrap();

        assert_eq!(extra_information.as_slice(), expected_mrz.as_bytes())
    }
}

const W3_ORG_NS_CREDENTIALS_V2: &str = r#"{
  "@context": {
    "@protected": true,
    "id": "@id",
    "type": "@type",
    "credentialStatus": "https://www.w3.org/2018/credentials#credentialStatus",
    "credentialSubject": "https://www.w3.org/2018/credentials#credentialSubject",
    "issuer": "https://www.w3.org/2018/credentials#issuer",
    "VerifiableCredential": "https://www.w3.org/2018/credentials#VerifiableCredential",
    "DataIntegrityProof": "https://w3id.org/security#DataIntegrityProof",
    "proofPurpose":"https://w3id.org/security#proofPurpose",
    "assertionMethod": "https://w3id.org/security#assertionMethod",
    "cryptosuite": "https://w3id.org/security#cryptosuite",
    "proofValue":"https://w3id.org/security#proofValue",
    "verificationMethod": "https://w3id.org/security#verificationMethod"
  }
}"#;

const BARCODE_CONTEXT: &str = r#"{
  "@context": {
    "@protected": true,
    "id": "@id",
    "type": "@type",
    "MachineReadableZone": "https://w3id.org/vc-barcodes#MachineReadableZone",
    "AamvaDriversLicenseScannableInformation": "https://w3id.org/vc-barcodes#AamvaDriversLicenseScannableInformation",
    "protectedComponentIndex": {
      "@id": "https://w3id.org/vc-barcodes#protectedComponentIndex",
      "@type": "https://w3id.org/security#multibase"
    },
    "OpticalBarcodeCredential": "https://w3id.org/vc-barcodes#OpticalBarcodeCredential",
    "TerseBitstringStatusListEntry": {
      "@id": "https://w3id.org/vc-barcodes#TerseBitstringStatusListEntry",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "terseStatusListBaseUrl": {
          "@type": "@id",
          "@id": "https://w3id.org/vc-barcodes#terseStatusListBaseUrl"
        },
        "terseStatusListIndex": "https://w3id.org/vc-barcodes#terseStatusListIndex"
      }
    }
  }
}"#;

const UTOPIA_CONTEXT: &str = r#"{
  "@context": {
    "@protected": true,
    "id": "@id",
    "type": "@type",
    "did:key:zDnaeZSD9XcuULaS8qmgDUa6TMg2QjF9xABnZK42awDH3BEzj": "did:key:zDnaeZSD9XcuULaS8qmgDUa6TMg2QjF9xABnZK42awDH3BEzj",
    "did:key:zDnaeZSD9XcuULaS8qmgDUa6TMg2QjF9xABnZK42awDH3BEzj#zDnaeZSD9XcuULaS8qmgDUa6TMg2QjF9xABnZK42awDH3BEzj": "did:key:zDnaeZSD9XcuULaS8qmgDUa6TMg2QjF9xABnZK42awDH3BEzj#zDnaeZSD9XcuULaS8qmgDUa6TMg2QjF9xABnZK42awDH3BEzj",
    "did:key:zDnaeWjKfs1ob9QcgasjYSPEMkwq31hmvSAWPVAgnrt1e9GKj": "did:key:zDnaeWjKfs1ob9QcgasjYSPEMkwq31hmvSAWPVAgnrt1e9GKj",
    "did:key:zDnaeWjKfs1ob9QcgasjYSPEMkwq31hmvSAWPVAgnrt1e9GKj#zDnaeWjKfs1ob9QcgasjYSPEMkwq31hmvSAWPVAgnrt1e9GKj": "did:key:zDnaeWjKfs1ob9QcgasjYSPEMkwq31hmvSAWPVAgnrt1e9GKj#zDnaeWjKfs1ob9QcgasjYSPEMkwq31hmvSAWPVAgnrt1e9GKj",
    "https://sandbox.platform.veres.dev/statuses/z19rJ4oGrbFCqf3cNTVDHSbNd/status-lists": "https://sandbox.platform.veres.dev/statuses/z19rJ4oGrbFCqf3cNTVDHSbNd/status-lists"
  }
}"#;
