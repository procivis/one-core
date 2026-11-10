use coset::CborSerializable;
use similar_asserts::assert_eq;

use super::model::{DeviceResponse, dcapi};
use super::session_transcript::qr_code::QRHandover;
use super::session_transcript::{Handover, SessionTranscript};
use super::{try_build_dcapi_response, try_decrypt_dcapi_response};
use crate::provider::credential_formatter::mdoc_formatter::util::{Bstr, MDLVersion};
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_algorithm::key::{KeyAgreementHandle, PublicKeyAgreementHandle};
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::nfc::NFCHandover;

fn generate_recipient_key() -> KeyAgreementHandle {
    Ecdsa
        .generate_key()
        .unwrap()
        .key
        .key_agreement()
        .unwrap()
        .to_owned()
}

fn encryption_parameters(
    recipient_public_key: &dyn PublicKeyAgreementHandle,
) -> dcapi::EncryptionParameters {
    let cose_key = recipient_public_key.as_cose().unwrap().to_vec().unwrap();
    let recipient_public_key = ciborium::from_reader(cose_key.as_slice()).unwrap();

    dcapi::EncryptionParameters {
        nonce: Bstr(vec![1, 2, 3]),
        recipient_public_key,
    }
}

fn session_transcript() -> SessionTranscript {
    SessionTranscript {
        device_engagement_bytes: None,
        e_reader_key_bytes: None,
        handover: Handover::QrCode(QRHandover),
    }
}

fn device_response() -> DeviceResponse {
    DeviceResponse {
        version: MDLVersion::default(),
        documents: None,
        document_errors: None,
        status: 0,
    }
}

#[tokio::test]
async fn test_dcapi_response_encryption_round_trip() {
    let key = generate_recipient_key();
    let device_response = device_response();
    let session_transcript = session_transcript();

    // encrypted using the `hpke` crate
    let encrypted = try_build_dcapi_response(
        device_response.clone(),
        &encryption_parameters(key.public().as_ref()),
        session_transcript.clone(),
    )
    .unwrap();

    // decrypted using `one_crypto::hpke`
    let decrypted = try_decrypt_dcapi_response(encrypted, &key, session_transcript)
        .await
        .unwrap();

    assert_eq!(decrypted, device_response);
}

#[tokio::test]
async fn test_dcapi_response_decryption_fails_with_different_session_transcript() {
    let key = generate_recipient_key();

    let encrypted = try_build_dcapi_response(
        device_response(),
        &encryption_parameters(key.public().as_ref()),
        session_transcript(),
    )
    .unwrap();

    let other_session_transcript = SessionTranscript {
        handover: Handover::Nfc(NFCHandover {
            select_message: Bstr(vec![0, 1]),
            request_message: None,
        }),
        ..session_transcript()
    };

    let result = try_decrypt_dcapi_response(encrypted, &key, other_session_transcript).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_dcapi_response_decryption_fails_with_different_key() {
    let key = generate_recipient_key();
    let other_key = generate_recipient_key();
    let session_transcript = session_transcript();

    let encrypted = try_build_dcapi_response(
        device_response(),
        &encryption_parameters(key.public().as_ref()),
        session_transcript.clone(),
    )
    .unwrap();

    let result = try_decrypt_dcapi_response(encrypted, &other_key, session_transcript).await;

    assert!(result.is_err());
}
