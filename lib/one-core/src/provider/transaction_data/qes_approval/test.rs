use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use serde_json::json;
use similar_asserts::assert_eq;

use super::*;

fn qes_approval_transaction_data() -> QesApprovalTransactionData {
    QesApprovalTransactionData::new(
        "QES_APPROVAL".into(),
        json!({
            "transactionDataDisplayParams": {
                "groupPath": "$.documentInfos[*]",
                "titlePath": "$.label",
                "attributes": []
            }
        }),
    )
    .unwrap()
}

fn encode(transaction_data: serde_json::Value) -> String {
    Base64UrlSafeNoPadding::encode_to_string(serde_json::to_vec(&transaction_data).unwrap())
        .unwrap()
}

// Example from https://cloudsignatureconsortium.org/wp-content/uploads/2025/10/data-model-bindings.pdf
fn csc_example() -> serde_json::Value {
    json!({
        "type": "https://cloudsignatureconsortium.org/2025/qes-approval",
        "credential_ids": ["xyz123"],
        "numSignatures": 2,
        "signatureQualifier": "eu_eidas_qes",
        "documentInfos": [
            {
                "label": "Example Contract",
                "hash": "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
                "hashType": "sodr",
                "access": { "type": "OTP", "oneTimePassword": "51623" },
                "href": "https://protected.rp.example/contract-01.pdf?token=HS9naJKWwp901hBcK348IUHiuH8374",
                "checksum": "sha256-sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI="
            },
            {
                "label": "Example Terms of Service",
                "hash": "HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0=",
                "hashType": "sodr",
                "access": { "type": "public" },
                "href": "https://public.rp-cdn.example/terms-and-conditions.pdf",
                "checksum": "sha256-HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0="
            },
            {
                "label": "Example Invoice",
                "hash": "nL7zQmAKfQ2jADrOxkEZh2UqV4Lx4WsmelSivP6LjoQ=",
                "hashType": "sodr",
                "access": { "type": "OTP", "oneTimePassword": "83920" },
                "href": "https://protected.rp.example/invoice-2025-07.pdf?token=jk47ns88sna9a",
                "checksum": "sha256-nL7zQmAKfQ2jADrOxkEZh2UqV4Lx4WsmelSivP6LjoQ="
            }
        ],
        "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
    })
}

#[test]
fn test_validate_transaction_data_csc_example() {
    let metadata = qes_approval_transaction_data()
        .validate_transaction_data(&encode(csc_example()))
        .unwrap();

    assert_eq!(
        metadata.credential_ids,
        vec![CredentialQueryId::from("xyz123")]
    );
}

#[tokio::test]
async fn test_process_transaction_data_returns_qes_approval_kb_jwt_claim() {
    use one_crypto::Hasher;
    use one_crypto::hasher::sha256::SHA256;

    let transaction_data = encode(csc_example());

    let processed = qes_approval_transaction_data()
        .process_transaction_data(
            &transaction_data,
            FormatType::SdJwtVc,
            iana::HashAlgorithm::Sha256,
        )
        .await
        .unwrap();

    // hashed over the encoded string as received
    let expected = SHA256.hash_base64(transaction_data.as_bytes()).unwrap();
    let ProcessedTransactionData::KbJwtClaims(fields) = processed else {
        panic!("expected KbJwtClaims, got {processed:?}");
    };
    assert_eq!(
        fields.get("org.cloudsignatureconsortium.dm.1.qesApproval"),
        Some(&serde_json::Value::from(expected))
    );
    assert_eq!(fields.len(), 1);
}

#[tokio::test]
async fn test_process_transaction_data_returns_qes_approval_device_signed_element() {
    use one_crypto::Hasher;
    use one_crypto::hasher::sha256::SHA256;

    let transaction_data = encode(csc_example());

    let processed = qes_approval_transaction_data()
        .process_transaction_data(
            &transaction_data,
            FormatType::Mdoc,
            iana::HashAlgorithm::Sha256,
        )
        .await
        .unwrap();

    // hashed over the decoded payload, as raw bytes
    let expected = SHA256
        .hash(&serde_json::to_vec(&csc_example()).unwrap())
        .unwrap();
    let ProcessedTransactionData::DeviceSignedElements(namespaces) = processed else {
        panic!("expected DeviceSignedElements, got {processed:?}");
    };
    assert_eq!(
        namespaces["org.cloudsignatureconsortium.dm.1"]["qesApproval"],
        ciborium::Value::Bytes(expected)
    );
}

#[tokio::test]
async fn test_process_transaction_data_rejects_unsupported_credential_format() {
    let result = qes_approval_transaction_data()
        .process_transaction_data(
            &encode(csc_example()),
            FormatType::Jwt,
            iana::HashAlgorithm::Sha256,
        )
        .await;

    assert!(matches!(
        result,
        Err(TransactionDataError::UnsupportedCredentialFormat(_))
    ));
}

#[test]
fn test_get_display_data_groups_by_document() {
    // same display params as in config-procivis-base.yml
    let provider = QesApprovalTransactionData::new(
        "QES_APPROVAL".into(),
        json!({
            "transactionDataDisplayParams": {
                "groupPath": "$.documentInfos[*]",
                "titlePath": "$.label",
                "attributes": [
                    { "path": "$.access.oneTimePassword", "display": "transactionData.qesApproval.documentInfo.access.oneTimePassword" },
                    { "path": "$.href", "display": "transactionData.qesApproval.documentInfo.href" },
                    { "path": "$.checksum", "display": "transactionData.qesApproval.documentInfo.checksum" },
                    { "path": "$.signed_props", "display": "transactionData.qesApproval.documentInfo.signedProps" }
                ]
            }
        }),
    )
    .unwrap();

    let display_data = provider.get_display_data(&encode(csc_example())).unwrap();

    assert_eq!(
        serde_json::to_value(&display_data).unwrap(),
        json!([
            {
                "title": "Example Contract",
                "attributes": [
                    {
                        "key": "transactionData.qesApproval.documentInfo.access.oneTimePassword",
                        "value": "51623"
                    },
                    {
                        "key": "transactionData.qesApproval.documentInfo.href",
                        "value": "https://protected.rp.example/contract-01.pdf?token=HS9naJKWwp901hBcK348IUHiuH8374"
                    },
                    {
                        "key": "transactionData.qesApproval.documentInfo.checksum",
                        "value": "sha256-sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI="
                    }
                ]
            },
            {
                "title": "Example Terms of Service",
                "attributes": [
                    {
                        "key": "transactionData.qesApproval.documentInfo.href",
                        "value": "https://public.rp-cdn.example/terms-and-conditions.pdf"
                    },
                    {
                        "key": "transactionData.qesApproval.documentInfo.checksum",
                        "value": "sha256-HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0="
                    }
                ]
            },
            {
                "title": "Example Invoice",
                "attributes": [
                    {
                        "key": "transactionData.qesApproval.documentInfo.access.oneTimePassword",
                        "value": "83920"
                    },
                    {
                        "key": "transactionData.qesApproval.documentInfo.href",
                        "value": "https://protected.rp.example/invoice-2025-07.pdf?token=jk47ns88sna9a"
                    },
                    {
                        "key": "transactionData.qesApproval.documentInfo.checksum",
                        "value": "sha256-nL7zQmAKfQ2jADrOxkEZh2UqV4Lx4WsmelSivP6LjoQ="
                    }
                ]
            }
        ])
    );
}

#[test]
fn test_get_display_data_empty_when_group_path_matches_nothing() {
    let mut transaction_data = csc_example();
    transaction_data
        .as_object_mut()
        .unwrap()
        .remove("documentInfos");

    let display_data = qes_approval_transaction_data()
        .get_display_data(&encode(transaction_data))
        .unwrap();
    assert_eq!(serde_json::to_value(&display_data).unwrap(), json!([]));
}

fn display_provider(display_params: serde_json::Value) -> QesApprovalTransactionData {
    QesApprovalTransactionData::new(
        "QES_APPROVAL".into(),
        json!({ "transactionDataDisplayParams": display_params }),
    )
    .unwrap()
}

#[test]
fn test_get_display_data_group_path_matching_a_single_object() {
    // ungrouped transaction data, e.g. an EUDI TS12 SCA payment payload
    let provider = display_provider(json!({
        "groupPath": "$.payload",
        "titlePath": "$.payee.name",
        "attributes": [
            { "path": "$.amount", "display": "amount" },
            { "path": "$.currency", "display": "currency" }
        ]
    }));

    let transaction_data = json!({
        "type": "urn:eudi:sca:payment:1",
        "payload": {
            "payee": { "name": "Merchant X" },
            "currency": "EUR",
            "amount": 12.99
        }
    });

    let display_data = provider
        .get_display_data(&encode(transaction_data))
        .unwrap();
    assert_eq!(
        serde_json::to_value(&display_data).unwrap(),
        json!([
            {
                "title": "Merchant X",
                "attributes": [
                    { "key": "amount", "value": "12.99" },
                    { "key": "currency", "value": "EUR" }
                ]
            }
        ])
    );
}

#[test]
fn test_get_display_data_without_title_path() {
    let provider = display_provider(json!({
        "groupPath": "$.payload",
        "attributes": [
            { "path": "$.action", "display": "action" }
        ]
    }));

    let transaction_data = json!({
        "type": "urn:eudi:sca:login_risk_transaction:1",
        "payload": { "action": "Log in to Online Banking" }
    });

    let display_data = provider
        .get_display_data(&encode(transaction_data))
        .unwrap();
    assert_eq!(
        serde_json::to_value(&display_data).unwrap(),
        json!([
            {
                "title": null,
                "attributes": [
                    { "key": "action", "value": "Log in to Online Banking" }
                ]
            }
        ])
    );
}

#[test]
fn test_get_display_data_group_path_matching_the_root() {
    let provider = display_provider(json!({
        "groupPath": "$",
        "titlePath": "$.type",
        "attributes": [
            { "path": "$.amount", "display": "amount" }
        ]
    }));

    let transaction_data = json!({ "type": "flat-example", "amount": 5 });

    let display_data = provider
        .get_display_data(&encode(transaction_data))
        .unwrap();
    assert_eq!(
        serde_json::to_value(&display_data).unwrap(),
        json!([
            {
                "title": "flat-example",
                "attributes": [
                    { "key": "amount", "value": "5" }
                ]
            }
        ])
    );
}

#[test]
fn test_validate_transaction_data_rejects_empty_credential_ids() {
    let mut transaction_data = csc_example();
    transaction_data["credential_ids"] = json!([]);

    let result =
        qes_approval_transaction_data().validate_transaction_data(&encode(transaction_data));
    assert!(matches!(
        result,
        Err(TransactionDataError::InvalidTransactionData(_))
    ));
}

#[test]
fn test_validate_transaction_data_rejects_missing_credential_id_and_qualifier() {
    let mut transaction_data = csc_example();
    transaction_data
        .as_object_mut()
        .unwrap()
        .remove("signatureQualifier");

    let result =
        qes_approval_transaction_data().validate_transaction_data(&encode(transaction_data));
    assert!(matches!(
        result,
        Err(TransactionDataError::InvalidTransactionData(_))
    ));
}

#[test]
fn test_validate_transaction_data_rejects_unsupported_hash_algorithm() {
    let mut transaction_data = csc_example();
    // sha-384, valid per CSC but not supported by crypto
    transaction_data["hashAlgorithmOID"] = json!("2.16.840.1.101.3.4.2.2");

    let result =
        qes_approval_transaction_data().validate_transaction_data(&encode(transaction_data));
    assert!(matches!(result, Err(TransactionDataError::Hashing(_))));
}

#[test]
fn test_validate_transaction_data_rejects_unknown_hash_algorithm_oid() {
    let mut transaction_data = csc_example();
    // sha-1
    transaction_data["hashAlgorithmOID"] = json!("1.3.14.3.2.26");

    let result =
        qes_approval_transaction_data().validate_transaction_data(&encode(transaction_data));
    assert!(matches!(result, Err(TransactionDataError::Parsing(_))));
}

#[test]
fn test_validate_transaction_data_rejects_invalid_base64url() {
    let result = qes_approval_transaction_data().validate_transaction_data("not/valid+base64url");
    assert!(matches!(result, Err(TransactionDataError::Encoding(_))));
}

#[test]
fn test_prepare_transaction_data_composes_csc_example() {
    let mut data = csc_example();
    let content = data.as_object_mut().unwrap();
    content.remove("type");
    content.remove("credential_ids");

    let encoded = qes_approval_transaction_data()
        .prepare_transaction_data(vec!["xyz123".into()], Some(data))
        .unwrap();

    let decoded: serde_json::Value = decode_transaction_data(&encoded).unwrap();
    assert_eq!(decoded, csc_example());
}

#[test]
fn test_prepare_transaction_data_rejects_invalid_content() {
    let mut data = csc_example();
    let content = data.as_object_mut().unwrap();
    content.remove("type");
    content.remove("credential_ids");
    // neither credentialID nor signatureQualifier present
    content.remove("signatureQualifier");

    let err = qes_approval_transaction_data()
        .prepare_transaction_data(vec!["xyz123".into()], Some(data))
        .unwrap_err();

    assert!(matches!(
        err,
        TransactionDataError::InvalidTransactionData(_)
    ));
}

#[tokio::test]
async fn test_verify_transaction_data_matches_recomputed_evidence() {
    let transaction_data = encode(csc_example());
    let provider = qes_approval_transaction_data();

    let ProcessedTransactionData::KbJwtClaims(claims) = provider
        .process_transaction_data(
            &transaction_data,
            FormatType::SdJwtVc,
            iana::HashAlgorithm::Sha256,
        )
        .await
        .unwrap()
    else {
        panic!("expected KbJwtClaims");
    };

    let authorization = provider
        .verify_transaction_data(
            &transaction_data,
            FormatType::SdJwtVc,
            &PresentedTransactionData::KbJwtClaims(claims),
        )
        .await
        .unwrap();

    assert_eq!(authorization, TransactionDataAuthorization::Authorized);
}

#[tokio::test]
async fn test_verify_transaction_data_rejects_missing_evidence() {
    let transaction_data = encode(csc_example());

    let authorization = qes_approval_transaction_data()
        .verify_transaction_data(
            &transaction_data,
            FormatType::SdJwtVc,
            &PresentedTransactionData::KbJwtClaims(Default::default()),
        )
        .await
        .unwrap();

    assert_eq!(authorization, TransactionDataAuthorization::NotAuthorized);
}
