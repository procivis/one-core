use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use one_crypto::hasher::sha512::SHA512;
use serde_json::json;
use similar_asserts::assert_eq;

use super::*;

fn provider(transaction_type: TransactionType) -> ScaTransactionData {
    ScaTransactionData::new(
        "SCA_LOGIN_RISK_TRANSACTION".into(),
        transaction_type,
        // same params as in config-procivis-base.yml
        json!({
            "leewaySeconds": 60,
            "transactionDataDisplayParams": {
                "groupPath": "$.payload",
                "attributes": [
                    { "path": "$.transaction_id", "display": "transactionData.loginRiskTransaction.transactionId" },
                    { "path": "$.action", "display": "transactionData.loginRiskTransaction.action" },
                    { "path": "$.service", "display": "transactionData.loginRiskTransaction.service" },
                    { "path": "$.date_time", "display": "transactionData.loginRiskTransaction.dateTime" }
                ]
            }
        }),
    )
    .unwrap()
}

fn encode(transaction_data: serde_json::Value) -> String {
    Base64UrlSafeNoPadding::encode_to_string(serde_json::to_vec(&transaction_data).unwrap())
        .unwrap()
}

/// A date the given number of days from today, so fixtures stay valid
fn date_in(days: i64) -> String {
    (crate::clock::now_utc().date() + time::Duration::days(days))
        .format(crate::config::validator::datatype::DATE_FORMAT)
        .unwrap()
}

fn login_risk_example() -> serde_json::Value {
    json!({
        "type": "urn:eudi:sca:login_risk_transaction:1",
        "credential_ids": ["sca_attestation"],
        "transaction_data_hashes_alg": ["sha-256"],
        "payload": {
            "transaction_id": "3f2a1b7c-8d4e-4f60-9a1b-0c2d3e4f5a6b",
            "date_time": "2026-08-04T12:34:56Z",
            "service": "Superbank Online Banking",
            "action": "Log in to Online Banking"
        }
    })
}

#[test]
fn test_validate_transaction_data_login_risk_example() {
    let metadata = provider(TransactionType::LoginRiskTransaction)
        .validate_transaction_data(&encode(login_risk_example()))
        .unwrap();

    assert_eq!(
        metadata.credential_ids,
        vec![CredentialQueryId::from("sca_attestation")]
    );
}

#[test]
fn test_validate_transaction_data_rejects_empty_credential_ids() {
    let mut transaction_data = login_risk_example();
    transaction_data["credential_ids"] = json!([]);

    let result = provider(TransactionType::LoginRiskTransaction)
        .validate_transaction_data(&encode(transaction_data));

    assert!(matches!(
        result,
        Err(TransactionDataError::InvalidTransactionData(_))
    ));
}

#[test]
fn test_validate_transaction_data_rejects_unanswerable_hash_algorithms() {
    let mut transaction_data = login_risk_example();
    // sha-384 has no hasher registered, sha3-256 is not a known algorithm at all
    transaction_data["transaction_data_hashes_alg"] = json!(["sha-384", "sha3-256"]);

    let result = provider(TransactionType::LoginRiskTransaction)
        .validate_transaction_data(&encode(transaction_data));

    assert!(matches!(
        result,
        Err(TransactionDataError::UnsupportedHashAlgorithm(_))
    ));
}

#[tokio::test]
async fn test_process_transaction_data_hashes_with_the_agreed_algorithm() {
    // hashed over the encoded string as received
    let transaction_data = encode(login_risk_example());

    let processed = provider(TransactionType::LoginRiskTransaction)
        .process_transaction_data(
            &transaction_data,
            FormatType::SdJwtVc,
            iana::HashAlgorithm::Sha512,
        )
        .await
        .unwrap();

    let expected = SHA512.hash_base64_url(transaction_data.as_bytes()).unwrap();
    let ProcessedTransactionData::KbJwtClaims(claims) = processed else {
        panic!("expected KbJwtClaims, got {processed:?}");
    };
    assert_eq!(
        serde_json::Value::Object(claims),
        json!({
            "transaction_data_hashes": [expected],
            "transaction_data_hashes_alg": "sha-512"
        })
    );
}

#[test]
fn test_prepare_transaction_data_wraps_the_payload_in_an_entry() {
    let encoded = provider(TransactionType::LoginRiskTransaction)
        .prepare_transaction_data(
            vec!["sca_attestation".into()],
            Some(json!({
                "transactionId": "3f2a1b7c-8d4e-4f60-9a1b-0c2d3e4f5a6b",
                "dateTime": "2026-08-04T12:34:56Z",
                "service": "Superbank Online Banking",
                "action": "Log in to Online Banking"
            })),
        )
        .unwrap();

    let decoded: serde_json::Value = decode_transaction_data(&encoded).unwrap();
    assert_eq!(decoded, login_risk_example());
}

#[test]
fn test_prepare_transaction_data_drops_parameters_the_type_does_not_define() {
    let encoded = provider(TransactionType::LoginRiskTransaction)
        .prepare_transaction_data(
            vec!["sca_attestation".into()],
            Some(json!({
                "transactionId": "3f2a1b7c-8d4e-4f60-9a1b-0c2d3e4f5a6b",
                "dateTime": "2026-08-04T12:34:56Z",
                "service": "Superbank Online Banking",
                "action": "Log in to Online Banking",
                "signAlgo": "1.2.840.113549.1.1.1"
            })),
        )
        .unwrap();

    let decoded: serde_json::Value = decode_transaction_data(&encoded).unwrap();
    assert_eq!(decoded, login_risk_example());
}

#[test]
fn test_payment_request_maps_onto_the_payload() {
    let encoded = provider(TransactionType::Payment)
        .prepare_transaction_data(
            vec!["sca_attestation".into()],
            Some(json!({
                "transactionId": "8D8AC610-566D-4EF0-9C22-186B2A5ED793",
                "dateTime": "2026-08-04T12:34:56Z",
                "payee": {
                    "name": "Demo Shop",
                    "id": "merchant:ch:123456789",
                    "logo": "https://shop.example/logo.png",
                    "website": "https://shop.example"
                },
                "pisp": {
                    "legalName": "Initiator AG",
                    "brandName": "Initiator",
                    "domainName": "pisp.example"
                },
                "currency": "EUR",
                "amount": 30.0,
                "amountEstimated": true,
                "amountEarmarked": false,
                "sctInst": true,
                "recurrence": {
                    "startDate": "2026-09-01",
                    "endDate": "2027-09-01",
                    "number": 12,
                    "frequency": "MNTH",
                    "mitOptions": {
                        "amountVariable": true,
                        "minAmount": 10.0,
                        "maxAmount": 50.0,
                        "totalAmount": 360.0,
                        "initialAmount": 5.0,
                        "initialAmountNumber": 2,
                        "apr": 4.5
                    }
                }
            })),
        )
        .unwrap();

    let entry: ScaEntry = decode_transaction_data(&encoded).unwrap();
    assert_eq!(
        entry.extension.payload,
        json!({
            "transaction_id": "8D8AC610-566D-4EF0-9C22-186B2A5ED793",
            "date_time": "2026-08-04T12:34:56Z",
            "payee": {
                "name": "Demo Shop",
                "id": "merchant:ch:123456789",
                "logo": "https://shop.example/logo.png",
                "website": "https://shop.example"
            },
            "pisp": {
                "legal_name": "Initiator AG",
                "brand_name": "Initiator",
                "domain_name": "pisp.example"
            },
            "currency": "EUR",
            "amount": 30.0,
            "amount_estimated": true,
            "amount_earmarked": false,
            "sct_inst": true,
            "recurrence": {
                "start_date": "2026-09-01",
                "end_date": "2027-09-01",
                "number": 12,
                "frequency": "MNTH",
                "mit_options": {
                    "amount_variable": true,
                    "min_amount": 10.0,
                    "max_amount": 50.0,
                    "total_amount": 360.0,
                    "initial_amount": 5.0,
                    "initial_amount_number": 2,
                    "apr": 4.5
                }
            }
        })
    );
}

#[test]
fn test_prepare_transaction_data_rejects_an_execution_date_on_a_recurring_payment() {
    let result = provider(TransactionType::Payment).prepare_transaction_data(
        vec!["sca".into()],
        Some(json!({
            "transactionId": "8D8AC610-566D-4EF0-9C22-186B2A5ED793",
            "payee": { "name": "Demo Shop", "id": "merchant:ch:123456789" },
            "currency": "EUR",
            "amount": 30.0,
            "executionDate": "2026-09-01",
            "recurrence": { "frequency": "MNTH" }
        })),
    );

    assert!(matches!(
        result,
        Err(TransactionDataError::InvalidTransactionData(_))
    ));
}

#[test]
fn test_prepare_transaction_data_rejects_an_execution_date_in_the_past() {
    let payment = |execution_date: String| {
        json!({
            "transactionId": "8D8AC610-566D-4EF0-9C22-186B2A5ED793",
            "payee": { "name": "Demo Shop", "id": "merchant:ch:123456789" },
            "currency": "EUR",
            "amount": 30.0,
            "executionDate": execution_date
        })
    };

    let result = provider(TransactionType::Payment)
        .prepare_transaction_data(vec!["sca".into()], Some(payment(date_in(-1))));

    assert!(matches!(
        result,
        Err(TransactionDataError::InvalidTransactionData(_))
    ));

    // a payment executing today has not been missed yet
    provider(TransactionType::Payment)
        .prepare_transaction_data(vec!["sca".into()], Some(payment(date_in(0))))
        .unwrap();
}

#[test]
fn test_prepare_transaction_data_rejects_a_mandate_without_a_purpose_or_payment() {
    let result = provider(TransactionType::Emandate).prepare_transaction_data(
        vec!["sca".into()],
        Some(json!({
            "transactionId": "3F2A1B7C-8D4E-4F60-9A1B-0C2D3E4F5A6B",
            "creditorId": "DE98ZZZ09999999999"
        })),
    );

    assert!(matches!(
        result,
        Err(TransactionDataError::InvalidTransactionData(_))
    ));
}

#[tokio::test]
async fn test_verify_transaction_data_matches_recomputed_evidence() {
    let transaction_data = encode(login_risk_example());
    let provider = provider(TransactionType::LoginRiskTransaction);

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
async fn test_verify_transaction_data_accepts_hash_alongside_those_of_other_entries() {
    let transaction_data = encode(login_risk_example());
    let hash = SHA256.hash_base64_url(transaction_data.as_bytes()).unwrap();

    let presented = json!({
        "transaction_data_hashes": ["hash-of-another-entry", hash, "hash-of-a-third-entry"],
        "transaction_data_hashes_alg": "sha-256"
    });

    let authorization = provider(TransactionType::LoginRiskTransaction)
        .verify_transaction_data(
            &transaction_data,
            FormatType::SdJwtVc,
            &PresentedTransactionData::KbJwtClaims(presented.as_object().unwrap().clone()),
        )
        .await
        .unwrap();

    assert_eq!(authorization, TransactionDataAuthorization::Authorized);
}

#[tokio::test]
async fn test_verify_transaction_data_defaults_to_sha256_where_the_entry_names_no_algorithm() {
    let mut entry = login_risk_example();
    entry
        .as_object_mut()
        .unwrap()
        .remove("transaction_data_hashes_alg");
    let transaction_data = encode(entry);
    let hash = SHA256.hash_base64_url(transaction_data.as_bytes()).unwrap();

    // without algorithms in the entry, the KB-JWT may omit the algorithm claim
    let presented = json!({ "transaction_data_hashes": [hash] });

    let authorization = provider(TransactionType::LoginRiskTransaction)
        .verify_transaction_data(
            &transaction_data,
            FormatType::SdJwtVc,
            &PresentedTransactionData::KbJwtClaims(presented.as_object().unwrap().clone()),
        )
        .await
        .unwrap();

    assert_eq!(authorization, TransactionDataAuthorization::Authorized);
}

#[tokio::test]
async fn test_verify_transaction_data_rejects_missing_evidence() {
    let authorization = provider(TransactionType::LoginRiskTransaction)
        .verify_transaction_data(
            &encode(login_risk_example()),
            FormatType::SdJwtVc,
            &PresentedTransactionData::KbJwtClaims(Default::default()),
        )
        .await
        .unwrap();

    assert_eq!(authorization, TransactionDataAuthorization::NotAuthorized);
}

#[tokio::test]
async fn test_verify_transaction_data_rejects_hash_of_another_entry() {
    let presented = json!({
        "transaction_data_hashes": ["hash-of-another-entry"],
        "transaction_data_hashes_alg": "sha-256"
    });

    let authorization = provider(TransactionType::LoginRiskTransaction)
        .verify_transaction_data(
            &encode(login_risk_example()),
            FormatType::SdJwtVc,
            &PresentedTransactionData::KbJwtClaims(presented.as_object().unwrap().clone()),
        )
        .await
        .unwrap();

    assert_eq!(authorization, TransactionDataAuthorization::NotAuthorized);
}

#[tokio::test]
async fn test_verify_transaction_data_rejects_algorithm_that_was_not_offered() {
    let transaction_data = encode(login_risk_example());
    // correctly computed, but with an algorithm the entry does not offer
    let hash = SHA512.hash_base64_url(transaction_data.as_bytes()).unwrap();

    let presented = json!({
        "transaction_data_hashes": [hash],
        "transaction_data_hashes_alg": "sha-512"
    });

    let authorization = provider(TransactionType::LoginRiskTransaction)
        .verify_transaction_data(
            &transaction_data,
            FormatType::SdJwtVc,
            &PresentedTransactionData::KbJwtClaims(presented.as_object().unwrap().clone()),
        )
        .await
        .unwrap();

    assert_eq!(authorization, TransactionDataAuthorization::NotAuthorized);
}

#[test]
fn test_get_display_data_lists_payload_attributes() {
    let display_data = provider(TransactionType::LoginRiskTransaction)
        .get_display_data(&encode(login_risk_example()))
        .unwrap();

    assert_eq!(
        serde_json::to_value(&display_data).unwrap(),
        json!([
            {
                "title": null,
                "attributes": [
                    {
                        "key": "transactionData.loginRiskTransaction.transactionId",
                        "value": "3f2a1b7c-8d4e-4f60-9a1b-0c2d3e4f5a6b"
                    },
                    {
                        "key": "transactionData.loginRiskTransaction.action",
                        "value": "Log in to Online Banking"
                    },
                    {
                        "key": "transactionData.loginRiskTransaction.service",
                        "value": "Superbank Online Banking"
                    },
                    {
                        "key": "transactionData.loginRiskTransaction.dateTime",
                        "value": "2026-08-04T12:34:56Z"
                    }
                ]
            }
        ])
    );
}
