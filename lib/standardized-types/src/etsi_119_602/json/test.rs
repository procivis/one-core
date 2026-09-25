use ct_codecs::Decoder as _;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::etsi_119_602::json::*;

fn minimal_payload() -> LoTEPayload {
    LoTEPayload {
        list_and_scheme_information: ListAndSchemeInformation {
            lote_version_identifier: 1,
            lote_sequence_number: 1,
            lote_type: Some(LoTEType::EuPidProvidersList),
            scheme_operator_name: vec![MultiLangString {
                lang: "en".into(),
                value: "Test Operator".into(),
            }],
            scheme_information_uri: None,
            status_determination_approach:
                "http://uri.etsi.org/19602/PIDProvidersList/StatusDetn/EU".into(),
            scheme_type_community_rules: None,
            scheme_territory: Some("EU".to_string()),
            scheme_operator_address: None,
            scheme_name: None,
            policy_or_legal_notice: None,
            historical_information_period: None,
            pointers_to_other_lote: None,
            distribution_points: None,
            scheme_extensions: None,
            list_issue_date_time: OffsetDateTime::parse("2025-06-15T12:00:00Z", &Rfc3339).unwrap(),
            next_update: OffsetDateTime::parse("2025-06-16T12:00:00Z", &Rfc3339).unwrap(),
        },
        trusted_entities_list: None,
    }
}

#[test]
fn round_trip_minimal() {
    let payload = minimal_payload();
    let json = serde_json::to_string(&payload).unwrap();
    let deserialized: LoTEPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(payload, deserialized);
}

#[test]
fn document_has_lote_root() {
    let document = LoTEDocument {
        lote: minimal_payload(),
    };
    let json = serde_json::to_value(&document).unwrap();
    assert_eq!(
        json,
        serde_json::json!({ "LoTE": serde_json::to_value(minimal_payload()).unwrap() })
    );
    assert_eq!(document, serde_json::from_value(json).unwrap());
}

/// Backwards compatibility, see [`LoTEDocument`].
#[test]
fn document_accepts_list_without_root() {
    let json = serde_json::to_string(&minimal_payload()).unwrap();
    let document: LoTEDocument = serde_json::from_str(&json).unwrap();
    assert_eq!(minimal_payload(), document.lote);
}

#[test]
fn round_trip_full() {
    let base = minimal_payload();
    let payload = LoTEPayload {
        list_and_scheme_information: ListAndSchemeInformation {
            scheme_operator_address: Some(SchemeOperatorAddress {
                scheme_operator_postal_address: vec![PostalAddress {
                    lang: "en".into(),
                    country: "CH".into(),
                    locality: Some("Zurich".into()),
                    postal_code: Some("8001".into()),
                    street_address: "Bahnhofstrasse 1".into(),
                    state_or_province: None,
                }],
                scheme_operator_electronic_address: vec![MultiLangUri {
                    lang: "en".into(),
                    uri_value: "https://operator.example.com".into(),
                }],
            }),
            scheme_name: Some(vec![MultiLangString {
                lang: "en".into(),
                value: "EU PID Providers List".into(),
            }]),
            scheme_information_uri: Some(vec![MultiLangUri {
                lang: "en".into(),
                uri_value: "https://example.com/scheme-info".into(),
            }]),
            scheme_type_community_rules: Some(vec![MultiLangUri {
                lang: "en".into(),
                uri_value: "http://uri.etsi.org/19602/PIDProviders/schemerules/EU".into(),
            }]),
            policy_or_legal_notice: Some(vec![
                PolicyOrLegalNoticeItem::Policy {
                    lote_policy: MultiLangUri {
                        lang: "en".into(),
                        uri_value: "https://example.com/policy".into(),
                    },
                },
                PolicyOrLegalNoticeItem::LegalNotice {
                    lote_legal_notice: "Legal notice text".into(),
                },
            ]),
            historical_information_period: Some(365),
            distribution_points: Some(vec!["https://example.com/dist".into()]),
            ..base.list_and_scheme_information
        },
        trusted_entities_list: Some(vec![TrustedEntity {
            trusted_entity_information: TrustedEntityInformation {
                te_name: vec![MultiLangString {
                    lang: "en".into(),
                    value: "Example Provider".into(),
                }],
                te_trade_name: Some(vec![MultiLangString {
                    lang: "en".into(),
                    value: "ExProv".into(),
                }]),
                te_address: Some(TEAddress {
                    te_postal_address: Some(vec![PostalAddress {
                        lang: "en".into(),
                        country: "DE".into(),
                        locality: Some("Berlin".into()),
                        postal_code: None,
                        street_address: "Hauptstr. 1".into(),
                        state_or_province: Some("Berlin".into()),
                    }]),
                    te_electronic_address: Some(vec![MultiLangUri {
                        lang: "en".into(),
                        uri_value: "https://example.com".into(),
                    }]),
                }),
                te_information_uri: Some(vec![MultiLangUri {
                    lang: "en".into(),
                    uri_value: "https://example.com/info".into(),
                }]),
                te_information_extensions: None,
            },
            trusted_entity_services: vec![TrustedEntityService {
                service_information: ServiceInformation {
                    service_type_identifier: Some(
                        "http://uri.etsi.org/19602/SvcType/PID/Issuance".to_string(),
                    ),
                    service_name: vec![MultiLangString {
                        lang: "en".into(),
                        value: "PID Issuance".into(),
                    }],
                    service_digital_identity: Some(ServiceDigitalIdentity {
                        x509_certificates: Some(vec![PkiObject {
                            val: "MIIB+base64data".into(),
                            encoding: None,
                            spec_ref: None,
                        }]),
                        x509_subject_names: Some(vec!["CN=Test".into()]),
                        x509_skis: Some(vec!["abc123".into()]),
                        other_ids: None,
                        public_key_values: None,
                    }),
                    service_status: Some(ServiceStatus::PubEaaNotified),
                    status_starting_time: Some(
                        OffsetDateTime::parse("2025-01-01T00:00:00Z", &Rfc3339).unwrap(),
                    ),
                    scheme_service_definition_uri: Some(vec![MultiLangUri {
                        lang: "en".into(),
                        uri_value: "https://example.com/scheme-svc-def".into(),
                    }]),
                    service_supply_points: Some(vec![ServiceSupplyPoint {
                        service_type: Some("issuance".into()),
                        uri_value: "https://example.com/pid".into(),
                    }]),
                    service_definition_uri: Some(vec![MultiLangUri {
                        lang: "en".into(),
                        uri_value: "https://example.com/te-svc-def".into(),
                    }]),
                    service_information_extensions: None,
                },
                service_history: None,
            }],
        }]),
    };

    let json = serde_json::to_string(&payload).unwrap();
    let deserialized: LoTEPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(payload, deserialized);
}

#[test]
fn lote_type_known_variants_serde() {
    let variants = [
        (
            LoTEType::EuPidProvidersList,
            "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList",
        ),
        (
            LoTEType::EuWalletProvidersList,
            "http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList",
        ),
        (
            LoTEType::EuWrpAcProvidersList,
            "http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList",
        ),
        (
            LoTEType::EuWrpRcProvidersList,
            "http://uri.etsi.org/19602/LoTEType/EUWRPRCProvidersList",
        ),
        (
            LoTEType::EuPubEaaProvidersList,
            "http://uri.etsi.org/19602/LoTEType/EUPubEAAProvidersList",
        ),
        (
            LoTEType::EuRegistrarsAndRegistersList,
            "http://uri.etsi.org/19602/LoTEType/EURegistrarsAndRegistersList",
        ),
    ];

    for (variant, uri) in variants {
        let json = serde_json::to_string(&variant).unwrap();
        assert_eq!(json, format!("\"{uri}\""));
        let deserialized: LoTEType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, variant);
    }
}

#[test]
fn lote_type_unknown_variant_serde() {
    let uri = "http://example.org/custom/LoTEType";
    let json = format!("\"{uri}\"");
    let deserialized: LoTEType = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, LoTEType::Other(uri.to_string()));
    let reserialized = serde_json::to_string(&deserialized).unwrap();
    assert_eq!(reserialized, json);
}

/// SPRIND LoTE payload (base64url-decoded from their published JWS).
/// Tests that we correctly parse a real-world JSON LoTE payload.
#[test]
fn parse_sprind_lote_payload() {
    // Payload portion of the SPRIND JWS (base64url-encoded)
    let payload_b64 = "eyJMaXN0QW5kU2NoZW1lSW5mb3JtYXRpb24iOnsiTG9URVZlcnNpb25JZGVudGlmaWVyIjoxLCJMb1RFU2VxdWVuY2VOdW1iZXIiOjEsIkxvVEVUeXBlIjoiaHR0cDovL3VyaS5ldHNpLm9yZy8xOTYwMi9Mb1RFVHlwZS9SZWdpc3RyYXJzQW5kUmVnaXN0ZXJzTGlzdFByb3ZpZGVyc0xpc3QiLCJTY2hlbWVJbmZvcm1hdGlvblVSSSI6W3sibGFuZyI6ImRlLURFIiwidXJpVmFsdWUiOiJodHRwczovL2V4YW1wbGUuY29tL3ByZXZpb3VzLWxpc3RzIn1dLCJTdGF0dXNEZXRlcm1pbmF0aW9uQXBwcm9hY2giOiJodHRwOi8vdXJpLmV0c2kub3JnLzE5NjAyL1JlZ2lzdHJhcnNBbmRSZWdpc3RlcnNMaXN0UHJvdmlkZXJzTGlzdC9TdGF0dXNEZXRuL0VVLiIsIlNjaGVtZVR5cGVDb21tdW5pdHlSdWxlcyI6W3sibGFuZyI6ImRlLURFIiwidXJpVmFsdWUiOiJodHRwOi8vdXJpLmV0c2kub3JnLzE5NjAyL1JlZ2lzdHJhcnNBbmRSZWdpc3RlcnNMaXN0UHJvdmlkZXJzTGlzdC9zY2hlbWVydWxlcy9FVSJ9XSwiU2NoZW1lVGVycml0b3J5IjoiRVUiLCJOZXh0VXBkYXRlIjoiMjAyNi0wMy0wM1QyMzoxMTowNy4xMzNaIiwiU2NoZW1lT3BlcmF0b3JOYW1lIjpbeyJsYW5nIjoiZGUtREUiLCJ2YWx1ZSI6IlNQUklORCBHbWJIIn1dLCJMaXN0SXNzdWVEYXRlVGltZSI6IjIwMjYtMDMtMDJUMjM6MTE6MDcuMTMzWiJ9LCJUcnVzdGVkRW50aXRpZXNMaXN0IjpbeyJUcnVzdGVkRW50aXR5SW5mb3JtYXRpb24iOnsiVEVJbmZvcm1hdGlvblVSSSI6W3sibGFuZyI6ImRlLURFIiwidXJpVmFsdWUiOiJodHRwczovL3d3dy5zcHJpbmQub3JnIn1dLCJURU5hbWUiOlt7ImxhbmciOiJkZS1ERSIsInZhbHVlIjoiU1BSSU5EIEdtYkgifV0sIlRFQWRkcmVzcyI6eyJURUVsZWN0cm9uaWNBZGRyZXNzIjpbeyJsYW5nIjoiZGUtREUiLCJ1cmlWYWx1ZSI6Imh0dHBzOi8vc3ByaW5kLm9yZy9jb250YWN0In1dLCJURVBvc3RhbEFkZHJlc3MiOlt7IkNvdW50cnkiOiJERSIsImxhbmciOiJkZSIsIkxvY2FsaXR5IjoiTGVpcHppZyIsIlBvc3RhbENvZGUiOiIwNDEwMyIsIlN0cmVldEFkZHJlc3MiOiJMYWdlcmhvZnN0cmHDn2UgNCJ9XX19LCJUcnVzdGVkRW50aXR5U2VydmljZXMiOlt7IlNlcnZpY2VJbmZvcm1hdGlvbiI6eyJTZXJ2aWNlVHlwZUlkZW50aWZpZXIiOiJodHRwOi8vdXJpLmV0c2kub3JnLzE5NjAyL1N2Y1R5cGUvUmVnaXN0cmFyc0FuZFJlZ2lzdGVyc0xpc3RTb2x1dGlvbi9Jc3N1YW5jZSIsIlNlcnZpY2VOYW1lIjpbeyJsYW5nIjoiZGUtREUiLCJ2YWx1ZSI6IkFjY2VzcyBDZXJ0aWZpY2F0ZSBBdXNzdGVsbHVuZ3NkaWVuc3QgZGVyIFNQUklORCBHbWJIIn1dLCJTZXJ2aWNlRGlnaXRhbElkZW50aXR5Ijp7Ilg1MDlDZXJ0aWZpY2F0ZXMiOlt7InZhbCI6Ik1JSUNMekNDQWRTZ0F3SUJBZ0lVSHlSakU0NjZZQTd0Yzg4OGswM091MlFvZEY0d0NnWUlLb1pJemowRUF3SXdLREVMTUFrR0ExVUVCaE1DUkVVeEdUQVhCZ05WQkFNTUVFZGxjbTFoYmlCU1pXZHBjM1J5WVhJd0hoY05Nall3TVRFMk1URXhOVFUwV2hjTk1qZ3dNVEUyTVRFeE5UVTBXakFvTVFzd0NRWURWUVFHRXdKRVJURVpNQmNHQTFVRUF3d1FSMlZ5YldGdUlGSmxaMmx6ZEhKaGNqQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJNZWZZMlg0aXhmUmtXRXZwOWdyRjJpMjF6NlBLWnNyOHp6QmFKLytHbm90Q2VIMmNKNkd0TGh4WGhIZkpqckVUc01OSUdoVmFKb0hvSGNaVEJISnJmeWpnZHN3Z2Rnd0hRWURWUjBPQkJZRUZLbkNvOW92YmF4VTdzNjVUdWdzeVN3QWc0QXpNQjhHQTFVZEl3UVlNQmFBRktuQ285b3ZiYXhVN3M2NVR1Z3N5U3dBZzRBek1CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRQXdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Db0dBMVVkRWdRak1DR0dIMmgwZEhCek9pOHZjMkZ1WkdKdmVDNWxkV1JwTFhkaGJHeGxkQzV2Y21jd1JnWURWUjBmQkQ4d1BUQTdvRG1nTjRZMWFIUjBjSE02THk5ellXNWtZbTk0TG1WMVpHa3RkMkZzYkdWMExtOXlaeTl6ZEdGMGRYTXRiV0Z1WVdkbGJXVnVkQzlqY213d0NnWUlLb1pJemowRUF3SURTUUF3UmdJaEFJWTdFUnBSckRSbDBscjVINXV4ako4M0pSNHF1YTJzZlBLeFgrcGw0UXcrQWlFQTJxTDZMWFZPUkEycjJWWmpTRWtuZmNpd0lHN2xhQTEya2pueUdBRDNWL0E9In1dfX19LHsiU2VydmljZUluZm9ybWF0aW9uIjp7IlNlcnZpY2VOYW1lIjpbeyJsYW5nIjoiZGUtREUiLCJ2YWx1ZSI6IkFjY2VzcyBDZXJ0aWZpY2F0ZS1SZXZva2F0aW9uc2RpZW5zdCBkZXIgU1BSSU5EIEdtYkgifV0sIlNlcnZpY2VUeXBlSWRlbnRpZmllciI6Imh0dHA6Ly91cmkuZXRzaS5vcmcvMTk2MDIvU3ZjVHlwZS9SZWdpc3RyYXJzQW5kUmVnaXN0ZXJzTGlzdFNvbHV0aW9uL1Jldm9jYXRpb24iLCJTZXJ2aWNlRGlnaXRhbElkZW50aXR5Ijp7Ilg1MDlDZXJ0aWZpY2F0ZXMiOlt7InZhbCI6Ik1JSUNMekNDQWRTZ0F3SUJBZ0lVSHlSakU0NjZZQTd0Yzg4OGswM091MlFvZEY0d0NnWUlLb1pJemowRUF3SXdLREVMTUFrR0ExVUVCaE1DUkVVeEdUQVhCZ05WQkFNTUVFZGxjbTFoYmlCU1pXZHBjM1J5WVhJd0hoY05Nall3TVRFMk1URXhOVFUwV2hjTk1qZ3dNVEUyTVRFeE5UVTBXakFvTVFzd0NRWURWUVFHRXdKRVJURVpNQmNHQTFVRUF3d1FSMlZ5YldGdUlGSmxaMmx6ZEhKaGNqQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJNZWZZMlg0aXhmUmtXRXZwOWdyRjJpMjF6NlBLWnNyOHp6QmFKLytHbm90Q2VIMmNKNkd0TGh4WGhIZkpqckVUc01OSUdoVmFKb0hvSGNaVEJISnJmeWpnZHN3Z2Rnd0hRWURWUjBPQkJZRUZLbkNvOW92YmF4VTdzNjVUdWdzeVN3QWc0QXpNQjhHQTFVZEl3UVlNQmFBRktuQ285b3ZiYXhVN3M2NVR1Z3N5U3dBZzRBek1CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRQXdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Db0dBMVVkRWdRak1DR0dIMmgwZEhCek9pOHZjMkZ1WkdKdmVDNWxkV1JwTFhkaGJHeGxkQzV2Y21jd1JnWURWUjBmQkQ4d1BUQTdvRG1nTjRZMWFIUjBjSE02THk5ellXNWtZbTk0TG1WMVpHa3RkMkZzYkdWMExtOXlaeTl6ZEdGMGRYTXRiV0Z1WVdkbGJXVnVkQzlqY213d0NnWUlLb1pJemowRUF3SURTUUF3UmdJaEFJWTdFUnBSckRSbDBscjVINXV4ako4M0pSNHF1YTJzZlBLeFgrcGw0UXcrQWlFQTJxTDZMWFZPUkEycjJWWmpTRWtuZmNpd0lHN2xhQTEya2pueUdBRDNWL0E9In1dfX19XX1dfQ";

    let payload_json = ct_codecs::Base64UrlSafeNoPadding::decode_to_vec(payload_b64, None).unwrap();
    let payload: LoTEPayload = serde_json::from_slice(&payload_json).unwrap();

    let info = &payload.list_and_scheme_information;
    assert_eq!(info.lote_version_identifier, 1);
    assert_eq!(info.lote_sequence_number, 1);
    assert_eq!(
        info.lote_type,
        Some(LoTEType::Other(
            "http://uri.etsi.org/19602/LoTEType/RegistrarsAndRegistersListProvidersList"
                .to_string()
        ))
    );
    assert_eq!(info.scheme_territory, Some("EU".to_string()));
    assert_eq!(info.scheme_operator_name[0].value, "SPRIND GmbH");

    let entities = payload.trusted_entities_list.as_ref().unwrap();
    assert_eq!(entities.len(), 1);
    assert_eq!(
        entities[0].trusted_entity_information.te_name[0].value,
        "SPRIND GmbH"
    );
    assert_eq!(entities[0].trusted_entity_services.len(), 2);

    let te_addr = entities[0]
        .trusted_entity_information
        .te_address
        .as_ref()
        .unwrap();
    let postal = te_addr.te_postal_address.as_ref().unwrap();
    assert_eq!(postal[0].country, "DE");
    assert_eq!(postal[0].locality, Some("Leipzig".into()));
    assert_eq!(postal[0].street_address, "Lagerhofstra\u{df}e 4");
}

#[test]
fn pascal_case_field_names() {
    let payload = minimal_payload();
    let json = serde_json::to_string(&payload).unwrap();

    assert!(json.contains("\"ListAndSchemeInformation\""));
    assert!(json.contains("\"LoTEVersionIdentifier\""));
    assert!(json.contains("\"LoTESequenceNumber\""));
    assert!(json.contains("\"SchemeOperatorName\""));
    assert!(json.contains("\"StatusDeterminationApproach\""));
    assert!(json.contains("\"ListIssueDateTime\""));
    assert!(json.contains("\"NextUpdate\""));
}

#[test]
fn optional_fields_absent_when_none() {
    let payload = minimal_payload();
    let json = serde_json::to_string(&payload).unwrap();

    assert!(!json.contains("\"TrustedEntitiesList\""));
    assert!(!json.contains("\"SchemeOperatorAddress\""));
    assert!(!json.contains("\"SchemeName\""));
    assert!(!json.contains("\"PolicyOrLegalNotice\""));
    assert!(!json.contains("\"HistoricalInformationPeriod\""));
    assert!(!json.contains("\"PointersToOtherLoTE\""));
    assert!(!json.contains("\"DistributionPoints\""));
    assert!(!json.contains("\"SchemeExtensions\""));
}

/// `LoTEQualifiers` is an array in the JSON binding (TS 119 602 v1.1.1) and a single object in XML.
/// Earlier versions of core published a single object in JSON; that is fixed, and such lists stay readable.
#[test]
fn pointer_qualifiers_are_an_array() {
    let qualifier = serde_json::json!({
        "LoTEType": "http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList",
        "SchemeOperatorName": [{ "lang": "en", "value": "Example" }],
        "MimeType": "application/jose"
    });
    let pointer = |qualifiers: serde_json::Value| -> OtherLoTEPointer {
        serde_json::from_value(serde_json::json!({
            "LoTELocation": "https://example.com/lote.jwt",
            "ServiceDigitalIdentities": [],
            "LoTEQualifiers": qualifiers
        }))
        .unwrap()
    };

    assert_eq!(
        1,
        pointer(serde_json::json!([qualifier]))
            .lote_qualifiers
            .len()
    );
    assert_eq!(1, pointer(qualifier).lote_qualifiers.len());
}
