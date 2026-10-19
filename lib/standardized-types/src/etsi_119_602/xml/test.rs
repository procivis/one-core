use similar_asserts::assert_eq;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::etsi_119_602::xml::*;

fn serialize(payload: &LoTEPayload) -> String {
    let mut output = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    output.push_str(&quick_xml::se::to_string(payload).unwrap());
    output
}

fn deserialize(xml: &str) -> LoTEPayload {
    quick_xml::de::from_str(xml).unwrap()
}

fn minimal_payload() -> LoTEPayload {
    let issue_date = OffsetDateTime::parse("2025-06-15T12:00:00Z", &Rfc3339).unwrap();
    let next_update = OffsetDateTime::parse("2025-06-16T12:00:00Z", &Rfc3339).unwrap();

    LoTEPayload {
        lote_tag: "http://uri.etsi.org/019602/tag#".to_string(),
        xmlns: "http://uri.etsi.org/019602/v1#".to_string(),
        list_and_scheme_information: ListAndSchemeInformation {
            lote_version_identifier: 1,
            lote_sequence_number: 1,
            lote_type: Some(LoTEType::EuPidProvidersList),
            scheme_operator_name: MultiLangNameList {
                names: vec![MultiLangString {
                    lang: "en".into(),
                    value: "Test Operator".into(),
                }],
            },
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
            list_issue_date_time: issue_date,
            next_update: NextUpdate {
                date_time: next_update,
            },
        },
        trusted_entities_list: None,
    }
}

#[test]
fn serialize_empty_trust_list() {
    let payload = minimal_payload();
    let xml = serialize(&payload);

    println!("{}", xml);

    assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    assert!(xml.contains("xmlns=\"http://uri.etsi.org/019602/v1#\""));
    assert!(xml.contains("LOTETag=\"http://uri.etsi.org/019602/tag#\""));
    assert!(xml.contains("<LoTEVersionIdentifier>1</LoTEVersionIdentifier>"));
    assert!(xml.contains("<LoTESequenceNumber>1</LoTESequenceNumber>"));
    assert!(
        xml.contains("<LoTEType>http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList</LoTEType>")
    );
    assert!(xml.contains("<SchemeOperatorName>"));
    assert!(xml.contains("<Name xml:lang=\"en\">Test Operator</Name>"));
    assert!(xml.contains("<SchemeTerritory>EU</SchemeTerritory>"));
    assert!(xml.contains("<ListIssueDateTime>2025-06-15T12:00:00Z</ListIssueDateTime>"));
    assert!(xml.contains("<NextUpdate>"));
    assert!(xml.contains("<dateTime>2025-06-16T12:00:00Z</dateTime>"));
    assert!(!xml.contains("<TrustedEntitiesList>"));
}

#[test]
fn serialize_trust_list_with_entity() {
    let payload = LoTEPayload {
        trusted_entities_list: Some(TrustedEntitiesList {
            entities: vec![TrustedEntity {
                trusted_entity_information: TrustedEntityInformation {
                    te_name: MultiLangNameList {
                        names: vec![MultiLangString {
                            lang: "en".into(),
                            value: "Example Provider".into(),
                        }],
                    },
                    te_information_uri: Some(MultiLangUriList {
                        uris: vec![MultiLangUri {
                            lang: "en".into(),
                            uri_value: "https://example.com/info".into(),
                        }],
                    }),
                    te_address: Some(TEAddress {
                        te_electronic_address: Some(MultiLangUriList {
                            uris: vec![MultiLangUri {
                                lang: "en".into(),
                                uri_value: "https://example.com".into(),
                            }],
                        }),
                        te_postal_address: Some(PostalAddresses {
                            addresses: vec![PostalAddress {
                                lang: "en".into(),
                                country: "DE".into(),
                                locality: Some("Berlin".into()),
                                postal_code: None,
                                street_address: "Hauptstr. 1".into(),
                                state_or_province: None,
                            }],
                        }),
                    }),
                    te_trade_name: None,
                    te_information_extensions: None,
                },
                trusted_entity_services: TrustedEntityServices {
                    services: vec![TrustedEntityService {
                        service_information: ServiceInformation {
                            service_type_identifier: Some(
                                "http://uri.etsi.org/19602/SvcType/PID/Issuance".to_string(),
                            ),
                            service_name: MultiLangNameList {
                                names: vec![MultiLangString {
                                    lang: "en".into(),
                                    value: "PID Issuance".into(),
                                }],
                            },
                            service_digital_identity: Some(ServiceDigitalIdentity {
                                x509_certificates: Some(vec!["MIIB...".into()]),
                                ..Default::default()
                            }),
                            service_supply_points: Some(ServiceSupplyPoints {
                                points: vec![ServiceSupplyPoint {
                                    service_type: None,
                                    uri_value: "https://example.com/pid".into(),
                                }],
                            }),
                            service_status: None,
                            status_starting_time: None,
                            scheme_service_definition_uri: None,
                            service_definition_uri: None,
                            service_information_extensions: None,
                        },
                        service_history: None,
                    }],
                },
            }],
        }),
        ..minimal_payload()
    };

    let xml = serialize(&payload);

    assert!(xml.contains("<TrustedEntitiesList>"));
    assert!(xml.contains("<TrustedEntity>"));
    assert!(xml.contains("<TEName>"));
    assert!(xml.contains("<Name xml:lang=\"en\">Example Provider</Name>"));
    assert!(xml.contains("<TEAddress>"));
    assert!(xml.contains("<PostalAddresses>"));
    assert!(xml.contains("<PostalAddress xml:lang=\"en\">"));
    assert!(xml.contains("<CountryName>DE</CountryName>"));
    assert!(xml.contains("<StreetAddress>Hauptstr. 1</StreetAddress>"));
    assert!(xml.contains("<ElectronicAddress>"));
    assert!(xml.contains("<TEInformationURI>"));
    assert!(xml.contains("<ServiceTypeIdentifier>http://uri.etsi.org/19602/SvcType/PID/Issuance</ServiceTypeIdentifier>"));
    assert!(xml.contains("<X509Certificate>MIIB...</X509Certificate>"));
    assert!(xml.contains("<ServiceSupplyPoint>https://example.com/pid</ServiceSupplyPoint>"));
}

#[test]
fn round_trip_minimal() {
    let mut payload = minimal_payload();
    payload.list_and_scheme_information.lote_sequence_number = 42;
    let xml = serialize(&payload);
    let deserialized = deserialize(&xml);
    assert_eq!(payload, deserialized);
}

#[test]
fn round_trip_with_entities() {
    let mut base = minimal_payload();
    base.list_and_scheme_information.lote_sequence_number = 42;

    let original = LoTEPayload {
        lote_tag: LOTE_TAG.to_string(),
        xmlns: LOTE_NS.to_string(),
        list_and_scheme_information: ListAndSchemeInformation {
            scheme_operator_address: Some(SchemeOperatorAddress {
                scheme_operator_postal_address: PostalAddresses {
                    addresses: vec![PostalAddress {
                        lang: "en".into(),
                        country: "CH".into(),
                        locality: Some("Zurich".into()),
                        postal_code: Some("8001".into()),
                        street_address: "Bahnhofstrasse 1".into(),
                        state_or_province: None,
                    }],
                },
                scheme_operator_electronic_address: MultiLangUriList {
                    uris: vec![MultiLangUri {
                        lang: "en".into(),
                        uri_value: "https://operator.example.com".into(),
                    }],
                },
            }),
            scheme_name: Some(MultiLangNameList {
                names: vec![MultiLangString {
                    lang: "en".into(),
                    value: "EU PID Providers List".into(),
                }],
            }),
            scheme_information_uri: Some(MultiLangUriList {
                uris: vec![MultiLangUri {
                    lang: "en".into(),
                    uri_value: "https://example.com/scheme-info".into(),
                }],
            }),
            scheme_type_community_rules: Some(MultiLangUriList {
                uris: vec![MultiLangUri {
                    lang: "en".into(),
                    uri_value: "http://uri.etsi.org/19602/PIDProviders/schemerules/EU".into(),
                }],
            }),
            policy_or_legal_notice: Some(PolicyOrLegalNotice {
                items: vec![
                    PolicyOrLegalNoticeItem::LoTEPolicy(MultiLangUri {
                        lang: "en".into(),
                        uri_value: "https://example.com/policy".into(),
                    }),
                    PolicyOrLegalNoticeItem::LoTELegalNotice(MultiLangString {
                        lang: "en".into(),
                        value: "Legal notice text".into(),
                    }),
                ],
            }),
            historical_information_period: Some(365),
            distribution_points: Some(UriList {
                uris: vec!["https://example.com/dist".into()],
            }),
            ..base.list_and_scheme_information
        },
        trusted_entities_list: Some(TrustedEntitiesList {
            entities: vec![TrustedEntity {
                trusted_entity_information: TrustedEntityInformation {
                    te_name: MultiLangNameList {
                        names: vec![MultiLangString {
                            lang: "en".into(),
                            value: "Example Provider".into(),
                        }],
                    },
                    te_trade_name: Some(MultiLangNameList {
                        names: vec![MultiLangString {
                            lang: "en".into(),
                            value: "ExProv".into(),
                        }],
                    }),
                    te_address: Some(TEAddress {
                        te_postal_address: Some(PostalAddresses {
                            addresses: vec![PostalAddress {
                                lang: "en".into(),
                                country: "DE".into(),
                                locality: Some("Berlin".into()),
                                postal_code: None,
                                street_address: "Hauptstr. 1".into(),
                                state_or_province: Some("Berlin".into()),
                            }],
                        }),
                        te_electronic_address: Some(MultiLangUriList {
                            uris: vec![MultiLangUri {
                                lang: "en".into(),
                                uri_value: "https://example.com".into(),
                            }],
                        }),
                    }),
                    te_information_uri: Some(MultiLangUriList {
                        uris: vec![MultiLangUri {
                            lang: "en".into(),
                            uri_value: "https://example.com/info".into(),
                        }],
                    }),
                    te_information_extensions: None,
                },
                trusted_entity_services: TrustedEntityServices {
                    services: vec![TrustedEntityService {
                        service_information: ServiceInformation {
                            service_type_identifier: Some(
                                "http://uri.etsi.org/19602/SvcType/PID/Issuance".to_string(),
                            ),
                            service_name: MultiLangNameList {
                                names: vec![MultiLangString {
                                    lang: "en".into(),
                                    value: "PID Issuance".into(),
                                }],
                            },
                            service_digital_identity: Some(ServiceDigitalIdentity {
                                x509_certificates: Some(vec!["MIIB+base64data".into()]),
                                x509_subject_names: Some(vec!["CN=Test".into()]),
                                x509_skis: Some(vec!["abc123".into()]),
                                other_ids: None,
                                public_key_values: None,
                            }),
                            service_status: Some(ServiceStatus::PubEaaNotified),
                            status_starting_time: Some(
                                OffsetDateTime::parse("2025-01-01T00:00:00Z", &Rfc3339).unwrap(),
                            ),
                            scheme_service_definition_uri: Some(MultiLangUriList {
                                uris: vec![MultiLangUri {
                                    lang: "en".into(),
                                    uri_value: "https://example.com/scheme-svc-def".into(),
                                }],
                            }),
                            service_supply_points: Some(ServiceSupplyPoints {
                                points: vec![
                                    ServiceSupplyPoint {
                                        service_type: Some("issuance".into()),
                                        uri_value: "https://example.com/pid".into(),
                                    },
                                    ServiceSupplyPoint {
                                        service_type: None,
                                        uri_value: "https://example.com/pid2".into(),
                                    },
                                ],
                            }),
                            service_definition_uri: Some(MultiLangUriList {
                                uris: vec![MultiLangUri {
                                    lang: "en".into(),
                                    uri_value: "https://example.com/te-svc-def".into(),
                                }],
                            }),
                            service_information_extensions: None,
                        },
                        service_history: None,
                    }],
                },
            }],
        }),
    };

    let xml = serialize(&original);
    let deserialized = deserialize(&xml);
    assert_eq!(original, deserialized);
}

#[test]
fn parse_minimal_xml() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListOfTrustedEntities xmlns="http://uri.etsi.org/019602/v1#">
  <ListAndSchemeInformation>
    <LoTEVersionIdentifier>5</LoTEVersionIdentifier>
    <LoTESequenceNumber>10</LoTESequenceNumber>
    <LoTEType>http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList</LoTEType>
    <SchemeOperatorName>
      <Name xml:lang="en">My Operator</Name>
    </SchemeOperatorName>
    <StatusDeterminationApproach>http://example.com/status</StatusDeterminationApproach>
    <SchemeTerritory>EU</SchemeTerritory>
    <ListIssueDateTime>2025-07-01T00:00:00Z</ListIssueDateTime>
    <NextUpdate>
      <dateTime>2025-07-02T00:00:00Z</dateTime>
    </NextUpdate>
  </ListAndSchemeInformation>
</ListOfTrustedEntities>"#;

    let payload: LoTEPayload = deserialize(xml);

    assert_eq!(
        payload.list_and_scheme_information.lote_version_identifier,
        5
    );
    assert_eq!(payload.list_and_scheme_information.lote_sequence_number, 10);
    assert_eq!(
        payload.list_and_scheme_information.lote_type,
        Some(LoTEType::EuPidProvidersList)
    );
    assert_eq!(
        payload
            .list_and_scheme_information
            .scheme_operator_name
            .names[0]
            .value,
        "My Operator"
    );
    assert_eq!(
        payload
            .list_and_scheme_information
            .scheme_operator_name
            .names[0]
            .lang,
        "en"
    );
    assert_eq!(
        payload.list_and_scheme_information.scheme_territory,
        Some("EU".to_string())
    );
    assert_eq!(
        payload.list_and_scheme_information.list_issue_date_time,
        OffsetDateTime::parse("2025-07-01T00:00:00Z", &Rfc3339).unwrap()
    );
    assert_eq!(
        payload.list_and_scheme_information.next_update.date_time,
        OffsetDateTime::parse("2025-07-02T00:00:00Z", &Rfc3339).unwrap()
    );
    assert!(payload.trusted_entities_list.is_none());
}

const DSS_VALID_EMPTY_TE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<ListOfTrustedEntities xmlns="http://uri.etsi.org/019602/v1#" LOTETag="http://uri.etsi.org/019602/tag#"
                       xmlns:tie="http://uri.etsi.org/019602/v1/TrustedEntityExtensions">
    <ListAndSchemeInformation>
        <LoTEVersionIdentifier>1</LoTEVersionIdentifier>
        <LoTESequenceNumber>42</LoTESequenceNumber>
        <LoTEType>http://example.org/LoTE/type</LoTEType>
        <SchemeOperatorName>
            <Name xml:lang="fr">Agence Nationale de la Confiance Num&#233;rique</Name>
            <Name xml:lang="en">National Agency for Digital Trust</Name>
        </SchemeOperatorName>
        <SchemeOperatorAddress>
            <PostalAddresses>
                <PostalAddress xml:lang="fr">
                    <StreetAddress>12 Boulevard S&#233;curit&#233;</StreetAddress>
                    <Locality>Paris</Locality>
                    <StateOrProvince>&#206;le-de-France</StateOrProvince>
                    <PostalCode>75015</PostalCode>
                    <CountryName>FR</CountryName>
                </PostalAddress>
                <PostalAddress xml:lang="en">
                    <StreetAddress>12 Security Boulevard</StreetAddress>
                    <Locality>Paris</Locality>
                    <StateOrProvince>Ile-de-France</StateOrProvince>
                    <PostalCode>75015</PostalCode>
                    <CountryName>FR</CountryName>
                </PostalAddress>
            </PostalAddresses>
            <ElectronicAddress>
                <URI xml:lang="en">mailto@schemeoperator.com</URI>
            </ElectronicAddress>
        </SchemeOperatorAddress>
        <SchemeName>
            <Name xml:lang="fr">Liste de confiance fran&#231;aise</Name>
            <Name xml:lang="en">French Trusted List</Name>
        </SchemeName>
        <SchemeInformationURI>
            <URI xml:lang="en">https://example.org/scheme-info</URI>
        </SchemeInformationURI>
        <StatusDeterminationApproach>https://example.org/status</StatusDeterminationApproach>
        <ListIssueDateTime>2025-07-16T12:00:00Z</ListIssueDateTime>
        <NextUpdate>
            <dateTime>2025-08-16T12:00:00Z</dateTime>
        </NextUpdate>
    </ListAndSchemeInformation>
</ListOfTrustedEntities>"#;

const DSS_VALID: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<ListOfTrustedEntities xmlns="http://uri.etsi.org/019602/v1#" LOTETag="http://uri.etsi.org/019602/tag#"
                       xmlns:tie="http://uri.etsi.org/019602/v1/TrustedEntityExtensions">
    <ListAndSchemeInformation>
        <LoTEVersionIdentifier>1</LoTEVersionIdentifier>
        <LoTESequenceNumber>42</LoTESequenceNumber>
        <LoTEType>http://example.org/LoTE/type</LoTEType>
        <SchemeOperatorName>
            <Name xml:lang="fr">Agence Nationale de la Confiance Num&#233;rique</Name>
            <Name xml:lang="en">National Agency for Digital Trust</Name>
        </SchemeOperatorName>
        <SchemeOperatorAddress>
            <PostalAddresses>
                <PostalAddress xml:lang="fr">
                    <StreetAddress>12 Boulevard S&#233;curit&#233;</StreetAddress>
                    <Locality>Paris</Locality>
                    <StateOrProvince>&#206;le-de-France</StateOrProvince>
                    <PostalCode>75015</PostalCode>
                    <CountryName>FR</CountryName>
                </PostalAddress>
                <PostalAddress xml:lang="en">
                    <StreetAddress>12 Security Boulevard</StreetAddress>
                    <Locality>Paris</Locality>
                    <StateOrProvince>Ile-de-France</StateOrProvince>
                    <PostalCode>75015</PostalCode>
                    <CountryName>FR</CountryName>
                </PostalAddress>
            </PostalAddresses>
            <ElectronicAddress>
                <URI xml:lang="en">mailto@schemeoperator.com</URI>
            </ElectronicAddress>
        </SchemeOperatorAddress>
        <SchemeName>
            <Name xml:lang="fr">Liste de confiance fran&#231;aise</Name>
            <Name xml:lang="en">French Trusted List</Name>
        </SchemeName>
        <SchemeInformationURI>
            <URI xml:lang="en">https://example.org/scheme-info</URI>
        </SchemeInformationURI>
        <StatusDeterminationApproach>https://example.org/status</StatusDeterminationApproach>
        <ListIssueDateTime>2025-07-16T12:00:00Z</ListIssueDateTime>
        <NextUpdate>
            <dateTime>2025-08-16T12:00:00Z</dateTime>
        </NextUpdate>
    </ListAndSchemeInformation>
    <TrustedEntitiesList>
        <TrustedEntity>
            <TrustedEntityInformation>
                <TEName>
                    <Name xml:lang="fr">Prestataire Confiance SA</Name>
                    <Name xml:lang="en">Trust Provider Inc.</Name>
                </TEName>
                <TEAddress>
                    <PostalAddresses>
                        <PostalAddress xml:lang="fr">
                            <StreetAddress>1 Rue de la Confiance</StreetAddress>
                            <Locality>Paris</Locality>
                            <PostalCode>75001</PostalCode>
                            <CountryName>FR</CountryName>
                        </PostalAddress>
                    </PostalAddresses>
                    <ElectronicAddress>
                        <URI xml:lang="en">https://example.org</URI>
                        <URI xml:lang="en">mailto:contact@example.org</URI>
                    </ElectronicAddress>
                </TEAddress>
                <TEInformationURI>
                    <URI xml:lang="en">https://example.org/info</URI>
                </TEInformationURI>
                <TEInformationExtensions>
                    <Extension Critical="false">
                        <tie:OtherAssociatedBodies>
                            <tie:AssociatedBody>
                                <tie:AssociatedBodyName>
                                    <Name xml:lang="fr">Minist&#232;re de la Transition Num&#233;rique</Name>
                                    <Name xml:lang="en">Ministry of Digital Transformation</Name>
                                </tie:AssociatedBodyName>
                            </tie:AssociatedBody>
                        </tie:OtherAssociatedBodies>
                    </Extension>
                </TEInformationExtensions>
            </TrustedEntityInformation>
            <TrustedEntityServices>
                <TrustedEntityService>
                    <ServiceInformation>
                        <ServiceName>
                            <Name xml:lang="fr">Horodatage</Name>
                            <Name xml:lang="en">Timestamping</Name>
                        </ServiceName>
                        <ServiceDigitalIdentity>
                            <DigitalId>
                                <X509Certificate>c2FtcGxlY2VydGlmaWNhdGU=</X509Certificate>
                            </DigitalId>
                        </ServiceDigitalIdentity>
                        <StatusStartingTime>2019-06-01T00:00:00Z</StatusStartingTime>
                    </ServiceInformation>
                </TrustedEntityService>
            </TrustedEntityServices>
        </TrustedEntity>
    </TrustedEntitiesList>
</ListOfTrustedEntities>"#;

const DSS_VALID_FULL: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<ListOfTrustedEntities xmlns="http://uri.etsi.org/019602/v1#" LOTETag="http://uri.etsi.org/019602/tag#"
                       xmlns:tie="http://uri.etsi.org/019602/v1/TrustedEntityExtensions" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ListAndSchemeInformation>
        <LoTEVersionIdentifier>1</LoTEVersionIdentifier>
        <LoTESequenceNumber>42</LoTESequenceNumber>
        <LoTEType>http://example.org/LoTE/type</LoTEType>
        <SchemeOperatorName>
            <Name xml:lang="fr">Agence Nationale de la Confiance Num&#233;rique</Name>
            <Name xml:lang="en">National Agency for Digital Trust</Name>
        </SchemeOperatorName>
        <SchemeOperatorAddress>
            <PostalAddresses>
                <PostalAddress xml:lang="fr">
                    <StreetAddress>12 Boulevard S&#233;curit&#233;</StreetAddress>
                    <Locality>Paris</Locality>
                    <StateOrProvince>&#206;le-de-France</StateOrProvince>
                    <PostalCode>75015</PostalCode>
                    <CountryName>FR</CountryName>
                </PostalAddress>
                <PostalAddress xml:lang="en">
                    <StreetAddress>12 Security Boulevard</StreetAddress>
                    <Locality>Paris</Locality>
                    <StateOrProvince>Ile-de-France</StateOrProvince>
                    <PostalCode>75015</PostalCode>
                    <CountryName>FR</CountryName>
                </PostalAddress>
            </PostalAddresses>
            <ElectronicAddress>
                <URI xml:lang="fr">mailto:contact@trust.gov.fr</URI>
                <URI xml:lang="en">mailto:contact@trust.gov.fr</URI>
            </ElectronicAddress>
        </SchemeOperatorAddress>
        <SchemeName>
            <Name xml:lang="fr">Liste de confiance fran&#231;aise</Name>
            <Name xml:lang="en">French Trusted List</Name>
        </SchemeName>
        <SchemeInformationURI>
            <URI xml:lang="fr">https://trust.gov.fr/info</URI>
            <URI xml:lang="en">https://trust.gov.fr/en/info</URI>
        </SchemeInformationURI>
        <StatusDeterminationApproach>http://example.org/status/automated</StatusDeterminationApproach>
        <SchemeTypeCommunityRules>
            <URI xml:lang="en">https://rules.eutrust.org</URI>
        </SchemeTypeCommunityRules>
        <SchemeTerritory>FR</SchemeTerritory>
        <PolicyOrLegalNotice>
            <LoTEPolicy xml:lang="fr">https://trust.gov.fr/politique</LoTEPolicy>
        </PolicyOrLegalNotice>
        <HistoricalInformationPeriod>24</HistoricalInformationPeriod>
        <PointersToOtherLoTE>
            <OtherLoTEPointer>
                <ServiceDigitalIdentities>
                    <ServiceDigitalIdentity>
                        <DigitalId>
                            <ds:KeyValue>
                                <ds:RSAKeyValue>
                                    <ds:Modulus>c2FtcGxlY2VydGlmaWNhdGU=</ds:Modulus>
                                    <ds:Exponent>AQAB</ds:Exponent>
                                </ds:RSAKeyValue>
                            </ds:KeyValue>
                        </DigitalId>
                    </ServiceDigitalIdentity>
                </ServiceDigitalIdentities>
                <LoTELocation>https://other-lote.example.org/lotefile.xml</LoTELocation>
                <AdditionalInformation>
                    <TextualInformation xml:lang="en">Additional information description</TextualInformation>
                </AdditionalInformation>
            </OtherLoTEPointer>
        </PointersToOtherLoTE>
        <ListIssueDateTime>2025-07-16T12:00:00Z</ListIssueDateTime>
        <NextUpdate>
            <dateTime>2025-08-16T12:00:00Z</dateTime>
        </NextUpdate>
        <DistributionPoints>
            <URI>https://trust.gov.fr/distribution.xml</URI>
        </DistributionPoints>
        <SchemeExtensions>
            <Extension Critical="false">
                <re:Remark xmlns:re="http://uri.etsi.org/019602/v1/remark">Extension personnalis&#233;e</re:Remark>
            </Extension>
        </SchemeExtensions>
    </ListAndSchemeInformation>
    <TrustedEntitiesList>
        <TrustedEntity>
            <TrustedEntityInformation>
                <TEName>
                    <Name xml:lang="fr">Prestataire Confiance SA</Name>
                    <Name xml:lang="en">Trust Provider Inc.</Name>
                </TEName>
                <TETradeName>
                    <Name xml:lang="fr">PSC France</Name>
                </TETradeName>
                <TEAddress>
                    <PostalAddresses>
                        <PostalAddress xml:lang="fr">
                            <StreetAddress>1 Rue de la Confiance</StreetAddress>
                            <Locality>Paris</Locality>
                            <StateOrProvince>Auvergne-Rh&#244;ne-Alpes</StateOrProvince>
                            <PostalCode>75001</PostalCode>
                            <CountryName>FR</CountryName>
                        </PostalAddress>
                    </PostalAddresses>
                    <ElectronicAddress>
                        <URI xml:lang="fr">mailto:support@psc.fr</URI>
                        <URI xml:lang="en">mailto:contact@example.org</URI>
                    </ElectronicAddress>
                </TEAddress>
                <TEInformationURI>
                    <URI xml:lang="en">https://example.org/info</URI>
                </TEInformationURI>
                <TEInformationExtensions>
                    <Extension Critical="false">
                        <tie:OtherAssociatedBodies>
                            <tie:AssociatedBody>
                                <tie:AssociatedBodyName>
                                    <Name xml:lang="fr">Minist&#232;re de la Transition Num&#233;rique</Name>
                                </tie:AssociatedBodyName>
                            </tie:AssociatedBody>
                        </tie:OtherAssociatedBodies>
                    </Extension>
                </TEInformationExtensions>
            </TrustedEntityInformation>
            <TrustedEntityServices>
                <TrustedEntityService>
                    <ServiceInformation>
                        <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/QES</ServiceTypeIdentifier>
                        <ServiceName>
                            <Name xml:lang="en">Signature Qualifi&#233;e</Name>
                        </ServiceName>
                        <ServiceDigitalIdentity>
                            <DigitalId>
                                <X509Certificate>c2FtcGxlY2VydGlmaWNhdGU=</X509Certificate>
                            </DigitalId>
                        </ServiceDigitalIdentity>
                        <ServiceStatus>http://uri.etsi.org/TrstSvc/Status/underSupervision</ServiceStatus>
                        <StatusStartingTime>2019-06-01T00:00:00Z</StatusStartingTime>
                        <SchemeServiceDefinitionURI>
                            <URI xml:lang="rn">https://psc.fr/docs/signature.pdf</URI>
                        </SchemeServiceDefinitionURI>
                        <ServiceSupplyPoints>
                            <ServiceSupplyPoint>https://psc.fr/api/sign</ServiceSupplyPoint>
                        </ServiceSupplyPoints>
                        <ServiceInformationExtensions>
                            <Extension Critical="false">
                                Service audit&#233; par ANSSI
                            </Extension>
                        </ServiceInformationExtensions>
                    </ServiceInformation>
                    <ServiceHistory>
                        <ServiceHistoryInstance>
                            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/QES</ServiceTypeIdentifier>
                            <ServiceName>
                                <Name xml:lang="en">Signature Qualifi&#233;e</Name>
                            </ServiceName>
                            <ServiceDigitalIdentity>
                                <DigitalId>
                                    <X509Certificate>c2FtcGxlY2VydGlmaWNhdGU=</X509Certificate>
                                </DigitalId>
                            </ServiceDigitalIdentity>
                            <ServiceStatus>http://uri.etsi.org/TrstSvc/Status/recognised</ServiceStatus>
                            <StatusStartingTime>2017-01-01T00:00:00Z</StatusStartingTime>
                            <ServiceInformationExtensions>
                                <Extension Critical="false">
                                    <Name xml:lang="en">Audit 2022-Q4</Name>
                                </Extension>
                            </ServiceInformationExtensions>
                        </ServiceHistoryInstance>
                    </ServiceHistory>
                </TrustedEntityService>
            </TrustedEntityServices>
        </TrustedEntity>
    </TrustedEntitiesList>
</ListOfTrustedEntities>"#;

#[test]
fn parse_dss_valid_empty_te() {
    let payload: LoTEPayload = deserialize(DSS_VALID_EMPTY_TE);
    let info = &payload.list_and_scheme_information;

    assert_eq!(info.lote_version_identifier, 1);
    assert_eq!(info.lote_sequence_number, 42);
    assert_eq!(
        info.lote_type.as_ref().unwrap().to_string(),
        "http://example.org/LoTE/type"
    );

    assert_eq!(info.scheme_operator_name.names.len(), 2);
    assert_eq!(info.scheme_operator_name.names[0].lang, "fr");
    assert_eq!(
        info.scheme_operator_name.names[0].value,
        "Agence Nationale de la Confiance Num\u{e9}rique"
    );
    assert_eq!(info.scheme_operator_name.names[1].lang, "en");
    assert_eq!(
        info.scheme_operator_name.names[1].value,
        "National Agency for Digital Trust"
    );

    let addr = info.scheme_operator_address.as_ref().unwrap();
    assert_eq!(addr.scheme_operator_postal_address.addresses.len(), 2);
    assert_eq!(addr.scheme_operator_electronic_address.uris.len(), 1);

    let pa = &addr.scheme_operator_postal_address.addresses[0];
    assert_eq!(pa.lang, "fr");
    assert_eq!(pa.street_address, "12 Boulevard S\u{e9}curit\u{e9}");
    assert_eq!(pa.locality, Some("Paris".into()));
    assert_eq!(pa.state_or_province, Some("\u{ce}le-de-France".into()));
    assert_eq!(pa.postal_code, Some("75015".into()));
    assert_eq!(pa.country, "FR");

    let sn = info.scheme_name.as_ref().unwrap();
    assert_eq!(sn.names.len(), 2);

    let si = info.scheme_information_uri.as_ref().unwrap();
    assert_eq!(si.uris.len(), 1);

    assert_eq!(
        info.status_determination_approach,
        "https://example.org/status"
    );
    assert_eq!(
        info.list_issue_date_time,
        OffsetDateTime::parse("2025-07-16T12:00:00Z", &Rfc3339).unwrap()
    );
    assert_eq!(
        info.next_update.date_time,
        OffsetDateTime::parse("2025-08-16T12:00:00Z", &Rfc3339).unwrap()
    );

    assert!(payload.trusted_entities_list.is_none());
}

#[test]
fn parse_dss_valid() {
    let payload: LoTEPayload = deserialize(DSS_VALID);
    let info = &payload.list_and_scheme_information;

    assert_eq!(info.lote_version_identifier, 1);
    assert_eq!(info.lote_sequence_number, 42);
    assert_eq!(
        info.lote_type.as_ref().unwrap().to_string(),
        "http://example.org/LoTE/type"
    );

    let entities = payload.trusted_entities_list.as_ref().unwrap();
    assert_eq!(entities.entities.len(), 1);

    let entity = &entities.entities[0];
    let te_info = &entity.trusted_entity_information;

    assert_eq!(te_info.te_name.names.len(), 2);
    assert_eq!(te_info.te_name.names[0].lang, "fr");
    assert_eq!(te_info.te_name.names[0].value, "Prestataire Confiance SA");
    assert_eq!(te_info.te_name.names[1].lang, "en");
    assert_eq!(te_info.te_name.names[1].value, "Trust Provider Inc.");

    let te_addr = te_info.te_address.as_ref().unwrap();
    let postal = te_addr.te_postal_address.as_ref().unwrap();
    assert_eq!(postal.addresses.len(), 1);
    assert_eq!(postal.addresses[0].lang, "fr");
    assert_eq!(postal.addresses[0].street_address, "1 Rue de la Confiance");

    let electronic = te_addr.te_electronic_address.as_ref().unwrap();
    assert_eq!(electronic.uris.len(), 2);

    let te_uri = te_info.te_information_uri.as_ref().unwrap();
    assert_eq!(te_uri.uris.len(), 1);

    assert_eq!(entity.trusted_entity_services.services.len(), 1);
    let svc = &entity.trusted_entity_services.services[0].service_information;

    // ServiceTypeIdentifier absent => None
    assert_eq!(svc.service_type_identifier, None);

    assert_eq!(svc.service_name.names.len(), 2);
    assert_eq!(svc.service_name.names[0].lang, "fr");
    assert_eq!(svc.service_name.names[0].value, "Horodatage");
    assert_eq!(svc.service_name.names[1].lang, "en");
    assert_eq!(svc.service_name.names[1].value, "Timestamping");

    let identity = svc.service_digital_identity.as_ref().unwrap();
    let certs = identity.x509_certificates.as_ref().unwrap();
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0], "c2FtcGxlY2VydGlmaWNhdGU=");

    assert_eq!(
        svc.status_starting_time,
        Some(OffsetDateTime::parse("2019-06-01T00:00:00Z", &Rfc3339).unwrap())
    );

    // TEInformationExtensions is present in the XML but opaque (serde_json::Value)
    assert!(te_info.te_information_extensions.is_some());
}

#[test]
fn parse_dss_valid_full() {
    let payload: LoTEPayload = deserialize(DSS_VALID_FULL);
    let info = &payload.list_and_scheme_information;

    let rules = info.scheme_type_community_rules.as_ref().unwrap();
    assert_eq!(rules.uris.len(), 1);

    assert_eq!(info.scheme_territory, Some("FR".to_string()));

    let notices = info.policy_or_legal_notice.as_ref().unwrap();
    assert_eq!(notices.items.len(), 1);
    match &notices.items[0] {
        PolicyOrLegalNoticeItem::LoTEPolicy(policy) => {
            assert_eq!(policy.uri_value, "https://trust.gov.fr/politique");
        }
        other => panic!("expected LoTEPolicy, got {:?}", other),
    }

    assert_eq!(info.historical_information_period, Some(24));

    let pointers = info.pointers_to_other_lote.as_ref().unwrap();
    assert_eq!(pointers.pointers.len(), 1);
    assert_eq!(
        pointers.pointers[0].lote_location,
        "https://other-lote.example.org/lotefile.xml"
    );

    let dist = info.distribution_points.as_ref().unwrap();
    assert_eq!(dist.uris.len(), 1);
    assert_eq!(dist.uris[0], "https://trust.gov.fr/distribution.xml");

    let entities = payload.trusted_entities_list.as_ref().unwrap();
    assert_eq!(entities.entities.len(), 1);
    let te_info = &entities.entities[0].trusted_entity_information;

    let trade = te_info.te_trade_name.as_ref().unwrap();
    assert_eq!(trade.names.len(), 1);
    assert_eq!(trade.names[0].lang, "fr");
    assert_eq!(trade.names[0].value, "PSC France");

    let svc = &entities.entities[0].trusted_entity_services.services[0].service_information;
    assert_eq!(
        svc.service_type_identifier,
        Some("http://uri.etsi.org/TrstSvc/Svctype/QES".to_string())
    );
    assert_eq!(
        svc.service_status,
        Some(ServiceStatus::Other(
            "http://uri.etsi.org/TrstSvc/Status/underSupervision".to_string()
        ))
    );

    let def_uri = svc.scheme_service_definition_uri.as_ref().unwrap();
    assert_eq!(def_uri.uris.len(), 1);

    let supply = svc.service_supply_points.as_ref().unwrap();
    assert_eq!(supply.points.len(), 1);
    assert_eq!(supply.points[0].uri_value, "https://psc.fr/api/sign");

    let history = entities.entities[0].trusted_entity_services.services[0]
        .service_history
        .as_ref()
        .unwrap();
    assert_eq!(history.instances.len(), 1);
    assert_eq!(
        history.instances[0].service_type_identifier.as_deref(),
        Some("http://uri.etsi.org/TrstSvc/Svctype/QES")
    );
    assert_eq!(
        history.instances[0].service_status,
        ServiceStatus::Other("http://uri.etsi.org/TrstSvc/Status/recognised".to_string())
    );
    assert_eq!(
        history.instances[0].status_starting_time,
        OffsetDateTime::parse("2017-01-01T00:00:00Z", &Rfc3339).unwrap()
    );
}
