use std::collections::HashSet;
use std::sync::Arc;

use coset::{AsCborValue, CborSerializable};
use hex_literal::hex;
use maplit::hashmap;
use secrecy::SecretSlice;
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::ble::common::{ConnectedPeer, PeerInfo};
use super::ble::holder::{MdocBleHolderInteractionData, MdocBleHolderInteractionSessionData};
use super::ble::verifier::{IsoMdlVerifier, prepare_reader_auth};
use super::common::{DeviceRequest, DocRequest, ItemsRequest, SkDevice, SkReader, to_cbor};
use super::{BleMode, IsoMdl};
use crate::config::core_config::{KeyAlgorithmType, VerificationEngagement};
use crate::mapper::credential_schema_claim::backfill_default_translations;
use crate::model::certificate::Certificate;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{
    Credential, CredentialCommon, CredentialRole, CredentialStateEnum, CredentialType,
    GetCredentialList,
};
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::proof::{Proof, ProofRole, ProofStateEnum};
use crate::model::proof_schema::{ProofInputSchema, ProofSchema};
use crate::proto::bluetooth_low_energy::ble_resource::{BleWaiter, OnConflict};
use crate::proto::bluetooth_low_energy::low_level::ble_central::MockBleCentral;
use crate::proto::bluetooth_low_energy::low_level::ble_peripheral::MockBlePeripheral;
use crate::proto::wrp_validator::MockWRPValidator;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::mdoc_formatter::util::EmbeddedCbor;
use crate::provider::credential_formatter::model::MockSignatureProvider;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::ecosystem::directory::MockEcosystemDirectory;
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::SessionTranscript;
use crate::provider::presentation_formatter::provider::MockPresentationFormatterProvider;
use crate::provider::verification_protocol::VerificationProtocol;
use crate::provider::verification_protocol::dto::ApplicableCredentialOrFailureHintEnum;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::service::test_utilities::{
    dummy_certificate, dummy_identifier, dummy_key, dummy_organisation, generic_config,
};

#[tokio::test]
async fn test_presentation_reject_ok() {
    let core_config = generic_config().core;
    let mut ble_peripheral = MockBlePeripheral::new();
    ble_peripheral
        .expect_notify_characteristic_data()
        .times(1)
        .returning(move |_, _, _, _| Ok(()));

    ble_peripheral
        .expect_is_advertising()
        .times(1)
        .returning(move || Ok(false));

    ble_peripheral
        .expect_stop_server()
        .times(1)
        .returning(move || Ok(()));

    let mut ble_central = MockBleCentral::new();
    ble_central
        .expect_is_scanning()
        .times(1)
        .returning(move || Ok(false));

    let ble_waiter = BleWaiter::new(Arc::new(ble_central), Arc::new(ble_peripheral));
    let (continuation_task_id, _) = ble_waiter
        .schedule(
            Uuid::new_v4(),
            |_, _, _| async { Ok(()) as Result<(), VerificationProtocolError> },
            |_, _| async {},
            OnConflict::DoNothing,
            true,
        )
        .await
        .value_or(anyhow::anyhow!("test"))
        .await
        .unwrap();

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .return_once(|_| Ok(Arc::new(Ecdsa)));

    let provider = IsoMdl::new(
        "ISO_MDL".to_string(),
        serde_json::json!({
            "holder": {
                "sessionEncryptionAlgorithm": "ECDSA",
                "bleMode": "PERIPHERAL"
            }
        }),
        Arc::new(core_config),
        Arc::new(MockCredentialRepository::new()),
        Arc::new(MockPresentationFormatterProvider::new()),
        Arc::new(MockKeyProvider::new()),
        Arc::new(key_algorithm_provider),
        Arc::new(MockCredentialSchemaRepository::new()),
        Arc::new(MockCredentialFormatterProvider::new()),
        Arc::new(MockEcosystemDirectory::new()),
        Arc::new(MockWRPValidator::new()),
        Some(ble_waiter),
        None,
    )
    .unwrap();

    let ecosystem_schema_id = "org.iso.18013.5.1".to_string();
    let organisation_id = Uuid::new_v4().into();
    let device_request_bytes = to_cbor(&DeviceRequest {
        version: Default::default(),
        doc_requests: vec![DocRequest {
            items_request: EmbeddedCbor::new(ItemsRequest {
                doc_type: ecosystem_schema_id.clone(),
                name_spaces: hashmap! {
                    "org.iso.18013.5.1.mDL".to_string() => hashmap! {
                        "name".to_string() => true,
                        "age".to_string() => true,
                        "country".to_string() => true,
                        "info".to_string() => true,
                    }
                },
                request_info: None,
            })
            .unwrap(),
            reader_auth: None,
        }],
    })
    .unwrap();

    let interaction_data = serde_json::to_vec(&MdocBleHolderInteractionData {
        service_uuid: Uuid::new_v4(),
        continuation_task_id,
        organisation_id,
        mode: BleMode::Peripheral,
        engagement: HashSet::from([VerificationEngagement::QrCode]),
        session: Some(MdocBleHolderInteractionSessionData {
            sk_device: SkDevice::new(SecretSlice::from(vec![0; 32])),
            sk_reader: SkReader::new(SecretSlice::from(vec![0; 32])),
            device_request_bytes,
            session_transcript_bytes: vec![],
            connected_verifier: ConnectedPeer::PeripheralServerMode(PeerInfo {
                address: "test address".to_string(),
                max_payload_size: 512,
                service_uuid: Uuid::new_v4(),
            }),
        }),
    })
    .unwrap();
    let credential_schema_id = Uuid::new_v4().into();
    let proof = Proof {
        ecosystem: None,
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        protocol: "ISO_MDL".to_string(),
        transport: "BLE".to_string(),
        redirect_uri: None,
        state: ProofStateEnum::Pending,
        role: ProofRole::Verifier,
        requested_date: Some(crate::clock::now_utc()),
        completed_date: None,
        schema: Some(
            ProofSchema {
                ecosystem: None,
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                imported_source_url: Some("CORE_URL".to_string()),
                last_modified: crate::clock::now_utc(),
                deleted_at: None,
                name: "".to_string(),
                expire_duration: 0,
                input_schemas: vec![ProofInputSchema {
                    formats: vec!["MDOC".into()],
                    claim_schemas: Default::default(),
                    credential_schema: CredentialSchema {
                        expiration: None,
                        batch_size: None,
                        allow_revocation: false,
                        id: credential_schema_id,
                        created_date: crate::clock::now_utc(),
                        imported_source_url: "CORE_URL".to_string(),
                        last_modified: crate::clock::now_utc(),
                        deleted_at: None,
                        name: "".to_string(),
                        formats: vec![CredentialSchemaFormat {
                            id: Uuid::new_v4().into(),
                            created_date: crate::clock::now_utc(),
                            last_modified: crate::clock::now_utc(),
                            credential_schema_id,
                            format: "".into(),
                            ecosystem_schema_id,
                            claim_mappings: Default::default(),
                        }]
                        .into(),
                        wallet_attestation: Default::default(),
                        layout_properties: None,
                        claim_schemas: Default::default(),
                        organisation: dummy_organisation(Some(organisation_id)).into(),
                        allow_suspension: true,
                        transaction_code: None,
                        translations: Default::default(),
                        embedded_disclosure_policy: None,
                        ecosystem: None,
                    }
                    .into(),
                }]
                .into(),
                organisation: dummy_organisation(Some(organisation_id)).into(),
            }
            .into(),
        ),
        claims: Default::default(),
        verifier_identifier: None,
        verifier_key: None,
        verifier_certificate: None,
        interaction: Some(
            Interaction {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                data: Some(interaction_data),
                last_modified: crate::clock::now_utc(),
                organisation: dummy_organisation(None).into(),
                interaction_type: InteractionType::Verification,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: Default::default(),
            }
            .into(),
        ),
        profile: None,
        proof_blob_id: None,
        engagement: None,
        webhook_url: None,
        subscriber_information: None,
    };

    let result = provider.holder_reject_proof(&proof).await;
    assert!(result.is_ok(), "Reject proof should succeed");
}

#[tokio::test]
async fn test_get_presentation_definition_v2() {
    let organisation_id = Uuid::new_v4().into();
    let ecosystem_schema_id = "org.iso.18013.5.1".to_string();
    let device_request_bytes = to_cbor(&DeviceRequest {
        version: Default::default(),
        doc_requests: vec![DocRequest {
            items_request: EmbeddedCbor::new(ItemsRequest {
                doc_type: ecosystem_schema_id.clone(),
                name_spaces: hashmap! {
                    "org.iso.18013.5.1.mDL".to_string() => hashmap! {
                        "name".to_string() => true,
                        "age".to_string() => true,
                        "country".to_string() => true,
                        "info".to_string() => true,
                    }
                },
                request_info: None,
            })
            .unwrap(),
            reader_auth: None,
        }],
    })
    .unwrap();

    let interaction_data = serde_json::to_value(MdocBleHolderInteractionData {
        service_uuid: Uuid::new_v4(),
        continuation_task_id: Uuid::new_v4(),
        engagement: HashSet::from([VerificationEngagement::QrCode]),
        organisation_id,
        mode: BleMode::Peripheral,
        session: Some(MdocBleHolderInteractionSessionData {
            sk_device: SkDevice::new(SecretSlice::from(vec![0; 32])),
            sk_reader: SkReader::new(SecretSlice::from(vec![0; 32])),
            device_request_bytes,
            session_transcript_bytes: vec![],
            connected_verifier: ConnectedPeer::PeripheralServerMode(PeerInfo {
                address: "test address".to_string(),
                max_payload_size: 512,
                service_uuid: Uuid::new_v4(),
            }),
        }),
    })
    .unwrap();

    let proof_id = Uuid::new_v4().into();
    let proof = Proof {
        ecosystem: None,
        id: proof_id,
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        protocol: "ISO_MDL".to_string(),
        transport: "BLE".to_string(),
        redirect_uri: None,
        state: ProofStateEnum::Pending,
        role: ProofRole::Holder,
        requested_date: Some(crate::clock::now_utc()),
        completed_date: None,
        schema: None,
        claims: Default::default(),
        verifier_identifier: None,
        verifier_key: None,
        verifier_certificate: None,
        interaction: Some(
            Interaction {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                data: Some(interaction_data.to_string().as_bytes().to_vec()),
                organisation: dummy_organisation(Some(organisation_id)).into(),
                interaction_type: InteractionType::Verification,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: Default::default(),
            }
            .into(),
        ),
        profile: None,
        proof_blob_id: None,
        engagement: None,
        webhook_url: None,
        subscriber_information: None,
    };

    let credential_id = Uuid::new_v4().into();
    let credential_schema_id = Uuid::new_v4().into();

    let claim_schemas = hashmap![
        "org.iso.18013.5.1.mDL_name" => ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "org.iso.18013.5.1.mDL_name".to_string(),
            data_type: "STRING".to_string(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            array: false,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
        "org.iso.18013.5.1.mDL_age" => ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "org.iso.18013.5.1.mDL_age".to_string(),
            data_type: "NUMBER".to_string(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            array: false,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
        "org.iso.18013.5.1.mDL_country" => ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "org.iso.18013.5.1.mDL_country".to_string(),
            data_type: "STRING".to_string(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            array: false,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
        "org.iso.18013.5.1.mDL_country_code" => ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "org.iso.18013.5.1.mDL_country_code".to_string(),
            data_type: "STRING".to_string(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            array: false,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
        "org.iso.18013.5.1.mDL_info" => ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "org.iso.18013.5.1.mDL_info".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            array: false,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
        "org.iso.18013.5.1.mDL_info/code" => ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "org.iso.18013.5.1.mDL_info/code".to_string(),
            data_type: "STRING".to_string(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            array: false,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
    ];
    let credential_schema_format_id = Uuid::new_v4().into();
    let claim_mappings = vec![
        CredentialSchemaFormatClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            credential_schema_format_id,
            claim_schema_id: claim_schemas["org.iso.18013.5.1.mDL_name"].id,
            technical_key: "name".to_string(),
            namespace: Some("org.iso.18013.5.1.mDL".to_string()),
        },
        CredentialSchemaFormatClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            credential_schema_format_id,
            claim_schema_id: claim_schemas["org.iso.18013.5.1.mDL_age"].id,
            technical_key: "age".to_string(),
            namespace: Some("org.iso.18013.5.1.mDL".to_string()),
        },
        CredentialSchemaFormatClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            credential_schema_format_id,
            claim_schema_id: claim_schemas["org.iso.18013.5.1.mDL_country"].id,
            technical_key: "country".to_string(),
            namespace: Some("org.iso.18013.5.1.mDL".to_string()),
        },
        CredentialSchemaFormatClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            credential_schema_format_id,
            claim_schema_id: claim_schemas["org.iso.18013.5.1.mDL_country_code"].id,
            technical_key: "country_code".to_string(),
            namespace: Some("org.iso.18013.5.1.mDL".to_string()),
        },
        CredentialSchemaFormatClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            credential_schema_format_id,
            claim_schema_id: claim_schemas["org.iso.18013.5.1.mDL_info"].id,
            technical_key: "info".to_string(),
            namespace: Some("org.iso.18013.5.1.mDL".to_string()),
        },
        CredentialSchemaFormatClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            credential_schema_format_id,
            claim_schema_id: claim_schemas["org.iso.18013.5.1.mDL_info/code"].id,
            technical_key: "info/code".to_string(),
            namespace: Some("org.iso.18013.5.1.mDL".to_string()),
        },
    ];
    let format = CredentialSchemaFormat {
        id: credential_schema_format_id,
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        credential_schema_id,
        format: "MDOC".into(),
        ecosystem_schema_id: ecosystem_schema_id.clone(),
        claim_mappings: claim_mappings.into(),
    };
    let credential_schema = backfill_default_translations(
        CredentialSchema {
            expiration: None,
            ecosystem: None,
            batch_size: None,
            allow_revocation: false,
            id: credential_schema_id,
            created_date: crate::clock::now_utc(),
            imported_source_url: "CORE_URL".to_string(),
            last_modified: crate::clock::now_utc(),
            name: "schema-name".to_string(),
            formats: vec![format.clone()].into(),
            organisation: dummy_organisation(Some(organisation_id)).into(),
            layout_properties: None,
            claim_schemas: claim_schemas.values().cloned().collect::<Vec<_>>().into(),
            wallet_attestation: Default::default(),
            deleted_at: None,
            allow_suspension: true,
            transaction_code: None,
            translations: Default::default(),
            embedded_disclosure_policy: None,
        },
        "en",
    )
    .await
    .unwrap();

    let claims = vec![
        Claim {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            schema: claim_schemas["org.iso.18013.5.1.mDL_name"].clone().into(),
            path: "org.iso.18013.5.1.mDL_name".to_string(),
            value: Some("John".to_string()),
            selectively_disclosable: true,
        },
        Claim {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            schema: claim_schemas["org.iso.18013.5.1.mDL_age"].clone().into(),
            path: "org.iso.18013.5.1.mDL_age".to_string(),
            value: Some("55".to_string()),
            selectively_disclosable: true,
        },
        Claim {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            schema: claim_schemas["org.iso.18013.5.1.mDL_country"]
                .clone()
                .into(),
            path: "org.iso.18013.5.1.mDL_country".to_string(),
            value: Some("Germany".to_string()),
            selectively_disclosable: true,
        },
        Claim {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            schema: claim_schemas["org.iso.18013.5.1.mDL_country_code"]
                .clone()
                .into(),
            path: "org.iso.18013.5.1.mDL_country_code".to_string(),
            value: Some("DE".to_string()),
            selectively_disclosable: true,
        },
        Claim {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            schema: claim_schemas["org.iso.18013.5.1.mDL_info"].clone().into(),
            path: "org.iso.18013.5.1.mDL_info".to_string(),
            value: None,
            selectively_disclosable: true,
        },
        Claim {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            schema: claim_schemas["org.iso.18013.5.1.mDL_info/code"]
                .clone()
                .into(),
            path: "org.iso.18013.5.1.mDL_info/code".to_string(),
            value: Some("ABCDEFG".to_string()),
            selectively_disclosable: false,
        },
    ];

    let credential = Credential {
        common: CredentialCommon {
            expires_at: None,
            ecosystem: None,
            id: credential_id,
            created_date: crate::clock::now_utc(),
            issuance_date: None,
            last_modified: crate::clock::now_utc(),
            protocol: "ISO_MDL".to_string(),
            schema: credential_schema.into(),
            deleted_at: None,
            redirect_uri: None,
            state: CredentialStateEnum::Accepted,
            interaction: None,
            profile: None,
        },
        role: CredentialRole::Holder,
        suspend_end_date: None,
        claims: claims.into(),
        issuer_identifier: None,
        issuer_certificate: None,
        holder_identifier: None,
        key: None,
        credential_blob_id: None,
        wallet_key_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: None,
        consumed_at: None,
        r#type: CredentialType::Single,
        parent: None,
        embedded_disclosure_policy: None,
        subscriber_information: None,
        format: Some(format.into()),
    };

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential_list()
        .returning({
            let credential = credential.clone();
            move |_| {
                Ok(GetCredentialList {
                    values: vec![credential.clone()],
                    total_items: Some(1),
                    total_pages: Some(1),
                })
            }
        });
    credential_repository
        .expect_get_credential()
        .return_once(move |_| Ok(credential));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .returning(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_user_claims_path().return_const(vec![]);
            formatter.expect_revocation_method_id().return_const(None);

            Ok(Arc::new(formatter))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .return_once(|_| Ok(Arc::new(Ecdsa)));

    let service = IsoMdl::new(
        "ISO_MDL".to_string(),
        serde_json::json!({
            "holder": {
                "sessionEncryptionAlgorithm": "ECDSA",
                "bleMode": "PERIPHERAL"
            }
        }),
        Arc::new(generic_config().core),
        Arc::new(credential_repository),
        Arc::new(MockPresentationFormatterProvider::new()),
        Arc::new(MockKeyProvider::new()),
        Arc::new(key_algorithm_provider),
        Arc::new(MockCredentialSchemaRepository::new()),
        Arc::new(formatter_provider),
        Arc::new(MockEcosystemDirectory::new()),
        Arc::new(MockWRPValidator::new()),
        None,
        None,
    )
    .unwrap();

    let presentation_definition = service
        .holder_get_presentation_definition_v2(&proof, interaction_data, &[])
        .await
        .unwrap();

    assert_eq!(1, presentation_definition.credential_sets.len());
    assert_eq!(1, presentation_definition.credential_queries.len());
    assert!(
        presentation_definition
            .credential_queries
            .contains_key(&ecosystem_schema_id)
    );

    let credential_query = &presentation_definition.credential_queries[&ecosystem_schema_id];

    assert_eq!(credential_query.multiple, false);
    let ApplicableCredentialOrFailureHintEnum::ApplicableCredentials {
        applicable_credentials,
        ..
    } = &credential_query.credential_or_failure_hint
    else {
        panic!("Invalid query");
    };

    assert_eq!(1, applicable_credentials.len());
    assert_eq!(credential_id, applicable_credentials[0].credential.id);
    assert!(
        applicable_credentials[0]
            .credential
            .claims
            .iter()
            .any(|claim| { claim.path == "org.iso.18013.5.1.mDL_country" })
    );
    assert!(
        applicable_credentials[0]
            .credential
            .claims
            .iter()
            .any(|claim| { claim.path == "org.iso.18013.5.1.mDL_name" })
    );
    assert!(
        applicable_credentials[0]
            .credential
            .claims
            .iter()
            .any(|claim| { claim.path == "org.iso.18013.5.1.mDL_age" })
    );
    assert!(
        applicable_credentials[0]
            .credential
            .claims
            .iter()
            .any(|claim| { claim.path == "org.iso.18013.5.1.mDL_info" })
    );
    // filtered out because not requested by the proof request
    assert!(
        !applicable_credentials[0]
            .credential
            .claims
            .iter()
            .any(|claim| { claim.path == "org.iso.18013.5.1.mDL_country_code" })
    );
}

#[tokio::test]
async fn test_prepare_reader_auth() {
    let transcript = hex!(
        "83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac"
    );
    let transcript: SessionTranscript = ciborium::from_reader(transcript.as_slice()).unwrap();

    let items_request = EmbeddedCbor::new(ItemsRequest {
        doc_type: "org.iso.18013.5.1.mDL".to_string(),
        name_spaces: hashmap! {
            "org.iso.18013.5.1".to_string() => hashmap! {
                "family_name".to_string() => true
            }
        },
        request_info: None,
    })
    .unwrap();

    let mut signature_provider = MockSignatureProvider::new();
    signature_provider
        .expect_get_key_algorithm()
        .returning(|| Ok(KeyAlgorithmType::Ecdsa));
    signature_provider
        .expect_sign()
        .return_once(|_| Ok(vec![0x0, 0x1]));

    const CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIICLzCCAdSgAwIBAgIUHyRjE466YA7tc888k03Ou2QodF4wCgYIKoZIzj0EAwIw
KDELMAkGA1UEBhMCREUxGTAXBgNVBAMMEEdlcm1hbiBSZWdpc3RyYXIwHhcNMjYw
MTE2MTExNTU0WhcNMjgwMTE2MTExNTU0WjAoMQswCQYDVQQGEwJERTEZMBcGA1UE
AwwQR2VybWFuIFJlZ2lzdHJhcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMef
Y2X4ixfRkWEvp9grF2i21z6PKZsr8zzBaJ/+GnotCeH2cJ6GtLhxXhHfJjrETsMN
IGhVaJoHoHcZTBHJrfyjgdswgdgwHQYDVR0OBBYEFKnCo9ovbaxU7s65TugsySwA
g4AzMB8GA1UdIwQYMBaAFKnCo9ovbaxU7s65TugsySwAg4AzMBIGA1UdEwEB/wQI
MAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMCoGA1UdEgQjMCGGH2h0dHBzOi8vc2Fu
ZGJveC5ldWRpLXdhbGxldC5vcmcwRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cHM6Ly9z
YW5kYm94LmV1ZGktd2FsbGV0Lm9yZy9zdGF0dXMtbWFuYWdlbWVudC9jcmwwCgYI
KoZIzj0EAwIDSQAwRgIhAIY7ERpRrDRl0lr5H5uxjJ83JR4qua2sfPKxX+pl4Qw+
AiEA2qL6LXVORA2r2VZjSEknfciwIG7laA12kjnyGAD3V/A=
-----END CERTIFICATE-----
"#;

    let verifier = IsoMdlVerifier {
        identifier: dummy_identifier(),
        key: dummy_key(),
        certificate: Certificate {
            chain: CERT.to_string(),
            ..dummy_certificate(dummy_identifier().id)
        },
        auth_fn: Box::new(signature_provider),
    };

    let reader_auth = prepare_reader_auth(transcript, items_request, &verifier)
        .await
        .unwrap();

    assert_eq!(
        reader_auth.0.to_cbor_value().unwrap().to_vec().unwrap(),
        hex!(
            "8443a10126a118215902333082022f308201d4a00302010202141f2463138eba600eed73cf3c934dcebb6428745e300a06082a8648ce3d0403023028310b30090603550406130244453119301706035504030c104765726d616e20526567697374726172301e170d3236303131363131313535345a170d3238303131363131313535345a3028310b30090603550406130244453119301706035504030c104765726d616e205265676973747261723059301306072a8648ce3d020106082a8648ce3d03010703420004c79f6365f88b17d191612fa7d82b1768b6d73e8f299b2bf33cc1689ffe1a7a2d09e1f6709e86b4b8715e11df263ac44ec30d206855689a07a077194c11c9adfca381db3081d8301d0603551d0e04160414a9c2a3da2f6dac54eeceb94ee82cc92c00838033301f0603551d23041830168014a9c2a3da2f6dac54eeceb94ee82cc92c0083803330120603551d130101ff040830060101ff020100300e0603551d0f0101ff040403020106302a0603551d1204233021861f68747470733a2f2f73616e64626f782e657564692d77616c6c65742e6f726730460603551d1f043f303d303ba039a037863568747470733a2f2f73616e64626f782e657564692d77616c6c65742e6f72672f7374617475732d6d616e6167656d656e742f63726c300a06082a8648ce3d0403020349003046022100863b111a51ac3465d25af91f9bb18c9f37251e2ab9adac7cf2b15fea65e10c3e022100daa2fa2d754e440dabd956634849277dc8b0206ee5680d769239f21800f757f0f6420001"
        )
    );
}
