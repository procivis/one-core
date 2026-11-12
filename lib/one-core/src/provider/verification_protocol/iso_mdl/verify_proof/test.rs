use std::assert_matches;
use std::sync::{Arc, Mutex};

use similar_asserts::assert_eq;
use time::Duration;
use uuid::Uuid;

use super::{ValidatedProofCredential, accept_proof, validate_proof};
use crate::mapper::ValidatedProofClaim;
use crate::model::credential::Credential;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::identifier::IdentifierData;
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::proof::ProofStateEnum;
use crate::model::proof_schema::ProofInputSchema;
use crate::proto::certificate_validator::MockCertificateValidator;
use crate::proto::ecosystem_resolver::EcosystemResolverProto;
use crate::proto::identifier_creator::{
    IdentifierName, MockIdentifierCreator, RemoteIdentifierRelation,
};
use crate::proto::session_provider::NoSessionProvider;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::{
    CredentialClaim, CredentialClaimValue, CredentialStatus, DetailCredential, IdentifierDetails,
    TokenStatus,
};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::ecosystem::directory::MockEcosystemDirectory;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::presentation_formatter::MockPresentationFormatter;
use crate::provider::presentation_formatter::model::ExtractedPresentation;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::qr_code::QRHandover;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::{
    Handover, SessionTranscript,
};
use crate::provider::presentation_formatter::provider::MockPresentationFormatterProvider;
use crate::provider::revocation::MockRevocationMethod;
use crate::provider::revocation::model::{CredentialDataByRole, RevocationState};
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::repository::proof_repository::MockProofRepository;
use crate::service::error::ServiceError;
use crate::service::test_utilities::{
    dummy_claim_schema, dummy_credential_schema_with_format, dummy_did, dummy_identifier,
    dummy_jwk, dummy_key, dummy_organisation, dummy_proof_schema, dummy_proof_with_protocol,
};

/// Validates a presented mdoc whose status list entry the revocation method resolves to `state`
async fn validate_proof_with_credential_status(
    state: RevocationState,
) -> Result<Vec<ValidatedProofCredential>, ServiceError> {
    let holder = IdentifierDetails::Key(dummy_jwk());

    let mut proof_schema = dummy_proof_schema();
    proof_schema.input_schemas = vec![ProofInputSchema {
        formats: vec!["MDOC".into()],
        claim_schemas: Default::default(),
        credential_schema: dummy_credential_schema_with_format("MDOC").into(),
    }]
    .into();

    let mut presentation_formatter = MockPresentationFormatter::new();
    presentation_formatter
        .expect_extract_presentation()
        .once()
        .return_once({
            let holder = holder.clone();
            move |_, _, _| {
                Ok(ExtractedPresentation {
                    id: None,
                    issued_at: None,
                    expires_at: None,
                    issuer: Some(holder),
                    nonce: None,
                    credentials: vec!["mdoc".into()],
                    transaction_data: None,
                })
            }
        });
    presentation_formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(60));
    let mut presentation_formatter_provider = MockPresentationFormatterProvider::new();
    presentation_formatter_provider
        .expect_get_presentation_formatter()
        .return_once(move |_| Some(Arc::new(presentation_formatter)));

    let mut credential_formatter = MockCredentialFormatter::new();
    credential_formatter
        .expect_extract_credentials()
        .once()
        .return_once(move |_, _, _| {
            Ok(DetailCredential {
                issuance_date: None,
                valid_from: None,
                valid_until: None,
                update_at: None,
                invalid_before: None,
                issuer: IdentifierDetails::Did(dummy_did().did),
                subject: Some(holder),
                claims: Default::default(),
                status: Some(CredentialStatus::TokenStatusList(TokenStatus {
                    index: 1,
                    uri: "https://status.example/list".parse().unwrap(),
                    certificate: None,
                })),
            })
        });
    let mut credential_formatter_provider = MockCredentialFormatterProvider::new();
    credential_formatter_provider
        .expect_get_credential_formatter()
        .return_once(move |_| Ok(Arc::new(credential_formatter)));

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_check_credential_revocation_status()
        .once()
        .withf(|_, _, credential_data, _| {
            matches!(credential_data, Some(CredentialDataByRole::Verifier(_)))
        })
        .return_once(move |_, _, _, _| Ok(state));
    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method_by_status()
        .once()
        .return_once(|_| Some((Arc::new(revocation_method), "TOKENSTATUSLIST".into())));

    validate_proof(
        &proof_schema,
        "presentation",
        SessionTranscript {
            device_engagement_bytes: None,
            e_reader_key_bytes: None,
            handover: Handover::QrCode(QRHandover),
        },
        &credential_formatter_provider,
        &presentation_formatter_provider,
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockCertificateValidator::new()),
        &revocation_method_provider,
    )
    .await
}

#[tokio::test]
async fn test_validate_proof_rejects_revoked_credential() {
    let error = validate_proof_with_credential_status(RevocationState::Revoked)
        .await
        .unwrap_err();

    assert_matches!(error, ServiceError::ValidationError(message) if message == "Credential is revoked or suspended");
}

#[tokio::test]
async fn test_validate_proof_rejects_suspended_credential() {
    let error = validate_proof_with_credential_status(RevocationState::Suspended {
        suspend_end_date: None,
    })
    .await
    .unwrap_err();

    assert_matches!(error, ServiceError::ValidationError(message) if message == "Credential is revoked or suspended");
}

#[tokio::test]
async fn test_validate_proof_accepts_valid_credential() {
    let credentials = validate_proof_with_credential_status(RevocationState::Valid)
        .await
        .unwrap();

    assert_eq!(credentials.len(), 1);
}

#[tokio::test]
async fn test_accept_proof_persists_holder_identifier_for_each_credential() {
    let organisation = dummy_organisation(None);
    let organisation_id = organisation.id;
    let mut proof_schema = dummy_proof_schema();
    proof_schema.organisation = organisation.clone().into();

    let issuer_did = dummy_did();
    let issuer_details = IdentifierDetails::Did(issuer_did.did.clone());
    let mut issuer_identifier = dummy_identifier();
    issuer_identifier.data = IdentifierData::Did(issuer_did.clone().into());
    let issuer_identifier_id = issuer_identifier.id;

    let holder_details = IdentifierDetails::Key(dummy_jwk());
    let holder_key = dummy_key();
    let mut holder_identifier = dummy_identifier();
    holder_identifier.data = IdentifierData::Key(holder_key.clone().into());
    holder_identifier.organisation = organisation.clone().into();
    holder_identifier.is_remote = true;
    holder_identifier.autogenerated = true;
    let holder_identifier_id = holder_identifier.id;

    let mut input_schemas = vec![];
    let mut proved_credentials = vec![];
    for _ in 0..2 {
        let claim_schema = dummy_claim_schema();
        let mut credential_schema = dummy_credential_schema_with_format("MDOC");
        credential_schema.organisation = organisation.clone().into();
        credential_schema.claim_schemas = vec![claim_schema.clone()].into();
        let mut formats = credential_schema.formats.as_ref().await.unwrap().to_vec();
        formats[0].claim_mappings = vec![CredentialSchemaFormatClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            credential_schema_format_id: formats[0].id,
            claim_schema_id: claim_schema.id,
            technical_key: "family_name".to_string(),
            namespace: Some("org.iso.18013.5.1".to_string()),
        }]
        .into();
        credential_schema.formats = formats.into();

        proved_credentials.push(ValidatedProofCredential {
            credential: DetailCredential {
                issuance_date: None,
                valid_from: None,
                valid_until: None,
                update_at: None,
                invalid_before: None,
                issuer: issuer_details.clone(),
                subject: Some(holder_details.clone()),
                claims: Default::default(),
                status: None,
            },
            credential_schema_id: credential_schema.id,
            claims: vec![ValidatedProofClaim {
                claim_schema,
                value: CredentialClaim {
                    selectively_disclosable: true,
                    metadata: false,
                    value: CredentialClaimValue::String("Doe".to_string()),
                },
            }],
        });
        input_schemas.push(ProofInputSchema {
            formats: vec!["MDOC".into()],
            claim_schemas: Default::default(),
            credential_schema: credential_schema.into(),
        });
    }
    proof_schema.input_schemas = input_schemas.into();
    let mut proof = dummy_proof_with_protocol("ISO_MDL");
    proof.schema = Some(proof_schema.into());
    let proof_id = proof.id;

    let interaction = Interaction {
        dpop_key: None,
        client_attestation_key: None,
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        data: None,
        organisation: organisation.into(),
        interaction_type: InteractionType::Verification,
        expires_at: None,
        ecosystem: None,
        ecosystem_data: Default::default(),
    };
    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_get_interaction()
        .times(1)
        .return_once({
            let interaction = interaction.clone();
            move |_, _| Ok(interaction)
        });
    let ecosystem_resolver = EcosystemResolverProto::new(
        Arc::new(interaction_repository),
        Arc::new(MockEcosystemDirectory::new()),
        Arc::new(MockHistoryRepository::new()),
        Arc::new(NoSessionProvider),
    );

    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .withf(
            move |org_id, details, name, autogenerated, translations, logo| {
                org_id == &organisation_id
                    && details == &issuer_details
                    && name == &IdentifierName::PrefixForId("issuer".to_string())
                    && *autogenerated
                    && translations.is_none()
                    && logo.is_none()
            },
        )
        .times(2)
        .returning(move |_, _, _, _, _, _| {
            Ok((
                issuer_identifier.clone(),
                RemoteIdentifierRelation::Did(issuer_did.clone()),
            ))
        });
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .withf(
            move |org_id, details, name, autogenerated, translations, logo| {
                org_id == &organisation_id
                    && details == &holder_details
                    && name == &IdentifierName::PrefixForId("holder".to_string())
                    && *autogenerated
                    && translations.is_none()
                    && logo.is_none()
            },
        )
        .times(2)
        .returning(move |_, _, _, _, _, _| {
            Ok((
                holder_identifier.clone(),
                RemoteIdentifierRelation::Key(holder_key.clone()),
            ))
        });

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_create_credential()
        .times(2)
        .returning(move |credential| {
            assert_matches!(credential, Credential::Verifier { .. });
            assert_eq!(credential.common().protocol, "ISO_MDL");
            assert_eq!(
                credential.verifier().unwrap().data.issuer.identifier.id(),
                issuer_identifier_id
            );
            assert_eq!(
                credential
                    .verifier()
                    .unwrap()
                    .data
                    .holder_identifier
                    .as_ref()
                    .unwrap()
                    .id(),
                holder_identifier_id
            );
            Ok(credential.common().id)
        });

    let mut proof_repository = MockProofRepository::new();
    proof_repository
        .expect_update_proof()
        .times(1)
        .returning(move |id, update, _| {
            assert_eq!(id, &proof_id);
            assert_eq!(update.state, Some(ProofStateEnum::Accepted));
            Ok(())
        });
    let saved_claims = Arc::new(Mutex::new(vec![]));
    proof_repository
        .expect_set_proof_claims()
        .times(1)
        .return_once({
            let saved_claims = saved_claims.clone();
            move |id, claims| {
                assert_eq!(id, &proof_id);
                *saved_claims.lock().unwrap() = claims;
                Ok(())
            }
        });

    accept_proof(
        &proof,
        &interaction,
        proved_credentials,
        &credential_repository,
        &proof_repository,
        &identifier_creator,
        &ecosystem_resolver,
    )
    .await
    .unwrap();

    let claims = saved_claims.lock().unwrap().clone();
    assert_eq!(claims.len(), 2);
    for claim in claims {
        let credential = claim.credential.as_ref().await.unwrap();
        assert_eq!(
            credential
                .verifier()
                .unwrap()
                .data
                .holder_identifier
                .as_ref()
                .unwrap()
                .id(),
            holder_identifier_id
        );
    }
}
