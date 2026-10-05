use std::borrow::Cow;
use std::sync::{Arc, LazyLock, Mutex};

use mockall::predicate::eq;
use shared_types::{CredentialId, ProofId};
use similar_asserts::assert_eq;
use standardized_types::openid4vci::CredentialIssuerMetadata;
use uuid::Uuid;

use super::*;
use crate::clock::now_utc;
use crate::error::{ErrorCode, ErrorCodeMixin, ErrorData, NestedError};
use crate::model::credential_schema::WalletAttestation;
use crate::model::history::HistoryErrorMetadata;
use crate::model::interaction::{InteractionEcosystems, InteractionType};
use crate::model::organisation::Organisation;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::DecomposedJwt;
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::proto::session_provider::{NoSessionProvider, Session};
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::provider::ecosystem::MockEcosystem;
use crate::provider::ecosystem::directory::MockEcosystemDirectory;
use crate::provider::ecosystem::error::EcosystemError;
use crate::provider::ecosystem::model::{IssuerMetadataRepresentation, WalletAttestationArtifact};
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::service::managed_instance::dto::WalletInstanceAttestationClaims;
use crate::service::test_utilities::{dummy_credential, dummy_organisation};

fn issued_credential() -> CredentialId {
    Uuid::from_u128(1).into()
}

fn submitted_proof() -> ProofId {
    Uuid::from_u128(2).into()
}

fn submitted_credential(index: usize) -> CredentialId {
    Uuid::from_u128(100 + index as u128).into()
}

fn resolver(
    interaction_repository: MockInteractionRepository,
    ecosystem_provider: MockEcosystemDirectory,
) -> EcosystemResolverProto {
    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|history| Ok(history.id));

    EcosystemResolverProto::new(
        Arc::new(interaction_repository),
        Arc::new(ecosystem_provider),
        Arc::new(history_repository),
        Arc::new(NoSessionProvider),
    )
}

fn recording_history() -> (MockHistoryRepository, Arc<Mutex<Vec<History>>>) {
    let written = Arc::new(Mutex::new(vec![]));
    let captured = written.to_owned();

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(move |history| {
            let id = history.id;
            captured.lock().unwrap().push(history);
            Ok(id)
        });

    (history_repository, written)
}

fn recorded_on(written: &Mutex<Vec<History>>) -> Vec<(EntityId, EcosystemOutcomes)> {
    written
        .lock()
        .unwrap()
        .iter()
        .map(|event| {
            assert_eq!(HistoryAction::EcosystemsResolved, event.action);
            let Some(HistoryMetadata::EcosystemsResolved(outcomes)) = &event.metadata else {
                panic!("the event carries the outcomes");
            };
            (event.entity_id.unwrap(), outcomes.to_owned())
        })
        .collect()
}

fn configuration(selected: &[&str]) -> OrganisationConfiguration {
    OrganisationConfiguration {
        selected_ecosystems: selected.iter().map(|id| EcosystemId::from(*id)).collect(),
        ..Default::default()
    }
}

fn interaction(earlier_outcomes: EcosystemOutcomes) -> Interaction {
    let mut ecosystem_data = InteractionEcosystems::default();
    ecosystem_data.merge_outcomes(&earlier_outcomes);

    Interaction {
        id: Uuid::new_v4().into(),
        created_date: now_utc(),
        last_modified: now_utc(),
        data: None,
        organisation: dummy_organisation(None).into(),
        interaction_type: InteractionType::Issuance,
        expires_at: None,
        ecosystem: None,
        ecosystem_data,
    }
}

/// Sorted, because [`remaining_candidates`] does not guarantee an order.
fn applicable(earlier_outcomes: EcosystemOutcomes, selected: &[&str]) -> Vec<EcosystemId> {
    let mut candidates =
        remaining_candidates(&interaction(earlier_outcomes), &configuration(selected));
    candidates.sort();
    candidates
}

fn earlier_outcomes(kept: &[&str], dropped: &[&str]) -> EcosystemOutcomes {
    let mut result = EcosystemOutcomes::default();
    for ecosystem in kept {
        result.record(EcosystemId::from(*ecosystem), Ok(()));
    }
    for ecosystem in dropped {
        result.record(
            EcosystemId::from(*ecosystem),
            rejected(EcosystemError::MissingIdentifier),
        );
    }
    result
}

#[test]
fn test_first_step_starts_from_the_organisation_selection() {
    assert_eq!(
        vec![EcosystemId::from("EUDI"), EcosystemId::from("OTHER")],
        applicable(EcosystemOutcomes::default(), &["EUDI", "OTHER"])
    );
}

#[test]
fn test_later_steps_only_ask_the_remaining_candidates() {
    assert_eq!(
        vec![EcosystemId::from("OTHER")],
        applicable(
            earlier_outcomes(&["OTHER"], &["EUDI"]),
            &["EUDI", "OTHER", "THIRD"]
        )
    );
}

#[test]
fn test_no_remaining_candidates_stays_empty() {
    assert!(
        applicable(
            earlier_outcomes(&[], &["EUDI", "OTHER"]),
            &["EUDI", "OTHER"]
        )
        .is_empty()
    );
}

#[test]
fn test_candidates_deselected_by_the_organisation_drop_out() {
    assert_eq!(
        vec![EcosystemId::from("EUDI")],
        applicable(earlier_outcomes(&["EUDI", "OTHER"], &[]), &["EUDI"])
    );
}

/// An `EcosystemDirectory` where each named ecosystem accepts or rejects every artifact.
fn ecosystem_directory(verdicts: &[(&str, bool)]) -> MockEcosystemDirectory {
    let mut directory = MockEcosystemDirectory::new();

    for (ecosystem_id, accepts) in verdicts.iter().copied() {
        directory
            .expect_get()
            .with(eq(EcosystemId::from(ecosystem_id)))
            .returning(move |_| {
                let mut ecosystem = MockEcosystem::new();
                ecosystem
                    .expect_validate_interaction()
                    .returning(move |_, _| {
                        accepts
                            .then_some(None)
                            .ok_or(EcosystemError::MissingIdentifier)
                    });
                Ok(Arc::new(ecosystem))
            });
    }

    directory
}

fn organisation(selected: &[&str], enforced: bool) -> Organisation {
    Organisation {
        configuration: OrganisationConfiguration {
            selected_ecosystems: selected.iter().map(|id| EcosystemId::from(*id)).collect(),
            enforce_ecosystem_as_issuer: enforced,
            enforce_ecosystem_as_holder: enforced,
            enforce_ecosystem_as_verifier: enforced,
        },
        ..dummy_organisation(None)
    }
}

/// What `resolve` wrote to the interaction.
#[derive(Debug, Default)]
struct Persisted {
    ecosystem: Option<Option<EcosystemId>>,
    outcomes: EcosystemOutcomes,
    ecosystem_data: InteractionEcosystems,
}

impl Persisted {
    fn applicable(&self) -> Vec<EcosystemId> {
        self.outcomes.applicable()
    }
}

fn interaction_under_test(
    organisation: Organisation,
    earlier_outcomes: EcosystemOutcomes,
    committed: Option<&str>,
) -> (
    InteractionId,
    MockInteractionRepository,
    Arc<std::sync::Mutex<Persisted>>,
) {
    let interaction = Interaction {
        organisation: organisation.into(),
        ecosystem: committed.map(EcosystemId::from),
        ..interaction(earlier_outcomes.to_owned())
    };
    let interaction_id = interaction.id;

    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_get_interaction()
        .returning(move |_, _| Ok(interaction.to_owned()));

    // If `resolve` does not write to the interaction, these values stay.
    let persisted = Arc::new(std::sync::Mutex::new(Persisted {
        outcomes: earlier_outcomes,
        ..Default::default()
    }));
    let captured = persisted.to_owned();
    interaction_repository
        .expect_update_interaction()
        .returning(move |_, request| {
            let mut captured = captured.lock().unwrap();
            if let Some(ecosystem_data) = request.ecosystem_data {
                captured.outcomes = ecosystem_data.outcomes().to_owned();
                captured.ecosystem_data = ecosystem_data;
            }
            if let Some(committed) = request.ecosystem {
                captured.ecosystem = Some(committed);
            }
            Ok(())
        });

    (interaction_id, interaction_repository, persisted)
}

fn issuer_artifact() -> ProtocolArtifact<'static> {
    // an unsigned WIA with an empty payload, header `{"alg":"ES256"}`
    const WIA_TOKEN: &str = "eyJhbGciOiJFUzI1NiJ9.e30";
    static WIA: LazyLock<DecomposedJwt<WalletInstanceAttestationClaims>> = LazyLock::new(|| {
        Jwt::<WalletInstanceAttestationClaims>::decompose_token(WIA_TOKEN).unwrap()
    });

    static REQUIREMENTS: WalletAttestation = WalletAttestation {
        require_instance_attestation: true,
        key_storage_security_level: None,
        preferred_key_storage_attestation_lifetime: None,
        preferred_instance_attestation_lifetime: None,
    };

    ProtocolArtifact::IssuerIssuance {
        attestation: WalletAttestationArtifact::WalletInstance {
            token: WIA_TOKEN,
            jwt: &WIA,
        },
        requirements: &REQUIREMENTS,
        credential_id: issued_credential(),
    }
}

fn invitation_artifact() -> ProtocolArtifact<'static> {
    ProtocolArtifact::HolderIssuanceInvitation {
        issuer_metadata: IssuerMetadataRepresentation::Unsigned(Box::new(
            CredentialIssuerMetadata {
                credential_issuer: "credential_issuer".to_string(),
                authorization_servers: None,
                credential_endpoint: "credential_endpoint".to_string(),
                nonce_endpoint: None,
                notification_endpoint: None,
                credential_configurations_supported: Default::default(),
                display: None,
                issuer_info: Default::default(),
                batch_credential_issuance: None,
                credential_request_encryption: None,
                credential_response_encryption: None,
                preferred_client_status_period: None,
            },
        )),
        credential_configuration_ids: vec![],
    }
}

fn rejected(error: impl ErrorCodeMixin) -> Result<(), HistoryErrorMetadata> {
    Err((&error).into())
}

fn outcomes(entries: &[(&str, Result<(), HistoryErrorMetadata>)]) -> EcosystemOutcomes {
    let mut outcomes = EcosystemOutcomes::default();
    for (ecosystem, outcome) in entries {
        outcomes.record(EcosystemId::from(*ecosystem), outcome.to_owned());
    }
    outcomes
}

/// A directory that cannot provide the ecosystem.
fn unavailable() -> NestedError {
    Err::<(), _>(EcosystemError::MissingIdentifier)
        .error_while("getting ecosystem")
        .unwrap_err()
}

/// Returns the result and the candidates stored for the next step.
async fn detect(
    organisation: Organisation,
    earlier_outcomes: EcosystemOutcomes,
    verdicts: &[(&str, bool)],
) -> Result<(ResolvedEcosystems, Vec<EcosystemId>), EcosystemValidationError> {
    detect_over(organisation, earlier_outcomes, verdicts, None).await
}

async fn detect_over(
    organisation: Organisation,
    earlier_outcomes: EcosystemOutcomes,
    verdicts: &[(&str, bool)],
    committed: Option<&str>,
) -> Result<(ResolvedEcosystems, Vec<EcosystemId>), EcosystemValidationError> {
    let (interaction_id, interaction_repository, persisted) =
        interaction_under_test(organisation, earlier_outcomes, committed);

    let resolution = resolver(interaction_repository, ecosystem_directory(verdicts))
        .resolve(interaction_id, &[issuer_artifact()], None)
        .await?;

    let applicable = persisted.lock().unwrap().applicable();
    Ok((resolution, applicable))
}

async fn select_over(
    organisation: Organisation,
    verdicts: &[(&str, bool)],
    committed: Option<&str>,
    selection: &str,
) -> Result<(EcosystemOutcomes, Persisted), EcosystemValidationError> {
    let (interaction_id, interaction_repository, persisted) =
        interaction_under_test(organisation, EcosystemOutcomes::default(), committed);

    let outcomes = resolver(interaction_repository, ecosystem_directory(verdicts))
        .resolve(
            interaction_id,
            &[issuer_artifact()],
            Some(&EcosystemId::from(selection)),
        )
        .await?
        .outcomes;

    let persisted = persisted.lock().unwrap();
    Ok((
        outcomes,
        Persisted {
            ecosystem: persisted.ecosystem.to_owned(),
            outcomes: persisted.outcomes.to_owned(),
            ecosystem_data: persisted.ecosystem_data.to_owned(),
        },
    ))
}

#[tokio::test]
async fn test_a_user_selection_is_committed_on_the_interaction() {
    let (outcomes, persisted) = select_over(
        organisation(&["EUDI", "OTHER"], false),
        &[("EUDI", true)],
        None,
        "EUDI",
    )
    .await
    .unwrap();

    assert_eq!(Some(Some(EcosystemId::from("EUDI"))), persisted.ecosystem);
    assert_eq!(vec![EcosystemId::from("EUDI")], persisted.applicable());
    assert_eq!(
        EcosystemOutcomes::validated(EcosystemId::from("EUDI")),
        outcomes
    );
    assert_eq!(outcomes, persisted.outcomes);
}

#[tokio::test]
async fn test_a_step_stores_its_outcomes_on_the_interaction() {
    let (interaction_id, interaction_repository, persisted) = interaction_under_test(
        organisation(&["EUDI", "OTHER"], false),
        EcosystemOutcomes::default(),
        None,
    );

    resolver(
        interaction_repository,
        ecosystem_directory(&[("EUDI", false), ("OTHER", true)]),
    )
    .resolve(interaction_id, &[issuer_artifact()], None)
    .await
    .unwrap();

    assert_eq!(
        outcomes(&[
            ("EUDI", rejected(EcosystemError::MissingIdentifier)),
            ("OTHER", Ok(())),
        ]),
        persisted.lock().unwrap().outcomes
    );
}

#[tokio::test]
async fn test_a_step_keeps_the_data_each_ecosystem_stores_for_its_later_steps() {
    let (interaction_id, interaction_repository, persisted) = interaction_under_test(
        organisation(&["EUDI", "OTHER"], false),
        EcosystemOutcomes::default(),
        None,
    );

    let mut directory = MockEcosystemDirectory::new();
    directory.expect_get().returning(|ecosystem_id| {
        let data = serde_json::json!({ "of": ecosystem_id.to_string() });
        let mut ecosystem = MockEcosystem::new();
        ecosystem
            .expect_validate_interaction()
            .returning(move |_, _| Ok(Some(data.to_owned())));
        Ok(Arc::new(ecosystem))
    });

    resolver(interaction_repository, directory)
        .resolve(interaction_id, &[issuer_artifact()], None)
        .await
        .unwrap();

    let persisted = persisted.lock().unwrap();
    for ecosystem_id in ["EUDI", "OTHER"] {
        assert_eq!(
            Some(serde_json::json!({ "of": ecosystem_id })),
            persisted
                .ecosystem_data
                .get::<serde_json::Value>(&EcosystemId::from(ecosystem_id))
                .unwrap()
        );
    }
    assert_eq!(
        vec![EcosystemId::from("EUDI"), EcosystemId::from("OTHER")],
        persisted.ecosystem_data.outcomes().applicable()
    );
}

#[tokio::test]
async fn test_a_user_selection_the_organisation_does_not_permit_fails() {
    let error = select_over(organisation(&["EUDI"], false), &[], None, "OTHER")
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        EcosystemValidationError::EcosystemNotPermitted
    ));
    assert_eq!(ErrorCode::BR_0475, error.error_code());
}

#[tokio::test]
async fn test_a_user_selection_rejecting_the_artifact_fails() {
    let error = select_over(
        organisation(&["EUDI"], false),
        &[("EUDI", false)],
        None,
        "EUDI",
    )
    .await
    .unwrap_err();

    assert_eq!(ErrorCode::BR_0477, error.error_code());
}

#[tokio::test]
async fn test_selecting_over_an_already_committed_interaction_fails() {
    let error = select_over(
        organisation(&["EUDI", "OTHER"], false),
        &[],
        Some("EUDI"),
        "OTHER",
    )
    .await
    .unwrap_err();

    assert!(matches!(
        error,
        EcosystemValidationError::EcosystemAlreadyCommitted(_)
    ));
    assert_eq!(ErrorCode::BR_0477, error.error_code());
}

#[tokio::test]
async fn test_a_committed_ecosystem_is_kept_without_autodetection() {
    // The mock directory panics if `OTHER` is asked.
    let (resolution, applicable) = detect_over(
        organisation(&["EUDI", "OTHER"], false),
        EcosystemOutcomes::default(),
        &[("EUDI", true)],
        Some("EUDI"),
    )
    .await
    .unwrap();

    assert_eq!(Some(EcosystemId::from("EUDI")), resolution.ecosystem);
    assert_eq!(vec![EcosystemId::from("EUDI")], applicable);
    assert_eq!(
        EcosystemOutcomes::validated(EcosystemId::from("EUDI")),
        resolution.outcomes
    );
}

#[tokio::test]
async fn test_a_committed_ecosystem_rejecting_the_artifact_fails() {
    let error = detect_over(
        organisation(&["EUDI"], false),
        EcosystemOutcomes::default(),
        &[("EUDI", false)],
        Some("EUDI"),
    )
    .await
    .unwrap_err();

    assert_eq!(ErrorCode::BR_0477, error.error_code());
    let Some(ErrorData::EcosystemsResolved(recorded)) = error.error_data() else {
        panic!("a rejection carries the outcome");
    };
    assert_eq!(
        outcomes(&[("EUDI", rejected(EcosystemError::MissingIdentifier))]),
        recorded
    );
}

#[tokio::test]
async fn test_every_accepting_ecosystem_stays_a_candidate() {
    let (resolution, applicable) = detect(
        organisation(&["EUDI", "OTHER"], false),
        EcosystemOutcomes::default(),
        &[("EUDI", true), ("OTHER", true)],
    )
    .await
    .unwrap();

    assert_eq!(
        vec![EcosystemId::from("EUDI"), EcosystemId::from("OTHER")],
        applicable
    );
    assert_eq!(Some(EcosystemId::from("EUDI")), resolution.ecosystem);
}

#[tokio::test]
async fn test_rejecting_ecosystem_is_dropped_from_the_candidates() {
    let (resolution, applicable) = detect(
        organisation(&["EUDI", "OTHER"], false),
        EcosystemOutcomes::default(),
        &[("EUDI", false), ("OTHER", true)],
    )
    .await
    .unwrap();

    assert_eq!(vec![EcosystemId::from("OTHER")], applicable);
    assert_eq!(Some(EcosystemId::from("OTHER")), resolution.ecosystem);
    assert_eq!(
        outcomes(&[
            ("EUDI", rejected(EcosystemError::MissingIdentifier)),
            ("OTHER", Ok(())),
        ]),
        resolution.outcomes
    );
}

#[tokio::test]
async fn test_unavailable_ecosystem_is_dropped_with_the_reason() {
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI", "OTHER"], false),
        EcosystemOutcomes::default(),
        None,
    );
    let mut directory = ecosystem_directory(&[("OTHER", true)]);
    directory
        .expect_get()
        .with(eq(EcosystemId::from("EUDI")))
        .returning(|_| Err(unavailable()));

    let resolution = resolver(interaction_repository, directory)
        .resolve(interaction_id, &[issuer_artifact()], None)
        .await
        .unwrap();

    assert_eq!(Some(EcosystemId::from("OTHER")), resolution.ecosystem);
    assert_eq!(
        outcomes(&[("EUDI", rejected(unavailable())), ("OTHER", Ok(()))]),
        resolution.outcomes
    );
}

#[tokio::test]
async fn test_a_rejecting_ecosystem_is_not_asked_again() {
    let (_, applicable) = detect(
        organisation(&["EUDI", "OTHER"], false),
        earlier_outcomes(&["OTHER"], &["EUDI"]),
        &[("OTHER", true)],
    )
    .await
    .unwrap();

    assert_eq!(vec![EcosystemId::from("OTHER")], applicable);
}

#[tokio::test]
async fn test_a_later_step_still_reports_the_ecosystems_dropped_earlier() {
    let (resolution, _) = detect(
        organisation(&["EUDI", "OTHER"], false),
        earlier_outcomes(&["OTHER"], &["EUDI"]),
        &[("OTHER", true)],
    )
    .await
    .unwrap();

    assert_eq!(earlier_outcomes(&["OTHER"], &["EUDI"]), resolution.outcomes);
}

#[tokio::test]
async fn test_no_applicable_ecosystem_assigns_nothing_when_not_enforced() {
    let (resolution, applicable) = detect(
        organisation(&["EUDI"], false),
        EcosystemOutcomes::default(),
        &[("EUDI", false)],
    )
    .await
    .unwrap();

    assert_eq!(None, resolution.ecosystem);
    assert!(applicable.is_empty());
}

#[tokio::test]
async fn test_no_applicable_ecosystem_fails_when_enforced() {
    let error = detect(
        organisation(&["EUDI"], true),
        EcosystemOutcomes::default(),
        &[("EUDI", false)],
    )
    .await
    .unwrap_err();

    assert_eq!(ErrorCode::BR_0476, error.error_code());
    let EcosystemValidationError::NoEcosystemDetected(recorded) = error else {
        panic!("enforcement fails on nothing detected");
    };
    assert_eq!(
        outcomes(&[("EUDI", rejected(EcosystemError::MissingIdentifier))]),
        recorded
    );
}

#[tokio::test]
async fn test_an_invitation_does_not_store_an_ecosystem() {
    let (interaction_id, interaction_repository, persisted) = interaction_under_test(
        organisation(&["EUDI", "OTHER"], false),
        EcosystemOutcomes::default(),
        None,
    );

    let resolution = resolver(
        interaction_repository,
        ecosystem_directory(&[("EUDI", false), ("OTHER", true)]),
    )
    .resolve(interaction_id, &[invitation_artifact()], None)
    .await
    .unwrap();

    assert_eq!(None, resolution.ecosystem);
    let persisted = persisted.lock().unwrap();
    assert_eq!(None, persisted.ecosystem);
    assert_eq!(vec![EcosystemId::from("OTHER")], persisted.applicable());
}

fn submission_artifact(index: usize) -> ProtocolArtifact<'static> {
    ProtocolArtifact::VerifierSubmission {
        credential: Cow::Owned({
            let mut updated_credential = dummy_credential();
            updated_credential.common_mut().id = submitted_credential(index);
            updated_credential
        }),
        issuer_details: Cow::Owned(submission_issuer(index)),
        proof_id: submitted_proof(),
    }
}

fn submission_issuer(index: usize) -> IdentifierDetails {
    IdentifierDetails::Did(format!("did:credential:{index}").parse().unwrap())
}

/// An `EcosystemDirectory` where each named ecosystem accepts the submitted credentials at the
/// given [`submission_artifact`] indices, and rejects the rest.
fn submission_directory(accepts: &[(&str, &[usize])]) -> MockEcosystemDirectory {
    let mut directory = MockEcosystemDirectory::new();

    for (ecosystem_id, accepted) in accepts.iter() {
        let accepted: Vec<_> = accepted.iter().copied().map(submission_issuer).collect();
        directory
            .expect_get()
            .with(eq(EcosystemId::from(*ecosystem_id)))
            .returning(move |_| {
                let accepted = accepted.to_owned();
                let mut ecosystem = MockEcosystem::new();
                ecosystem
                    .expect_validate_interaction()
                    .returning(move |artifact, _| {
                        let ProtocolArtifact::VerifierSubmission { issuer_details, .. } = artifact
                        else {
                            panic!("submission resolution consults no other artifact");
                        };
                        accepted
                            .contains(issuer_details.as_ref())
                            .then_some(None)
                            .ok_or(EcosystemError::MissingIdentifier)
                    });
                Ok(Arc::new(ecosystem))
            });
    }

    directory
}

#[tokio::test]
async fn test_submission_committed_ecosystem_covers_every_credential() {
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI"], false),
        EcosystemOutcomes::default(),
        Some("EUDI"),
    );

    let ecosystems = resolver(
        interaction_repository,
        submission_directory(&[("EUDI", &[0, 1])]),
    )
    .resolve(
        interaction_id,
        &[submission_artifact(0), submission_artifact(1)],
        None,
    )
    .await
    .unwrap();

    assert_eq!(Some(EcosystemId::from("EUDI")), ecosystems.ecosystem);
    assert_eq!(
        vec![
            Some(EcosystemId::from("EUDI")),
            Some(EcosystemId::from("EUDI"))
        ],
        ecosystems.per_credential
    );
    assert_eq!(
        EcosystemOutcomes::validated(EcosystemId::from("EUDI")),
        ecosystems.outcomes
    );
}

#[tokio::test]
async fn test_submission_committed_ecosystem_rejecting_any_credential_fails() {
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI"], false),
        EcosystemOutcomes::default(),
        Some("EUDI"),
    );

    let error = resolver(
        interaction_repository,
        submission_directory(&[("EUDI", &[0])]),
    )
    .resolve(
        interaction_id,
        &[submission_artifact(0), submission_artifact(1)],
        None,
    )
    .await
    .unwrap_err();

    assert_eq!(ErrorCode::BR_0477, error.error_code());
    let Some(ErrorData::EcosystemsResolved(recorded)) = error.error_data() else {
        panic!("a rejection carries the outcome");
    };
    assert_eq!(
        outcomes(&[("EUDI", rejected(EcosystemError::MissingIdentifier))]),
        recorded
    );
}

#[tokio::test]
async fn test_submission_ecosystem_validating_every_credential_is_committed() {
    let (interaction_id, interaction_repository, persisted) = interaction_under_test(
        organisation(&["EUDI"], false),
        EcosystemOutcomes::default(),
        None,
    );

    let ecosystems = resolver(
        interaction_repository,
        submission_directory(&[("EUDI", &[0, 1])]),
    )
    .resolve(
        interaction_id,
        &[submission_artifact(0), submission_artifact(1)],
        None,
    )
    .await
    .unwrap();

    assert_eq!(Some(EcosystemId::from("EUDI")), ecosystems.ecosystem);
    assert_eq!(
        vec![
            Some(EcosystemId::from("EUDI")),
            Some(EcosystemId::from("EUDI"))
        ],
        ecosystems.per_credential
    );
    assert_eq!(
        vec![EcosystemId::from("EUDI")],
        persisted.lock().unwrap().applicable()
    );
}

#[tokio::test]
async fn test_submission_partially_validating_ecosystem_is_not_committed() {
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI", "OTHER"], false),
        EcosystemOutcomes::default(),
        None,
    );

    let ecosystems = resolver(
        interaction_repository,
        submission_directory(&[("EUDI", &[0]), ("OTHER", &[0, 1])]),
    )
    .resolve(
        interaction_id,
        &[submission_artifact(0), submission_artifact(1)],
        None,
    )
    .await
    .unwrap();

    assert_eq!(Some(EcosystemId::from("OTHER")), ecosystems.ecosystem);
    assert_eq!(
        vec![
            Some(EcosystemId::from("OTHER")),
            Some(EcosystemId::from("OTHER"))
        ],
        ecosystems.per_credential
    );
}

#[tokio::test]
async fn test_submission_outcomes_cover_every_credential() {
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI", "OTHER"], false),
        EcosystemOutcomes::default(),
        None,
    );

    let ecosystems = resolver(
        interaction_repository,
        submission_directory(&[("EUDI", &[1]), ("OTHER", &[0, 1])]),
    )
    .resolve(
        interaction_id,
        &[submission_artifact(0), submission_artifact(1)],
        None,
    )
    .await
    .unwrap();

    assert_eq!(Some(EcosystemId::from("OTHER")), ecosystems.ecosystem);
    assert_eq!(
        outcomes(&[
            ("EUDI", rejected(EcosystemError::MissingIdentifier)),
            ("OTHER", Ok(())),
        ]),
        ecosystems.outcomes
    );
}

#[tokio::test]
async fn test_submission_credential_keeps_its_ecosystem_when_other_credentials_are_rejected() {
    let (interaction_id, interaction_repository, persisted) = interaction_under_test(
        organisation(&["EUDI", "OTHER"], false),
        EcosystemOutcomes::default(),
        None,
    );

    let ecosystems = resolver(
        interaction_repository,
        submission_directory(&[("EUDI", &[0]), ("OTHER", &[1])]),
    )
    .resolve(
        interaction_id,
        &[submission_artifact(0), submission_artifact(1)],
        None,
    )
    .await
    .unwrap();

    assert_eq!(None, ecosystems.ecosystem);
    assert_eq!(
        vec![
            Some(EcosystemId::from("EUDI")),
            Some(EcosystemId::from("OTHER"))
        ],
        ecosystems.per_credential
    );
    assert!(persisted.lock().unwrap().applicable().is_empty());
}

#[tokio::test]
async fn test_submission_credential_gets_no_trust_from_an_ecosystem_dropped_earlier() {
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI", "OTHER"], false),
        earlier_outcomes(&["OTHER"], &["EUDI"]),
        None,
    );

    let ecosystems = resolver(
        interaction_repository,
        submission_directory(&[("EUDI", &[0]), ("OTHER", &[1])]),
    )
    .resolve(
        interaction_id,
        &[submission_artifact(0), submission_artifact(1)],
        None,
    )
    .await
    .unwrap();

    assert_eq!(None, ecosystems.ecosystem);
    assert_eq!(
        vec![None, Some(EcosystemId::from("OTHER"))],
        ecosystems.per_credential
    );
}

#[tokio::test]
async fn test_submission_credential_complying_with_no_ecosystem_gets_no_trust() {
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI"], false),
        EcosystemOutcomes::default(),
        None,
    );

    let ecosystems = resolver(
        interaction_repository,
        submission_directory(&[("EUDI", &[0])]),
    )
    .resolve(
        interaction_id,
        &[submission_artifact(0), submission_artifact(1)],
        None,
    )
    .await
    .unwrap();

    assert_eq!(None, ecosystems.ecosystem);
    assert_eq!(
        vec![Some(EcosystemId::from("EUDI")), None],
        ecosystems.per_credential
    );
}

#[tokio::test]
async fn test_submission_without_credentials_commits_nothing() {
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI"], false),
        EcosystemOutcomes::default(),
        None,
    );

    let ecosystems = resolver(interaction_repository, submission_directory(&[]))
        .resolve(interaction_id, &[], None)
        .await
        .unwrap();

    assert_eq!(None, ecosystems.ecosystem);
    assert!(ecosystems.per_credential.is_empty());
}

#[tokio::test]
async fn test_submission_with_nothing_applicable_fails_when_enforced() {
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI"], true),
        EcosystemOutcomes::default(),
        None,
    );

    let error = resolver(
        interaction_repository,
        submission_directory(&[("EUDI", &[0])]),
    )
    .resolve(
        interaction_id,
        &[submission_artifact(0), submission_artifact(1)],
        None,
    )
    .await
    .unwrap_err();

    assert_eq!(ErrorCode::BR_0476, error.error_code());
    let EcosystemValidationError::NoEcosystemDetected(recorded) = error else {
        panic!("enforcement fails on nothing detected");
    };
    assert_eq!(
        outcomes(&[("EUDI", rejected(EcosystemError::MissingIdentifier))]),
        recorded
    );
}

const USER: &str = "user";

fn recording_resolver(
    interaction_repository: MockInteractionRepository,
    ecosystem_provider: MockEcosystemDirectory,
    history_repository: MockHistoryRepository,
) -> EcosystemResolverProto {
    EcosystemResolverProto::new(
        Arc::new(interaction_repository),
        Arc::new(ecosystem_provider),
        Arc::new(history_repository),
        Arc::new(StaticSessionProvider(Session {
            organisation_id: None,
            permissions: vec![],
            user_id: USER.to_string(),
            actor: None,
        })),
    )
}

#[tokio::test]
async fn test_a_step_records_its_outcome_on_the_credential_or_proof() {
    let organisation = organisation(&["EUDI"], false);
    let organisation_id = organisation.id;
    let (interaction_id, interaction_repository, _) =
        interaction_under_test(organisation, EcosystemOutcomes::default(), None);
    let (history_repository, written) = recording_history();

    recording_resolver(
        interaction_repository,
        ecosystem_directory(&[("EUDI", true)]),
        history_repository,
    )
    .resolve(interaction_id, &[issuer_artifact()], None)
    .await
    .unwrap();

    assert_eq!(
        vec![(issued_credential().into(), outcomes(&[("EUDI", Ok(()))]))],
        recorded_on(&written)
    );
    let event = &written.lock().unwrap()[0];
    assert_eq!(HistoryEntityType::Credential, event.entity_type);
    assert_eq!(Some(organisation_id), event.organisation_id);
    assert_eq!(Some(USER.to_string()), event.user);
}

#[tokio::test]
async fn test_a_step_records_the_outcomes_of_earlier_steps_too() {
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI", "OTHER"], false),
        earlier_outcomes(&["EUDI"], &["OTHER"]),
        None,
    );
    let (history_repository, written) = recording_history();

    recording_resolver(
        interaction_repository,
        ecosystem_directory(&[("EUDI", true)]),
        history_repository,
    )
    .resolve(interaction_id, &[issuer_artifact()], None)
    .await
    .unwrap();

    assert_eq!(
        vec![(
            issued_credential().into(),
            outcomes(&[
                ("EUDI", Ok(())),
                ("OTHER", rejected(EcosystemError::MissingIdentifier))
            ])
        )],
        recorded_on(&written)
    );
}

#[tokio::test]
async fn test_a_failed_step_records_the_reason() {
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI"], true),
        EcosystemOutcomes::default(),
        None,
    );
    let (history_repository, written) = recording_history();

    recording_resolver(
        interaction_repository,
        ecosystem_directory(&[("EUDI", false)]),
        history_repository,
    )
    .resolve(interaction_id, &[issuer_artifact()], None)
    .await
    .unwrap_err();

    assert_eq!(
        vec![(
            issued_credential().into(),
            outcomes(&[("EUDI", rejected(EcosystemError::MissingIdentifier))])
        )],
        recorded_on(&written)
    );
}

#[tokio::test]
async fn test_a_rejection_by_the_committed_ecosystem_is_recorded() {
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI"], false),
        EcosystemOutcomes::default(),
        Some("EUDI"),
    );
    let (history_repository, written) = recording_history();

    recording_resolver(
        interaction_repository,
        ecosystem_directory(&[("EUDI", false)]),
        history_repository,
    )
    .resolve(interaction_id, &[issuer_artifact()], None)
    .await
    .unwrap_err();

    assert_eq!(
        vec![(
            issued_credential().into(),
            outcomes(&[("EUDI", rejected(EcosystemError::MissingIdentifier))])
        )],
        recorded_on(&written)
    );
}

#[tokio::test]
async fn test_nothing_is_recorded_when_no_ecosystem_is_asked() {
    let (interaction_id, interaction_repository, _) =
        interaction_under_test(organisation(&[], false), EcosystemOutcomes::default(), None);
    let (history_repository, written) = recording_history();

    recording_resolver(
        interaction_repository,
        ecosystem_directory(&[]),
        history_repository,
    )
    .resolve(interaction_id, &[issuer_artifact()], None)
    .await
    .unwrap();

    assert!(recorded_on(&written).is_empty());
}

#[tokio::test]
async fn test_a_submission_records_each_credential_on_its_own() {
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI"], false),
        EcosystemOutcomes::default(),
        None,
    );
    let (history_repository, written) = recording_history();

    recording_resolver(
        interaction_repository,
        submission_directory(&[("EUDI", &[0])]),
        history_repository,
    )
    .resolve(
        interaction_id,
        &[submission_artifact(0), submission_artifact(1)],
        None,
    )
    .await
    .unwrap();

    assert_eq!(
        vec![
            (
                submitted_credential(0).into(),
                outcomes(&[("EUDI", Ok(()))])
            ),
            (
                submitted_credential(1).into(),
                outcomes(&[("EUDI", rejected(EcosystemError::MissingIdentifier))])
            ),
        ],
        recorded_on(&written)
    );
}

#[tokio::test]
async fn test_a_failed_submission_records_only_on_the_proof() {
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI"], true),
        EcosystemOutcomes::default(),
        None,
    );
    let (history_repository, written) = recording_history();

    recording_resolver(
        interaction_repository,
        submission_directory(&[("EUDI", &[0])]),
        history_repository,
    )
    .resolve(
        interaction_id,
        &[submission_artifact(0), submission_artifact(1)],
        None,
    )
    .await
    .unwrap_err();

    assert_eq!(
        vec![(
            submitted_proof().into(),
            outcomes(&[("EUDI", rejected(EcosystemError::MissingIdentifier))])
        )],
        recorded_on(&written)
    );
}

#[tokio::test]
async fn test_an_issued_batch_item_records_on_its_batch() {
    let batch = dummy_credential();
    let item = {
        let mut updated_credential = dummy_credential();
        *updated_credential.parent_mut() = Some(batch.to_owned().into());
        updated_credential
    };
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI"], false),
        EcosystemOutcomes::default(),
        None,
    );
    let (history_repository, written) = recording_history();

    recording_resolver(
        interaction_repository,
        ecosystem_directory(&[("EUDI", true)]),
        history_repository,
    )
    .resolve(
        interaction_id,
        &[ProtocolArtifact::HolderIssuanceCredential {
            credential: Cow::Owned(item),
            serialized: "credential".into(),
            credential_configuration_id: "configuration".to_string(),
        }],
        None,
    )
    .await
    .unwrap();

    assert_eq!(
        vec![(batch.common().id.into(), outcomes(&[("EUDI", Ok(()))]))],
        recorded_on(&written)
    );
}

#[tokio::test]
async fn test_a_revalidation_fails_when_the_committed_ecosystem_rejects() {
    let interaction = Interaction {
        organisation: organisation(&["EUDI"], false).into(),
        ecosystem: Some(EcosystemId::from("EUDI")),
        ..interaction(EcosystemOutcomes::default())
    };

    let error = resolver(
        MockInteractionRepository::new(),
        ecosystem_directory(&[("EUDI", false)]),
    )
    .revalidate(&interaction, &[issuer_artifact()])
    .await
    .unwrap_err();

    assert!(matches!(error, EcosystemValidationError::Rejected { .. }));
}

#[tokio::test]
async fn test_a_revalidation_fails_when_the_committed_ecosystem_was_deselected() {
    let interaction = Interaction {
        organisation: organisation(&[], false).into(),
        ecosystem: Some(EcosystemId::from("EUDI")),
        ..interaction(EcosystemOutcomes::default())
    };

    let error = resolver(MockInteractionRepository::new(), ecosystem_directory(&[]))
        .revalidate(&interaction, &[issuer_artifact()])
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        EcosystemValidationError::EcosystemNotPermitted
    ));
}
