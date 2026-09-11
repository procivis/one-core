use std::borrow::Cow;
use std::sync::Arc;

use mockall::predicate::eq;
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::*;
use crate::clock::now_utc;
use crate::model::interaction::{InteractionEcosystems, InteractionType};
use crate::model::organisation::Organisation;
use crate::provider::credential_formatter::model::{IdentifierDetails, PublicKeySource};
use crate::provider::ecosystem::MockEcosystem;
use crate::provider::ecosystem::directory::MockEcosystemDirectory;
use crate::provider::ecosystem::error::EcosystemError;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::service::test_utilities::{dummy_credential, dummy_organisation};

fn configuration(selected: &[&str]) -> OrganisationConfiguration {
    OrganisationConfiguration {
        selected_ecosystems: selected.iter().map(|id| EcosystemId::from(*id)).collect(),
        ..Default::default()
    }
}

fn interaction(narrowed_to: EcosystemOutcomes) -> Interaction {
    let mut ecosystem_data = InteractionEcosystems::default();
    ecosystem_data.merge_outcomes(&narrowed_to);

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

/// sorted: [`remaining_candidates`] makes no promise about ordering
fn applicable(narrowed_to: EcosystemOutcomes, selected: &[&str]) -> Vec<EcosystemId> {
    let mut candidates = remaining_candidates(&interaction(narrowed_to), &configuration(selected));
    candidates.sort();
    candidates
}

/// State left by an earlier step. `kept` validated the artifact, `dropped` did not.
fn narrowed_to(kept: &[&str], dropped: &[&str]) -> EcosystemOutcomes {
    let mut narrowed = EcosystemOutcomes::default();
    for ecosystem in kept {
        narrowed.record(EcosystemId::from(*ecosystem), Ok(()));
    }
    for ecosystem in dropped {
        narrowed.record(
            EcosystemId::from(*ecosystem),
            rejected(EcosystemError::MissingIdentifier),
        );
    }
    narrowed
}

#[test]
fn test_first_step_starts_from_the_organisation_selection() {
    assert_eq!(
        vec![EcosystemId::from("EUDI"), EcosystemId::from("OTHER")],
        applicable(EcosystemOutcomes::default(), &["EUDI", "OTHER"])
    );
}

#[test]
fn test_later_steps_only_reconsult_what_is_left() {
    assert_eq!(
        vec![EcosystemId::from("OTHER")],
        applicable(
            narrowed_to(&["OTHER"], &["EUDI"]),
            &["EUDI", "OTHER", "THIRD"]
        )
    );
}

#[test]
fn test_exhausted_candidates_are_never_widened_again() {
    assert!(applicable(narrowed_to(&[], &["EUDI", "OTHER"]), &["EUDI", "OTHER"]).is_empty());
}

#[test]
fn test_candidates_deselected_by_the_organisation_drop_out() {
    assert_eq!(
        vec![EcosystemId::from("EUDI")],
        applicable(narrowed_to(&["EUDI", "OTHER"], &[]), &["EUDI"])
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
                            .then_some(())
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
            enforce_ecosystem_as_holder: enforced,
            enforce_ecosystem_as_verifier: enforced,
            ..Default::default()
        },
        ..dummy_organisation(None)
    }
}

/// What a run wrote back to the interaction.
#[derive(Debug, Default)]
struct Persisted {
    /// the commit writes `ecosystem`
    committed: Option<Option<EcosystemId>>,
    /// what is still trusted here is what narrowing still allows
    outcomes: EcosystemOutcomes,
}

impl Persisted {
    fn applicable(&self) -> Vec<EcosystemId> {
        self.outcomes.applicable()
    }
}

/// An interaction in the given state, plus a repository that records what a run writes back.
fn interaction_under_test(
    organisation: Organisation,
    narrowed_to: EcosystemOutcomes,
    committed: Option<&str>,
) -> (
    InteractionId,
    MockInteractionRepository,
    Arc<std::sync::Mutex<Persisted>>,
) {
    let interaction = Interaction {
        organisation: organisation.into(),
        ecosystem: committed.map(EcosystemId::from),
        ..interaction(narrowed_to.to_owned())
    };
    let interaction_id = interaction.id;

    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_get_interaction()
        .returning(move |_, _| Ok(interaction.to_owned()));

    // seeded with what the interaction already carries: an unchanged set is not written again
    let persisted = Arc::new(std::sync::Mutex::new(Persisted {
        committed: None,
        outcomes: narrowed_to,
    }));
    let captured = persisted.to_owned();
    interaction_repository
        .expect_update_interaction()
        .returning(move |_, request| {
            let mut captured = captured.lock().unwrap();
            if let Some(ecosystem_data) = request.ecosystem_data {
                captured.outcomes = ecosystem_data.outcomes().to_owned();
            }
            if let Some(committed) = request.ecosystem {
                captured.committed = Some(committed);
            }
            Ok(())
        });

    (interaction_id, interaction_repository, persisted)
}

fn issuer_artifact() -> ProtocolArtifact<'static> {
    ProtocolArtifact::IssuerIssuance {
        wallet_provider: PublicKeySource::X5c { x5c: &[] },
        source: crate::provider::ecosystem::model::WalletProviderAttestationSource::WalletInstanceAttestation,
    }
}

fn rejected(error: impl ErrorCodeMixin) -> Result<(), HistoryErrorMetadata> {
    Err(error.into())
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

/// Runs one narrowing round and the commit after it. Returns the resolution and what was
/// persisted as applicable.
async fn detect(
    organisation: Organisation,
    narrowed_to: EcosystemOutcomes,
    verdicts: &[(&str, bool)],
) -> Result<(EcosystemResolution, Vec<EcosystemId>), EcosystemValidationError> {
    detect_over(organisation, narrowed_to, verdicts, None).await
}

/// As [`detect`], over an interaction that already carries `committed`.
async fn detect_over(
    organisation: Organisation,
    narrowed_to: EcosystemOutcomes,
    verdicts: &[(&str, bool)],
    committed: Option<&str>,
) -> Result<(EcosystemResolution, Vec<EcosystemId>), EcosystemValidationError> {
    let (interaction_id, interaction_repository, persisted) =
        interaction_under_test(organisation, narrowed_to, committed);

    let resolution = resolve_ecosystem(
        interaction_id,
        &issuer_artifact(),
        &interaction_repository,
        &ecosystem_directory(verdicts),
        SelectionRole::Holder,
    )
    .await?;

    let applicable = persisted.lock().unwrap().applicable();
    Ok((resolution, applicable))
}

/// Commits `selection` on an interaction that already carries `committed`. Returns the outcome
/// and what the run wrote back.
async fn select_over(
    organisation: Organisation,
    verdicts: &[(&str, bool)],
    committed: Option<&str>,
    selection: &str,
) -> Result<(EcosystemOutcomes, Persisted), EcosystemValidationError> {
    let (interaction_id, interaction_repository, persisted) =
        interaction_under_test(organisation, EcosystemOutcomes::default(), committed);

    let outcomes = commit_selected_ecosystem(
        interaction_id,
        &issuer_artifact(),
        &EcosystemId::from(selection),
        &interaction_repository,
        &ecosystem_directory(verdicts),
    )
    .await?;

    let persisted = persisted.lock().unwrap();
    Ok((
        outcomes,
        Persisted {
            committed: persisted.committed.to_owned(),
            outcomes: persisted.outcomes.to_owned(),
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

    // the selection is a commitment, from the very step it is made
    assert_eq!(Some(Some(EcosystemId::from("EUDI"))), persisted.committed);
    // and it is not autodetection, so no other ecosystem is consulted
    assert_eq!(vec![EcosystemId::from("EUDI")], persisted.applicable());
    assert_eq!(
        EcosystemOutcomes::validated(EcosystemId::from("EUDI")),
        outcomes
    );
    // a committed interaction still carries the outcome of the step
    assert_eq!(outcomes, persisted.outcomes);
}

#[tokio::test]
async fn test_a_step_carries_its_outcomes_on_the_interaction() {
    // trust is resolved here but only reported when the interaction ends, so it has to survive
    // on the interaction until then
    let (interaction_id, interaction_repository, persisted) = interaction_under_test(
        organisation(&["EUDI", "OTHER"], false),
        EcosystemOutcomes::default(),
        None,
    );

    resolve_ecosystem(
        interaction_id,
        &issuer_artifact(),
        &interaction_repository,
        &ecosystem_directory(&[("EUDI", false), ("OTHER", true)]),
        SelectionRole::Holder,
    )
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
    // a selection is not a candidate: it may not be silently dropped the way narrowing drops one
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
    // committing is a one-time operation: a step after the commit cannot change the outcome and
    // has no business calling this
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
    // `OTHER` is selected by the organisation but never consulted: the mock directory has no
    // expectation for it and would panic if it were
    let (resolution, applicable) = detect_over(
        organisation(&["EUDI", "OTHER"], false),
        EcosystemOutcomes::default(),
        &[("EUDI", true)],
        Some("EUDI"),
    )
    .await
    .unwrap();

    assert_eq!(Some(EcosystemId::from("EUDI")), resolution.committed);
    // only the commitment is ever recorded, so `OTHER` never becomes a candidate again
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

    // narrowing may not stop at the first ecosystem that happens to validate
    assert_eq!(
        vec![EcosystemId::from("EUDI"), EcosystemId::from("OTHER")],
        applicable
    );
    assert_eq!(Some(EcosystemId::from("EUDI")), resolution.committed);
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
    assert_eq!(Some(EcosystemId::from("OTHER")), resolution.committed);
    // dropped, and the reason is kept
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

    let resolution = resolve_ecosystem(
        interaction_id,
        &issuer_artifact(),
        &interaction_repository,
        &directory,
        SelectionRole::Holder,
    )
    .await
    .unwrap();

    assert_eq!(Some(EcosystemId::from("OTHER")), resolution.committed);
    assert_eq!(
        outcomes(&[("EUDI", rejected(unavailable())), ("OTHER", Ok(()))]),
        resolution.outcomes
    );
}

#[tokio::test]
async fn test_narrowing_never_reconsiders_a_dropped_ecosystem() {
    let (_, applicable) = detect(
        organisation(&["EUDI", "OTHER"], false),
        narrowed_to(&["OTHER"], &["EUDI"]),
        &[("OTHER", true)],
    )
    .await
    .unwrap();

    // `EUDI` would accept, but it is no longer a candidate and is never asked
    assert_eq!(vec![EcosystemId::from("OTHER")], applicable);
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

    assert_eq!(None, resolution.committed);
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
    // the failure carries why each candidate was dropped
    let EcosystemValidationError::NoEcosystemDetected(recorded) = error else {
        panic!("enforcement fails on nothing detected");
    };
    assert_eq!(
        outcomes(&[("EUDI", rejected(EcosystemError::MissingIdentifier))]),
        recorded
    );
}

// Submission tests: the submitted credentials are numbered, `submission_artifact(0)` is
// credential 0, and `submission_directory(&[("EUDI", &[0])])` is an ecosystem `EUDI` that
// accepts credential 0 and rejects all others.

/// An artifact of the submitted credential at `index`, identifiable by its issuer.
fn submission_artifact(index: usize) -> ProtocolArtifact<'static> {
    ProtocolArtifact::VerifierSubmission {
        credential: Cow::Owned(dummy_credential()),
        issuer_details: Cow::Owned(submission_issuer(index)),
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
                            .then_some(())
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

    let ecosystems = resolve_credential_ecosystems(
        interaction_id,
        &[submission_artifact(0), submission_artifact(1)],
        &interaction_repository,
        &submission_directory(&[("EUDI", &[0, 1])]),
        SelectionRole::Verifier,
    )
    .await
    .unwrap();

    assert_eq!(Some(EcosystemId::from("EUDI")), ecosystems.committed);
    assert_eq!(
        vec![
            Some(EcosystemId::from("EUDI")),
            Some(EcosystemId::from("EUDI"))
        ],
        ecosystems.per_credential
    );
    assert_eq!(
        vec![EcosystemOutcomes::validated(EcosystemId::from("EUDI")); 2],
        ecosystems.outcomes
    );
}

#[tokio::test]
async fn test_submission_committed_ecosystem_rejecting_any_credential_fails() {
    // the commitment leaves no room for narrowing, not even per credential
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI"], false),
        EcosystemOutcomes::default(),
        Some("EUDI"),
    );

    let error = resolve_credential_ecosystems(
        interaction_id,
        &[submission_artifact(0), submission_artifact(1)],
        &interaction_repository,
        &submission_directory(&[("EUDI", &[0])]),
        SelectionRole::Verifier,
    )
    .await
    .unwrap_err();

    assert_eq!(ErrorCode::BR_0477, error.error_code());
}

#[tokio::test]
async fn test_submission_ecosystem_validating_every_credential_is_committed() {
    let (interaction_id, interaction_repository, persisted) = interaction_under_test(
        organisation(&["EUDI"], false),
        EcosystemOutcomes::default(),
        None,
    );

    let ecosystems = resolve_credential_ecosystems(
        interaction_id,
        &[submission_artifact(0), submission_artifact(1)],
        &interaction_repository,
        &submission_directory(&[("EUDI", &[0, 1])]),
        SelectionRole::Verifier,
    )
    .await
    .unwrap();

    assert_eq!(Some(EcosystemId::from("EUDI")), ecosystems.committed);
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
    // only `OTHER` validates the whole submission: it wins, and all credentials carry it
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI", "OTHER"], false),
        EcosystemOutcomes::default(),
        None,
    );

    let ecosystems = resolve_credential_ecosystems(
        interaction_id,
        &[submission_artifact(0), submission_artifact(1)],
        &interaction_repository,
        &submission_directory(&[("EUDI", &[0]), ("OTHER", &[0, 1])]),
        SelectionRole::Verifier,
    )
    .await
    .unwrap();

    assert_eq!(Some(EcosystemId::from("OTHER")), ecosystems.committed);
    assert_eq!(
        vec![
            Some(EcosystemId::from("OTHER")),
            Some(EcosystemId::from("OTHER"))
        ],
        ecosystems.per_credential
    );
}

#[tokio::test]
async fn test_submission_records_what_each_ecosystem_made_of_each_credential() {
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI", "OTHER"], false),
        EcosystemOutcomes::default(),
        None,
    );

    let ecosystems = resolve_credential_ecosystems(
        interaction_id,
        &[submission_artifact(0), submission_artifact(1)],
        &interaction_repository,
        &submission_directory(&[("EUDI", &[1]), ("OTHER", &[0, 1])]),
        SelectionRole::Verifier,
    )
    .await
    .unwrap();

    assert_eq!(Some(EcosystemId::from("OTHER")), ecosystems.committed);
    assert_eq!(
        vec![
            outcomes(&[
                ("EUDI", rejected(EcosystemError::MissingIdentifier)),
                ("OTHER", Ok(())),
            ]),
            // `EUDI` already failed on credential 0, so it is not asked about credential 1
            outcomes(&[("OTHER", Ok(()))]),
        ],
        ecosystems.outcomes
    );
}

#[tokio::test]
async fn test_submission_credential_trust_survives_non_complying_other_credentials() {
    // nothing validates the whole submission: no commit, trust stays per credential
    let (interaction_id, interaction_repository, persisted) = interaction_under_test(
        organisation(&["EUDI", "OTHER"], false),
        EcosystemOutcomes::default(),
        None,
    );

    let ecosystems = resolve_credential_ecosystems(
        interaction_id,
        &[submission_artifact(0), submission_artifact(1)],
        &interaction_repository,
        &submission_directory(&[("EUDI", &[0]), ("OTHER", &[1])]),
        SelectionRole::Verifier,
    )
    .await
    .unwrap();

    assert_eq!(None, ecosystems.committed);
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
async fn test_submission_credential_complying_with_no_ecosystem_gets_no_trust() {
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI"], false),
        EcosystemOutcomes::default(),
        None,
    );

    let ecosystems = resolve_credential_ecosystems(
        interaction_id,
        &[submission_artifact(0), submission_artifact(1)],
        &interaction_repository,
        &submission_directory(&[("EUDI", &[0])]),
        SelectionRole::Verifier,
    )
    .await
    .unwrap();

    assert_eq!(None, ecosystems.committed);
    assert_eq!(
        vec![Some(EcosystemId::from("EUDI")), None],
        ecosystems.per_credential
    );
}

#[tokio::test]
async fn test_submission_without_credentials_commits_nothing() {
    // nothing submitted: no candidate is consulted, nothing is committed
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI"], false),
        EcosystemOutcomes::default(),
        None,
    );

    let ecosystems = resolve_credential_ecosystems(
        interaction_id,
        &[],
        &interaction_repository,
        &submission_directory(&[]),
        SelectionRole::Verifier,
    )
    .await
    .unwrap();

    assert_eq!(None, ecosystems.committed);
    assert!(ecosystems.per_credential.is_empty());
}

#[tokio::test]
async fn test_submission_with_nothing_applicable_fails_when_enforced() {
    // per-credential trust does not satisfy enforcement: the interaction needs an ecosystem
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI"], true),
        EcosystemOutcomes::default(),
        None,
    );

    let error = resolve_credential_ecosystems(
        interaction_id,
        &[submission_artifact(0), submission_artifact(1)],
        &interaction_repository,
        &submission_directory(&[("EUDI", &[0])]),
        SelectionRole::Verifier,
    )
    .await
    .unwrap_err();

    assert_eq!(ErrorCode::BR_0476, error.error_code());
    // the failure merges the credentials: `EUDI` rejected credential 1
    let EcosystemValidationError::NoEcosystemDetected(recorded) = error else {
        panic!("enforcement fails on nothing detected");
    };
    assert_eq!(
        outcomes(&[("EUDI", rejected(EcosystemError::MissingIdentifier))]),
        recorded
    );
}
