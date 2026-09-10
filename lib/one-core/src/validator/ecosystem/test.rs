use std::borrow::Cow;
use std::sync::Arc;

use mockall::predicate::eq;
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::*;
use crate::clock::now_utc;
use crate::model::interaction::{EcosystemDetection, InteractionEcosystems, InteractionType};
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

fn interaction(detection: EcosystemDetection) -> Interaction {
    let mut ecosystem_data = InteractionEcosystems::default();
    ecosystem_data.set_detection(detection);

    Interaction {
        id: Uuid::new_v4().into(),
        created_date: now_utc(),
        last_modified: now_utc(),
        data: None,
        organisation: dummy_organisation(None).into(),
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
        ecosystem: None,
        ecosystem_data,
    }
}

/// sorted: [`remaining_candidates`] makes no promise about ordering
fn applicable(detection: EcosystemDetection, selected: &[&str]) -> Vec<EcosystemId> {
    let mut candidates = remaining_candidates(&interaction(detection), &configuration(selected));
    candidates.sort();
    candidates
}

#[test]
fn test_first_step_starts_from_the_organisation_selection() {
    assert_eq!(
        vec![EcosystemId::from("EUDI"), EcosystemId::from("OTHER")],
        applicable(EcosystemDetection::Pending, &["EUDI", "OTHER"])
    );
}

#[test]
fn test_later_steps_only_reconsult_what_is_left() {
    assert_eq!(
        vec![EcosystemId::from("OTHER")],
        applicable(
            EcosystemDetection::Applicable(vec![EcosystemId::from("OTHER")]),
            &["EUDI", "OTHER", "THIRD"]
        )
    );
}

#[test]
fn test_exhausted_candidates_are_never_widened_again() {
    assert!(applicable(EcosystemDetection::Applicable(vec![]), &["EUDI", "OTHER"]).is_empty());
}

#[test]
fn test_candidates_deselected_by_the_organisation_drop_out() {
    assert_eq!(
        vec![EcosystemId::from("EUDI")],
        applicable(
            EcosystemDetection::Applicable(vec![
                EcosystemId::from("EUDI"),
                EcosystemId::from("OTHER"),
            ]),
            &["EUDI"]
        )
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
    /// the narrowing writes `ecosystem_data`
    applicable: Vec<EcosystemId>,
}

/// An interaction that has narrowed down to `detection` and already carries `committed`, together
/// with a repository recording what a run writes back to it.
fn interaction_under_test(
    organisation: Organisation,
    detection: EcosystemDetection,
    committed: Option<&str>,
) -> (
    InteractionId,
    MockInteractionRepository,
    Arc<std::sync::Mutex<Persisted>>,
) {
    let mut ecosystem_data = InteractionEcosystems::default();
    ecosystem_data.set_detection(detection.to_owned());

    let interaction = Interaction {
        organisation: organisation.into(),
        ecosystem_data,
        ecosystem: committed.map(EcosystemId::from),
        ..interaction(EcosystemDetection::Pending)
    };
    let interaction_id = interaction.id;

    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_get_interaction()
        .returning(move |_, _| Ok(interaction.to_owned()));

    // seeded with what the interaction already carries: an unchanged set is not written again
    let persisted = Arc::new(std::sync::Mutex::new(Persisted {
        committed: None,
        applicable: detection.applicable().to_owned(),
    }));
    let captured = persisted.to_owned();
    interaction_repository
        .expect_update_interaction()
        .returning(move |_, request| {
            let mut captured = captured.lock().unwrap();
            if let Some(ecosystem_data) = request.ecosystem_data {
                let EcosystemDetection::Applicable(applicable) =
                    ecosystem_data.detection().to_owned()
                else {
                    panic!("narrowing never leaves the detection pending");
                };
                captured.applicable = applicable;
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

/// Runs one narrowing round followed by the commit, returning the committed selection and
/// what was persisted as applicable.
async fn detect(
    organisation: Organisation,
    detection: EcosystemDetection,
    verdicts: &[(&str, bool)],
) -> Result<(Option<EcosystemId>, Vec<EcosystemId>), EcosystemValidationError> {
    detect_over(organisation, detection, verdicts, None).await
}

/// As [`detect`], over an interaction that already carries `committed`.
async fn detect_over(
    organisation: Organisation,
    detection: EcosystemDetection,
    verdicts: &[(&str, bool)],
    committed: Option<&str>,
) -> Result<(Option<EcosystemId>, Vec<EcosystemId>), EcosystemValidationError> {
    let (interaction_id, interaction_repository, persisted) =
        interaction_under_test(organisation, detection, committed);

    let selection = resolve_ecosystem(
        interaction_id,
        &issuer_artifact(),
        &interaction_repository,
        &ecosystem_directory(verdicts),
        SelectionRole::Holder,
    )
    .await?;

    let applicable = persisted.lock().unwrap().applicable.to_owned();
    Ok((selection, applicable))
}

/// Commits `selection` on an interaction that already carries `committed`, returning what the
/// run wrote back.
async fn select_over(
    organisation: Organisation,
    verdicts: &[(&str, bool)],
    committed: Option<&str>,
    selection: &str,
) -> Result<Persisted, EcosystemValidationError> {
    let (interaction_id, interaction_repository, persisted) =
        interaction_under_test(organisation, EcosystemDetection::Pending, committed);

    commit_selected_ecosystem(
        interaction_id,
        &issuer_artifact(),
        &EcosystemId::from(selection),
        &interaction_repository,
        &ecosystem_directory(verdicts),
    )
    .await?;

    let persisted = persisted.lock().unwrap();
    Ok(Persisted {
        committed: persisted.committed.to_owned(),
        applicable: persisted.applicable.to_owned(),
    })
}

#[tokio::test]
async fn test_a_user_selection_is_committed_on_the_interaction() {
    let persisted = select_over(
        organisation(&["EUDI", "OTHER"], false),
        &[("EUDI", true)],
        None,
        "EUDI",
    )
    .await
    .unwrap();

    // the selection is a commitment, from the very step it is made
    assert_eq!(Some(Some(EcosystemId::from("EUDI"))), persisted.committed);
    // and it is not autodetection: nothing is recorded as merely applicable
    assert!(persisted.applicable.is_empty());
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
    let (selection, applicable) = detect_over(
        organisation(&["EUDI", "OTHER"], false),
        EcosystemDetection::Pending,
        &[("EUDI", true)],
        Some("EUDI"),
    )
    .await
    .unwrap();

    assert_eq!(Some(EcosystemId::from("EUDI")), selection);
    assert!(applicable.is_empty());
}

#[tokio::test]
async fn test_a_committed_ecosystem_rejecting_the_artifact_fails() {
    let error = detect_over(
        organisation(&["EUDI"], false),
        EcosystemDetection::Pending,
        &[("EUDI", false)],
        Some("EUDI"),
    )
    .await
    .unwrap_err();

    assert_eq!(ErrorCode::BR_0477, error.error_code());
}

#[tokio::test]
async fn test_every_accepting_ecosystem_stays_a_candidate() {
    let (selection, applicable) = detect(
        organisation(&["EUDI", "OTHER"], false),
        EcosystemDetection::Pending,
        &[("EUDI", true), ("OTHER", true)],
    )
    .await
    .unwrap();

    // narrowing may not stop at the first ecosystem that happens to validate
    assert_eq!(
        vec![EcosystemId::from("EUDI"), EcosystemId::from("OTHER")],
        applicable
    );
    assert_eq!(Some(EcosystemId::from("EUDI")), selection);
}

#[tokio::test]
async fn test_rejecting_ecosystem_is_dropped_from_the_candidates() {
    let (selection, applicable) = detect(
        organisation(&["EUDI", "OTHER"], false),
        EcosystemDetection::Pending,
        &[("EUDI", false), ("OTHER", true)],
    )
    .await
    .unwrap();

    assert_eq!(vec![EcosystemId::from("OTHER")], applicable);
    assert_eq!(Some(EcosystemId::from("OTHER")), selection);
}

#[tokio::test]
async fn test_narrowing_never_reconsiders_a_dropped_ecosystem() {
    let (_, applicable) = detect(
        organisation(&["EUDI", "OTHER"], false),
        EcosystemDetection::Applicable(vec![EcosystemId::from("OTHER")]),
        &[("OTHER", true)],
    )
    .await
    .unwrap();

    // `EUDI` would accept, but it is no longer a candidate and is never asked
    assert_eq!(vec![EcosystemId::from("OTHER")], applicable);
}

#[tokio::test]
async fn test_no_applicable_ecosystem_assigns_nothing_when_not_enforced() {
    let (selection, applicable) = detect(
        organisation(&["EUDI"], false),
        EcosystemDetection::Pending,
        &[("EUDI", false)],
    )
    .await
    .unwrap();

    assert_eq!(None, selection);
    assert!(applicable.is_empty());
}

#[tokio::test]
async fn test_no_applicable_ecosystem_fails_when_enforced() {
    let error = detect(
        organisation(&["EUDI"], true),
        EcosystemDetection::Pending,
        &[("EUDI", false)],
    )
    .await
    .unwrap_err();

    assert_eq!(ErrorCode::BR_0476, error.error_code());
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
        EcosystemDetection::Pending,
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
}

#[tokio::test]
async fn test_submission_committed_ecosystem_rejecting_any_credential_fails() {
    // the commitment leaves no room for narrowing, not even per credential
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI"], false),
        EcosystemDetection::Pending,
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
        EcosystemDetection::Pending,
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
        persisted.lock().unwrap().applicable
    );
}

#[tokio::test]
async fn test_submission_partially_validating_ecosystem_is_not_committed() {
    // only `OTHER` validates the whole submission: it wins, and all credentials carry it
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI", "OTHER"], false),
        EcosystemDetection::Pending,
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
async fn test_submission_credential_trust_survives_non_complying_other_credentials() {
    // nothing validates the whole submission: no commit, trust stays per credential
    let (interaction_id, interaction_repository, persisted) = interaction_under_test(
        organisation(&["EUDI", "OTHER"], false),
        EcosystemDetection::Pending,
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
    assert!(persisted.lock().unwrap().applicable.is_empty());
}

#[tokio::test]
async fn test_submission_credential_complying_with_no_ecosystem_gets_no_trust() {
    let (interaction_id, interaction_repository, _) = interaction_under_test(
        organisation(&["EUDI"], false),
        EcosystemDetection::Pending,
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
        EcosystemDetection::Pending,
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
        EcosystemDetection::Pending,
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
}
