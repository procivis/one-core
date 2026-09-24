use shared_types::EcosystemId;

use crate::error::{ErrorCode, ErrorCodeMixin, ErrorData, NestedError};
use crate::model::ecosystem::EcosystemOutcomes;
use crate::model::organisation::{Organisation, OrganisationConfiguration};
use crate::provider::ProviderExt;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::ecosystem::error::EcosystemError;

#[derive(thiserror::Error, Debug)]
pub(crate) enum EcosystemValidationError {
    #[error("No ecosystem selected")]
    NoEcosystemSelected,
    /// no candidate validated the artifact; the reason each gave is kept
    #[error("No ecosystem detected")]
    NoEcosystemDetected(EcosystemOutcomes),
    #[error("Ecosystem not permitted")]
    EcosystemNotPermitted,
    #[error("Ecosystem `{0}` already committed on this interaction")]
    EcosystemAlreadyCommitted(EcosystemId),
    /// the committed ecosystem rejected the artifact
    #[error("Ecosystem `{ecosystem}` rejected the artifact: {source}")]
    Rejected {
        ecosystem: EcosystemId,
        source: EcosystemError,
    },

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for EcosystemValidationError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::NoEcosystemSelected | Self::NoEcosystemDetected(_) => ErrorCode::BR_0476,
            Self::EcosystemNotPermitted => ErrorCode::BR_0475,
            Self::EcosystemAlreadyCommitted(_) => ErrorCode::BR_0477,
            Self::Rejected { source, .. } => source.error_code(),
            Self::Nested(nested) => nested.error_code(),
        }
    }

    fn error_data(&self) -> Option<ErrorData> {
        match self {
            Self::NoEcosystemDetected(outcomes) => {
                Some(ErrorData::EcosystemsResolved(outcomes.to_owned()))
            }
            Self::Rejected { ecosystem, source } => Some(ErrorData::EcosystemsResolved(
                EcosystemOutcomes::rejected(ecosystem.to_owned(), source),
            )),
            Self::Nested(nested) => nested.error_data(),
            _ => None,
        }
    }
}

/// check user selection of ecosystem, always allows no selection (e.g. for later possible autodetection)
pub(crate) fn validate_ecosystem_selection_allow_not_set(
    user_selection: Option<&EcosystemId>,
    organisation: &Organisation,
    ecosystem_provider: &dyn EcosystemDirectory,
) -> Result<(), EcosystemValidationError> {
    if let Some(ecosystem_id) = user_selection {
        let ecosystem = ecosystem_provider.get(ecosystem_id)?;
        ecosystem.ensure_enabled()?;

        if !organisation
            .configuration
            .selected_ecosystems
            .contains(ecosystem_id)
        {
            return Err(EcosystemValidationError::EcosystemNotPermitted);
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum SelectionRole {
    Issuer,
    Verifier,
}

/// checks ecosystem selection, enforcing selection based on organisation config
pub(crate) fn validate_ecosystem_selection_final(
    user_selection: Option<&EcosystemId>,
    organisation: &Organisation,
    ecosystem_provider: &dyn EcosystemDirectory,
    role: SelectionRole,
) -> Result<(), EcosystemValidationError> {
    if user_selection.is_some() {
        return validate_ecosystem_selection_allow_not_set(
            user_selection,
            organisation,
            ecosystem_provider,
        );
    }

    if ecosystem_enforced(&organisation.configuration, role) {
        return Err(EcosystemValidationError::NoEcosystemSelected);
    }

    Ok(())
}

fn ecosystem_enforced(configuration: &OrganisationConfiguration, role: SelectionRole) -> bool {
    match role {
        SelectionRole::Issuer => configuration.enforce_ecosystem_as_issuer,
        SelectionRole::Verifier => configuration.enforce_ecosystem_as_verifier,
    }
}
