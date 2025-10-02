use one_core::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, ValueComparison,
};
use one_core::provider::verification_protocol::dto::ApplicableCredentialOrFailureHintEnum;
use one_core::service::error::ServiceError;
use one_core::service::proof::dto::ProofFilterValue;
use one_dto_mapper::{convert_inner, try_convert_inner};

use super::dto::{ApplicableCredentialOrFailureHintRestEnum, ProofsFilterQueryParamsRest};
use crate::dto::common::ExactColumn;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::mapper::MapperError;

impl TryFrom<ProofsFilterQueryParamsRest> for ListFilterCondition<ProofFilterValue> {
    type Error = ServiceError;

    fn try_from(value: ProofsFilterQueryParamsRest) -> Result<Self, Self::Error> {
        let exact = value.exact.unwrap_or_default();

        let organisation_id = ProofFilterValue::OrganisationId(
            fallback_organisation_id_from_session(value.organisation_id)?,
        )
        .condition();

        let name = value.name.map(|name| {
            let filter = if exact.contains(&ExactColumn::Name) {
                StringMatch::equals(name)
            } else {
                StringMatch::starts_with(name)
            };

            ProofFilterValue::Name(filter)
        });

        let proof_states = value
            .proof_states
            .map(|proof_states| ProofFilterValue::ProofStates(convert_inner(proof_states)));
        let proof_roles = value
            .proof_roles
            .map(|proof_roles| ProofFilterValue::ProofRoles(convert_inner(proof_roles)));

        let proof_ids = value.ids.map(ProofFilterValue::ProofIds);
        let proof_schema_ids = value.proof_schema_ids.map(ProofFilterValue::ProofSchemaIds);

        let profile = value
            .profile
            .map(|profile| ProofFilterValue::Profile(StringMatch::equals(profile)));

        let created_date_after = value.created_date_after.map(|date| {
            ProofFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            ProofFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = value.last_modified_after.map(|date| {
            ProofFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = value.last_modified_before.map(|date| {
            ProofFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let requested_date_after = value.requested_date_after.map(|date| {
            ProofFilterValue::RequestedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let requested_date_before = value.requested_date_before.map(|date| {
            ProofFilterValue::RequestedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let completed_date_after = value.completed_date_after.map(|date| {
            ProofFilterValue::CompletedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let completed_date_before = value.completed_date_before.map(|date| {
            ProofFilterValue::CompletedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        Ok(organisation_id
            & name
            & proof_states
            & proof_roles
            & proof_schema_ids
            & proof_ids
            & profile
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
            & requested_date_after
            & requested_date_before
            & completed_date_after
            & completed_date_before)
    }
}

impl TryFrom<ApplicableCredentialOrFailureHintEnum> for ApplicableCredentialOrFailureHintRestEnum {
    type Error = MapperError;

    fn try_from(value: ApplicableCredentialOrFailureHintEnum) -> Result<Self, Self::Error> {
        Ok(match value {
            ApplicableCredentialOrFailureHintEnum::ApplicableCredentials {
                applicable_credentials,
            } => Self::ApplicableCredentials {
                applicable_credentials: try_convert_inner(applicable_credentials)?,
            },
            ApplicableCredentialOrFailureHintEnum::FailureHint { failure_hint } => {
                Self::FailureHint {
                    failure_hint: Box::new(convert_inner(*failure_hint)),
                }
            }
        })
    }
}
