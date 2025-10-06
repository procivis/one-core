use one_core::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use one_core::service::credential::dto::{
    CredentialDetailResponseDTO, CredentialFilterValue, DetailCredentialClaimValueResponseDTO,
};
use one_core::service::error::{BusinessLogicError, ServiceError};
use one_dto_mapper::{convert_inner, try_convert_inner};

use super::dto::{
    CredentialDetailClaimValueResponseRestDTO, CredentialsFilterQueryParamsRest,
    GetCredentialResponseRestDTO, SearchType,
};
use crate::dto::common::ExactColumn;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::mapper::MapperError;

impl TryFrom<CredentialsFilterQueryParamsRest> for ListFilterCondition<CredentialFilterValue> {
    type Error = ServiceError;

    fn try_from(value: CredentialsFilterQueryParamsRest) -> Result<Self, Self::Error> {
        if value.name.is_some() && value.search_type.is_some() && value.search_text.is_some() {
            return Err(BusinessLogicError::GeneralInputValidationError.into());
        }

        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let organisation_id = CredentialFilterValue::OrganisationId(
            fallback_organisation_id_from_session(value.organisation_id)?,
        )
        .condition();

        let name = value.name.map(|name| {
            CredentialFilterValue::CredentialSchemaName(StringMatch {
                r#match: get_string_match_type(ExactColumn::Name),
                value: name,
            })
        });

        let profile = value.profile.map(|profile| {
            CredentialFilterValue::Profile(StringMatch {
                r#match: StringMatchType::Equals,
                value: profile,
            })
        });

        let search_filters = match (value.search_text, value.search_type) {
            (Some(search_test), Some(search_type)) => {
                organisation_id
                    & ListFilterCondition::Or(
                        search_type
                            .into_iter()
                            .map(|filter| {
                                match filter {
                                    SearchType::ClaimName => {
                                        CredentialFilterValue::ClaimName(StringMatch {
                                            r#match: StringMatchType::Contains,
                                            value: search_test.clone(),
                                        })
                                    }
                                    SearchType::ClaimValue => {
                                        CredentialFilterValue::ClaimValue(StringMatch {
                                            r#match: StringMatchType::Contains,
                                            value: search_test.clone(),
                                        })
                                    }
                                    SearchType::CredentialSchemaName => {
                                        CredentialFilterValue::CredentialSchemaName(StringMatch {
                                            r#match: StringMatchType::Contains,
                                            value: search_test.clone(),
                                        })
                                    }
                                }
                                .condition()
                            })
                            .collect(),
                    )
            }
            _ => organisation_id,
        };

        let role = value
            .role
            .map(|role| CredentialFilterValue::Role(role.into()));

        let credential_ids = value.ids.map(CredentialFilterValue::CredentialIds);

        let credential_schema_ids = value
            .credential_schema_ids
            .map(CredentialFilterValue::CredentialSchemaIds);

        let states = value.status.map(|values| {
            CredentialFilterValue::State(values.into_iter().map(|status| status.into()).collect())
        });

        let created_date_after = value.created_date_after.map(|date| {
            CredentialFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            CredentialFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = value.last_modified_after.map(|date| {
            CredentialFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = value.last_modified_before.map(|date| {
            CredentialFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let issuance_date_after = value.issuance_date_after.map(|date| {
            CredentialFilterValue::IssuanceDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let issuance_date_before = value.issuance_date_before.map(|date| {
            CredentialFilterValue::IssuanceDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let revocation_date_after = value.revocation_date_after.map(|date| {
            CredentialFilterValue::RevocationDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let revocation_date_before = value.revocation_date_before.map(|date| {
            CredentialFilterValue::RevocationDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        Ok(search_filters
            & name
            & role
            & credential_ids
            & credential_schema_ids
            & states
            & profile
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
            & issuance_date_after
            & issuance_date_before
            & revocation_date_after
            & revocation_date_before)
    }
}

impl<IN, OUT: From<IN>> TryFrom<CredentialDetailResponseDTO<IN>>
    for GetCredentialResponseRestDTO<OUT>
{
    type Error = MapperError;

    fn try_from(value: CredentialDetailResponseDTO<IN>) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id.into(),
            created_date: value.created_date,
            issuance_date: value.issuance_date,
            revocation_date: value.revocation_date,
            state: value.state.into(),
            last_modified: value.last_modified,
            schema: value.schema.into(),
            issuer: convert_inner(value.issuer),
            issuer_certificate: try_convert_inner(value.issuer_certificate)?,
            claims: convert_inner(value.claims),
            redirect_uri: value.redirect_uri,
            role: value.role.into(),
            lvvc_issuance_date: value.lvvc_issuance_date,
            suspend_end_date: value.suspend_end_date,
            mdoc_mso_validity: convert_inner(value.mdoc_mso_validity),
            holder: convert_inner(value.holder),
            protocol: value.protocol,
            profile: value.profile,
            wallet_unit_attestation: convert_inner(value.wallet_unit_attestation),
        })
    }
}

impl<IN, OUT: From<IN>> From<DetailCredentialClaimValueResponseDTO<IN>>
    for CredentialDetailClaimValueResponseRestDTO<OUT>
{
    fn from(value: DetailCredentialClaimValueResponseDTO<IN>) -> Self {
        match value {
            DetailCredentialClaimValueResponseDTO::Boolean(val) => Self::Boolean(val),
            DetailCredentialClaimValueResponseDTO::Float(val) => Self::Float(val),
            DetailCredentialClaimValueResponseDTO::Integer(val) => Self::Integer(val),
            DetailCredentialClaimValueResponseDTO::String(val) => Self::String(val),
            DetailCredentialClaimValueResponseDTO::Nested(nested) => {
                Self::Nested(convert_inner(nested))
            }
        }
    }
}
